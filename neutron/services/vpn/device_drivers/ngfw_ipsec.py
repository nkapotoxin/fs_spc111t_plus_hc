# Copyright 2013, Nachi Ueno, NTT I3, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
import abc
import copy
import os
import re
import shutil

import jinja2
import netaddr
from oslo.config import cfg
from oslo import messaging
import six
import json
from FSComponentUtil import crypt

from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils

from neutron.common import utils as common_utils
from neutron.common import rpc as n_rpc
from neutron import context
from neutron.openstack.common import lockutils
from neutron.openstack.common import log as logging
from neutron.openstack.common import loopingcall
from neutron.plugins.common import constants
from neutron.plugins.common import utils as plugin_utils
from neutron.services.vpn.common import topics
from neutron.services.vpn import device_drivers
from neutron.services.firewall import ngfw_plugin
from neutron.services.firewall.agents.ngfw import ngfw_api
from neutron.services.firewall.agents.ngfw import ngfw_utils
from neutron.services.vpn.device_drivers.template.ngfw import template as ngfw_template
import xmltodict
from netaddr import IPNetwork


LOG = logging.getLogger(__name__)
TEMPLATE_PATH = os.path.dirname(__file__)

ipsec_opts = [
    cfg.IntOpt('ipsec_status_check_interval',
               default=60,
               help=_("Interval for checking ipsec status"))
]
cfg.CONF.register_opts(ipsec_opts, 'ipsec')


JINJA_ENV = None

STATUS_MAP = {
    'negotiating': constants.DOWN,
    'waiting': constants.PENDING_CREATE,
    'succeed': constants.ACTIVE,
    'failure': constants.DOWN,
    'error': constants.ERROR,
    'pending_delete': constants.PENDING_DELETE
}

IPSEC_CONNS = 'ipsec_site_connections'

FAIL_CODE = 400
SUCCESS_CODE = 200
VPN_ACL_ID_START = 3000
NOCONTENT = 204
VPN_ACL_ID_END = 4000
VPN_ACL_NUMBERS = set(range(VPN_ACL_ID_START, VPN_ACL_ID_END))

def _get_template(template_file):
    global JINJA_ENV
    if not JINJA_ENV:
        templateLoader = jinja2.FileSystemLoader(searchpath="/")
        JINJA_ENV = jinja2.Environment(loader=templateLoader)
    return JINJA_ENV.get_template(template_file)


@six.add_metaclass(abc.ABCMeta)
class BaseSwanProcess():
    """Swan Family Process Manager

    This class manages start/restart/stop ipsec process.
    This class create/delete config template
    """

    binary = "ipsec"
    CONFIG_DIRS = [
        'var/run',
        'log',
        'etc',
        'etc/ipsec.d/aacerts',
        'etc/ipsec.d/acerts',
        'etc/ipsec.d/cacerts',
        'etc/ipsec.d/certs',
        'etc/ipsec.d/crls',
        'etc/ipsec.d/ocspcerts',
        'etc/ipsec.d/policies',
        'etc/ipsec.d/private',
        'etc/ipsec.d/reqs',
        'etc/pki/nssdb/'
    ]

    DIALECT_MAP = {
        "3des": "3des",
        "aes-128": "aes128",
        "aes-256": "aes256",
        "aes-192": "aes192",
        "group2": "modp1024",
        "group5": "modp1536",
        "group14": "modp2048",
        "group15": "modp3072",
        "bi-directional": "start",
        "response-only": "add",
        "v2": "insist",
        "v1": "never"
    }

    def __init__(self, conf, root_helper, process_id,
                 vpnservice, namespace):
        self.conf = conf
        self.id = process_id
        self.root_helper = root_helper
        self.updated_pending_status = False
        self.namespace = namespace
        self.connection_status = {}
        self.update_vpnservice(vpnservice)
        self.update_vpnservice_cache(vpnservice)

    def update_vpnservice_cache(self, vpnservice):
        self.vpnservice_cache = vpnservice

    def update_vpnservice(self, vpnservice):
        self.vpnservice = vpnservice

    @abc.abstractmethod
    def ensure_configs(self,conn_id):
        pass

    @abc.abstractmethod
    def delete_ngfw_config(self):
        pass

    @abc.abstractmethod
    def get_status(self,conn_id):
        pass

    @property
    def status(self):
        if self.active:
            return constants.ACTIVE
        return constants.DOWN

    @property
    def active(self):
        """Check if the process is active or not."""
        LOG.debug("report active")
        try:
            flag = True
            for i in range(len(self.vpnservice['ipsec_site_connections'])):
                conn_id = self.vpnservice['ipsec_site_connections'][i]['id']
                service_id = self.vpnservice['id']
                status = self.get_status(conn_id)
                if status != 'succeed':
                    flag = False
                LOG.debug(_('_update_connection_status %s'),status)
                self._update_connection_status(status,conn_id)
            return flag
        except RuntimeError:
            return False

    def update(self):
        """Update Status based on vpnservice configuration."""
        if self.vpnservice and not self.vpnservice['admin_state_up']:
            self.disable()
        else:
            self.enable()

        if plugin_utils.in_pending_status(self.vpnservice['status']):
            self.updated_pending_status = True

        for ipsec_site_conn in self.vpnservice['ipsec_site_connections']:
            if plugin_utils.in_pending_status(ipsec_site_conn['status']):
                conn_id = ipsec_site_conn['id']
                conn_status = self.connection_status.get(conn_id)
                if not conn_status:
                    continue
                conn_status['updated_pending_status'] = True
                ipsec_site_conn['status'] = conn_status['status']

    def enable(self):
        """Enabling the process."""
        try:
            if self.active:
                self.restart()
            else:
                self.start()
        except RuntimeError:
            LOG.exception(
                _("Failed to enable vpn process on router %s"),
                self.id)

    def disable(self):
        """Disabling the process."""
        try:
            self.delete_ngfw_config()
        except RuntimeError:
            LOG.exception(
                _("Failed to disable vpn process on router %s"),
                self.id)

    @abc.abstractmethod
    def restart(self):
        """Restart process."""

    @abc.abstractmethod
    def start(self):
        """Start process."""

    @abc.abstractmethod
    def stop(self):
        """Stop process."""

    def _update_connection_status(self, status_output,connection_id):
        #status{negotiating/ waiting/ succeed / failure}
        status = status_output
        if not self.connection_status.get(connection_id):
            self.connection_status[connection_id] = {
                'status': None,
                'updated_pending_status': False
            }
        self.connection_status[
            connection_id]['status'] = STATUS_MAP[status]


class NGFWProcess(BaseSwanProcess):
    """OpenSwan Process manager class.

    This process class uses three commands
    (1) ipsec pluto:  IPsec IKE keying daemon
    (2) ipsec addconn: Adds new ipsec addconn
    (3) ipsec whack:  control interface for IPSEC keying daemon
    """
    def __init__(self, conf, root_helper, process_id,
                 vpnservice, namespace,kwargs):
        super(NGFWProcess, self).__init__(
            conf, root_helper, process_id,
            vpnservice, namespace)
        self.ike_peer = {}
        self.ike_proposal = {}
        self.ipsec_proposal = {}
        self.ipsec_policy = {}
        self.ipsec_acl = {}
        self.ipsec_static_routes = []
        self.ipsec_static_routes_with_vpn = []
        self.rest = ngfw_api.ngfwRestAPI()
        self.common_conf = kwargs


    def ensure_ike_peer(self,vpnservice,vsys_num,ike_proposal_id,connection_id):
        ipsec_site_connections = vpnservice['ipsec_site_connections'][connection_id]
        ikepolicy = ipsec_site_connections['ikepolicy']
        self.ike_peer = {
            'ike_peer_name' : self.get_format_name(ipsec_site_connections['id'][0:15]),
            'vsys_num' : vsys_num,
            'pre_shared_key' : crypt.decrypt(ipsec_site_connections['psk']),
            'ike_version' : ikepolicy['ike_version'],
            'ike_proposal' : ike_proposal_id,
            'peer_address' : ipsec_site_connections['peer_address'], # peer-address type
            'phase1_mode' : ikepolicy['phase1_negotiation_mode'],
            'vpn_instance' : vsys_num
        }

    def ensure_ike_proposal(self,vpnservice,connection_id):
        ipsec_site_connections = vpnservice['ipsec_site_connections'][connection_id]
        ikepolicy = ipsec_site_connections['ikepolicy']
        # TODO id ?
        self.ike_proposal = {
            'id' : self.get_ike_proposal_id(), #
            'auth_algorithm' : ikepolicy['auth_algorithm'],
            'integrity_algorithm' : '',
            'encryption_algorithm' : ikepolicy['encryption_algorithm'],
            'auth_mode' : 'pre-share',
            'dh' : ikepolicy['pfs'],
            'lifetime' : ikepolicy['lifetime_value']
        }

    def ensure_acl(self,vpnservice,connection_id,acl_id,index):
        if not acl_id:
            acl_id = self.alloc_acl_id_from_ngfw()
        if not acl_id:
            return False
        ipsec_site_connections = vpnservice['ipsec_site_connections'][connection_id]
        access_list_entries = []
        rule_name = 0
        for i in range(len(ipsec_site_connections['peer_cidrs'])):
            for subnet in vpnservice['local_subnets']:
                rule_name += 1
                access_list_entry = [{
                    'rule_name': rule_name,
                    'destination_ipv4_network': ipsec_site_connections['peer_cidrs'][i],
                    'source_ipv4_network': subnet['cidr'],
                    'protocol': 0
                }]
                access_list_entries = access_list_entries + access_list_entry
        self.ipsec_acl = {
            'access_control_list_name' : acl_id,
            'access_list_entries' : access_list_entries,
            'vsys':"vpn" + str(index)
        }
        return True

    def ensure_ipsec_policy(self,vpnservice,ike_peer_name,ipsec_proposal_name,acl_id ,interface_name,connection_id):
        ipsec_site_connections = vpnservice['ipsec_site_connections'][connection_id]
        ipsec_alias = ipsec_site_connections['id']
        ipsecpolicy = ipsec_site_connections['ipsecpolicy']
        self.ipsec_policy = {
            'alias' : self.get_format_name(ipsec_alias),
            'name' : self.get_format_name(self.vpnservice['id'][0:15]),
            'sequence' : self.vpnservice["sequences"][self.id],
            'scenario' : 'p2p',
            'acl' : acl_id,
            'ike_peer_name' : ike_peer_name,
            'ipsec_proposal_name' : ipsec_proposal_name,
            'pfs' : self.get_ngfw_pfs(ipsecpolicy['pfs']),
            'interface_name' : interface_name,
            'local_address' : ipsec_site_connections['description']
        }

    def ensure_ipsec_proposal(self,vpnservice,connection_id):
        ipsec_site_connections = vpnservice['ipsec_site_connections'][connection_id]
        ipsecpolicy = ipsec_site_connections['ipsecpolicy']
        #TODO ipsec_proposal_name
        if ipsecpolicy['transform_protocol'] == 'esp':
            self.ipsec_proposal = {
                'ipsec_proposal_name' : self.get_format_name(ipsec_site_connections['id'][0:15]),
                'transform_protocol' : ipsecpolicy['transform_protocol'],
                'esp_auth_algorithm' : ' ' + ipsecpolicy['auth_algorithm'],
                'esp_encryption_algorithm' : ' ' + ipsecpolicy['encryption_algorithm'],
                'ah_auth_algorithm' : '',
                'encapsulation_mode' : ipsecpolicy['encapsulation_mode']
            }
        else:
            self.ipsec_proposal = {
                'ipsec_proposal_name' : self.get_format_name(ipsec_site_connections['id'][0:15]),
                'transform_protocol' : ipsecpolicy['transform_protocol'],
                'esp_auth_algorithm' : '',
                'esp_encryption_algorithm' : '',
                'ah_auth_algorithm' : ' ' + ipsecpolicy['auth_algorithm'],
                'encapsulation_mode' : ipsecpolicy['encapsulation_mode']
            }

    def ensure_ipsec_static_route(self,vpnservice,connection_id,index):
        self.ipsec_static_routes = []
        if len(vpnservice['ipsec_site_connections']) > 1:
            return
        outgoing_interface = self.common_conf.get('vpn_ngfw_private_interface') + '.' + str(index)
        for subnet in vpnservice['local_subnets']:
            ipsec_static_route = [{
                'description':'',
                'ip_address':str(IPNetwork(subnet['cidr']).ip),
                'mask_length':str(IPNetwork(subnet['cidr']).prefixlen),
                'next_hop_address':vpnservice['virtual_ip'],
                'outgoing_interface':outgoing_interface,
                'priority': self.common_conf.get('static_route_priority'),
                'name': 'vpn' + str(index)
            }]
            self.ipsec_static_routes = ipsec_static_route + self.ipsec_static_routes

    def ensure_ipsec_static_route_with_vpn(self,vpnservice,connection_id,index):
        self.ipsec_static_routes_with_vpn = []
        outgoing_interface = self.common_conf.get('vpn_ngfw_public_interface') + '.' + str(index)
        peer_cidrs = vpnservice['ipsec_site_connections'][connection_id]['peer_cidrs']
        for subnet in peer_cidrs:
            ipsec_static_route = [{
                'description':'',
                'ip_address':str(IPNetwork(subnet).ip),
                'mask_length':str(IPNetwork(subnet).prefixlen),
                'next_hop_address':self.common_conf.get('vpn_nexthop'),
                'outgoing_interface':outgoing_interface,
                'priority': self.common_conf.get('static_route_priority'),
                'name': 'vpn' + str(index)
            }]
            self.ipsec_static_routes_with_vpn = ipsec_static_route + self.ipsec_static_routes_with_vpn

    def get_ngfw_ipsec_proposal_name(self):
        return self.ipsec_proposal.get('ipsec_proposal_name')

    def get_ngfw_pfs(self,pfs):
        return "dh-" + pfs

    def get_ngfw_ipsec_policy_name(self):
        return self.ipsec_policy.get('name')

    def _parse_xml_to_dict(self,data, parent_attr, son_attr):
        ret = []
        if not data:
            return ret
        try:
            tmp = "<response>" + data + "</response>"
            parse = xmltodict.parse(tmp)
            parent = []
            if type(parse['response'][parent_attr]) is list:
                parent = parse['response'][parent_attr]
            else:
                parent.append(parse['response'][parent_attr])
            if type(parent[0][son_attr]) is list:
                ret = parent[0][son_attr]
            else:
                ret.append(parent[0][son_attr])
            for i in range(1, len(parent)):
                if type(parent[i][son_attr]) is list:
                    ret.extend(parent[i][son_attr])
                else:
                    ret.append(parent[i][son_attr])
        except:
            LOG.debug("xml parse error")
            ret = []
        return ret

    def alloc_acl_id_from_ngfw(self):
        """
        allocate a free acl number for a vpn site connection

        The VPN_ACL_NUMBERS is set(range(3000, 3999)
        :return: None, that means there happened a error, or the available acl number have used up.
                 return the a available acl number for the vpn site connection
        """
        response = self.rest.rest_api("GET", ngfw_utils.NGFW_URL_VPN_IPSEC_ACL)
        if response['status'] == 204:
            LOG.debug("Request acls failed! please check!")
            return VPN_ACL_ID_START
        if response['status'] != SUCCESS_CODE:
            return None
        body = response['body']
        acls = self._parse_xml_to_dict(body,'access-lists','access-list')
        used_acl_number = set()

        for acl in acls:
            used_acl_number.add(int(acl['access-control-list-name']))

        ret = VPN_ACL_NUMBERS - used_acl_number
        if not ret:
            return None
        return ret.pop()

    def get_acl_id(self):
        return self.ipsec_acl.get('access_control_list_name')

    def get_ike_peer_name(self):
        return self.ike_peer.get('ike_peer_name')

    def get_ike_proposal_id(self):
        return int(self.ipsec_acl.get('access_control_list_name')) - 2999

    def get_acl_id(self):
        return self.ipsec_acl.get('access_control_list_name')

    def get_interface_name(self):
        return self.common_conf.get('vpn_ngfw_public_interface')

    def ensure_configs(self,conn_index,acl_id = None):
        """Generate config files which are needed for OpenSwan.

        If there is no directory, this function will create
        dirs.
        """
        vpn_ip = self.vpnservice['ipsec_site_connections'][conn_index]['description']
        index = ngfw_utils.get_index_from_value("ip_pool",vpn_ip, self.common_conf.get('vpn_ip_pool'))
        if not self.ensure_acl(self.vpnservice,conn_index,acl_id,index):
            return False
        self.ensure_ipsec_proposal(self.vpnservice,conn_index)
        self.ensure_ike_proposal(self.vpnservice,conn_index)
        self.ensure_ike_peer(self.vpnservice,"vpn" + str(index) ,self.get_ike_proposal_id(),conn_index)
        self.ensure_ipsec_static_route(self.vpnservice,conn_index,index)
        self.ensure_ipsec_static_route_with_vpn(self.vpnservice,conn_index,index)
        interface_name = self.get_interface_name() + "." + str(index)
        self.ensure_ipsec_policy(self.vpnservice, self.get_ike_peer_name(),
                                 self.get_ngfw_ipsec_proposal_name(),
                                 self.get_acl_id(), interface_name ,conn_index)
        return True

    def get_format_name(self,name):
        return name.replace('-','_')

    def parse(self,xml):
        return xmltodict.parse(xml)

    def unparse(self,dict):
        return xmltodict.unparse(dict)

    def get_delete_acl_body(self,ngfw_ipsec_policy, index=0):
        return """
            <access-lists>
                <access-list>
                    <access-control-list-name>""" + ngfw_ipsec_policy[
            'acl'][index] +"""</access-control-list-name>
                </access-list>
            </access-lists>
        """

    def filter_xml_summary(self,xml,filter):
        if xml:
            index = xml.find(filter)
            if index == -1:
                return None
            bodyinfo = xml[index:]
            return bodyinfo
        return None

    def get_delete_ipsec_policy_body(self,ipsec_xml_body):
        return self.filter_xml_summary(ipsec_xml_body,'<ipsec-policy>')

    def _gen_delete_ipsec_policy_body(self, ipsec_policy_dict, index):
        if not ipsec_policy_dict:
            return None
        ipsec_policy = ipsec_policy_dict['ipsec-policy']['ipsec-policy']
        cols = ['alias', 'name', 'sequence', 'acl', 'ike-peer-name',
                'ipsec-proposal-name', 'status', 'scenario']
        for col in cols:
            attr_list = ipsec_policy.get(col)
            if not isinstance(attr_list, list):
                ipsec_policy[col] = [ipsec_policy.get(col)]
                attr_list = [attr_list]
            if not attr_list[index]:
                ipsec_policy[col][index] = ''

        if not isinstance((ipsec_policy['local-information']), list):
            ipsec_policy['local-information'] = [ipsec_policy['local-information']]

        if not ipsec_policy['local-information'][index]['interface-name']:
            ipsec_policy['local-information'][index]['interface-name'] = ''

        ipsec_policy_body = "<ipsec-policy><ipsec-policy>" \
                            "<alias>%s</alias><name>%s</name>" \
                            "<sequence>%s</sequence><acl>%s</acl>" \
                            "<ike-peer-name>%s</ike-peer-name>" \
                            "<ipsec-proposal-name>%s</ipsec-proposal-name>" \
                            "<status>%s</status><scenario>%s</scenario>" \
                            "<local-information>" \
                            "<interface-name>%s</interface-name>" \
                            "</local-information>" \
                            "</ipsec-policy></ipsec-policy>" % (
               ipsec_policy['alias'][index],
               ipsec_policy['name'][index],
               ipsec_policy['sequence'][index],
               ipsec_policy['acl'][index],
               ipsec_policy['ike-peer-name'][index],
               ipsec_policy['ipsec-proposal-name'][index],
               ipsec_policy['status'][index],
               ipsec_policy['scenario'][index],
               ipsec_policy['local-information'][index]['interface-name'])

        return ipsec_policy_body

    def delete_ngfw_config(self):
        try:
            if len(self.vpnservice_cache['ipsec_site_connections']) > len(self.vpnservice['ipsec_site_connections']):
                site_conn_deleted = set(self.vpnservice['ipsec_site_connections']) - set(self.vpnservice_cache['ipsec_site_connections'])
            if not self.vpnservice:
                return
            for conn_index in range(len(self.vpnservice['ipsec_site_connections'])):
                ipsec_site_connections = self.vpnservice['ipsec_site_connections'][conn_index]
                conn_id = self.get_format_name(ipsec_site_connections['id'])

                LOG.debug(_('start to delete ipsec site connection :(%s)'),
                          conn_id)

                if conn_id != self.get_format_name(self.id):
                    continue

                # get ipsec policy
                response = self.rest.rest_api('GET', ngfw_utils.NGFW_URL_VPN_IPSEC_POLICY_GET + \
                                              '&name=' + conn_id)
                LOG.debug(_('delete vpn_ipsec_policy body:(%s)'), response['body'])
                # index for specific connection in the ngfw response body
                index = self._get_connection_index_in_ngfw(response, conn_id)
                if index is not None:
                    ngfw_ipsec_policy = self.parse(self.filter_xml_summary(response['body'],'<ipsec-policy>'))
                    #delete ipsec policy
                    delete_ipsec_policy_xml = \
                        self._gen_delete_ipsec_policy_body(ngfw_ipsec_policy,
                                                           index)
                    if not delete_ipsec_policy_xml:
                        LOG.error(_('get delete_ipsec_policy_xml fail!'))
                        continue
                    response = self.rest.rest_api('DELETE', ngfw_utils.NGFW_URL_VPN_IPSEC_POLICY,delete_ipsec_policy_xml)
                    if response['status'] == SUCCESS_CODE:
                        LOG.debug(_('delete ipsec policy success!'))
                    else:
                        LOG.error(_('delete ipsec policy fail!'))
                        continue

                    # delete ipsec acl
                    delete_acl_body = self.get_delete_acl_body(
                        ngfw_ipsec_policy['ipsec-policy']['ipsec-policy'], index)
                    response = self.rest.rest_api('DELETE', ngfw_utils.NGFW_URL_VPN_IPSEC_ACL,delete_acl_body)
                    if response['status'] == SUCCESS_CODE:
                        LOG.debug(_('delete ipsec acl success!'))
                    else:
                        LOG.error(_('delete ike acl fail!'))
                        continue

                    #delete ipsec proposal
                    ipsec_proposal_names = ngfw_ipsec_policy['ipsec-policy']['ipsec-policy']['ipsec-proposal-name']
                    if not isinstance(ipsec_proposal_names, list):
                        ipsec_proposal_names = [ipsec_proposal_names]
                    response = self.rest.rest_api('GET', ngfw_utils.NGFW_URL_VPN_IPSEC_PROPOSAL_GET +
                                                  '&name=' +ipsec_proposal_names[index])
                    if self.is_exist(response['body'],'<ipsec-proposal>'):
                        delete_ipsec_proposal_body = self.filter_xml_summary(response['body'],'<ipsec-proposal>')
                        response = self.rest.rest_api('DELETE', ngfw_utils.NGFW_URL_VPN_IPSEC_PROPOSAL,
                                                      delete_ipsec_proposal_body)
                        if response['status'] == SUCCESS_CODE:
                            LOG.debug(_('delete ipsec proposal success!'))
                        else:
                            LOG.error(_('delete ipsec proposal fail!'))
                            continue

                    #delete ike peer
                    response = self.rest.rest_api('GET', ngfw_utils.NGFW_URL_VPN_IKE_PEER_GET + \
                                              '&name=' + self.get_format_name(ipsec_site_connections['id'][0:15]))
                    if self.is_exist(response['body'],'<ike-peer>'):
                        delete_ike_proposal_body = self.filter_xml_summary(response['body'],'<ike-peer>')
                        response = self.rest.rest_api('DELETE', ngfw_utils.NGFW_URL_VPN_IKE_PEER,delete_ike_proposal_body)
                        if response['status'] == SUCCESS_CODE:
                            LOG.debug(_('delete ike peer success!'))
                        else:
                            LOG.error(_('delete ike peer fail!'))
                            continue

                        #delete ike proposal
                        delete_ike_peer_body = self.parse(delete_ike_proposal_body)
                        response = self.rest.rest_api('GET', ngfw_utils.NGFW_URL_VPN_IKE_PROPOSAL_GET +
                                                      '&name=' +delete_ike_peer_body['ike-peer']['ike-peer']['ike-proposal'])
                        if self.is_exist(response['body'],'<ike-proposal>'):
                            delete_ike_proposal_body = self.filter_xml_summary(response['body'],'<ike-proposal>')
                            response = self.rest.rest_api('DELETE', ngfw_utils.NGFW_URL_VPN_IKE_PROPOSAL,delete_ike_proposal_body)
                            if response['status'] == SUCCESS_CODE:
                                LOG.debug(_('delete ike proposal success!'))
                            else:
                                LOG.error(_('delete ike proposal fail!'))
                                continue
                    # static route
                    for i in range(len(self.ipsec_static_routes)):
                        static_route = self.ipsec_static_routes[i]
                        self._clear_static_route(static_route)

                    for i in range(len(self.ipsec_static_routes_with_vpn)):
                        static_route = self.ipsec_static_routes_with_vpn[i]
                        self._clear_static_route(static_route)
        except Exception as e:
            LOG.error(_("delete ngfw config has exception %s"),e)

    def _clear_static_route(self, static_route):
        LOG.debug(_('enter _clear_static_route.'))
        ret = self.check_static_route("delete", static_route)
        if not ret:
            LOG.error(_('static_route is invalid.'))
            return False

        bodyinfo = ngfw_utils.get_static_route(static_route)
        LOG.debug(_('_clear_static_route xml body is: %s' % bodyinfo))
        response = self.rest.rest_api('DELETE', ngfw_utils.NGFW_URL_STATIC_ROUTE, bodyinfo)
        if response['status'] >= 200 and response['status'] < 300:
            return True
        return False


    def _make_static_route(self, static_route):
        '''
        {"ip_address":"172.28.0.0",
         "mask_length":"24",
         "next_hop_address":"172.28.0.1",
         "outgoing_interface":"eth3",
         "priority":"63",
         "description":"aaaaaaaaaaa"
         }
        '''
        LOG.debug(_('enter _make_static_route.'))
        ret = self.check_static_route("add", static_route)
        if not ret:
            LOG.error(_('static_route is invalid.'))
            return False

        bodyinfo = ngfw_utils.get_static_route(static_route)
        LOG.debug(_('_make_static_route xml body is: %s' % bodyinfo))

        response = self.rest.rest_api('POST', ngfw_utils.NGFW_URL_STATIC_ROUTE, bodyinfo)
        if response['status'] >= 400:
            LOG.error(_('_make_static_route failed.'))
            self._clear_static_route(static_route)
            return False
        LOG.debug(_('_make_static_route success.'))
        return True


    def check_static_route(self, action, static_route):

        LOG.debug(_('static_route is: %s.' % static_route))
        if ( not static_route.has_key("ip_address") ) or ( not static_route["ip_address"]):
            LOG.error(_('static_route ip_address is invalid.'))
            return False

        if ( not static_route.has_key("mask_length") ) or ( not static_route["mask_length"]):
            LOG.error(_('static_route mask_length is invalid.'))
            return False

        if "add" == action:
            #outgoing_interface and next_hop_address must has one
            if(( not static_route.has_key("outgoing_interface") ) or ( not static_route["outgoing_interface"]) ) and \
                ( ( not static_route.has_key("next_hop_address") ) or ( not static_route["next_hop_address"]) ):
                LOG.error(_('static_route outgoing_interface and next_hop_address is invalid.'))
                return False

        return True

    def get_status(self,conn_id):
        """
            call get_status of ngfw
        """
        #status {negotiating/ waiting/ succeed / failure}
        response = self.rest.rest_api('GET', ngfw_utils.NGFW_URL_VPN_IPSEC_POLICY_GET + \
                                          '&name=' + self.get_format_name(conn_id))
        try:
            for connection in self.vpnservice['ipsec_site_connections']:
                if connection['id'] == conn_id:
                    if connection['status'] == constants.PENDING_DELETE:
                        return 'pending_delete'
	        LOG.debug(_("get_status response is :%s "),response)

            if response['status'] == SUCCESS_CODE and response['body']:
                ipsec_policy = self.parse(self.filter_xml_summary(response['body'],'<ipsec-policy>'))
                index = self._get_connection_index_in_ngfw(response, conn_id)

                if not isinstance(ipsec_policy['ipsec-policy']
                                  ['ipsec-policy']['status'], list):
                    ipsec_policy['ipsec-policy']['ipsec-policy']['status'] =\
                        [ipsec_policy['ipsec-policy']['ipsec-policy']['status']]
                status =  ipsec_policy['ipsec-policy']['ipsec-policy']['status'][index]

                if status:
                    return status
                else:
                    return 'failure'
            elif response['status'] == NOCONTENT and self.id == conn_id:
                self.start()
                return 'failure'
            else:
                return 'error'
        except Exception as e:
            LOG.debug(_("get_status exception is :%s "),e)
            return 'failure'


    def restart(self):
        """Restart the process."""
        self.stop()
        self.start()

    def _virtual_privates(self):
        """Returns line of virtual_privates.

        virtual_private contains the networks
        that are allowed as subnet for the remote client.
        """
        virtual_privates = []
        nets = [self.vpnservice['subnet']['cidr']]
        for ipsec_site_conn in self.vpnservice['ipsec_site_connections']:
            nets += ipsec_site_conn['peer_cidrs']
        for net in nets:
            version = netaddr.IPNetwork(net).version
            virtual_privates.append('%%v%s:%s' % (version, net))
        return ','.join(virtual_privates)

    def is_exist(self,body,key):
        try:
            if self.filter_xml_summary(body,key):
                return True
            return False
        except:
            return False

    def _is_connection_exist(self, ngfw_ipsec_response, conn_id):
        conn_tag = "<alias>" + conn_id + "</alias>"
        if conn_tag in ngfw_ipsec_response:
            return True
        else:
            return False

    def _get_connection_index_in_ngfw(self, ngfw_ipsec_response, conn_id):
        conn_id = self.get_format_name(conn_id)
        xml_body = self.filter_xml_summary(ngfw_ipsec_response['body'], '<ipsec-policy>')
        if not xml_body:
            return None
        ngfw_ipsec_policy = self.parse(xml_body)

        connection_ids = ngfw_ipsec_policy['ipsec-policy']['ipsec-policy']['alias']
        if not isinstance(connection_ids, list):
            connection_ids = [connection_ids]

        for index, connection_id in enumerate(connection_ids):
            if conn_id == connection_id:
                return index
        else:
            return None


    def start(self):
        """Start the process.

        Note: if there is not namespace yet,
        just do nothing, and wait next event.
        """
        
        try:
            self.update_vpnservice_cache(self.vpnservice)
            for conn_index in range(len(self.vpnservice['ipsec_site_connections'])):
                connection = self.vpnservice['ipsec_site_connections'][conn_index]
                conn_id = self.get_format_name(connection['id'])
                if conn_id != self.get_format_name(self.id):
                    continue
                response = self.vpnservice["ngfw_infos"][self.id]
                if response:
                    ngfw_ipsec_policy = self.parse(self.filter_xml_summary(response['body'],'<ipsec-policy>'))
                    acl_id = ngfw_ipsec_policy['ipsec-policy']['ipsec-policy']['acl']

                    if not self.ensure_configs(conn_index,acl_id):
                        continue
                else:
                    if not self.ensure_configs(conn_index):
                        continue

                # ipsec acl
                body = ngfw_utils.get_vpn_ipsec_acl_list(self.ipsec_acl)
                LOG.debug(_('_config_vpn_ipsec_acl body:(%s)'), body)
                response = self.rest.rest_api('GET', ngfw_utils.NGFW_URL_VPN_IPSEC_ACL + "?acl=" + str(self.ipsec_acl['access_control_list_name']))
                if self.is_exist(response['body'],'<access-lists>'):
                    response = self.rest.rest_api('PUT', ngfw_utils.NGFW_URL_VPN_IPSEC_ACL, body)
                    if response['status'] == SUCCESS_CODE:
                        LOG.debug(_('update ipsec acl success!'))
                    elif response['status'] != SUCCESS_CODE:
                        LOG.debug(_('update ipsec acl fail!'))
                        continue
                else:
                    response = self.rest.rest_api('POST', ngfw_utils.NGFW_URL_VPN_IPSEC_ACL, body)
                    if response['status'] == SUCCESS_CODE:
                        LOG.debug(_('create ipsec acl success!'))
                    else:
                        LOG.debug(_('create ipsec acl fail!'))
                        continue

                # ike proposal
                body = ngfw_utils.get_vpn_ike_proposal(self.ike_proposal)
                LOG.debug(_('_config_vpn_ike_proposal body:(%s)'), body)
                response = self.rest.rest_api('GET', ngfw_utils.NGFW_URL_VPN_IKE_PROPOSAL_GET + \
                                              '&name=' + str(self.get_ike_proposal_id()))
                if self.is_exist(response['body'],'<ike-proposal>'):
                    response = self.rest.rest_api('PUT', ngfw_utils.NGFW_URL_VPN_IKE_PROPOSAL, body)
                    if response['status'] == SUCCESS_CODE:
                        LOG.debug(_('update ike proposal success!'))
                    else:
                        LOG.debug(_('update ike proposal fail!'))
                        continue
                else:
                    response = self.rest.rest_api('POST', ngfw_utils.NGFW_URL_VPN_IKE_PROPOSAL, body)
                    if response['status'] == SUCCESS_CODE:
                        LOG.debug(_('create ike proposal success!'))
                    else:
                        LOG.debug(_('create ike proposal fail!'))
                        continue

                # ike peer

                body = ngfw_utils.get_vpn_ike_peer(self.ike_peer)
                
                response = self.rest.rest_api('GET', ngfw_utils.NGFW_URL_VPN_IKE_PEER_GET + \
                                              '&name=' + self.get_ike_peer_name())
                if self.is_exist(response['body'],'<ike-peer>'):
                    response = self.rest.rest_api('PUT', ngfw_utils.NGFW_URL_VPN_IKE_PEER, body)
                    if response['status'] == SUCCESS_CODE:
                        LOG.debug(_('update ike peer success!'))
                    else:
                        LOG.debug(_('update ike peer fail!'))
                        continue
                else:
                    response = self.rest.rest_api('POST', ngfw_utils.NGFW_URL_VPN_IKE_PEER, body)
                    if response['status'] == SUCCESS_CODE:
                        LOG.debug(_('create ike peer success!'))
                    else:
                        LOG.debug(_('create ike peer fail!'))
                        continue

                # ipsec proposal
                body = ngfw_utils.get_vpn_ipsec_proposal(self.ipsec_proposal)
                LOG.debug(_('_config_vpn_ipsec_proposal body:(%s)'), body)
                response = self.rest.rest_api('GET', ngfw_utils.NGFW_URL_VPN_IPSEC_PROPOSAL_GET + \
                                              '&name=' + self.get_ngfw_ipsec_proposal_name())
                if self.is_exist(response['body'],'<ipsec-proposal>'):
                    response = self.rest.rest_api('PUT', ngfw_utils.NGFW_URL_VPN_IPSEC_PROPOSAL, body)
                    if response['status'] == SUCCESS_CODE:
                        LOG.debug(_('update ipsec proposal success!'))
                    else:
                        LOG.debug(_('update ipsec proposal fail!'))
                        continue
                else:
                    response = self.rest.rest_api('POST', ngfw_utils.NGFW_URL_VPN_IPSEC_PROPOSAL, body)
                    if response['status'] == SUCCESS_CODE:
                        LOG.debug(_('create ipsec proposal success!'))
                    else:
                        LOG.debug(_('create ipsec proposal fail!'))
                        continue


                # ipsec policy
                body = ngfw_utils.get_vpn_ipsec_policy(self.ipsec_policy)
                LOG.debug(_('_config_vpn_ipsec_policy body:(%s)'), body)
                response = self.rest.rest_api('GET', ngfw_utils.NGFW_URL_VPN_IPSEC_POLICY_GET + \
                                              '&name=' + conn_id)
                if self._is_connection_exist(response['body'], conn_id):
                    response = self.rest.rest_api('PUT', ngfw_utils.NGFW_URL_VPN_IPSEC_POLICY, body)
                    if response['status'] == SUCCESS_CODE:
                        LOG.debug(_('update ipsec policy success!'))
                    else:
                        LOG.debug(_('update ipsec policy fail!'))
                        continue
                else:
                    response = self.rest.rest_api('POST', ngfw_utils.NGFW_URL_VPN_IPSEC_POLICY, body)
                    if response['status'] == SUCCESS_CODE:
                        LOG.debug(_('create ipsec policy success!'))
                    else:
                        LOG.debug(_('create ipsec policy fail!'))
                        continue

                # static route
                for i in range(len(self.ipsec_static_routes)):
                    static_route = self.ipsec_static_routes[i]
                    self._make_static_route(static_route)

                for i in range(len(self.ipsec_static_routes_with_vpn)):
                    static_route = self.ipsec_static_routes_with_vpn[i]
                    self._make_static_route(static_route)
        except Exception as e:
            LOG.error(_('start has exception %s'),e)


    def disconnect(self):
        if not self.vpnservice:
            return


    def stop(self):
        #Stop process using whack
        #Note this will also stop pluto
        self.disconnect()
        #clean connection_status info
        self.connection_status = {}


class IPsecVpnDriverApi(n_rpc.RpcProxy):
    """IPSecVpnDriver RPC api."""
    IPSEC_PLUGIN_VERSION = '1.0'

    def get_vpn_services_on_host(self, context, host):
        """Get list of vpnservices.

        The vpnservices including related ipsec_site_connection,
        ikepolicy and ipsecpolicy on this host
        """
        return self.call(context,
                         self.make_msg('get_vpn_services_on_host',
                                       host=host),
                         version=self.IPSEC_PLUGIN_VERSION)

    def update_status(self, context, status):
        """Update local status.

        This method call updates status attribute of
        VPNServices.
        """
        return self.cast(context,
                         self.make_msg('update_status',
                                       status=status),
                         version=self.IPSEC_PLUGIN_VERSION)

    def delete_connections(self, context, conn_ids):
        return self.call(context,
                         self.make_msg('delete_connections',
                                       conn_ids=conn_ids),
                         version=self.IPSEC_PLUGIN_VERSION)

    def update_router(self, context, id, router):
        """update router routes

        This method call updates status attribute of
        VPNServices
        """
        return self.call(context,
                         self.make_msg('update_router',
                                       id=id, router=router),
                         version=self.IPSEC_PLUGIN_VERSION)

    def get_networks(self, context, filters=None, fields=None):
        return self.call(context, self.make_msg("get_networks",
                                                filters=filters, fields=fields),
                         version=self.IPSEC_PLUGIN_VERSION)

    def get_router(self, context, id):
        """
        get router information by router id
        :param context:
        :param id:
        :return:
        """
        return self.call(context, self.make_msg("get_router",
                                                id=id),
                         version=self.IPSEC_PLUGIN_VERSION)

    def get_agent_by_router_id(self, context, id):
        """
        get router information by router id
        :param context:
        :param id:
        :return:
        """
        return self.call(context, self.make_msg("get_agent_by_router_id",
                                                router_id=id),
                         version=self.IPSEC_PLUGIN_VERSION)

@six.add_metaclass(abc.ABCMeta)
class IPsecDriver(device_drivers.DeviceDriver):
    """VPN Device Driver for IPSec.

    This class is designed for use with L3-agent now.
    However this driver will be used with another agent in future.
    so the use of "Router" is kept minimul now.
    Instead of router_id,  we are using process_id in this code.
    """
    # history
    #   1.0 Initial version

    RPC_API_VERSION = '1.0'

    # TODO(ihrachys): we can't use RpcCallback here due to inheritance
    # issues
    target = messaging.Target(version=RPC_API_VERSION)

    def __init__(self, agent, host):
        self.agent = agent
        self.conf = self.agent.conf
        self.root_helper = self.agent.root_helper
        self.host = host
        self.conn = n_rpc.create_connection(new=True)
        self.context = context.get_admin_context_without_session()
        self.topic = topics.IPSEC_AGENT_TOPIC
        node_topic = '%s.%s' % (self.topic, self.host)

        self.processes = {}
        self.process_status_cache = {}
        self.rest = ngfw_api.ngfwRestAPI()
        self.ngfw_agent_utils = ngfw_plugin.NGFWAgentUtils()
        self.plugutil = ngfw_plugin.NGFWPluginUtils()

        self.endpoints = [self]
        self.conn.create_consumer(node_topic, self.endpoints, fanout=False)
        self.conn.consume_in_threads()
        self.agent_rpc = IPsecVpnDriverApi(topics.IPSEC_DRIVER_TOPIC, '1.0')
        self.process_status_cache_check = loopingcall.FixedIntervalLoopingCall(
            self.report_status, self.context)
        self.process_status_cache_check.start(
            interval=self.conf.ipsec.ipsec_status_check_interval)

    def vpnservice_updated(self, context, **kwargs):
        """Vpnservice updated rpc handler

        VPN Service Driver will call this method
        when vpnservices updated.
        Then this method start sync with server.
        """
        self.sync(context, [])

    @abc.abstractmethod
    def create_process(self, process_id, vpnservice, namespace, kwargs):
        pass

    def ensure_process(self, process_id, vpnservice=None):
        """Ensuring process.

        If the process doesn't exist, it will create process
        and store it in self.processs
        """
        kwargs = {
            'vpn_ip_pool':self.conf.ngfw.vpn_ip_pool,
            'vpn_ngfw_private_interface':self.conf.ngfw.vpn_ngfw_private_interface,
            'vpn_ngfw_public_interface':self.conf.ngfw.vpn_ngfw_public_interface,
            'vsys_ranges':self.conf.ngfw.vsys_ranges,
            'static_route_priority':self.conf.ngfw.static_route_priority,
            'vpn_nexthop':self.conf.ngfw.vpn_nexthop
        }
        process = self.processes.get(process_id)
        if not process:
            process = self.create_process(
                process_id,
                vpnservice,
                "",
                kwargs)
            self.processes[process_id] = process
        elif vpnservice:
            process.update_vpnservice(vpnservice)
        return process

    def create_router(self, process_id):
        """Handling create router event.

        Agent calls this method, when the process namespace
        is ready.
        """
        if process_id in self.processes:
            # In case of vpnservice is created
            # before router's namespace
            process = self.processes[process_id]
            self._update_router(self.context, process.vpnservice, 'add')
            process.enable()

    def destroy_router(self, process_id):
        """Handling destroy_router event.

        Agent calls this method, when the process namespace
        is deleted.
        """
        if process_id in self.processes:
            process = self.processes[process_id]
            process.disable()
            if process:
                self._update_router(self.context, process, "remove")
            del self.processes[process_id]


    def get_process_status_cache(self, process):
        if not self.process_status_cache.get(process.id):
            self.process_status_cache[process.id] = {
                'status': None,
                'id': process.vpnservice['id'],
                'updated_pending_status': False,
                'ipsec_site_connections': {}}
        return self.process_status_cache[process.id]

    def is_status_updated(self, process, previous_status):
        if process.updated_pending_status:
            return True
        if process.status != previous_status['status']:
            return True
        if (process.connection_status !=
            previous_status['ipsec_site_connections']):
            return True

    def unset_updated_pending_status(self, process):
        process.updated_pending_status = False
        for connection_status in process.connection_status.values():
            connection_status['updated_pending_status'] = False

    def copy_process_status(self, process):
        return {
            'id': process.vpnservice['id'],
            'status': process.status,
            'updated_pending_status': copy.deepcopy(process.updated_pending_status),
            'ipsec_site_connections': copy.deepcopy(process.connection_status)
        }

    def update_downed_connections(self, process_id, new_status):
        """Update info to be reported, if connections just went down.

        If there is no longer any information for a connection, because it
        has been removed (e.g. due to an admin down of VPN service or IPSec
        connection), but there was previous status information for the
        connection, mark the connection as down for reporting purposes.
        """
        if process_id in self.process_status_cache:
            for conn in self.process_status_cache[process_id][IPSEC_CONNS]:
                if conn not in new_status[IPSEC_CONNS]:
                    new_status[IPSEC_CONNS][conn] = {
                        'status': constants.DOWN,
                        'updated_pending_status': True
                    }

    def report_status(self, context):
        status_changed_vpn_services = []
        for process in self.processes.values():
            previous_status = self.get_process_status_cache(process)
            if self.is_status_updated(process, previous_status):
                new_status = self.copy_process_status(process)
                self.update_downed_connections(process.id, new_status)
                status_changed_vpn_services.append(new_status)
                self.process_status_cache[process.id] = (
                    self.copy_process_status(process))
                # We need unset updated_pending status after it
                # is reported to the server side
                self.unset_updated_pending_status(process)
        LOG.debug(_("report status %s"),status_changed_vpn_services)
        if status_changed_vpn_services:
            self.agent_rpc.update_status(
                context,
                status_changed_vpn_services)

    def delete_connection_in_db(self, context, conn_ids):
        self.agent_rpc.delete_connections(
                context,
                conn_ids)

    def _whether_my_vpnservice(self,vpnservice):
        if vpnservice.has_key('ipsec_site_connections'):
            result = self.plugutil._check_ip_in_ip_pool(vpnservice['ipsec_site_connections'][0]['description'],
                                                        self.conf.ngfw.vpn_ip_pool)
            if result:
                LOG.info(_("the vpnservice belong the agent."))
                return True
        LOG.info(_("the vpnservice is not belong the agent."))
        return False

    def get_index_of_public_ip(self, vpn_ip_pool, public_ip):
        try:
            p_ip = IPNetwork(public_ip)
            for index in range(len(vpn_ip_pool)):
                cidr = IPNetwork(vpn_ip_pool[index])
                if p_ip in cidr:
                    return index
        except:
            LOG.error("Public ip is invalid or not in the range of vpn_ip_pool")
            return None
        return None

    def get_tenant_router_info(self, context, vpnservice):
        try:
            description = json.loads(vpnservice['description'])
            tenant_router_id = description['tenant_router_id']
            tenant_router_info = self.agent_rpc.get_router(context, tenant_router_id)
            return tenant_router_info
        except Exception, e:
            LOG.error("get tenant_router_info error: %s", e)
            return None

    def _update_router(self, context, process, action=None):
        """
        Update the tennat router
        update the routes for destination is the peer cidrs, and the next hop is the vrrp of ngfw
        set the gateway of tenant router
        :param vpnservice:
        :return:
        """
        try:
            vpnservice = process.vpnservice
            process_id = process.id
            if not vpnservice:
                return

            nexthop = self.conf.ngfw.ngfw_vrrp_ip
            if not nexthop:
                LOG.error("ngfw vrrp do not set!")
                return False

            tenant_router_info = self.get_tenant_router_info(context, vpnservice)
            if not tenant_router_info:
                return False

            tenant_ext_network_prefix = self.conf.ngfw.tenant_ext_net_prefix
            if not tenant_ext_network_prefix:
                LOG.error("the ext network prefix do not set!")
                return False

            vpn_ip_pool = self.conf.ngfw.vpn_ip_pool
            if not vpn_ip_pool:
                LOG.error("the vlan ip pool do no set")
                return False

            vlan_ranges = self.conf.ngfw.vlan_ranges
            if not vlan_ranges:
                LOG.error("The VLAN range do not set!")
                return False

            old_routes = tenant_router_info.get("routes", [])
            old_external_gateway = tenant_router_info.get("external_gateway_info", {})
            old_external_network_id = ""
            if old_external_gateway:
                old_external_network_id = old_external_gateway.get("network_id", None)

            tenant_router_id = tenant_router_info.get('id', None)
            if not tenant_router_id:
                LOG.error("get tenant router id failed")
                return False

            new_routes = []
            routes = old_routes

            for ipsec_site_conn in vpnservice['ipsec_site_connections']:
                if process_id == ipsec_site_conn['id']:
                    for peer_cidr in ipsec_site_conn['peer_cidrs']:
                            new_routes.append({
                                "nexthop": nexthop,
                                "destination": peer_cidr
                            })
                    local_interface_ip = ipsec_site_conn['description']
                    index = self.get_index_of_public_ip(vpn_ip_pool, local_interface_ip)
                    if index is None:
                        return False
                    vlan_split = str(vlan_ranges[index]).split(":")
                    vlans = range(int(vlan_split[0]), int(vlan_split[1]))

                    if local_interface_ip:
                        i = list(IPNetwork(vpn_ip_pool[index])).index(IPNetwork(local_interface_ip).ip)
                        tenant_ext_network_name = tenant_ext_network_prefix + str(vlans[i])

                        filters = {'name': [tenant_ext_network_name]}
                        fields = ['id']
                        network_ids = self.agent_rpc.get_networks(context, filters=filters, fields=fields)
                        if not network_ids:
                            LOG.error("can not filter the network name %s." % tenant_ext_network_name)
                            return False
                        external_network_id = network_ids[0].get('id', None)
                        if not external_network_id:
                            LOG.error("the external network did not create.")
                            return False

                        if not old_external_network_id or old_external_network_id != \
                                external_network_id:
                            router = {
                                "router": {
                                    "external_gateway_info": {"network_id": external_network_id}
                                }
                            }
                            self.agent_rpc.update_router(context, tenant_router_id, router)

                        added, removed = common_utils.diff_list_of_dict(old_routes, new_routes)
                        if action == "add":
                            routes = old_routes + added
                        elif action == "remove":
                            routes = removed

                        router = {
                            "router": {
                                "routes": routes
                            }
                        }

                        self.agent_rpc.update_router(context, tenant_router_id, router)
        except Exception, e:
            LOG.debug("_update router exception:%s", e)
            return False

        return True

    def append_virtual_ip(self, context, vpnservice):
        agents = []
        try:
            tenant_router_id = vpnservice['tenant_router_info']['id']
            agents = self.agent_rpc.get_agent_by_router_id(context, tenant_router_id)
            for agent in agents['agents']:
                if agent['configurations']['agent_mode'] == 'dvr_snat':
                    virtual_ip = agent['configurations']['virtual_ip']
                    if virtual_ip:
                        vpnservice['virtual_ip'] = netaddr.IPNetwork(virtual_ip).ip
        except:
            LOG.error(_("Get virtual ip from agents error %s"), agents)
            return False
        LOG.debug(_("Get virtual ip success, the ip addr is %s"), vpnservice['virtual_ip'])
        return True

    @lockutils.synchronized('vpn-agent', 'neutron-')
    def sync(self, context, routers):
        """Sync status with server side.

        :param context: context object for RPC call
        :param routers: Router objects which is created in this sync event

        There could be many failure cases should be
        considered including the followings.
        1) Agent class restarted
        2) Failure on process creation
        3) VpnService is deleted during agent down
        4) RPC failure

        In order to handle, these failure cases,
        This driver takes simple sync strategies.
        """
        vpnservices = self.agent_rpc.get_vpn_services_on_host(
            context, self.host)

        pending_delete_connections = []
        # Ensure the ipsec process is enabled
        for vpnservice in vpnservices:
            connections = [connection for connection in vpnservice.get(
                "ipsec_site_connections")]
            vpnservice["ngfw_infos"] = {}
            vpnservice["sequences"] = {}
            sequences = []
            for connection in connections:
                conn_id = connection.get("id")
                if connection.get("status") == constants.PENDING_DELETE:
                    pending_delete_connections.append(conn_id)

                response = self.rest.rest_api('GET',
                                              ngfw_utils.NGFW_URL_VPN_IPSEC_POLICY_GET + '&name=' + copy.deepcopy(conn_id).replace('-','_'))

                vpnservice["ngfw_infos"][conn_id] = response
                sequence = self._get_sequence_index(response)
                if sequence:
                    sequences.append(int(sequence))
                    vpnservice["sequences"][conn_id] = int(sequence)
                else:
                    vpnservice["sequences"][conn_id] = -1
                    vpnservice["ngfw_infos"][conn_id] = None

            for connection in connections:
                conn_id = connection.get("id")
                if -1 == vpnservice["sequences"][conn_id]:
                    se = self._get_available_sequence(sequences)
                    vpnservice["sequences"][conn_id] = se
                    sequences.append(se)

                process = self.ensure_process(conn_id,
                                          vpnservice=vpnservice)
                ret = self._update_router(context, process, action='add')
                if not ret:
                    LOG.debug("update router for connection: %s failed!" %
                              connection.get("id"))
                    continue

                ret = self.append_virtual_ip(context, process.vpnservice)
                if not ret:
                    continue

                if connection.get("status") == constants.PENDING_DELETE:
                    continue
                process.update()

        # Delete any IPSec processes running
        # VPN that do not have an associated router.
        deleted_connections = []
        for process_id in pending_delete_connections:
            process = self.processes.get(process_id)
            if not process:
                deleted_connections.append(process_id)
                continue
            latest_vpnservice = process.vpnservice
            self.ensure_process(process_id, vpnservice=latest_vpnservice)
            self.destroy_router(process_id)
            if process_id not in self.processes:
                # already delete connection successfully
                deleted_connections.append(process_id)

        # notify neutron server to delete connection in db
        self.delete_connection_in_db(context, deleted_connections)
        self.report_status(context)

    def filter_xml_summary(self,xml,filter):
        if xml:
            index = xml.find(filter)
            if index == -1:
                return None
            bodyinfo = xml[index:]
            return bodyinfo
        return None

    def _get_sequence_index(self, response):
        if not response:
            return None

        # Only one ipsec-policy precisely matched with conn_id in the response
        # body, thus, we don't need to treat sequence as a list any more
        filter_xml = self.filter_xml_summary(response['body'],
                                             '<ipsec-policy>')
        if not filter_xml:
            return None
        ngfw_ipsec_policy = xmltodict.parse(filter_xml)
        try:
            sequence = ngfw_ipsec_policy['ipsec-policy']['ipsec-policy'][
                'sequence']
        except:
            LOG.error(_("Ipsec policy response from ngfw doesn't have "
                      "sequence info"))
            return None
        return sequence

    def _get_available_sequence(self, sequences):
        if not sequences:
            return 1
        for i in range(1, max(sequences)):
            if i not in sequences:
                return i
        else:
            return max(sequences) + 1

class NGFWDriver(IPsecDriver):
    def create_process(self, process_id, vpnservice, namespace,kwargs):
        return NGFWProcess(
            self.conf,
            self.root_helper,
            process_id,
            vpnservice,
            namespace,
            kwargs)
