#!/usr/bin/env python
# Copyright 2011 VMware, Inc.
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

import netaddr
import sys
import time
import os
import socket
import select
import Queue
import datetime
import random

from neutron import context as n_context
from neutron.common import constants as const

import eventlet
eventlet.monkey_patch()

from oslo.config import cfg
from six import moves

from neutron.agent import firewall
from neutron.agent import l2population_rpc
from neutron.agent.linux import ip_lib
from neutron.agent.linux import ovs_lib
from neutron.agent.linux import iptables_firewall
from neutron.agent import rpc as agent_rpc
from neutron.agent import securitygroups_rpc as sg_rpc
from neutron.api.rpc.handlers import dvr_rpc
from neutron.common import config as common_config
from neutron.agent.common import config
from neutron.common import constants as q_const
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.common import utils as q_utils
from neutron import context
from neutron.openstack.common import log as logging
from neutron.openstack.common import loopingcall
from neutron.openstack.common import jsonutils
from neutron.openstack.common import timeutils
from neutron.plugins.common import constants as p_const
from neutron.plugins.l2_proxy.common import constants
from neutron.plugins.l2_proxy.agent import neutron_proxy_context
from neutron.plugins.l2_proxy.agent import clients
from neutronclient.common import exceptions
from neutron.openstack.common import excutils
from neutron.extensions import qos
from neutron.services.qos.agents import qos_rpc
from neutron import service as neutron_service
from neutron.openstack.common import service


LOG = logging.getLogger(__name__)

# A placeholder for dead vlans.
DEAD_VLAN_TAG = str(q_const.MAX_VLAN_TAG + 1)


class DeviceListRetrievalError(exceptions.NeutronException):
    message = _("Unable to retrieve port details for devices: %(devices)s "
                "because of error: %(error)s")

class FirewallProxyDriver(iptables_firewall.IptablesFirewallDriver):
    """Driver which enforces security groups through cascaded API."""

    def __init__(self):
        super(FirewallProxyDriver, self).__init__()
        self.root_helper = cfg.CONF.AGENT.root_helper
        # list of port which has security group
        self.filtered_ports = {}
        # store new ports
        self.added_ports = {}
        # store update ports
        self.updated_ports = {}
        self._defer_apply = False
        self._pre_defer_filtered_ports = None
        # List of security group rules for ports residing on this host
        self.sg_rules = {}
        self.pre_sg_rules = None
        # List of security group member ips for ports residing on this host
        self.sg_members = {}
        self.pre_sg_members = None
        #Cache of cascade port info
        self.ports_mapping = {}
        # Cache of cascade secuirty group info
        self.sg_mapping = {}
        self.csd_sg = {}
        self.csg_sg = {}
        self.csd_sg_rules = {}
        self.local_member_ips = []
        # Get neutron client for cascaded
        self.csd_client = clients.CascadeNeutronClient(clients.CASCADED)
        self.csg_client = clients.CascadeNeutronClient(clients.CASCADING)
        self._sync_sg_mapping()

    def _sync_sg_mapping(self):
        req_props = {'name': 'default'}
        ret = self.csg_client('list_security_groups', **req_props)
        if not ret or not ret.get('security_groups') \
            or not len(ret.get('security_groups')):
            return {}

        csg_sg = {}
        for sg in ret.get('security_groups'):
            csg_sg[sg['tenant_id']] = sg

        #Try to clean unused security group on cascaded
        self.clean_security_groups_in_cascaded()

        ret = self.csd_client('list_security_groups')
        if not ret or not ret.get('security_groups') \
            or not len(ret.get('security_groups')):
            return {}

        for sg in ret.get('security_groups'):
            if sg['tenant_id'] in csg_sg and sg['name'] == 'default':
                self.sg_mapping[csg_sg[sg['tenant_id']]['id']] = sg['id']
            elif sg['name'] == 'default':
                LOG.warn("Can't find default security group from cascading by tenant_id(%s)", sg['tenant_id'])
                continue
            else:
                if len(sg['name'].split('@')) == 2:
                    self.sg_mapping[sg['name'].split('@')[1]] = sg['id']

        LOG.debug("_sync_sg_mapping (%s)", self.sg_mapping)

    def _get_port_from_cascaded(self, port_id):
        if self.ports_mapping.has_key(port_id):
            return self.ports_mapping[port_id]
        else:
            req_props = {'name': 'port@'+port_id}
            ret = self.csd_client('list_ports', **req_props)
            if not ret or not ret.get('ports') or not len(ret.get('ports')):
                return {}
            self.ports_mapping[port_id] = ret.get('ports')[0]

            return ret.get('ports')[0]

    def _create_sg_from_cascaded(self, sg_id, tenant_id):
        #create a new security group
        req_props = {'name' : 'security_group@'+sg_id,
                     'tenant_id' : tenant_id,
                     'description' : '', #can't get description from rpc info, so set empty.
                     }
        ret = self.csd_client('create_security_group', {'security_group' : req_props})

        return ret

    def _get_local_member_ips(self):
        ips_list = []

        req_props = {'binding:host_id': cfg.CONF.host}
        ret = self.csg_client('list_ports', **req_props)
        if not ret or not ret.get('ports'):
            return ips_list

        ports = ret.get('ports', [])
        for port in ports:
            fixed_ips = port['fixed_ips']
            for fixed_ip in fixed_ips:
                ip = fixed_ip['ip_address']
                ips_list.append(ip)

        return ips_list

    def _rebuild_sg_rules(self, sg_id):
        sg_rules = self.sg_rules.get(sg_id)
        if sg_rules:
            self._clear_all_sg_rules_from_cascaded(sg_id)
            self._add_new_sg_rules_from_cascaded(sg_id, sg_rules)
            LOG.debug("Rebuild security group rulees for sg_id(%s)" % sg_id)

    def add_sg_rule(self, sg_rule):
        sg_id = sg_rule['security_group_id']
        sg_rule.pop('id', None)
        sg_rules_data = sg_rule
        self._add_new_sg_rules_from_cascaded(sg_id, [sg_rules_data])

    def delete_sg_rule(self, id):
        try:
            self.csd_client('delete_security_group_rule', id)
        except exceptions.NeutronException as e:
            pass

    def _try_to_delete_sg(self, security_groups):
        #Try to delete security_groups
        for sg_id in security_groups:
            if sg_id in self.sg_mapping:
                try:
                    self.csd_client('delete_security_group', self.sg_mapping[sg_id])
                    self.sg_mapping.pop(sg_id, None)
                except exceptions.NeutronException as e:
                    pass

    def _clear_all_sg_rules_from_cascaded(self, sg_id):
        csd_sg_id = self.sg_mapping.get(sg_id)
        if csd_sg_id:
            req_props = {'security_group_id': csd_sg_id}
            sgr_ret = self.csd_client('list_security_group_rules', **req_props)['security_group_rules']
            for sgr in sgr_ret:
                self.delete_sg_rule(sgr['id'])

    def _add_new_sg_rules_from_cascaded(self, sg_id, sg_rules):
        sg_rules_list = list(sg_rules)
        new_sg_rules_set = []

        #regenerate securitygroup's rules with remote_group_id, the remote ip is across between openstack.
        for sg_rule in sg_rules_list:
            new_sg_rules_set.append(sg_rule)
            remote_sg_id = sg_rule.get('remote_group_id')
            #Could not support Ipv6 now.
            if remote_sg_id and sg_rule.get('ethertype') != 'IPv6':
                sg_member_ips = self.sg_members.get(remote_sg_id, {}).get('IPv4', [])
                remote_member_ips = set(sg_member_ips) - set(self.local_member_ips)
                for ip in remote_member_ips:
                    rule = {'ethertype': 'IPv4', 'direction': sg_rule.get('direction', 'ingress'), 'remote_ip_prefix': ip}
                    if sg_rule.get('protocol'):
                        rule['protocol'] = sg_rule.get('protocol')
                    if sg_rule.get('tenant_id'):
                        rule['tenant_id'] = sg_rule.get('tenant_id')
                    if sg_rule.get('port_range_max'):
                        rule['port_range_max'] = sg_rule.get('port_range_max')
                    if sg_rule.get('port_range_min'):
                        rule['port_range_min'] = sg_rule.get('port_range_min')

                    new_sg_rules_set.append(rule)

        rules_list = []
        #translate securitygroup's rules on cascaded openstack.
        for sg_rule in new_sg_rules_set:
            if not self.sg_mapping.get(sg_id):
                continue

            rule_dict = {"security_group_id" : self.sg_mapping.get(sg_id),
                         "remote_ip_prefix" : sg_rule.get('source_ip_prefix') or
                                              sg_rule.get('dest_ip_prefix') or
                                              sg_rule.get('remote_ip_prefix') or '',
                         'tenant_id' : self.csg_sg.get(sg_id, {}).get('tenant_id')}
            #if port_range_min is Null and port_range_max is not Null, then force set to 0
            if not sg_rule.get('port_range_min') and sg_rule.get('port_range_max'):
                rule_dict['port_range_min'] = 0

            for key in ('ethertype', 'protocol', 'port_range_min', 'port_range_max',
                        'remote_group_id', 'direction'):
                if sg_rule.has_key(key):
                    if key == 'remote_group_id':
                        csd_remote_group_id = self.sg_mapping.get(sg_rule['remote_group_id'])
                        if csd_remote_group_id:
                            rule_dict[key] = csd_remote_group_id
                        continue

                    rule_dict[key] = sg_rule[key]

            rules_list.append(rule_dict)

        LOG.debug("create security group rules on cascaded. sg_id(%s)", sg_id)
        #create security group rules by bulk API.
        if rules_list:
            try:
                ret = self.csd_client('create_security_group_rule', {'security_group_rules':rules_list})
            except exceptions.NeutronException as e:
                LOG.error("_add_new_sg_rules_from_cascaded exception(%s)", e)

    @property
    def ports(self):
        return self.filtered_ports

    def update_security_group_rules(self, sg_id, sg_rules):
        LOG.debug("Update rules of security group (%s)", sg_id)
        self.sg_rules[sg_id] = sg_rules

    def update_security_group_members(self, sg_id, sg_members):
        LOG.debug("Update members of security group (%s)", sg_id)
        self.sg_members[sg_id] = sg_members

    def prepare_port_filter(self, port):
        LOG.debug(_("Preparing device (%s) filter"), port['device'])
        self.filtered_ports[port['device']] = port
        self.added_ports[port['device']] = port

    def update_port_filter(self, port):
        LOG.debug(_("Updating device (%s) filter"), port['device'])
        if port['device'] not in self.filtered_ports:
            LOG.info(_('Attempted to update port filter which is not '
                       'filtered %s'), port['device'])
            return

        self.filtered_ports[port['device']] = port
        self.updated_ports[port['device']] = port

    def remove_port_filter(self, port):
        LOG.debug(_("Removing device (%s) filter"), port['device'])
        if not self.filtered_ports.get(port['device']):
            LOG.info(_('Attempted to remove port filter which is not '
                       'filtered %r'), port)
            return

        try:
            #Make a protection, maybe the vm is deleted failed in cascaded.
            self.csd_client('update_port', port['device'],
                                 {'port' : {'security_groups': []}})
        except:
            pass

        security_groups = port.get('security_groups', [])

        self._try_to_delete_sg(security_groups)

        self.filtered_ports.pop(port['device'], None)
        self.ports_mapping.pop(port['device'], None)

    def filter_def_apply_direct(self, security_groups):
        self.local_member_ips = self._get_local_member_ips()
        for sg_id in security_groups:
            self._rebuild_sg_rules(sg_id)

    def filter_defer_apply_on(self):
        if not self._defer_apply:
            self._pre_defer_filtered_ports = dict(self.filtered_ports)
            self.pre_sg_members = dict(self.sg_members)
            self.pre_sg_rules = dict(self.sg_rules)
            self._defer_apply = True

    def filter_defer_apply_off(self):
        if self._defer_apply:
            process_ports = {}
            self._defer_apply = False
            self.local_member_ips = self._get_local_member_ips()
            #Only process the added and updated ports
            process_ports.update(self.added_ports)
            self.added_ports = {}
            process_ports.update(self.updated_ports)
            self.updated_ports = {}
            self.setup_chains_apply(process_ports)
            self._pre_defer_filtered_ports = None

    def setup_chains_apply(self, ports):
        if not ports:
            return

        for port_id, port in ports.items():
            remote_sg_ids = set(port.get('security_group_source_groups', []) + port.get('security_groups', []))

            #check security group exist on cascaded, otherwise create its.
            for remote_sg_id in remote_sg_ids:
                is_default = False
                tenant_id = ''
                csg_sg = self.csg_sg.get(remote_sg_id)

                if not csg_sg:
                    ret = self.csg_client('show_security_group', remote_sg_id)
                    if ret and ret.get('security_group'):
                        self.csg_sg[remote_sg_id] = ret.get('security_group')
                        csg_sg = ret.get('security_group')
                    else:
                        LOG.error("Can not get security group info(%s) from cascading." % remote_sg_id)
                        continue

                #Set flag for default security group
                if csg_sg and csg_sg.get('name') == 'default':
                    is_default = True
                    tenant_id = csg_sg.get('tenant_id')

                if not self.sg_mapping.get(remote_sg_id):
                    if is_default and tenant_id:
                        req_props = {'name': 'default', 'tenant_id': tenant_id}
                        ret = self.csd_client('list_security_groups', **req_props)
                        if not ret or not ret.get('security_groups') \
                            or not len(ret.get('security_groups')):
                            LOG.error("Can not find default security group in cascaded. tenant_id:%s" % tenant_id)
                        else:
                            csd_sg_id = ret.get('security_groups')[0].get('id')
                            self.csd_sg[csd_sg_id] = ret.get('security_groups')[0]
                            self.sg_mapping[remote_sg_id] = csd_sg_id
                            self._rebuild_sg_rules(remote_sg_id)
                        continue

                    ret = self._create_sg_from_cascaded(remote_sg_id, self.csg_sg[remote_sg_id]['tenant_id'])
                    if ret and ret.get('security_group'):
                        csd_sg_id = ret.get('security_group').get('id')
                        self.csd_sg[csd_sg_id] = ret.get('security_group')
                        self.sg_mapping[remote_sg_id] = csd_sg_id
                        self._rebuild_sg_rules(remote_sg_id)
                    else:
                        LOG.error("Can not create security group info from cascading, ret:%s." % ret)
                        continue
                else:
                    sg_id = self.sg_mapping.get(remote_sg_id)
                    sg_rules = self.sg_rules.get(remote_sg_id)
                    ret = self.csd_client('show_security_group', sg_id)
                    if ret and ret.get('security_group') and sg_rules and \
                            not ret.get('security_group', {}).get('security_group_rules'):
                        self._add_new_sg_rules_from_cascaded(remote_sg_id, sg_rules)

            #check the port whether need update on cascaded.
            cascaded_port = self._get_port_from_cascaded(port_id)
            security_groups = port.get('security_groups', [])
            cascaded_sg_set = set([self.sg_mapping.get(sg_id) for sg_id in security_groups if sg_id in self.sg_mapping])
            old_cascaded_sg_set = set(cascaded_port.get('security_groups'))
            if not cascaded_port or cascaded_sg_set == old_cascaded_sg_set:
                continue
            LOG.debug(_("setup_chains_apply, update_port request(%s, %s). "), cascaded_port['id'], cascaded_sg_set)
            try:
                cascaded_port = self.csd_client('update_port', cascaded_port['id'],
                                 {'port' : {'security_groups': list(cascaded_sg_set)}})['port']
                self.ports_mapping[port_id] = cascaded_port
                self._try_to_delete_sg([csg_sg for csg_sg, csd_sg in self.sg_mapping.items()
                                        if csd_sg in old_cascaded_sg_set])
            except exceptions.NeutronException as e:
                #if port not found in cascaded, then remove it from cache.
                self.ports_mapping.pop(port_id, None)
                LOG.error(_("setup_chains_apply, update_port exception(%s). "), e)

    def clean_security_groups_in_cascaded(self):
        #clean all security groups if unbind with port.
        sg_ret = self.csd_client('list_security_groups').get('security_groups', [])
        for sg in sg_ret:
            try:
                self.csd_client('delete_security_group', sg['id'])
            except exceptions.NeutronException as e:
                pass

class QueryPortsInterface:

    cascaded_neutron_client = None

    def __init__(self):
        self.context = n_context.get_admin_context_without_session()

    def _get_cascaded_neutron_client(self):
        context = n_context.get_admin_context_without_session()
        neutron_admin_auth_url = cfg.CONF.AGENT.neutron_admin_auth_url
        kwargs = {'auth_token': None,
                  'username': cfg.CONF.AGENT.neutron_admin_user,
                  'password': cfg.CONF.AGENT.admin_password,
                  'aws_creds': None,
                  'tenant': cfg.CONF.AGENT.neutron_admin_tenant_name,
                  'auth_url': neutron_admin_auth_url,
                  'insecure': cfg.CONF.AGENT.auth_insecure,
                  'roles': context.roles,
                  'is_admin': context.is_admin,
                  'region_name': cfg.CONF.AGENT.neutron_region_name}
        reqCon = neutron_proxy_context.RequestContext(**kwargs)
        openStackClients = clients.OpenStackClients(reqCon)
        neutronClient = openStackClients.neutron()
        return neutronClient

    def _show_port(self, port_id):
        if(not QueryPortsFromCascadedNeutron.cascaded_neutron_client):
            QueryPortsFromCascadedNeutron.cascaded_neutron_client = \
            self._get_cascaded_neutron_client()
        retry = 0
        while(True):
            try:
                portResponse = QueryPortsFromCascadedNeutron.\
                cascaded_neutron_client.show_port(port_id)
                LOG.debug(_('show port, port_id=%s, Response:%s'), str(port_id),
                             str(portResponse))
                return portResponse
            except exceptions.Unauthorized:
                retry = retry + 1
                if(retry <= 3):
                    QueryPortsFromCascadedNeutron.cascaded_neutron_client = \
                        self._get_cascaded_neutron_client()
                    continue
                else:
                    with excutils.save_and_reraise_exception():
                        LOG.error(_('ERR: Try 3 times,Unauthorized to list ports!'))
                        return None
            except Exception:
                with excutils.save_and_reraise_exception():
                    LOG.error(_('ERR: show port %s failed!'), port_id)
                return None

    def _list_ports(self, since_time=None,
                    pagination_limit=None,
                    pagination_marker=None):
        filters = {'status': 'ACTIVE'}
        if(cfg.CONF.AGENT.port_timestamp_enabled and since_time):
            filters['changes_since'] = since_time
        if(pagination_limit):
            filters['limit'] = pagination_limit
            filters['page_reverse'] = 'False'
        if(pagination_marker):
            filters['marker'] = pagination_marker

        if(not QueryPortsFromCascadedNeutron.cascaded_neutron_client):
            QueryPortsFromCascadedNeutron.cascaded_neutron_client = \
                  self._get_cascaded_neutron_client()
        retry = 0
        while(True):
            try:
                portResponse = QueryPortsFromCascadedNeutron.\
                cascaded_neutron_client.get('/ports', params=filters)
                LOG.debug(_('list ports, filters:%s, since_time:%s, limit=%s, '
                            'marker=%s, Response:%s'), str(filters),
                             str(since_time), str(pagination_limit),
                             str(pagination_marker), str(portResponse))
                return portResponse
            except exceptions.Unauthorized:
                retry = retry + 1
                if(retry <= 3):
                    QueryPortsFromCascadedNeutron.cascaded_neutron_client = \
                        self._get_cascaded_neutron_client()
                    continue
                else:
                    with excutils.save_and_reraise_exception():
                        LOG.error(_('ERR: Try 3 times,Unauthorized to list ports!'))
                        return None
            except Exception:
                with excutils.save_and_reraise_exception():
                    LOG.error(_('ERR: list ports failed!'))
                return None

    def _get_ports_pagination(self, since_time=None):
        ports_info = {'ports': []}
        if cfg.CONF.AGENT.pagination_limit == -1:
            port_ret = self._list_ports(since_time)
            if port_ret:
                ports_info['ports'].extend(port_ret.get('ports', []))
            return ports_info
        else:
            pagination_limit = cfg.CONF.AGENT.pagination_limit
            first_page = self._list_ports(since_time, pagination_limit)
            if(not first_page):
                return ports_info
            ports_info['ports'].extend(first_page.get('ports', []))
            ports_links_list = first_page.get('ports_links', [])
            while(True):
                last_port_id = None
                current_page = None
                for pl in ports_links_list:
                    if (pl.get('rel', None) == 'next'):
                        port_count = len(ports_info['ports'])
                        last_port_id = ports_info['ports'][port_count - 1].get('id')
                if(last_port_id):
                    current_page = self._list_ports(since_time,
                                                    pagination_limit,
                                                    last_port_id)
                if(not current_page):
                    return ports_info
                ports_info['ports'].extend(current_page.get('ports', []))
                ports_links_list = current_page.get('ports_links', [])

class QueryPortsFromNovaproxy(QueryPortsInterface):

    ports_info = {'ports': {'add': [], 'del': []}}

    def __init__(self):
        self.context = n_context.get_admin_context_without_session()
        self.sock_path = None
        self.sock = None

    def check_or_create_path(self, file_path):
        dir_path = os.path.dirname(file_path)
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)

    def listen_and_recv_port_info(self, sock_path):
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            path = sock_path
            self.check_or_create_path(path)
            if os.path.exists(path):
                os.unlink(path)
            sock.bind(path)
            sock.listen(5)
            while(True):
                infds, outfds, errfds = select.select([sock,], [], [], 5)
                if len(infds) != 0:
                    con, addr = sock.accept()
                    recv_data = con.recv(1024)
                    self.process_recv_data(recv_data)
        except socket.error as e:
            LOG.warn(_('Error while connecting to socket: %s'), e)
            return {}


    def process_recv_data(self, data):
        LOG.debug(_('process_recv_data begin! data:%s'), data)
        data_dict = jsonutils.loads(data)
        ports = data_dict.get('ports', None)
        if(ports):
            added_ports = ports.get('add', [])
            for port_id in added_ports:
                port_ret = self._show_port(port_id)
                if port_ret and port_ret.get('port', None):
                    QueryPortsFromNovaproxy.ports_info['ports']['add']. \
                                      append(port_ret.get('port'))

    def get_update_net_port_info(self, since_time=None):
        if(since_time and (cfg.CONF.AGENT.query_ports_mode == 'nova_proxy')):
            ports_info = QueryPortsFromNovaproxy.ports_info['ports'].get('add', [])
            QueryPortsFromNovaproxy.ports_info['ports']['add'] = []
        else:
            all_ports = self._get_ports_pagination()
            ports_info = all_ports.get('ports', [])
        return ports_info

class QueryPortsFromCascadedNeutron(QueryPortsInterface):

    def __init__(self):
        self.context = n_context.get_admin_context_without_session()

    def get_update_net_port_info(self, since_time=None):
        if since_time:
            ports = self._get_ports_pagination(since_time)
        else:
            ports = self._get_ports_pagination()
        return ports.get("ports", [])

class RemotePort:

    def __init__(self, port_id, port_name, mac, binding_profile, ips=None):
        self.port_id = port_id
        self.port_name = port_name
        self.mac = mac
        self.binding_profile = binding_profile
        if(ips is None):
            self.ip = set()
        else:
            self.ip = set(ips)

class LocalPort:

    def __init__(self, port_id, cascaded_port_id, mac, ips=None):
        self.port_id = port_id
        self.cascaded_port_id = cascaded_port_id
        self.mac = mac
        if(ips is None):
            self.ip = set()
        else:
            self.ip = set(ips)

# A class to represent a VIF (i.e., a port that has 'iface-id' and 'vif-mac'
# attributes set).
class LocalVLANMapping:
    def __init__(self, network_type, physical_network, segmentation_id,
                 cascaded_net_id, vif_ports=None):
        if vif_ports is None:
            self.vif_ports = {}
        else:
            self.vif_ports = vif_ports

        self.network_type = network_type
        self.physical_network = physical_network
        self.segmentation_id = segmentation_id
        self.remote_ports = {}
        self.cascaded_net_id = cascaded_net_id
        self.cascaded_subnet = {}

    def __str__(self):
        return ("lv-id = %s type = %s phys-net = %s phys-id = %s" %
                (self.vlan, self.network_type, self.physical_network,
                 self.segmentation_id))


class ExclusivePortProcessor(object):

    _masters = {}
    _port_timestamps = {}

    def __init__(self, port_id):
        self._port_id = port_id

        if port_id not in self._masters:
            self._masters[port_id] = self
            self._queue = []

        self._master = self._masters[port_id]

    def _i_am_master(self):
        return self == self._master

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        if self._i_am_master():
            del self._masters[self._port_id]

    def _get_port_data_timestamp(self):
        return self._port_timestamps.get(self._port_id,
                                           datetime.datetime.min)

    def fetched_and_processed(self, timestamp):
        """Records the data timestamp after it is used to update the router"""
        new_timestamp = max(timestamp, self._get_port_data_timestamp())
        self._port_timestamps[self._port_id] = new_timestamp

    def queue_update(self, update):
        """Queues an update from a worker

        This is the queue used to keep new updates that come in while a router
        is being processed.  These updates have already bubbled to the front of
        the RouterProcessingQueue.
        """
        self._master._queue.append(update)

    def updates(self):
        """Processes the router until updates stop coming

        Only the master instance will process the router.  However, updates may
        come in from other workers while it is in progress.  This method loops
        until they stop coming.
        """
        if self._i_am_master():
            while self._queue:
                # Remove the update from the queue even if it is old.
                update = self._queue.pop(0)
                # Process the update only if it is fresh.
                if self._get_port_data_timestamp() < update.timestamp:
                    yield update


class PortProcessingQueue(object):
    """Manager of the queue of routers to process."""
    def __init__(self):
        self._queue = Queue.PriorityQueue()

    def add(self, update):
        self._queue.put(update)

    def each_update_to_next_port(self):
        """Grabs the next router from the queue and processes

        This method uses a for loop to process the router repeatedly until
        updates stop bubbling to the front of the queue.
        """
        LOG.debug(_("in queue."))
        next_update = self._queue.get()

        with ExclusivePortProcessor(next_update.id) as pp:
            # Queue the update whether this worker is the master or not.
            pp.queue_update(next_update)

            # Here, if the current worker is not the master, the call to
            # rp.updates() will not yield and so this will essentially be a
            # noop.
            for update in pp.updates():
                yield (pp, update)


class PortUpdate(object):
    """Encapsulates a router update

    An instance of this object carries the information necessary to prioritize
    and process a request to update a router.
    """
    def __init__(self, port_id,
                 timestamp=None, remove=False, add_periodic=False, full_sync=False,
                 network_id=None, mac_address=None):
        self.timestamp = timestamp
        if not timestamp:
            self.timestamp = timeutils.utcnow()
        self.id = port_id
        self.remove = remove
        self.network_id = network_id
        self.mac_address = mac_address
        self.add_periodic = add_periodic
        self.full_sync = full_sync

    def __lt__(self, other):
        if self.timestamp != other.timestamp:
            return self.timestamp < other.timestamp
        return self.id < other.id


class PortCache(object):
    def __init__(self):
        self.cache = {}

    def put(self, port_id, already_processing=False):
        if port_id in self.cache:
            self.remove(self.cache[port_id])

        port_cache_info = {'already_processing': already_processing}
        self.cache[port_id] = port_cache_info

    def remove(self, port_id):
        del self.cache[port_id]

    def update(self, port_id, already_processing):
        if port_id not in self.cache:
            return

        port_cache_info = {'already_processing': already_processing}
        self.cache[port_id] = port_cache_info

    def get(self, port_id):
        if port_id not in self.cache:
            return False
        return self.cache[port_id].get('already_processing')

class OVSPluginApi(agent_rpc.PluginApi,
                   dvr_rpc.DVRServerRpcApiMixin,
                   sg_rpc.SecurityGroupServerRpcApiMixin,
                   qos_rpc.QoSServerRpcApiMixin,):
    pass

class OVSSecurityGroupAgent(sg_rpc.SecurityGroupAgentRpcMixin):
    def __init__(self, context, plugin_rpc, root_helper):
        self.context = context
        self.plugin_rpc = plugin_rpc
        self.root_helper = root_helper
        self.init_firewall(defer_refresh_firewall=False)

    def security_groups_rule_updated(self, security_groups):
        LOG.info("Security group rule updated %s from porxy" % security_groups)
        self._security_group_updated(
            security_groups,
            'security_groups')

    def security_groups_member_updated(self, security_groups):
        LOG.info("Security group member updated %s from porxy" % security_groups)
        self._security_group_updated(
            security_groups,
            'security_group_source_groups')

    def _get_sec_grp_info(self, security_groups):
        sg_id = set()
        sg_rules = list()
        if isinstance(security_groups, dict):
            for sg_rule_info in security_groups.values():
                rule = sg_rule_info.get('rule', {})
                sg_id.update([rule.get('security_group_id')])
                sg_rules.append(sg_rule_info)
        else:
            sg_id = set(security_groups)

        return sg_id, sg_rules

    def _security_group_updated(self, security_groups, attribute):
        devices = []
        sec_grp_set, sg_rules = self._get_sec_grp_info(security_groups)
        for device in self.firewall.ports.values():
            if sec_grp_set & set(device.get(attribute, [])):
                devices.append(device['device'])
        if devices:
            if self.use_enhanced_rpc:
                devices_info = self.plugin_rpc.security_group_info_for_devices(
                    self.context, devices)
                devices = devices_info['devices']
                security_groups = devices_info['security_groups']
                security_group_member_ips = devices_info['sg_member_ips']
            else:
                devices = self.plugin_rpc.security_group_rules_for_devices(
                    self.context, devices)

            if self.use_enhanced_rpc:
                LOG.debug("Update security group information for ports %s in proxy",
                          devices.keys())
                self._update_security_group_info(
                    security_groups, security_group_member_ips)
                self.firewall.filter_def_apply_direct(security_groups.keys())
            else:
                for sg_rule in sg_rules:
                    if sg_rule.get('action') == "create":
                        self.firewall.add_sg_rule(sg_rule['rule'])
                    elif sg_rule.get("delete") == "delete":
                        self.firewall.delete_sg_rule(sg_rule['rule'])

class OVSQoSAgent(qos_rpc.QoSAgentRpcMixin):
    def __init__(self, context, plugin_rpc, root_helper):
        self.context = context
        self.plugin_rpc = plugin_rpc
        self.root_helper = root_helper

    def port_qos_updated(self, context, qos_id, port_id):
        result = {}
        result['qos'] = self.plugin_rpc.get_qos_details_by_port(self.context, port_id)
        self.qos.port_qos_updated(result['qos'].get("policies"), port_id, **result)

    def port_qos_deleted(self, context, qos_id, port_id):
        self.qos.delete_qos_for_port(qos_id, port_id)

class OVSNeutronAgent(n_rpc.RpcCallback,
                      sg_rpc.SecurityGroupAgentRpcCallbackMixin,
                      l2population_rpc.L2populationRpcCallBackTunnelMixin,
                      dvr_rpc.DVRAgentRpcCallbackMixin):
    '''Implements OVS-based tunneling, VLANs and flat networks.

    Two local bridges are created: an integration bridge (defaults to
    'br-int') and a tunneling bridge (defaults to 'br-tun'). An
    additional bridge is created for each physical network interface
    used for VLANs and/or flat networks.

    All VM VIFs are plugged into the integration bridge. VM VIFs on a
    given virtual network share a common "local" VLAN (i.e. not
    propagated externally). The VLAN id of this local VLAN is mapped
    to the physical networking details realizing that virtual network.

    For virtual networks realized as GRE tunnels, a Logical Switch
    (LS) identifier is used to differentiate tenant traffic on
    inter-HV tunnels. A mesh of tunnels is created to other
    Hypervisors in the cloud. These tunnels originate and terminate on
    the tunneling bridge of each hypervisor. Port patching is done to
    connect local VLANs on the integration bridge to inter-hypervisor
    tunnels on the tunnel bridge.

    For each virtual network realized as a VLAN or flat network, a
    veth or a pair of patch ports is used to connect the local VLAN on
    the integration bridge with the physical network bridge, with flow
    rules adding, modifying, or stripping VLAN tags as necessary.
    '''

    # history
    #   1.0 Initial version
    #   1.1 Support Security Group RPC
    #   1.2 Support DVR (Distributed Virtual Router) RPC
    RPC_API_VERSION = '1.2'

    DEFAULT_BRIDGE_MAPPINGS = []
    DEFAULT_VLAN_RANGES = []
    DEFAULT_TUNNEL_RANGES = []
    DEFAULT_TUNNEL_TYPES = []

    ovs_opts = [
    cfg.StrOpt('integration_bridge', default='br-int',
               help=_("Integration bridge to use.")),
    cfg.BoolOpt('enable_tunneling', default=False,
                help=_("Enable tunneling support.")),
    cfg.StrOpt('tunnel_bridge', default='br-tun',
               help=_("Tunnel bridge to use.")),
    cfg.StrOpt('int_peer_patch_port', default='patch-tun',
               help=_("Peer patch port in integration bridge for tunnel "
                      "bridge.")),
    cfg.StrOpt('tun_peer_patch_port', default='patch-int',
               help=_("Peer patch port in tunnel bridge for integration "
                      "bridge.")),
    cfg.StrOpt('local_ip', default='127.0.0.1',
               help=_("Local IP address of GRE tunnel endpoints.")),
    cfg.ListOpt('bridge_mappings',
                default=DEFAULT_BRIDGE_MAPPINGS,
                help=_("List of <physical_network>:<bridge>. "
                       "Deprecated for ofagent.")),
    cfg.StrOpt('tenant_network_type', default='local',
               help=_("Network type for tenant networks "
                      "(local, vlan, gre, vxlan, or none).")),
    cfg.ListOpt('network_vlan_ranges',
                default=DEFAULT_VLAN_RANGES,
                help=_("List of <physical_network>:<vlan_min>:<vlan_max> "
                       "or <physical_network>.")),
    cfg.ListOpt('tunnel_id_ranges',
                default=DEFAULT_TUNNEL_RANGES,
                help=_("List of <tun_min>:<tun_max>.")),
    cfg.StrOpt('tunnel_type', default='vxlan',
               help=_("The type of tunnels to use when utilizing tunnels, "
                      "either 'gre' or 'vxlan'.")),
    cfg.BoolOpt('use_veth_interconnection', default=False,
                help=_("Use veths instead of patch ports to interconnect the "
                       "integration bridge to physical bridges.")),
    ]

    agent_opts = [
        cfg.IntOpt('polling_interval', default=1,
                   help=_("The number of seconds the agent will wait between "
                          "polling for local device changes.")),
        cfg.BoolOpt('minimize_polling',
                    default=True,
                    help=_("Minimize polling by monitoring ovsdb for interface "
                           "changes.")),
        cfg.IntOpt('ovsdb_monitor_respawn_interval',
                   default=constants.DEFAULT_OVSDBMON_RESPAWN,
                   help=_("The number of seconds to wait before respawning the "
                          "ovsdb monitor after losing communication with it.")),
        cfg.ListOpt('tunnel_types', default=DEFAULT_TUNNEL_TYPES,
                    help=_("Network types supported by the agent "
                           "(gre and/or vxlan).")),
        cfg.IntOpt('vxlan_udp_port', default=p_const.VXLAN_UDP_PORT,
                   help=_("The UDP port to use for VXLAN tunnels.")),
        cfg.IntOpt('veth_mtu',
                   help=_("MTU size of veth interfaces")),
        cfg.BoolOpt('l2_population', default=False,
                    help=_("Use ML2 l2population mechanism driver to learn "
                           "remote MAC and IPs and improve tunnel scalability.")),
        cfg.BoolOpt('base_handle', default=False,
                    help=_("handle network subnet port update.")),
        cfg.BoolOpt('arp_responder', default=False,
                    help=_("Enable local ARP responder if it is supported. "
                           "Requires OVS 2.1 and ML2 l2population driver. "
                           "Allows the switch (when supporting an overlay) "
                           "to respond to an ARP request locally without "
                           "performing a costly ARP broadcast into the overlay.")),
        cfg.BoolOpt('dont_fragment', default=True,
                    help=_("Set or un-set the don't fragment (DF) bit on "
                           "outgoing IP packet carrying GRE/VXLAN tunnel.")),
        cfg.BoolOpt('enable_distributed_routing', default=False,
                    help=_("Make the l2 agent run in DVR mode.")),
        cfg.StrOpt('neutron_region_name', default=None,
                   help=_("cascaded neutron_region name to use")),
        cfg.StrOpt('neutron_admin_auth_url', default='http://127.0.0.1:35357/v2.0',
                   help=_("keystone auth url to use")),
        cfg.StrOpt('neutron_admin_user',
                   help=_("access neutron user name to use"),
                   secret=True),
        cfg.StrOpt('admin_password',
                   help=_("access neutron password to use"),
                   secret=True),
        cfg.StrOpt('neutron_admin_tenant_name',
                   help=_("access neutron tenant to use"),
                   secret=True),
        cfg.StrOpt('region_name', default=None,
                   help=_("cascading neutron_region name to use")),
        cfg.BoolOpt('auth_insecure',
                default=False,
                help=_("Turn off verification of the certificate for"
                       " ssl")),
        cfg.IntOpt('pagination_limit', default=-1,
                   help=_("list ports pagination limit, default value is -1,"
                          "means no pagination")),
        cfg.BoolOpt('port_timestamp_enabled', default=False,
                   help=_('Make timestamp field to port table for improve '
                          'l3-proxy performance.')),
        cfg.BoolOpt('remote_port_enabled',
               default=False,
               help=_('whether allowed create big2layer network '
                      'The Allowed values are:True or False')),
        cfg.StrOpt('query_ports_mode', default='nova_proxy',
                   help=_("query ports mode, default value is nova_proxy,"
                          "means query ports from nova_proxy")),
        cfg.StrOpt('proxy_sock_path', default='/var/l2proxysock',
                   help=_("socket path when query ports from nova_proxy")),
    ]

    def __init__(self, host, conf=None):
        if conf:
            self.conf = conf
        else:
            self.conf = cfg.CONF
        super(OVSNeutronAgent, self).__init__()

        self.use_veth_interconnection = self.conf.OVS.use_veth_interconnection
        self.veth_mtu = self.conf.AGENT.veth_mtu
        self.root_helper = config.get_root_helper(self.conf)
        self.available_local_vlans = set(moves.xrange(const.MIN_NET_NO,
                                                      const.MAX_NET_NO))
        self.use_call = True
        self.fullsync = True
        self.host = cfg.CONF.host
        self.tunnel_types = self.conf.AGENT.tunnel_types or []

        self.l2_pop = self.conf.AGENT.l2_population
        self.base_handle = self.conf.AGENT.base_handle
        # TODO(ethuleau): Change ARP responder so it's not dependent on the
        #                 ML2 l2 population mechanism driver.
        self.enable_distributed_routing = self.conf.AGENT.enable_distributed_routing
        self.arp_responder_enabled = self.conf.AGENT.arp_responder and self.l2_pop
        self.dhcp_distributed = cfg.CONF.dhcp_distributed

        try:
            bridge_mappings = q_utils.parse_mappings(self.conf.OVS.bridge_mappings)
        except ValueError as e:
            raise ValueError(_("Parsing bridge_mappings failed: %s.") % e)

        self.local_ip = None
        self.agent_state = {
            'binary': 'neutron-l2-proxy',
            'host': cfg.CONF.host,
            'topic': q_const.L2_AGENT_TOPIC,
            'configurations': {'bridge_mappings': bridge_mappings,
                               'tunnel_types': self.tunnel_types,
                               'tunneling_ip': self.local_ip,
                               'l2_population': self.l2_pop,
                               'arp_responder_enabled':
                               self.arp_responder_enabled,
                               'enable_distributed_routing':
                               self.enable_distributed_routing},
            'agent_type': q_const.AGENT_TYPE_OVS,
            'start_flag': True}

        #The dict format is {'cascading_port_id': 'cascaded_port_object'}
        self.cascaded_port_info = {}
        self.cascading_neutron_client = clients.CascadeNeutronClient(clients.CASCADING)
        self.cascaded_neutron_client = clients.CascadeNeutronClient(clients.CASCADED)

        # Keep track of int_br's device count for use by _report_state()
        self.int_br_device_count = 0

        self.int_br = ovs_lib.OVSBridge(self.conf.OVS.integration_bridge, self.root_helper)
        # Stores port update notifications for processing in main rpc loop
        self.updated_ports = set()
        self.setup_rpc()
        self.bridge_mappings = bridge_mappings
        self.local_vlan_map = {}
        self.tun_br_ofports = {p_const.TYPE_GRE: {},
                               p_const.TYPE_VXLAN: {}}

        self.polling_interval = self.conf.AGENT.polling_interval
        self.minimize_polling = self.conf.AGENT.minimize_polling
        self.ovsdb_monitor_respawn_interval = constants.DEFAULT_OVSDBMON_RESPAWN

        if self.tunnel_types:
            self.enable_tunneling = True
        else:
            self.enable_tunneling = False

        self.tunnel_count = 0
        self.vxlan_udp_port = self.conf.AGENT.vxlan_udp_port
        self.dont_fragment = self.conf.AGENT.dont_fragment
        self.tun_br = None
        self.patch_int_ofport = constants.OFPORT_INVALID
        self.patch_tun_ofport = constants.OFPORT_INVALID

        # Security group agent support
        self.sg_agent = OVSSecurityGroupAgent(self.context,
                                              self.plugin_rpc,
                                              self.root_helper)
        self._queue = PortProcessingQueue()
        self.period_queue = Queue.Queue()
        self.port_cache = PortCache()
        self.init_qos()
        # Initialize iteration counter
        self.iter_num = 0
        self.run_daemon_loop = True

    def init_qos(self):
        # QoS agent support
        self.qos_agent = OVSQoSAgent(self.context,
                                     self.plugin_rpc,
                                     self.root_helper)

        self.qos_agent.init_qos(ports_mapping=self.cascaded_port_info)

    def init_host(self):
        pass

    def periodic_tasks(self, context, raise_on_error=False):
        self.run_periodic_tasks(context, raise_on_error=raise_on_error)

    def run_periodic_tasks(self, context, raise_on_error=False):
        pass

    def network_qos_updated(self, context, **kwargs):
        #reservation method
        pass

    def network_qos_deleted(self, context, **kwargs):
        #reservation method
        pass

    def port_qos_deleted(self, context, **kwargs):
        qos_id = kwargs.get('qos_id', '')
        port_id = kwargs.get('port_id', '')
        self.qos_agent.port_qos_deleted(context, qos_id, port_id)

    def port_qos_updated(self, context, **kwargs):
        qos_id = kwargs.get('qos_id', '')
        port_id = kwargs.get('port_id', '')
        self.qos_agent.port_qos_updated(context, qos_id, port_id)

    def _report_state(self):
        # How many devices are likely used by a VM
        self.agent_state.get('configurations')['devices'] = (
            self.int_br_device_count)
        try:
            # retry to get cascaded neutron version to confirm cascaded neutron service is OK
            # ERROR will stop to report state to server
            # API error cause sync task
            csd_neutron_ready = self.check_cascaded_service_ready()
            if csd_neutron_ready:
                self.state_rpc.report_state(self.context,
                                            self.agent_state,
                                            self.use_call)
                self.use_call = False
                self.agent_state.pop('start_flag', None)
            else:
                LOG.error(_("Cascaded neutron service error!"))

        except Exception:
            LOG.exception(_("Failed reporting state!"))

    def setup_rpc(self):
        self.agent_id = 'ovs-agent-%s' % cfg.CONF.host
        self.topic = topics.AGENT
        self.plugin_rpc = OVSPluginApi(topics.PLUGIN)
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.PLUGIN)

        # RPC network init
        self.context = context.get_admin_context_without_session()
        # Handle updates from service
        self.endpoints = [self]
        # Define the listening consumers for the agent
        consumers = [[topics.PORT, topics.UPDATE],
                     [topics.PORT, topics.DELETE],
                     [topics.NETWORK, topics.DELETE],
                     [constants.TUNNEL, topics.UPDATE],
                     [topics.SECURITY_GROUP, topics.UPDATE],
                     [topics.DVR, topics.UPDATE],
                     [topics.QOS, topics.UPDATE]]
        if self.l2_pop:
            consumers.append([topics.L2POPULATION,
                              topics.UPDATE, cfg.CONF.host])
        if self.base_handle:
            LOG.debug(_("extend subnet network port update"))
            base_consumers = [[topics.SUBNET, topics.UPDATE],
                              [topics.SUBNET, topics.DELETE],
                              [topics.NETWORK, topics.UPDATE]]
            consumers.extend(base_consumers)
        self.connection = agent_rpc.create_consumers(self.endpoints,
                                                     self.topic,
                                                     consumers)
        report_interval = self.conf.AGENT.report_interval
        if report_interval:
            heartbeat = loopingcall.FixedIntervalLoopingCall(
                self._report_state)
            heartbeat.start(interval=report_interval)

    def check_cascaded_service_ready(self):
        for retry in range(const.GET_RETRY):
            try:
                neutron_extensions = self.cascaded_neutron_client('list_extensions')
                if neutron_extensions:
                    return True
            except Exception:
                if retry == (const.GET_RETRY - 1):
                    self.fullsync = True
                    return False

    def list_cascaded_network_by_name(self, name):
        search_opts = {'name': [name]}
        cascaded_net = self.cascaded_neutron_client('list_networks', **search_opts)
        return cascaded_net

    def list_cascading_network_by_id(self, id):
        search_opts = {'id': [id]}
        cascading_net = self.cascading_neutron_client('list_networks', **search_opts)
        return cascading_net

    def delete_cascaded_network_by_id(self, network_id):
        for i in range(const.DESTROY_RETRY):
            try:
                self.cascaded_neutron_client('delete_network', network_id)
                LOG.debug(_("Network %s was deleted successfully."), network_id)
                break
            except Exception as e:
                LOG.error('Delete cascaded network %s failed! Exception:%s',
                          network_id, str(e))
                subnets_ret = self.list_cascaded_subnet_by_network_id(network_id)
                if subnets_ret and len(subnets_ret.get('subnets')) > 0:
                    for subnet in subnets_ret.get('subnets'):
                        subnet_id = subnet['id']
                        self.clear_cascaded_port_for_subnet(subnet_id)
                        try:
                            self.cascaded_neutron_client('delete_subnet', subnet_id)
                            LOG.debug(_("Subnet %s was deleted successfully."), subnet_id)
                        except Exception as e:
                            LOG.error('Delete cascaded subnet %s failed! Exception:%s',
                                      subnet_id, str(e))
                            continue
                continue

    def get_csd_network_name(self, network_id):
        return 'network@' + network_id

    def get_network_request(self, network):
        updatenetwork = {}
        updatenetwork['router:external'] = network.get('router:external', False)
        updatenetwork['shared'] = network.get('shared', False)
        updatenetwork['admin_state_up'] = network.get('admin_state_up', True)
        return updatenetwork

    def network_update(self, context, **kwargs):
        LOG.debug(_("network_update received"))
        network = kwargs.get('network')
        if network:
            network_id = network.get('id')
            LOG.debug(_("start update network, the network_id is %s"), network_id)
            csd_network_name = self.get_csd_network_name(network_id)
            network_ret = self.list_cascaded_network_by_name(csd_network_name)
            if(network_ret and (network_ret.get('networks'))):
                req_props = self.get_network_request(network)
                network_ret = self.cascaded_neutron_client('update_network', \
                    network_ret.get('networks')[0]['id'], {'network': req_props})
                if not network_ret or not network_ret.get('network'):
                    LOG.error(_("update cascaded network for %s failed.") %
                               network_id)

    def network_delete(self, context, **kwargs):
        LOG.debug(_("network_delete received"))
        network_id = kwargs.get('network_id')
        LOG.debug(_("start delete network, the network_id is %s"), network_id)
        csd_network_name = self.get_csd_network_name(network_id)
        network_ret = self.list_cascaded_network_by_name(csd_network_name)
        if(network_ret and (network_ret.get('networks'))):
            cascaded_net = network_ret['networks'][0]
            self.delete_cascaded_network_by_id(cascaded_net['id'])

    def get_subnet_req(self, subnet):
        csg_network_id = subnet['network_id']
        csd_network_name = self.get_csd_network_name(csg_network_id)
        network_ret = self.list_cascaded_network_by_name(csd_network_name)
        if(network_ret and (network_ret.get('networks'))):
            csd_network_id = network_ret['networks'][0]['id']
        else:
            LOG.error(_("cascaded network get failed, "
                        "csg network id:%s"), csg_network_id)
            return
        subnet_req = {'subnet': {
                      'name': self.get_csd_subnet_name(subnet['id']),
                      'cidr': subnet['cidr'],
                      'enable_dhcp': subnet['enable_dhcp'],
                      'allocation_pools': subnet['allocation_pools'],
                      'host_routes': subnet['host_routes'],
                      'dns_nameservers': subnet['dns_nameservers'],
                      'gateway_ip': subnet['gateway_ip'],
                      'ip_version': subnet['ip_version'],
                      'network_id': csd_network_id,
                      'tenant_id': subnet['tenant_id']}}
        return subnet_req


    def create_cascaded_subnet(self, cascading_subnet):
        subnet_req = self.get_subnet_req(cascading_subnet)
        if not subnet_req:
            return
        try:
            bodyResponse = self.cascaded_neutron_client('create_subnet', subnet_req)
            LOG.debug(_('create subnet, Response:%s'),
                      str(bodyResponse))
            return bodyResponse
        except Exception as e:
            LOG.error('create subnet %s failed! Exception:%s',
                      cascading_subnet['id'], str(e))
            return None

    def get_csd_subnet_name(self, subnet_id):
        return 'subnet@' + subnet_id

    def list_cascading_subnet_by_network_id(self, id):
        search_opts = {'network_id': [id]}
        cascading_subnet = self.cascading_neutron_client('list_subnets', **search_opts)
        return cascading_subnet

    def list_cascaded_subnet_by_network_id(self, id):
        search_opts = {'network_id': [id]}
        cascaded_subnet = self.cascaded_neutron_client('list_subnets', **search_opts)
        return cascaded_subnet

    def list_cascaded_subnet_by_name(self, name):
        search_opts = {'name': [name]}
        cascaded_subnet = self.cascaded_neutron_client('list_subnets', **search_opts)
        return cascaded_subnet

    def get_subnet_request(self, subnet, original_subnet):
        updatesubnet = {}
        if subnet.get('gateway_ip') != original_subnet.get('gateway_ip'):
            updatesubnet['gateway_ip'] = subnet.get('gateway_ip')

        updatesubnet['allocation_pools'] = [{'start': ip['start'],\
                                                    'end': ip['end']} \
                                                   for ip in subnet.get('allocation_pools')]

        updatesubnet['host_routes'] = [{'destination': route['destination'],\
                                               'nexthop': route['nexthop']} \
                                                for route in subnet.get('host_routes')]
        updatesubnet['dns_nameservers'] = [dns for dns in subnet.get('dns_nameservers')]
        if subnet.get('enable_dhcp', None) is not None and subnet.get('enable_dhcp') != original_subnet.get(
                'enable_dhcp'):
            updatesubnet['enable_dhcp'] = subnet.get('enable_dhcp')
        return updatesubnet

    def subnet_update(self, context, **kwargs):
        LOG.debug(_("subnet_update received"))
        subnet = kwargs.get('subnet')
        original_subnet = kwargs.get('original_subnet')
        if subnet:
            subnet_id = subnet.get('id')
            LOG.debug(_("start update subnet, the subnet_id is %s"), subnet_id)
            csd_subnet_name = self.get_csd_subnet_name(subnet_id)
            subnet_ret = self.list_cascaded_subnet_by_name(csd_subnet_name)
            if(subnet_ret and (subnet_ret.get('subnets'))):
                req_props = self.get_subnet_request(subnet, original_subnet)
                if req_props.get('enable_dhcp', None) is True:
                    self._judge_dhcp_port(subnet['network_id'])
                elif req_props.get('enable_dhcp', None) is False:
                    LOG.debug(_("disable_dhcp: delete dhcp_port"))
                    self._delete_dhcp_port(subnet_ret.get('subnets')[0]['network_id'])
                subnet_ret = self.cascaded_neutron_client('update_subnet', \
                    subnet_ret.get('subnets')[0]['id'], {'subnet': req_props})
                if not subnet_ret or not subnet_ret.get('subnet'):
                    LOG.error(_("update cascaded subnet for %s failed.") %
                               subnet_id)

    def _delete_dhcp_port(self, cad_network_id):
        """
        delete cascaded dhcp ports, cascading dhcp ports deleted by neutron-server cascading_driver
        :param cad_network_id:
        :return:
        """
        search_opts = {'device_owner': 'network:dhcp',
                       'network_id': cad_network_id}
        dhcp_ports = self.cascaded_neutron_client('list_ports', **search_opts).get('ports', [])
        if dhcp_ports:
            for dhcp_port in dhcp_ports:
                self.cascaded_neutron_client('delete_port', dhcp_port.get('id'))

    def subnet_delete(self, context, **kwargs):
        LOG.debug(_("subnet_delete received"))
        subnet_id = kwargs.get('subnet_id')
        LOG.debug(_("start delete subnet, the subnet_id is %s"), subnet_id)
        csd_subnet_name = self.get_csd_subnet_name(subnet_id)
        subnet_ret = self.list_cascaded_subnet_by_name(csd_subnet_name)
        if(subnet_ret and (subnet_ret.get('subnets'))):
            self.delete_cascaded_subnet_by_id(subnet_ret.get('subnets')[0]['id'])

    def delete_cascaded_subnet_by_id(self, subnet_id):
        try:
            self.cascaded_neutron_client('delete_subnet', subnet_id)
        except Exception as e:
            LOG.error('Delete cascaded subnet %s failed! Exception:%s',
                      subnet_id, str(e))
            self.clear_cascaded_port_for_subnet(subnet_id)
            self.cascaded_neutron_client('delete_subnet', subnet_id)


    def clear_cascaded_port_for_subnet(self, subnet_id):
        ports_ret = self.list_cascaded_port_by_subnet_id(subnet_id)
        if ports_ret and len(ports_ret.get('ports')) > 0:
            for port in ports_ret.get('ports'):
                if port['device_owner'] == const.DEVICE_OWNER_DVR_INTERFACE or \
                    port['device_owner'] == const.DEVICE_OWNER_AGENT_GW or \
                    port['device_owner'] == const.DEVICE_OWNER_ROUTER_SNAT:
                    LOG.info(_("Subnet %s is bound on a router"), subnet_id)
                    router_id = port['device_id']
                    try:
                        self.remove_interface_router(router_id, subnet_id)
                    except Exception as e:
                        LOG.error('Remove router %s interface failed! Exception:%s',
                                  router_id, str(e))
                        self._delete_cascaded_floating_ips_by_subnet_id(subnet_id)
                        router_ret = self.cascaded_neutron_client('show_router', router_id)
                        if router_ret and router_ret.get('router'):
                            subnet_ret = self.cascaded_neutron_client('show_subnet', router_id)
                            cidr = subnet_ret.get('subnet', {}).get('cidr')
                            if cidr:
                                LOG.debug(_("Update Router routes to delete router_interface"))
                                self._delete_router_routes_for_interface(router_ret.get('router'), cidr)
                            try:
                                self.remove_interface_router(router_id, subnet_id)
                            except Exception as e:
                                LOG.error('Remove router %s interface failed again! Exception:%s',
                                      router_id, str(e))
                        continue
                else:
                    try:
                        self.cascaded_neutron_client('delete_port', port['id'])
                    except Exception as e:
                        LOG.error('Delete cascaded port %s failed! Exception:%s',
                                  port['id'], str(e))
                        continue

    def _delete_router_routes_for_interface(self, csd_router, subnet_cidr):
        subnet_cidr = netaddr.IPNetwork(subnet_cidr)
        extra_routes = csd_router.get('routes')
        final_routes = [route for route in extra_routes
                        if not netaddr.all_matching_cidrs(route['nexthop'], [subnet_cidr])]
        req_props = {"routes": final_routes}
        LOG.debug("update router: %s", req_props)
        self.cascaded_neutron_client('update_router', csd_router.get('id'), {'router': req_props})

    def get_cascaded_floating_ips_by_port(self, port_id):
        filters = {'port_id': port_id}
        floating_ips_ret = self.cascaded_neutron_client('list_floatingips', **filters)
        if (not floating_ips_ret) or (floating_ips_ret and not floating_ips_ret.get('floatingips')):
            return []
        else:
            return floating_ips_ret.get('floatingips')

    def _delete_cascaded_floating_ips_by_subnet_id(self, csd_subnet_id):
        req_props_list = {'fixed_ips': "subnet_id=" + csd_subnet_id}
        csd_ports = self.cascaded_neutron_client('list_ports', **req_props_list)
        if not csd_ports or not csd_ports.get('ports'):
            return
        csd_ports = csd_ports.get('ports')
        for csd_port in csd_ports:
            fips = self.get_cascaded_floating_ips_by_port(csd_port.get('id'))
            for fip in fips:
                try:
                    floating_ip_ret = self.cascaded_neutron_client('delete_floatingip', fip['id'])
                    LOG.debug(_('delete cascaded_floatingip for %s, Response:%s') %
                              (fip.get('id'), str(floating_ip_ret)))
                except Exception, e:
                    LOG.error(_("delete cascaded_floatingip for %s, failed: %s"), fip.get('id'), e)


    def list_cascaded_port_by_subnet_id(self, id):
        search_opts = {'fixed_ips': 'subnet_id=%s' % id}
        cascaded_ports = self.cascaded_neutron_client('list_ports', **search_opts)
        return cascaded_ports

    def remove_interface_router(self, router_id, subnet_id):
        req_props = {'subnet_id': [subnet_id]}
        remove_ret = self.cascaded_neutron_client('remove_interface_router', router_id, **req_props)
        return remove_ret

    def port_update(self, context, **kwargs):
        port = kwargs.get('port')
        # Put the port identifier in the updated_ports set.
        # Even if full port details might be provided to this call,
        # they are not used since there is no guarantee the notifications
        # are processed in the same order as the relevant API requests
        self._add_port_update(port['id'])

    def port_delete(self, context, **kwargs):
        port = kwargs.get('port')
        network_id =  port['network_id']
        mac_address = port['mac_address']
        self._add_port_delete(port['id'], network_id, mac_address)

    def is_port_updated(self, original_port, updated_port):
        check_attrs = ['allowed_address_pairs',
                       'extra_dhcp_opts',
                       'admin_state_up']
        for attr in check_attrs:
            if attr in updated_port and \
                updated_port[attr] != original_port[attr]:
                    return True
        if not self.compare_port_info(original_port, updated_port):
            return True

    def port_update_for_cascaded(self, port):
        LOG.debug("Starting cascaded port update for %s", port)
        if port['device_owner'] == const.DEVICE_OWNER_DVR_INTERFACE:
            req_props = {'name': 'router_port@' + port['id']}
        else:
            req_props = {'name': 'port@' + port['id']}
        port_ret = ''
        try:
            port_ret = self.cascaded_neutron_client('list_ports', **req_props)
            LOG.debug("port_ret is %s", port_ret)
            if not port_ret or len(port_ret.get('ports')) <= 0:
                return  False
            cascaded_port = port_ret['ports'][0]
            self.cascaded_port_info[port['id']] = cascaded_port
            if self.is_port_updated(cascaded_port, port):
                port_id = cascaded_port.get('id')
                req_props = self.get_port_request(port)
                if req_props:
                    port_ret = self.cascaded_neutron_client('update_port', port_id, {'port': req_props})
                    if not port_ret or not port_ret.get('port'):
                        LOG.error(_("update cascaded port for %s failed.") %
                                    port['id'])
                        return False
                    self.cascaded_port_info[port['id']] = port_ret.get('port')
                    LOG.debug("cascaded_port_info is %s", self.cascaded_port_info[port['id']])
                    return True
                else:
                    return False
            return True

        except Exception:
            LOG.error(_("update cascaded port for %s failed, Response is %s") %
                                      (port['id'],str(port_ret)))
            return False

    def get_port_request(self, port):
        updateport = {}
        updateport['extra_dhcp_opts'] = [{'opt_name': dopt['opt_name'],\
                                                    'opt_value': dopt['opt_value']} \
                                                   for dopt in port.get('extra_dhcp_opts')]
        updateport['admin_state_up'] = port.get('admin_state_up', True)
        updateport['fixed_ips'] = self.port_fixed_ips_update(port.get('fixed_ips'))
        if not updateport['fixed_ips']:
            return
        if cfg.CONF.SECURITYGROUP.enable_security_group:
            updateport['allowed_address_pairs'] = [{'ip_address': ip['ip_address'],\
                                                        'mac_address': ip['mac_address']} \
                                                       for ip in port.get('allowed_address_pairs')]
        return updateport



    def ensure_port_update_for_cascaded_dvr_port(self, port):
        if self.port_update_for_cascaded(port):
            return True
        return False

    def ensure_cascaded_nondvr_port_ready(self, port, port_info, add_periodic):
        if self.port_update_for_cascaded(port):
            if not add_periodic:
                try:
                    if qos.QOS in port:
                        if port[qos.QOS]:
                            self.qos_agent.port_qos_updated(self.context, port[qos.QOS],
                                                            port['id'])
                        else:
                            self.qos_agent.port_qos_deleted(self.context, None, port['id'])
                except Exception as e:
                    LOG.error('Handle qos failed! Exception:%s', str(e))

                try:
                    # TODO(salv-orlando): consider a solution for ensuring notifications
                    # are processed exactly in the same order in which they were
                    # received. This is tricky because there are two notification
                    # sources: the neutron server, and the ovs db monitor process
                    # If there is an exception while processing security groups ports
                    # will not be wired anyway, and a resync will be triggered
                    # TODO(salv-orlando): Optimize avoiding applying filters unnecessarily
                    # (eg: when there are no IP address changes)
                    self.sg_agent.setup_port_filters(port_info.get('added', set()),
                                                     port_info.get('updated', set()))
                except Exception as e:
                    LOG.error('Handle security group failed! Exception:%s', str(e))

                self._judge_dhcp_port(port['network_id'])

            if self.cascaded_port_info[port['id']]['status'] == const.PORT_STATUS_ACTIVE:
                return True
        return False

    def port_fixed_ips_update(self, fixed_ips):
        new_fixed_ips = []
        for ip in fixed_ips:
            subnet_id = ip['subnet_id']
            csd_subnet_name = self.get_csd_subnet_name(subnet_id)
            subnet_ret = self.list_cascaded_subnet_by_name(csd_subnet_name)
            if(subnet_ret and (subnet_ret.get('subnets'))):
                fixed_ip = {'subnet_id': subnet_ret.get('subnets')[0]['id'],\
                            'ip_address': ip['ip_address']}
                new_fixed_ips.append(fixed_ip)
            else:
                search_opts = {'id': subnet_id}
                subnet_ret = self.cascading_neutron_client('list_subnets', **search_opts)
                if(subnet_ret and (subnet_ret.get('subnets'))):
                    cascaded_subnet = self.create_cascaded_subnet(subnet_ret.get('subnets')[0])
                    if cascaded_subnet and cascaded_subnet.get('subnet'):
                        fixed_ip = {'subnet_id': cascaded_subnet.get('subnet')['id'],\
                                'ip_address': ip['ip_address']}
                        new_fixed_ips.append(fixed_ip)
                    else:
                        return

        return new_fixed_ips

    def network_dhcp_ports_update(self, network_id):
        cas_dhcp_ports, cas_network, cas_subnets, cas_subnet_ids = self.get_cascading_network_infos(network_id)
        need_update = False
        for cas_port in cas_dhcp_ports:
            if len(cas_port.get('fixed_ips')) != len(cas_subnet_ids):
                LOG.debug(_("dhcp_port for %s need update") % network_id)
                need_update = True
                break
        if (not need_update):
            return

        cad_dhcp_ports, cad_network, cad_subnets, cad_subnet_ids =  self.get_cascaded_network_infos(network_id)
        if (len(cad_subnets) == 0 or \
                (len(cas_subnets) != len(cad_subnets))):
            return
        for cad_dhcp_port in cad_dhcp_ports:
            for cas_dhcp_port in cas_dhcp_ports:
                if cad_dhcp_port.get('mac_address') == cas_dhcp_port.get('mac_address'):
                    cas_dhcp_fixed_ips = self.get_cascading_dhcp_ips(cas_dhcp_port, cas_subnet_ids)
                    new_dhcp_port = self.update_cascading_dhcp_port(cas_dhcp_port, cas_dhcp_fixed_ips)
                    self.update_cascaded_dhcp_port(new_dhcp_port, cad_subnets, cad_dhcp_port)
                    break

        self.handle_cad_dhcp_bind(cad_network.get('id'))

    def update_cascaded_dhcp_port(self, new_dhcp_port, cad_subnets, cad_dhcp_port):
        cad_new_fixed_ips = []
        for fixed_ip in new_dhcp_port.get('fixed_ips'):
            for cad_subnet in cad_subnets:
                if cad_subnet.get('name') == 'subnet@' + fixed_ip.get('subnet_id'):
                    new_fix_ip = {}
                    new_fix_ip['subnet_id'] = cad_subnet.get('id')
                    new_fix_ip['ip_address'] = fixed_ip.get('ip_address')
                    cad_new_fixed_ips.append(new_fix_ip)
                    break
        self.cascaded_neutron_client('update_port', cad_dhcp_port.get('id'),\
                                      {'port': {'fixed_ips':cad_new_fixed_ips, \
                                                'name': "port@" + new_dhcp_port.get('id')}})

    def update_cascading_dhcp_port(self, cas_dhcp_port, cas_dhcp_fixed_ips):
        LOG.debug(_("start update cascading_dhcp_port , the fixed_ips is %s") % cas_dhcp_fixed_ips)
        try:
            self.cascading_neutron_client('delete_port', cas_dhcp_port.get('id'))
            csd_req_body = {'tenant_id': cas_dhcp_port['tenant_id'],
                         'admin_state_up': cas_dhcp_port['admin_state_up'],
                         'name': 'dhcp_port',
                         'network_id': cas_dhcp_port['network_id'],
                         'fixed_ips': cas_dhcp_fixed_ips,
                         'mac_address': cas_dhcp_port['mac_address'],
                         'binding:profile': {},
                         'device_id': 'reserved_dhcp_port',
                         'device_owner': 'network:dhcp',
                         }
            new_dhcp_port = self.cascading_neutron_client('create_port', {'port': csd_req_body})['port']
        except Exception as e:
            LOG.error('update cascading_dhcp_port %s failed! Exception:%s',
                      cas_dhcp_port['id'], str(e))
            return

        return new_dhcp_port


    def get_cascading_dhcp_ips(self, cas_dhcp_port, cas_subnet_ids):
        cas_dhcp_fixed_ips = [{'subnet_id': subnet_id} for subnet_id in cas_subnet_ids]
        for subnet_fixed_ip in cas_dhcp_fixed_ips:
            for fixed_ip in cas_dhcp_port.get('fixed_ips'):
                if subnet_fixed_ip.get('subnet_id') == fixed_ip.get('subnet_id'):
                    subnet_fixed_ip['ip_address'] = fixed_ip.get('ip_address')
                    break
        return cas_dhcp_fixed_ips

    def handle_cad_dhcp_bind(self, cad_network_id):
        try:
            dhcp_agents = self.cascaded_neutron_client('list_dhcp_agent_hosting_networks',\
                                                       cad_network_id).get('agents')
            for dhcp_agent in dhcp_agents:
                self.cascaded_neutron_client('remove_network_from_dhcp_agent', dhcp_agent['id'] ,cad_network_id)
                self.cascaded_neutron_client('add_network_to_dhcp_agent', dhcp_agent['id'],
                                                                     {'network_id': cad_network_id
                                                                      })
        except Exception:
            LOG.error(_("bind network %s  for dhcp_agent failed") % network_id)

    def get_cascading_network_infos(self, network_id):
        cas_search_opts = {'device_owner': 'network:dhcp',
                           'network_id': network_id}
        try:
            cas_dhcp_ports = self.cascading_neutron_client('list_ports', **cas_search_opts).get('ports', [])
            cas_network = self.list_cascading_network_by_id(network_id).get('networks', [])
            cas_subnets = self.list_cascading_subnet_by_network_id(network_id).get('subnets', [])
            cas_subnet_ids = [subnet['id'] for subnet in cas_subnets]
        except Exception:
            LOG.error(_("get cascading networkinfos  "
                            "failed, the network_id is %s") % network_id)

        return cas_dhcp_ports, cas_network, cas_subnets, cas_subnet_ids

    def get_cascaded_network_infos(self, cas_network_id):
        try:
            cad_network_ret = self.list_cascaded_network_by_name(self.get_csd_network_name(cas_network_id))
            if (cad_network_ret and cad_network_ret.get('networks')):
                cad_network = cad_network_ret.get('networks')[0]
                cad_network_id = cad_network.get('id')
                cad_subnets = self.list_cascaded_subnet_by_network_id(cad_network_id).get('subnets', [])
                cad_subnet_ids = [subnet['id'] for subnet in cad_subnets]
                cad_serch_opts =  {'device_owner': 'network:dhcp',
                                   'network_id': cad_network_id}
                cad_dhcp_ports = self.cascaded_neutron_client('list_ports', **cad_serch_opts).get('ports', [])

        except Exception:
            LOG.error(_("get cascaded networkinfos  "
                            "failed, the cas_network_id is %s") % cas_network_id)

        return cad_dhcp_ports, cad_network, cad_subnets, cad_subnet_ids

    def tunnel_update(self, context, **kwargs):
        LOG.debug(_("tunnel_update received"))

    def _create_port(self, context, network_id, binding_profile, port_name,
                     mac_address, ips):
        if(not network_id):
            LOG.error(_("No network id is specified, cannot create port"))
            return
        req_props = {'network_id': network_id,
                     'name': port_name,
                     'admin_state_up': True,
                     'fixed_ips': [{'ip_address': ip} for ip in ips],
                     'mac_address': mac_address,
                     'binding:profile': binding_profile,
                     'device_owner': '',
                     'security_groups': [],
                     'tenant_id': ''#need empty until remote_port support security-group
                     }
        try:
            # clear the remain cascaded port to ensure the remote or dhcp port create successfully
            self.clear_remain_cascaded_port(context, mac_address, ips, network_id)
            port_ret = self.cascaded_neutron_client('create_port', {'port': req_props})
            LOG.debug(_('create port, response:%s'), str(port_ret))
        except Exception as e:
            LOG.error('Create port failed! Exception:%s',str(e))
            return

        return port_ret

    def _destroy_port(self, context, port_id):
        if(not port_id):
            LOG.error(_("No port id is specified, cannot destroy port"))
            return
        for retry in range(const.DESTROY_RETRY):
            try:
                bodyResponse = self.cascaded_neutron_client('delete_port', port_id)
                LOG.debug(_('destroy port, Response:%s'), str(bodyResponse))
                return bodyResponse
            except Exception as e:
                LOG.error('Delete port %s failed! Exception:%s',
                          port_id, str(e))
                continue
        return

    def get_cascaded_ports(self, context, filters):
        port_ret = self.cascaded_neutron_client('list_ports', **filters)
        if port_ret and len(port_ret.get('ports')) > 0:
            return port_ret.get('ports')
        return

    def clear_remain_cascaded_port(self, context, mac_address, ips, network_id):
        req_filters = {'mac_address': mac_address}
        self.delete_cascaded_ports(context, req_filters)
        for ip in ips:
            req_filters = {'fixed_ips': 'ip_address=%s' % ip,
                           'network_id': network_id}
            self.delete_cascaded_ports(context, req_filters)

    def delete_cascaded_ports(self, context, filters):
        ports = self.get_cascaded_ports(context, filters)
        if ports and len(ports) > 0:
            port_name = str(ports[0]['name'])
            if (len(port_name) > 36 and port_name.startswith("port@"))\
                or port_name == const.REMOTE_PORT_KEY:
                self._destroy_port(context, ports[0]['id'])

    def fdb_add(self, context, fdb_entries):
        LOG.debug("fdb_add received")
        if (not cfg.CONF.AGENT.remote_port_enabled):
            return
        LOG.debug("start create remote_port,the fdb_entries is %s, local_vlan_map is %s"
                  % (fdb_entries, self.local_vlan_map))
        for lvm, agent_ports in self.get_agent_ports(fdb_entries,
                                                     self.local_vlan_map):
            LOG.debug("start create remote_port,agent_ports is %s", agent_ports)
            cascaded_net_id = lvm.cascaded_net_id
            if not cascaded_net_id:
                continue

            if len(agent_ports):
                for agent_ip, ports in agent_ports.items():
                    binding_profile = {"port_key": "remote_port",
                                       "host_ip": agent_ip}
                    port_name = 'remote_port'
                    mac_ip_map = {}
                    for port in ports:
                        if(port == q_const.FLOODING_ENTRY):
                            continue
                        if(const.DEVICE_OWNER_DVR_INTERFACE in port[2]):
                            return
                        ips = mac_ip_map.get(port[0])
                        if(ips):
                            ips += port[1]
                            mac_ip_map[port[0]] = ips
                        else:
                            mac_ip_map[port[0]] = [port[1]]
                    for mac_address, ips in mac_ip_map.items():
                        if lvm.remote_ports.get(mac_address):
                            remote_port_tmp = lvm.remote_ports.get(mac_address)
                            if remote_port_tmp.binding_profile.get('host_ip') == agent_ip:
                                continue
                        if lvm.vif_ports.get(mac_address):
                            continue

                        port_ret = self._create_port(context,
                                                     cascaded_net_id,
                                                     binding_profile,
                                                     port_name,
                                                     mac_address,
                                                     ips)
                        if(not port_ret or
                           (port_ret and (not port_ret.get('port')))):
                            LOG.debug(_("remote port created failed, "
                                        "binding_profile:%s, mac_address:%s"),
                                      str(binding_profile), mac_address)
                            return
                        port_id = port_ret['port'].get('id', None)
                        if not port_id:
                            LOG.debug(_("remote port created failed, "
                                        "port_name%s, mac_address:%s"),
                                      port_name, mac_address)
                            return
                        remote_port = RemotePort(port_id,
                                                 port_name,
                                                 mac_address,
                                                 binding_profile,
                                                 ips)
                        lvm.remote_ports[mac_address] = remote_port

    def fdb_remove(self, context, fdb_entries):
        LOG.debug("fdb_remove received")
        #if remote_port_enabled value is false, nothing to do
        if (not cfg.CONF.AGENT.remote_port_enabled):
            return
        LOG.debug("start delete remote_port,the fdb_entries is %s, local_vlan_map is %s"
                  % (fdb_entries, self.local_vlan_map))
        for lvm, agent_ports in self.get_agent_ports(fdb_entries,
                                                     self.local_vlan_map):
            if len(agent_ports):
                for agent_ip, ports in agent_ports.items():
                    for port in ports:
                        local_p = lvm.vif_ports.pop(port[0], None)
                        if(local_p and local_p.port_id):
                            self.cascaded_port_info.pop(local_p.port_id, None)
                            continue
                        remote_p = lvm.remote_ports.pop(port[0], None)
                        if not remote_p:
                            req_props = {'mac_address': port[0]}
                            ports = self.get_cascaded_ports(context, req_props)
                            if ports:
                                port_id = ports[0].get('id')
                                self._destroy_port(context, port_id)
                            continue
                        self._destroy_port(context, remote_p.port_id)
                        if not lvm.vif_ports and not lvm.remote_ports:
                            self.reclaim_local_vlan(fdb_entries.keys()[0])

    def add_fdb_flow(self, br, port_info, remote_ip, lvm, ofport):
        '''TODO can not delete
        if delete,it will raise TypeError:
        Can't instantiate abstract class OVSNeutronAgent with abstract 
        methods add_fdb_flow, cleanup_tunnel_port, del_fdb_flow,
        setup_entry_for_arp_reply, setup_tunnel_port  '''
        LOG.debug("add_fdb_flow received")

    def del_fdb_flow(self, br, port_info, remote_ip, lvm, ofport):
        '''TODO can not
        if delete,it will raise TypeError:
        Can't instantiate abstract class OVSNeutronAgent with abstract
        methods add_fdb_flow, cleanup_tunnel_port, del_fdb_flow,
        setup_entry_for_arp_reply, setup_tunnel_port  '''
        LOG.debug("del_fdb_flow received")

    def setup_entry_for_arp_reply(self, br, action, local_vid, mac_address,
                                  ip_address):
        '''TODO can not delete
        if delete,it will raise TypeError: 
        Can't instantiate abstract class OVSNeutronAgent with abstract
        methods add_fdb_flow, cleanup_tunnel_port, del_fdb_flow,
        setup_entry_for_arp_reply, setup_tunnel_port  '''
        LOG.debug("setup_entry_for_arp_reply is called!")

    def provision_local_vlan(self, net_uuid, network_type, physical_network,
                             segmentation_id, cascaded_net_id):
        '''Provisions a local VLAN.

        :param net_uuid: the uuid of the network associated with this vlan.
        :param network_type: the network type ('gre', 'vxlan', 'vlan', 'flat',
                                               'local')
        :param physical_network: the physical network for 'vlan' or 'flat'
        :param segmentation_id: the VID for 'vlan' or tunnel ID for 'tunnel'
        '''

        # On a restart or crash of OVS, the network associated with this VLAN
        # will already be assigned, so check for that here before assigning a
        # new one.
        lvm = self.local_vlan_map.get(net_uuid)
        if lvm:
            lvid = lvm.vlan
        else:
            if not self.available_local_vlans:
                LOG.error(_("No local VLAN available for net-id=%s"), net_uuid)
                return
            lvid = self.available_local_vlans.pop()
            self.local_vlan_map[net_uuid] = LocalVLANMapping(
                                                             network_type,
                                                             physical_network,
                                                             segmentation_id,
                                                             cascaded_net_id)

        LOG.info(_("Assigning %(vlan_id)s as local vlan for "
                   "net-id=%(net_uuid)s"),
                 {'vlan_id': lvid, 'net_uuid': net_uuid})
        LOG.debug("local_vlan_map is %s", self.local_vlan_map)

    def reclaim_local_vlan(self, net_uuid):
        '''Reclaim a local VLAN.

        :param net_uuid: the network uuid associated with this vlan.
        :param lvm: a LocalVLANMapping object that tracks (vlan, lsw_id,
            vif_ids) mapping.
        '''
        lvm = self.local_vlan_map.pop(net_uuid, None)
        if lvm is None:
            LOG.debug(_("Network %s not used on agent."), net_uuid)
            return

        LOG.info(_("Reclaiming vlan = %(vlan_id)s from net-id = %(net_uuid)s"),
                 {'vlan_id': lvm.vlan,
                  'net_uuid': net_uuid})

        if len(lvm.vif_ports) > 0 or len(lvm.remote_ports) > 0:
            # should clear ports and delete network of cascaded layer
            pass
        else:
            LOG.error(_("Cannot reclaim unknown network type "
                        "%(network_type)s for net-id=%(net_uuid)s"),
                      {'network_type': lvm.network_type,
                       'net_uuid': net_uuid})

        self.available_local_vlans.add(lvm.vlan)

    def port_bound(self, port, net_uuid,
                   network_type, physical_network,
                   segmentation_id, fixed_ips, device_owner,
                   cascaded_port_info,
                   ovs_restarted):
        '''Bind port to net_uuid/lsw_id and install flow for inbound traffic
        to vm.

        :param port: a ovslib.VifPort object.
        :param net_uuid: the net_uuid this port is to be associated with.
        :param network_type: the network type ('gre', 'vlan', 'flat', 'local')
        :param physical_network: the physical network for 'vlan' or 'flat'
        :param segmentation_id: the VID for 'vlan' or tunnel ID for 'tunnel'
        :param fixed_ips: the ip addresses assigned to this port
        :param device_owner: the string indicative of owner of this port
        :param ovs_restarted: indicates if this is called for an OVS restart.
        '''
        if net_uuid not in self.local_vlan_map or ovs_restarted:
            self.provision_local_vlan(net_uuid, network_type,
                                      physical_network, segmentation_id,
                                      cascaded_port_info['network_id'])
        lvm = self.local_vlan_map[net_uuid]
        lvm.vif_ports[cascaded_port_info['mac_address']] = \
            LocalPort(port,
                      cascaded_port_info['id'],
                      cascaded_port_info['mac_address'])

    def port_unbound(self, vif_id, net_uuid, mac_address):
        '''Unbind port.

        Removes corresponding local vlan mapping object if this is its last
        VIF.

        :param vif_id: the id of the vif
        :param net_uuid: the net_uuid this port is associated with.
        '''

        if not self.local_vlan_map.get(net_uuid):
            LOG.info(_('port_unbound(): net_uuid %s not in local_vlan_map'),
                     net_uuid)
            return

        lvm = self.local_vlan_map[net_uuid]

        lvm.vif_ports.pop(mac_address, None)

        if not lvm.vif_ports and not lvm.remote_ports:
            self.reclaim_local_vlan(net_uuid)

    def get_port_id_from_profile(self, profile):
        return profile.get('cascading_port_id', None)

    def analysis_ports_info(self, ports_info):
        cur_ports = set()
        for port in ports_info:
            port_name = str(port['name'])
            if len(port_name) > 36 and port_name.startswith("port@"):
                cascading_port_id = port_name[-36:]
                LOG.debug(_("the cascading %s"), cascading_port_id)
            else:
                profile = port['binding:profile']
                cascading_port_id = self.get_port_id_from_profile(profile)
            if(not cascading_port_id):
                continue
            self.cascaded_port_info[cascading_port_id] = port
            cur_ports.add(cascading_port_id)
        return cur_ports

    def treat_vif_port(self, vif_port, port_id, network_id, network_type,
                       physical_network, segmentation_id, admin_state_up,
                       fixed_ips, device_owner, cascaded_port_info,
                       ovs_restarted):
        # When this function is called for a port, the port should have
        # an OVS ofport configured, as only these ports were considered
        # for being treated. If that does not happen, it is a potential
        # error condition of which operators should be aware

        if admin_state_up:
            self.port_bound(vif_port, network_id, network_type,
                            physical_network, segmentation_id,
                            fixed_ips, device_owner, cascaded_port_info,
                            ovs_restarted)

    def setup_tunnel_port(self, br, remote_ip, network_type):
        '''TODO can not delete
        if delete,it will raise TypeError: 
        Can't instantiate abstract class OVSNeutronAgent with abstract 
        methods add_fdb_flow, cleanup_tunnel_port, del_fdb_flow, 
        setup_entry_for_arp_reply, setup_tunnel_port  '''
        LOG.debug("cleanup_tunnel_port is called!")

    def cleanup_tunnel_port(self, br, tun_ofport, tunnel_type):
        '''TODO can not delete
        if delete,it will raise TypeError: 
        Can't instantiate abstract class OVSNeutronAgent with abstract 
        methods add_fdb_flow, cleanup_tunnel_port, del_fdb_flow, 
        setup_entry_for_arp_reply, setup_tunnel_port  '''
        LOG.debug("cleanup_tunnel_port is called!")

    def compare_port_info(self, details, cascaded_port_info):
        if details is None or cascaded_port_info is None:
            return False
        details_ips_set = set([ip['ip_address']
                               for ip in details['fixed_ips']])
        cascaded_ips_set = set([ip['ip_address']
                                for ip in cascaded_port_info['fixed_ips']])
        return details_ips_set == cascaded_ips_set

    def update_cascading_port_profile(self, cascaded_host_ip,
                                      cascaded_port_info, details):
        if(not cascaded_host_ip):
            return
        profile = {'host_ip': cascaded_host_ip,
                   'cascaded_net_id': {
                       details['network_id']: {}},
                   'cascaded_subnet_id': {}}
        net_map = profile['cascaded_net_id'][details['network_id']]
        net_map[cfg.CONF.host] = cascaded_port_info['network_id']
        subnet_map = profile['cascaded_subnet_id']
        for fi_ing in details['fixed_ips']:
            for fi_ed in cascaded_port_info['fixed_ips']:
                if (fi_ed['ip_address'] == fi_ing['ip_address']):
                    subnet_map[fi_ing['subnet_id']] = {}
                    subnet_map[fi_ing['subnet_id']][cfg.CONF.host] = \
                        fi_ed['subnet_id']
                    break
        req_props = {'port': {'binding:profile': profile}}
        try_times = 3
        for i in range(try_times):
            try:
                port_ret = self.plugin_rpc.update_port(self.context,
                    details['port_id'],
                    self.agent_id,
                    req_props)
                LOG.debug(_('update cascading port finished, Ret:%s'), str(port_ret))
                return port_ret
            except Exception as e:
                LOG.error(_('update cascading port profile for %(port)s failed,'
                            'try_times=%(try_times)d, msg:%(msg)s'),
                            {'port': details['port_id'], 'try_times': i, 'msg': str(e)})
        return

    def get_cascaded_host_ip(self, ed_host_id):
        if not ed_host_id:
            return
        LOG.debug(_('ed_host_id:%s'), ed_host_id)
        agent_ret = self.cascaded_neutron_client('list_agents',
                                                        host=ed_host_id,
                                                        agent_type='Open vSwitch agent')
        if(not agent_ret or
                (agent_ret and (not agent_ret.get('agents')))):
            LOG.debug(_("get agent failed, host_id:%s"), ed_host_id)
            return
        agent_config = agent_ret['agents'][0].get('configurations',
                                                  None)
        host_ip = agent_config.get('tunneling_ip')
        LOG.debug(_('host_ip:%s'), host_ip)
        return host_ip

    def treat_devices_added_or_updated(self, devices, ovs_restarted):
        skipped_devices = []
        try:
            devices_details_list = self.plugin_rpc.get_devices_details_list(
                self.context,
                devices,
                self.agent_id,
                cfg.CONF.host)
        except Exception as e:
            raise DeviceListRetrievalError(devices=devices, error=e)
        for details in devices_details_list:
            device = details['device']
            if 'port_id' in details:
                cascaded_port_info = self.cascaded_port_info.get(device)
                if(not self.compare_port_info(details, cascaded_port_info)):
                    LOG.info(_("Port %(device)s can not updated. "
                               "Because port info in cascading and cascaded layer"
                               "are different, Details: %(details)s"),
                             {'device': device, 'details': details})
                    skipped_devices.append(device)
                    return skipped_devices
                LOG.info(_("Port %(device)s updated. Details: %(details)s"),
                         {'device': device, 'details': details})
                self.treat_vif_port(device, details['port_id'],
                                    details['network_id'],
                                    details['network_type'],
                                    details['physical_network'],
                                    details['segmentation_id'],
                                    details['admin_state_up'],
                                    details['fixed_ips'],
                                    details['device_owner'],
                                    cascaded_port_info,
                                    ovs_restarted)
                # update cascading port, modify binding:profile to add host_ip
                # and cascaded net_id/cascaded_subnet_id
                if('compute' in details['device_owner']):
                    ed_host_id = cascaded_port_info['binding:host_id']
                    cascaded_host_ip = self.get_cascaded_host_ip(ed_host_id)
                    if not cascaded_host_ip:
                        LOG.error(_("Get cascaded host ip for %s failed"), device)
                        continue
                    if not self.update_cascading_port_profile(cascaded_host_ip,
                                                       cascaded_port_info,
                                                       details):
                        self._add_port_update_to_period_queue(details['port_id'])

                # update plugin about port status
                # FIXME(salv-orlando): Failures while updating device status
                # must be handled appropriately. Otherwise this might prevent
                # neutron server from sending network-vif-* events to the nova
                # API server, thus possibly preventing instance spawn.
                if details.get('admin_state_up'):
                    LOG.debug(_("Setting status for %s to UP"), device)
                    self.plugin_rpc.update_device_up(
                        self.context, device, self.agent_id, cfg.CONF.host)
                else:
                    LOG.debug(_("Setting status for %s to DOWN"), device)
                    self.plugin_rpc.update_device_down(
                        self.context, device, self.agent_id, cfg.CONF.host)
                LOG.info(_("Configuration for device %s completed."), device)

        return skipped_devices

    def treat_devices_removed(self, devices, network_id, mac_address):
        resync = False
        self.sg_agent.remove_devices_filter(devices)
        for device in devices:
            LOG.info(_("Attachment %s removed"), device)
            try:
                self.plugin_rpc.update_device_down(self.context,
                                                   device,
                                                   self.agent_id,
                                                   cfg.CONF.host)
            except Exception as e:
                LOG.debug(_("port_removed failed for %(device)s: %(e)s"),
                          {'device': device, 'e': e})
                resync = True
                continue

            self.port_unbound(device, network_id, mac_address)
        return resync

    def _judge_dhcp_port(self, cas_network_id):
        """
        whether to create cascaded dhcp ports
        :param cas_network_id:
        :return:
        """
        try:
            ret = self.plugin_rpc.get_subnet_dhcp_by_network_id(self.context, cas_network_id)
            cas_subnets = ret.get("subnets")
            if not cas_subnets or not cas_subnets[0]['enable_dhcp']:
                LOG.debug(_("create_dhcp_port: no subnet on network or subnet's enable_dhcp is False, network_id=%s"), cas_network_id)
                return
            cas_dhcp_ports = ret.get("dhcp_ports")
            if not cas_dhcp_ports:
                LOG.error(_("create_dhcp_port: no cascading dhcp ports, plz check neturon-server cascading-driver"))
                return
            LOG.debug(_("create_dhcp_port: cas_dhcp_ports: %s"), cas_dhcp_ports)
            cas_dhcp_macs = [x.get('mac_address') for x in cas_dhcp_ports]
            cad_network_ret = self.list_cascaded_network_by_name(self.get_csd_network_name(cas_network_id))
            if not cad_network_ret or not cad_network_ret.get('networks'):
                LOG.error(_("create_dhcp_port: cascaded network not exist, network_id=%s"), cas_network_id)
                return
            cad_network = cad_network_ret.get('networks')[0]
            cad_network_id = cad_network.get('id')
            cad_serch_opts = {'device_owner': 'network:dhcp',
                              'network_id': cad_network_id}
            cad_dhcp_ports = self.cascaded_neutron_client('list_ports', **cad_serch_opts).get('ports', [])
            if cad_dhcp_ports:
                for cad_dhcp_port in cad_dhcp_ports:
                    if cad_dhcp_port.get('mac_address') in cas_dhcp_macs:
                        cas_dhcp_macs.remove(cad_dhcp_port.get('mac_address'))
                    else:
                        LOG.warn("create_dhcp_port: delete illegal cascaded dhcp port: %s", cad_dhcp_port.get('id'))
                        self.cascaded_neutron_client('delete_port', cad_dhcp_port.get('id'))
                        cad_dhcp_ports.remove(cad_dhcp_port)
                if not cas_dhcp_macs:
                    LOG.debug(_("create_dhcp_port: cascaded dhcp port existed, network_id=%s"), cas_network_id)
                    return
            cas_subnets_id = cas_subnets[0].get('id')
            cad_subnets = self.list_cascaded_subnet_by_network_id(cad_network_id).get('subnets', [])
            if not cad_subnets:
                LOG.error(_("create_dhcp_port: cascaded subnet not exist, network_id=%s"), cas_network_id)
                return
            cad_subnet_id = cad_subnets[0].get('id')
            tenant_id = cad_network.get('tenant_id')
            LOG.debug(_("create_dhcp_port: start create dhcp port, dhcp_distributed: %s, network_id=%s"),
                      self.dhcp_distributed, cas_network_id)
            if self.dhcp_distributed:
                self._create_dhcp_port_distributed(cas_dhcp_ports, cad_network_id, cad_subnet_id, tenant_id)
            else:
                self._create_dhcp_port(cas_dhcp_ports, cad_dhcp_ports, cad_network_id, cad_subnet_id, tenant_id)
            # update cad_subnet to enable_dhcp
            req_props = {'enable_dhcp': True}
            subnet_ret = self.cascaded_neutron_client('update_subnet', cad_subnet_id, {'subnet': req_props})
            if not subnet_ret or not subnet_ret.get('subnet'):
                LOG.error(_("create_dhcp_port: update cascaded subnet for %s failed.") % cad_subnet_id)
        except Exception, e:
            LOG.exception(e)

    def _create_dhcp_port_distributed(self, cas_dhcp_ports, cad_network_id, cad_subnets_id, tenant_id):
        cas_dhcp_port = cas_dhcp_ports[0]
        port_info = {'id': cas_dhcp_port['id'],
                     'fixed_ips': cas_dhcp_port['fixed_ips'],
                     'mac_address': cas_dhcp_port['mac_address'],
                     'network_id': cas_dhcp_port['network_id'],
                     }

        LOG.debug('starting create cascaded dhcp port.')
        try:
            csd_req_body = {'port':
                                {'tenant_id': tenant_id,
                                 'admin_state_up': True,
                                 'name': 'port@'+str(port_info['id']),
                                 'network_id': cad_network_id,
                                 'fixed_ips': [{'subnet': cad_subnets_id,
                                                'ip_address': port_info['fixed_ips'][0]['ip_address']}],
                                 'mac_address': port_info['mac_address'],
                                 'binding:profile': {},
                                 'device_id': q_utils.get_dhcp_agent_device_id(cad_network_id, ''),
                                 'device_owner': 'network:dhcp',
                                 }}
            try:
                cad_dhcp_port = self.cascaded_neutron_client('create_port', csd_req_body)['port']['id']
                LOG.debug(_("create cascaded dhcp port: %s"), cad_dhcp_port)
            except exceptions.Conflict as e:
                # clear the remain cascaded port to ensure the remote or dhcp port create successfully
                LOG.exception(e)
                self.clear_remain_cascaded_port(context, cas_dhcp_port['mac_address'],
                                                [port_info['fixed_ips'][0]['ip_address']],
                                                cad_network_id)
                cad_dhcp_port = self.cascaded_neutron_client('create_port', csd_req_body)['port']['id']
                LOG.debug(_("create cascaded dhcp port: %s"), cad_dhcp_port)

        except Exception as e:
            raise e



    def _create_dhcp_port(self, cas_dhcp_ports, cad_dhcp_ports, cad_net_id, cad_subnet_id, tenant_id):
        agent_opts = {'agent_type': 'DHCP agent',
                      'admin_state_up': True}
        dhcp_agents_all = self.cascaded_neutron_client('list_agents', **agent_opts)['agents']
        dhcp_agents = [dhcp_agent for dhcp_agent in dhcp_agents_all if dhcp_agent.get('alive')]
        if len(dhcp_agents) == 0:
            LOG.warn("no active DHCP agent")
            return
        port_count = min(len(dhcp_agents), len(cas_dhcp_ports))
        if port_count == len(cad_dhcp_ports):
            LOG.debug(_("create_dhcp_port: cascaded dhcp port existed"))
            return
        dhcp_ports_mappings = {}
        for dhcp_port in cas_dhcp_ports:
            dhcp_ports_mappings[dhcp_port['mac_address']] = {'id': dhcp_port['id'],
                                                             'fixed_ips': dhcp_port['fixed_ips'],
                                                             'mac_address': dhcp_port['mac_address'],
                                                             'network_id': dhcp_port['network_id'],
                                                             }
        rand_seq = random.sample(range(0, len(dhcp_agents)), port_count)
        agent_idx_count = 0
        LOG.debug('need create %i cascaded dhcp_ports', port_count)
        try:
            for dhcp_port in cad_dhcp_ports:
                if dhcp_port['mac_address'] in dhcp_ports_mappings:
                    dhcp_ports_mappings.pop(dhcp_port['mac_address'])
                    agent_idx_count += 1

            for mac_addr in dhcp_ports_mappings:
                agent_idx_count = (agent_idx_count+1)
                if agent_idx_count <= len(dhcp_agents):
                    dhcp_agent = dhcp_agents[rand_seq[agent_idx_count % len(dhcp_agents)]]
                    LOG.debug('Add network  %s to  dhcp agent %s.', cad_net_id, dhcp_agent['id'])
                    cad_dhcp_agents = self.cascaded_neutron_client('list_dhcp_agent_hosting_networks', cad_net_id)
                    is_dhcp_agent_binding = False
                    if cad_dhcp_agents and cad_dhcp_agents.get('agents'):
                        for cad_dhcp_agent in cad_dhcp_agents.get('agents'):
                            if cad_dhcp_agent.get('id') == dhcp_agent['id']:
                                is_dhcp_agent_binding = True
                                break
                    if is_dhcp_agent_binding:
                        LOG.debug("network has added to dhcp agent")
                    else:
                        self.cascaded_neutron_client('add_network_to_dhcp_agent', dhcp_agent['id'],
                                                                     {'network_id': cad_net_id
                                                                      })
                    port_info = dhcp_ports_mappings[mac_addr]
                    csd_req_body = {'port':
                                        {'tenant_id': tenant_id,
                                         'admin_state_up': True,
                                         'name': 'port@'+str(port_info['id']),
                                         'network_id': cad_net_id,
                                         'fixed_ips': [{'subnet': cad_subnet_id,
                                                        'ip_address': port_info['fixed_ips'][0]['ip_address']}],
                                         'mac_address': port_info['mac_address'],
                                         'binding:profile': {},
                                         'device_id': q_utils.get_dhcp_agent_device_id(cad_net_id, dhcp_agent['host']),
                                         'device_owner': 'network:dhcp',
                                         }}
                    try:
                        cad_dhcp_port = self.cascaded_neutron_client('create_port', csd_req_body)['port']
                        LOG.debug(_("create cascaded dhcp port: %s"), cad_dhcp_port)
                    except exceptions.Conflict as e:
                        LOG.exception(e)
                        self.clear_remain_cascaded_port(context, port_info['mac_address'],
                                                        [port_info['fixed_ips'][0]['ip_address']],
                                                        cad_net_id)
                        cad_dhcp_port = self.cascaded_neutron_client('create_port', csd_req_body)['port']
                        LOG.debug(_("create cascaded dhcp port: %s"), cad_dhcp_port)

                    port_id = cad_dhcp_port['id']
                    self.cascaded_neutron_client('update_port', port_id, {'port': {
                                                                'binding:host_id': dhcp_agent['host'],
                                                                }})
                    LOG.debug(_("update_port binding:host_id success, port_id=%s, binding:host_id=%s"),
                              port_id,
                              dhcp_agent['host'])

        except Exception as e:
            raise e

    def process_network_ports(self, port_info, ovs_restarted, network_id, mac_address):
        resync_a = False
        resync_b = False

        # VIF wiring needs to be performed always for 'new' devices.
        # For updated ports, re-wiring is not needed in most cases, but needs
        # to be performed anyway when the admin state of a device is changed.
        # A device might be both in the 'added' and 'updated'
        # list at the same time; avoid processing it twice.
        devices_added_updated = (port_info.get('added', set()) |
                                 port_info.get('updated', set()))
        if devices_added_updated:
            start = time.time()
            try:
                skipped_devices = self.treat_devices_added_or_updated(
                    devices_added_updated, ovs_restarted)
                LOG.debug(_("process_network_ports - iteration:%(iter_num)d -"
                            "treat_devices_added_or_updated completed. "
                            "Time elapsed: %(elapsed).3f"),
                          {'iter_num': self.iter_num,
                           'elapsed': time.time() - start})
            except DeviceListRetrievalError:
                # Need to resync as there was an error with server
                # communication.
                LOG.exception(_("process_network_ports - iteration:%d - "
                                "failure while retrieving port details "
                                "from server"), self.iter_num)
                resync_a = True
        if 'removed' in port_info:
            start = time.time()
            resync_b = self.treat_devices_removed(port_info['removed'], network_id, mac_address)
            LOG.debug(_("process_network_ports - iteration:%(iter_num)d -"
                        "treat_devices_removed completed in %(elapsed).3f"),
                      {'iter_num': self.iter_num,
                       'elapsed': time.time() - start})
        # If one of the above operations fails => resync with plugin
        return (resync_a | resync_b)

    def _add_port_update(self, port_id, full_sync=False):
        if not self.port_cache.get(port_id):
            timestamp = timeutils.utcnow()
            update = PortUpdate(port_id,
                                timestamp,
                                full_sync=full_sync)
            self._queue.add(update)
            self.port_cache.update(port_id, already_processing=True)


    def _add_port_update_periodic(self, port_id):
        if not self.port_cache.get(port_id):
            timestamp = timeutils.utcnow()
            update = PortUpdate(port_id,
                                timestamp,
                                add_periodic=True)
            self._queue.add(update)
            self.port_cache.update(port_id, already_processing=True)

    def _add_port_delete(self, port_id, network_id, mac_address):
        timestamp = timeutils.utcnow()
        update = PortUpdate(port_id,
                            timestamp,
                            remove=True,
                            network_id=network_id,
                            mac_address=mac_address)
        self._queue.add(update)

    def _add_port_update_to_period_queue(self, port_id):
        LOG.debug("port:%s is not ready, add to slow period queue to handle", port_id)
        self.period_queue.put(port_id)

    def _process_port_loop(self):
        LOG.debug("Starting _process_port_update")
        pool = eventlet.GreenPool(size=5)
        while True:
            pool.spawn_n(self._process_port_update)

    def _process_port_update(self):
        for pp,update in self._queue.each_update_to_next_port():
            port_id = update.id
            # port_remove:the port will be deleted or not
            port_remove = update.remove
            network_id = update.network_id
            mac_address = update.mac_address
            add_periodic = update.add_periodic
            full_sync = update.full_sync
            updated_ports = set()
            updated_ports.add(port_id)
            ovs_restarted = False
            port_info = {}

            if not updated_ports:
                LOG.error("Process port:%s is not exist", port_id)
                continue

            LOG.info("Start process port:%s!", port_id)
            self.port_cache.update(port_id, already_processing=False)
            if port_remove:
                port_info['updated'] = set()
                port_info['added'] = set()
                port_info['removed'] = updated_ports
                self.port_cache.remove(port_id)
            else:
                try:
                    updated_port_info = self.plugin_rpc.get_port_detail(self.context, port_id,
                                                                            self.agent_id)
                    LOG.debug("Cascading detail port_info is %s", updated_port_info)
                except Exception:
                    msg = _("Failed to fetch port information for '%s'")
                    LOG.exception(msg, port_id)
                    self.fullsync = True
                    continue

                # DVR port
                if updated_port_info['device_owner'] == const.DEVICE_OWNER_DVR_INTERFACE:
                    if port_id in self.port_cache.cache:
                        port_info['updated'] = updated_ports
                        port_info['added'] = set()
                        port_info['removed'] = set()
                    else:
                        port_info['added'] = updated_ports
                        port_info['updated'] = set()
                        port_info['removed'] = set()
                        self.port_cache.put(port_id)
                # Other port
                else:
                    if port_id not in self.port_cache.cache:
                        if const.DEVICE_OWNER_COMPUTER in updated_port_info['device_owner']:
                            if (full_sync or updated_port_info['binding:profile'].get('refresh_notify')) and \
                                    updated_port_info['binding:host_id'] == self.conf.host:
                                port_info['added'] = updated_ports
                                port_info['updated'] = set()
                                port_info['removed'] = set()
                                self.port_cache.put(port_id)
                            else:
                                continue
                        else:
                            if updated_port_info['binding:host_id'] == self.conf.host:
                                port_info['added'] = updated_ports
                                port_info['updated'] = set()
                                port_info['removed'] = set()
                                self.port_cache.put(port_id)
                            else:
                                continue
                    else:
                        if updated_port_info['binding:host_id'] == self.conf.host:
                            port_info['updated'] = updated_ports
                            port_info['added'] = set()
                            port_info['removed'] = set()
                        else:
                            port_info['updated'] = set()
                            port_info['added'] = set()
                            port_info['removed'] = updated_ports
                            self.port_cache.remove(port_id)
                            mac_address = updated_port_info['mac_address']
                            network_id = updated_port_info['network_id']

                # handle the port for update cascaded port
                if updated_port_info['binding:host_id'] == self.conf.host and \
                        const.DEVICE_OWNER_COMPUTER in updated_port_info['device_owner']:
                    cascaded_port_ready = self.ensure_cascaded_nondvr_port_ready(updated_port_info, port_info, add_periodic)
                    if not cascaded_port_ready:
                        LOG.info("Cascaded port port@%s is not ready", port_id)
                        self._add_port_update_to_period_queue(port_id)
                        continue

                if updated_port_info['device_owner'] == const.DEVICE_OWNER_DVR_INTERFACE:
                    port_bound = self.plugin_rpc.port_bound_to_router(self.context, port_id,
                                                                      self.agent_id, self.conf.host)
                    LOG.debug("DVR port bound is %s", port_bound)
                    if not port_bound:
                        continue
                    # or compare_port_info will false
                    # must wait the cascaded dvr port is created
                    ret = self.ensure_port_update_for_cascaded_dvr_port(updated_port_info)
                    if not ret:
                        self._add_port_update_to_period_queue(port_id)
                        continue

            LOG.debug(_("Port_info is %(port_info)s, Port_cache.cache is %(cache)s"),
                       {'port_info': port_info,'cache': self.port_cache.cache})

            self.process_network_ports(port_info, ovs_restarted, network_id, mac_address)
            LOG.debug("Finish process port for %s", port_id)
            pp.fetched_and_processed(update.timestamp)

    def sync_ports_task(self, context):
        self._sync_ports_task(context)

    def sync_remote_ports(self, context):
        req_props = {'name': const.REMOTE_PORT_KEY}
        remote_ports = self.get_cascaded_ports(context, req_props)
        if not remote_ports:
            LOG.info("no remote ports, return")
            return
        for remote_port in remote_ports:
            try:
                if not self.plugin_rpc.get_ports(context, self.agent_id,
                                                 mac_address=remote_port['mac_address']):
                    self._destroy_port(context, remote_port.get('id'))
                    LOG.debug("Port not found in the cascading node,"
                        "delete the remote port:%s", remote_port)
            except Exception as e:
                LOG.error("sync_remote_ports %s exception: %s" %(remote_port, e))

    def sync_networks(self, context):
        csd_networks_info = self.cascaded_neutron_client('list_networks')
        if csd_networks_info and len(csd_networks_info.get('networks')) > 0:
            for network in csd_networks_info.get('networks'):
                temp_network_info = network['name'].split('@')
                if len(temp_network_info) <= 1:
                    continue

                cascading_network_id = temp_network_info[1]
                try:
                    net_ret = self.plugin_rpc.get_networks(context, self.agent_id,
                                                           cascading_network_id)
                    if not net_ret:
                        self.delete_cascaded_network_by_id(network['id'])
                        LOG.debug(_("Network not found in cascading node,"
                                    "clear the network:%s resource"),
                                  network['id'])
                except Exception as e:
                    LOG.error("sync_networks %s exception: %s" %(network['id'], e))

    def _sync_ports_task(self, context):
        LOG.debug(_("Starting _sync_ports_task - fullsync:%s"),
                  self.fullsync)
        if not self.fullsync:
            return

        try:
            ports_info = self.plugin_rpc.get_ports(context, self.agent_id,
                                                   host=self.host)
            for port in ports_info:
                if port['device_owner'] == const.DEVICE_OWNER_DHCP:
                    continue
                self._add_port_update(port['id'], self.fullsync)

            dvr_ports_info = self.plugin_rpc.get_ports(context, self.agent_id,
                                                       device_owner=const.DEVICE_OWNER_DVR_INTERFACE)
            for port in dvr_ports_info:
                self._add_port_update(port['id'], self.fullsync)

            self.sync_networks(context)
            self.sync_remote_ports(context)
            self.fullsync = False
            LOG.debug(_("_sync_ports_task successfully completed"))
        except n_rpc.RPCException:
            LOG.exception(_("Failed synchronizing ports due to RPC error"))
            self.fullsync = True
        except Exception:
            LOG.exception(_("Failed synchronizing ports"))
            self.fullsync = True

    def _periodic_process_punished_port_update(self):
        while True:
            LOG.debug(_("Starting process the punished port periodic"))
            while not self.period_queue.empty():
                try:
                    port_id = self.period_queue.get(block=True, timeout=2)
                    self._add_port_update_periodic(port_id)
                except:
                    LOG.warn("Period punished port process queue is error")
            self.sync_ports_task(self.context)
            # the punished port will be re-handled and run sync task per 10s
            time.sleep(10)


    def after_start(self):
        eventlet.spawn_n(self._process_port_loop)
        eventlet.spawn_n(self._periodic_process_punished_port_update)
        LOG.info(_("L2 proxy started"))
        self.sync_ports_task(self.context)

def _register_opts(conf):
    conf.register_opts(OVSNeutronAgent.ovs_opts,"OVS")
    conf.register_opts(OVSNeutronAgent.agent_opts,"AGENT")
    conf.register_opts(ip_lib.OPTS)
    config.register_agent_state_opts_helper(conf)
    config.register_root_helper(conf)

def main(manager='neutron.plugins.l2_proxy.agent.l2_proxy.OVSNeutronAgent'):
    _register_opts(cfg.CONF)
    common_config.init(sys.argv[1:])
    common_config.setup_logging()
    q_utils.log_opt_values(LOG)

    server = neutron_service.Service.create(
        binary='neutron-l2-proxy',
        topic=q_const.L2_AGENT_TOPIC,
        report_interval=cfg.CONF.AGENT.report_interval,
        manager=manager)
    service.launch(server).wait()

if __name__ == "__main__":
    main()
