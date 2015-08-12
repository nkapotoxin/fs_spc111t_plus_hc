# Copyright 2013 ngfw Networks Inc.
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

import sys
import copy
import eventlet
import datetime
eventlet.monkey_patch()

import netaddr
from oslo.config import cfg

from neutron.agent.common import config
from neutron.agent import l3_agent
from neutron.agent import l3_ha_agent
from neutron.agent.linux import external_process
from neutron.agent.linux import interface
from neutron.agent.linux import ip_lib
from neutron.common import config as common_config
from neutron.common import constants as l3_constants
from neutron.common import topics
from neutron.openstack.common import log as logging
from neutron.openstack.common import service
from neutron import service as neutron_service
from neutron.services.firewall.agents.l3reference import firewall_l3_agent
from neutron.services.firewall.agents.ngfw import ngfw_api
from neutron.services.firewall.agents.ngfw import ngfw_utils
from neutron.services.firewall import ngfw_plugin
from neutron.extensions import firewall as fw_ext
from neutron.plugins.common import constants
from neutron.extensions import vpnaas
from neutron.openstack.common import importutils
from neutron.openstack.common import periodic_task

LOG = logging.getLogger(__name__)

NAT_NAME_KEY_BEGIN = '<server-mapping><name>'
NAT_NAME_KEY_END = '</name>'
INSIDE_IP_KEY_BEGIN = '<inside><start-ip>'
INSIDE_IP_KEY_END = '</start-ip>'
GLOBAL_IP_KEY_BEGIN = '<global><start-ip>'
GLOBAL_IP_KEY_END = '</start-ip>'

vpn_agent_opts = [
    cfg.StrOpt(
        'acl_separate_name', 
        default='',
        help=_("separate fip and fw acl policy, fw insert before it and fip append after it")),
    cfg.StrOpt(
        'auto_ngfw_save_filename',
        default='auto.cfg',
        help=_("auto save ngfw filename")),
    cfg.BoolOpt(
        'vpn_enabled',
        default=False,
        help=_("Enable VPNaaS")),
    cfg.BoolOpt(
        'rule_failed_rollback',
        default=True,
        help=_("rule failed rollback")),
]

cfg.CONF.register_opts(vpn_agent_opts, 'ngfw')

class ngfwL3NATAgent(l3_agent.L3NATAgent,
                        firewall_l3_agent.FWaaSL3AgentRpcCallback):

    def __init__(self, host, conf=None):
        LOG.debug(_('ngfwL3NATAgent: __init__'))
        self.rest = ngfw_api.ngfwRestAPI()
        self.agent = ngfw_plugin.NGFWAgentUtils()
        self.plugutil = ngfw_plugin.NGFWPluginUtils()
        self.devices = []
        
        self.auto_ngfw_save_filename = cfg.CONF.ngfw.auto_ngfw_save_filename
        self.director_for_fip = self._get_director_for_fip()
        self.last_save_time = 0
        super(ngfwL3NATAgent, self).__init__(host, conf)
        super(ngfwL3NATAgent, self).process_services_sync(self.context)

        #attempt connect ngfw, if can not connect ngfw, then exit ngfw-agent process
        response = self.rest.rest_api('GET', ngfw_utils.NGFW_URL_POLICY_SECURITY)
        if response['status'] >= 400:
            LOG.error(_('attempt get security-policy failed, exit ngfw-agent process.'))
            exit(1)

    def get_namespace(self, router_id):
        """Get namespace of router.

        :router_id: router_id
        :returns: namespace string.
            Note if the router is not exist, this function
            returns None
        """
        router_info = self.router_info.get(router_id)
        if not router_info:
            return
        return router_info.ns_name

    def add_nat_rule(self, router_id, chain, rule, top=False):
        """Add nat rule in namespace.

        :param router_id: router_id
        :param chain: a string of chain name
        :param rule: a string of rule
        :param top: if top is true, the rule
            will be placed on the top of chain
            Note if there is no rotuer, this method do nothing
        """
        router_info = self.router_info.get(router_id)
        if not router_info:
            return
        router_info.iptables_manager.ipv4['nat'].add_rule(
            chain, rule, top=top)

    def remove_nat_rule(self, router_id, chain, rule, top=False):
        """Remove nat rule in namespace.

        :param router_id: router_id
        :param chain: a string of chain name
        :param rule: a string of rule
        :param top: unused
            needed to have same argument with add_nat_rule
        """
        router_info = self.router_info.get(router_id)
        if not router_info:
            return
        router_info.iptables_manager.ipv4['nat'].remove_rule(
            chain, rule, top=top)

    def iptables_apply(self, router_id):
        """Apply IPtables.

        :param router_id: router_id
        This method do nothing if there is no router
        """
        router_info = self.router_info.get(router_id)
        if not router_info:
            return
        router_info.iptables_manager.apply()

    def _router_added(self, router_id, router):
        """Router added event.

        This method overwrites parent class method.
        :param router_id: id of added router
        :param router: dict of rotuer
        """
        super(ngfwL3NATAgent, self)._router_added(router_id, router)
        for device in self.devices:
            device.create_router(router_id)

    def _router_removed(self, router_id):
        """Router removed event.

        This method overwrites parent class method.
        :param router_id: id of removed router
        """
        super(ngfwL3NATAgent, self)._router_removed(router_id)
        for device in self.devices:
            device.destroy_router(router_id)

    def _process_routers(self, routers, all_routers=False):
        """Router sync event.

        This method overwrites parent class method.
        :param routers: list of routers
        """
        super(ngfwL3NATAgent, self)._process_routers(routers, all_routers)
                                    
    def process_router_floating_ip_addresses(self, ri, ex_gw_port):
        fip_statuses = {}
        floating_ips = self.get_floating_ips(ri)
        for fip in floating_ips:
            fip_statuses[fip['id']] = l3_constants.FLOATINGIP_STATUS_ACTIVE
            
        return fip_statuses

    def _get_all_floating_ips_list(self):
        policy_security_str = ''
        response = self.rest.rest_api('GET', ngfw_utils.NGFW_URL_NAT_SERVER, device_ip=self.director_for_fip)
        if response['status'] >= 200 and response['status'] < 300:
            policy_security_str = response['body']
            
        return policy_security_str
    
    
    def _get_floatingip_by_prefix(self, floatingips, prefix):
        for floatingip in floatingips:
            if floatingip.startswith(prefix):
                return floatingip

    def get_ngfw_floating_ips(self, ri):
        """Filter Floating IPs to be hosted on this agent."""
        floating_ips = ri.router.get(l3_constants.FLOATINGIP_KEY, [])
        return floating_ips
    
    def set_acl_by_fip(self, name, source_ip_address, destination_ip_address):
        if cfg.CONF.ngfw.acl_separate_name:
            target_rule = cfg.CONF.ngfw.acl_separate_name
        else:
            target_rule = None        
        bodyinfo = ngfw_utils.get_in_acl_body(name, destination_ip_address, target_rule)
        LOG.debug(_('set_int_acl_by_fip body (%s)'), bodyinfo)
        response_inter = self.rest.rest_api('PUT', ngfw_utils.NGFW_URL_POLICY_SECURITY, bodyinfo, device_ip=self.director_for_fip)
        
        bodyinfo = ngfw_utils.get_out_acl_body(name, source_ip_address, target_rule)
        LOG.debug(_('set_out_acl_by_fip body (%s)'), bodyinfo)
        response_outer = self.rest.rest_api('PUT', ngfw_utils.NGFW_URL_POLICY_SECURITY, bodyinfo, device_ip=self.director_for_fip)
        
        if response_inter['status'] >= 400 or response_outer['status'] >= 400:
            LOG.error(_('set_acl_by_fip failed (%s)'), bodyinfo)
            self.del_acl_by_fip(name)
            return False  
        LOG.debug(_('set_acl_by_fip success (%s)'), bodyinfo)
        return True
    
    def del_acl_by_fip(self, name):
        body_inter = ngfw_utils.get_in_acl_body_to_delete(name)
        LOG.debug(_('del_in_acl_by_fip body (%s) (%s)'), name, body_inter)
        response_intel = self.rest.rest_api('DELETE', ngfw_utils.NGFW_URL_POLICY_SECURITY, body_inter, device_ip=self.director_for_fip)
        
        body_outer = ngfw_utils.get_out_acl_body_to_delete(name)
        LOG.debug(_('del_out_acl_by_fip body (%s) (%s)'), name, body_outer)
        response_outel = self.rest.rest_api('DELETE', ngfw_utils.NGFW_URL_POLICY_SECURITY, body_outer, device_ip=self.director_for_fip)
        
        if response_intel['status'] >= 200 and response_intel['status'] < 300 \
            and response_outel['status'] >= 200 and response_outel['status'] < 300:
            return True
        return False
    
    def _get_all_inside_ip(self, floating_ips_list):
        
        inside_ip_list = ngfw_utils.parse_xml_name(floating_ips_list,
                                                  INSIDE_IP_KEY_BEGIN,
                                                  INSIDE_IP_KEY_END)
        return inside_ip_list
    
    def _get_all_global_ip(self, floating_ips_list):
        global_ip_list = ngfw_utils.parse_xml_name(floating_ips_list,
                                                  GLOBAL_IP_KEY_BEGIN,
                                                  GLOBAL_IP_KEY_END)
        return global_ip_list
    
    def _get_all_nat_name(self, floating_ips_list):
        global_ip_list = ngfw_utils.parse_xml_name(floating_ips_list,
                                                  NAT_NAME_KEY_BEGIN,
                                                  NAT_NAME_KEY_END)
        return global_ip_list

    def _get_nat_server_mapping(self):
        floating_ips_list = self._get_all_floating_ips_list()
        all_inside_ips = self._get_all_inside_ip(floating_ips_list)
        all_global_ips = self._get_all_global_ip(floating_ips_list)
        all_nat_names = self._get_all_nat_name(floating_ips_list)
        
        nat_server_mapings = []
        if len(all_inside_ips) == len(all_global_ips) == len(all_nat_names) :
            for i in range(len(all_inside_ips)):
                nat_server_mapings.append({'name':all_nat_names[i], 'inside_ip':all_inside_ips[i],
                                           'global_ip':all_global_ips[i]})
        return nat_server_mapings
    
    def _add_configure_fip_no_reserve(self, fixedIP):
        nat_server_mapings = self._get_nat_server_mapping()
        
        for nat_server_maping in nat_server_mapings:
            if nat_server_maping['inside_ip'] == fixedIP:
                nat_server_name = nat_server_maping['name']
                #del the old nat_server which without no_reverse
                body = ngfw_utils.get_nat_server_static_map_to_delete(nat_server_name)
                response = self.rest.rest_api('DELETE', ngfw_utils.NGFW_URL_NAT_SERVER, body, device_ip=self.director_for_fip)
                if response['status'] <= 300 and response['status'] >= 200:
                    LOG.debug(_('_delete_floating_ips success (%s)'), nat_server_name)
                    #then add the new  nat_server with no_reverse
                    body = ngfw_utils.get_nat_server_static_map(nat_server_name, nat_server_maping['global_ip'], fixedIP, no_reverse=True)
                    response = self.rest.rest_api('POST', ngfw_utils.NGFW_URL_NAT_SERVER, body, device_ip=self.director_for_fip)
                    if response['status'] <= 300 and response['status'] >= 200: 
                        LOG.debug(_('_config_floating_ips body (%s) (%s)'), nat_server_name, body)
                        return True
        return False
              
    def _del_configure_fip_no_reserve(self, ri,floatingip,nat_server_name):
        nat_server_mapings = self._get_nat_server_mapping()
        fix_ip = ''
        flag = False
        for nat_server_maping in nat_server_mapings:
            if nat_server_maping['name'] == nat_server_name:
                fix_ip = nat_server_maping['inside_ip']
                flag = self._delete_floating_ips(ri, floatingip, nat_server_name)
                if flag:
                    nat_server_mapings.remove(nat_server_maping)
                    
        #count the last fip with the same inside ip
        count = 0
        for nat_server_maping in nat_server_mapings:
            if nat_server_maping['inside_ip'] == fix_ip:
                count = count + 1
                
        if count != 1 :
            return
        
        for nat_server_maping in nat_server_mapings:
            if nat_server_maping['inside_ip'] == fix_ip and nat_server_maping['name'] != nat_server_name and count == 1:
                nat_server_name = nat_server_maping['name']
                #del the old nat_server which with no_reverse
                body = ngfw_utils.get_nat_server_static_map_to_delete(nat_server_name)
                response = self.rest.rest_api('DELETE', ngfw_utils.NGFW_URL_NAT_SERVER, body, device_ip=self.director_for_fip)
                if response['status'] <= 300 and response['status'] >= 200: 
                    LOG.debug(_('_config__floating_ips_delete success (%s)'), nat_server_name)
                    #then add the new  nat_server without no_reverse
                    body = ngfw_utils.get_nat_server_static_map(nat_server_name, nat_server_maping['global_ip'], fix_ip, no_reverse=False)
                    response = self.rest.rest_api('POST', ngfw_utils.NGFW_URL_NAT_SERVER, body, device_ip=self.director_for_fip)
                    if response['status'] <= 300 and response['status'] >= 200: 
                        LOG.debug(_('_config_configure_fip_delete_no_reserve body (%s) (%s)'), nat_server_name, body)
    
    def _compare_floatingip_list(self, ri):
        collect_fip = {} 
        floating_ips = self.get_ngfw_floating_ips(ri)        
        for floating_ip in floating_ips:
            collect_fip.update({ngfw_utils.get_floatingip_name(floating_ip['id']):
                                floating_ip['id']})
        
        nat_fip = {}
        floating_ips_list = self._get_all_floating_ips_list()
        nat_name_list = ngfw_utils.parse_xml_name(floating_ips_list,
                                                  NAT_NAME_KEY_BEGIN,
                                                  NAT_NAME_KEY_END)
        for nat_name in nat_name_list:
            prefix = ngfw_utils.get_dnat_rule_name(ri)
            if nat_name.startswith(prefix):
                nat_fip.update({nat_name.split('_')[-1]:nat_name})
                    
        collect_fip_keys = collect_fip.keys()
        nat_name_list_keys = nat_fip.keys()
        
        need_add = set(collect_fip_keys) - set(nat_name_list_keys)
        need_del = set(nat_name_list_keys) - set(collect_fip_keys)
        
        return (need_add, need_del, collect_fip, nat_fip)
        

    def _delete_floating_ips(self, ri, floatingip, nat_name):
        body = ngfw_utils.get_nat_server_static_map_to_delete(nat_name)
        response = self.rest.rest_api('DELETE', ngfw_utils.NGFW_URL_NAT_SERVER, body, device_ip=self.director_for_fip)
        
        if response['status'] >= 400:
            LOG.error(_('_delete_floating_ips failed (%s)'), nat_name)
            if not floatingip:
                LOG.error(_('_delete_floating_ips failed and floatingip is None!!!'))
            return False
        
        fip_statuses = {floatingip:l3_constants.FLOATINGIP_STATUS_DOWN}
        self.plugin_rpc.update_floatingip_statuses(
            self.context, ri.router_id, fip_statuses)
        LOG.debug(_('update_floatingip_statuses success fip_id is:%s , '
                'fip_statuses is:%s'), floatingip, fip_statuses)
        
        LOG.debug(_('_config_floating_ips_delete success (%s)'), nat_name)
                    
        return True
        
                        
    def _config_floating_ips(self, ri, floating_ips_backup):
        floatingip_list = {}        
        for floatingip_id in floating_ips_backup:
            id_prefix = ngfw_utils.get_floatingip_name(floatingip_id)
            floatingip_list.update({id_prefix:floatingip_id})
        floatingip_list_keys = floatingip_list.keys()
        prefix = ngfw_utils.get_dnat_rule_name(ri)
        floating_ips = self.get_ngfw_floating_ips(ri)   
        
        (need_add, need_del, collect_fip, nat_fip) = self._compare_floatingip_list(ri)
        for del_floatingip in need_del:
            if del_floatingip in floatingip_list_keys:
                floatingip = del_floatingip
            else:
                floatingip = None
            #update the nat_server with no_reserve when its last 
            self._del_configure_fip_no_reserve(ri,floatingip, nat_fip[del_floatingip])
            
            #del port if _del_configure_fip_no_reserve dont del port succ
            self._delete_floating_ips(ri, floatingip, nat_fip[del_floatingip])
            
            #del acl rules of the fip
            nat_server_name = '%s_%s' % (prefix, ngfw_utils.get_floatingip_name(del_floatingip))
            self.del_acl_by_fip(nat_server_name)
        
        # add new dnat rules
        for fip in floating_ips:
            LOG.debug(_('_config_floating_ips_add: %s'), fip['id'])
            result = self.plugutil._check_ip_in_ip_pool(fip['floating_ip_address'], self.agent.fip_slb_ip_pool)
            if not result:
                continue
            if ngfw_utils.get_floatingip_name(fip['id']) in need_add:
                nat_server_name = '%s_%s' % (prefix, ngfw_utils.get_floatingip_name(fip['id']))
                floatingIP = fip['floating_ip_address']
                fixedIP = fip['fixed_ip_address']
                
                #configure fip with no_reserve
                is_no_reserve = self._add_configure_fip_no_reserve(fixedIP)
                
                body = ngfw_utils.get_nat_server_static_map(nat_server_name, floatingIP, fixedIP, no_reverse=is_no_reserve)
                LOG.debug(_('_config_floating_ips_add body (%s) (%s)'), nat_server_name, body)
                response = self.rest.rest_api('POST', ngfw_utils.NGFW_URL_NAT_SERVER, body, device_ip=self.director_for_fip)
                
                #update fip status if it handle success
                if response['status'] >= 400:
                    LOG.error(_('_config_floating_ips_add failed floatingIP is: (%s), fixedIP is :(%s),'
                                '(%s) response status is: (%s) ,response body is: (%s)'),
                                ri.router['id'], floatingIP, fixedIP, response['status'], response["body"])
                    fip_statuses = {fip['id']:l3_constants.FLOATINGIP_STATUS_ERROR}
                    self.plugin_rpc.update_floatingip_statuses(
                        self.context, ri.router_id, fip_statuses)
                    LOG.debug(_('update_floatingip_statuses success router_id is:%s , '
                        'fip_statuses is:%s'), ri.router_id, fip_statuses)
                    return False
                else :
                    fip_statuses = {fip['id']:l3_constants.FLOATINGIP_STATUS_ACTIVE}
                    self.plugin_rpc.update_floatingip_statuses(
                        self.context, ri.router_id, fip_statuses)
                    LOG.debug(_('update_floatingip_statuses success router_id is:%s , '
                        'fip_statuses is:%s'), ri.router_id, fip_statuses)
                
                # set acl rules for the fip 
                self.set_acl_by_fip(nat_server_name, fixedIP, floatingIP)
                
                LOG.debug(_('_config_floating_ips success (%s) (%s) (%s)'),
                          ri.router['id'], floatingIP, fixedIP)
        return True
            
    def process_router(self, ri):
        LOG.debug(_("process_router: %s"), ri.router['id'])
        floating_ips_backup = ri.floating_ips
#        try:
#            super(ngfwL3NATAgent, self).process_router(ri)
#        except:
#            LOG.error('orginal l3 process_router failed') 
        if ri.ex_gw_port:
            self._set_subnet_info(ri.ex_gw_port)
        self._config_floating_ips(ri, floating_ips_backup)

    def _get_router_info_list_for_tenant(self, router_ids, tenant_id):
        router_info_list = []
        routers = self.plugin_rpc.get_routers_for_ngfw(self.context)
        router_ids_temp = []
        router_details = []
        for router in routers:
            if router['tenant_id'] == tenant_id and router['id'] in router_ids:
                router_ids_temp.append(router['id'])
                router_details.append(router)
        
        for i, rid in enumerate(router_ids_temp):
            ri = l3_agent.RouterInfo(rid, self.root_helper,
                     self.conf.use_namespaces, router_details[i])
            router_info_list.append(ri)  
        LOG.debug(_("_get_router_info_list_for_tenant: %s"), router_info_list)
        return router_info_list

    @periodic_task.periodic_task(spacing=1800)
    def save_ngfw_cfg(self, context):
        time_now = datetime.datetime.now()
        time_day = time_now.day
        time_hour = time_now.hour
        if time_hour != 3 or time_day == self.last_save_time:
            return

        bodyinfo = ngfw_utils.build_auto_save_name(self.auto_ngfw_save_filename)
        response = self.rest.rest_api('POST', ngfw_utils.NGFW_URL_SAVE_CFG, bodyinfo, device_ip=self.director_for_fip)
        if response['status'] >= 400:
            LOG.error(_('save ngfw cfg failed.'))
            return False
        self.last_save_time = time_day
        LOG.debug(_('save ngfw cfg success.'))
        return True

    def _get_director_for_fip(self):
        try:
            director_for_fip = cfg.CONF.ngfw.director_for_fip
            ip_list = director_for_fip.split(',')
        except:
            LOG.error(_('get director ip for fip failed, invalid format'))
            return None
        ip = ip_list[0]
        if self.plugutil.is_ip(ip):
            return ip
        return None

class ngfwL3NATAgentWithStateReport(ngfwL3NATAgent,
                                       l3_agent.L3NATAgentWithStateReport):
    def __init__(self, host, conf=None):
        super(ngfwL3NATAgentWithStateReport, self).__init__(host=host, conf=conf)


    def _report_state(self):
        self.agent_state['binary'] = 'neutron-ngfw-agent'
        configurations = self.agent_state['configurations']
        configurations['fip_slb_ip_pool'] = self.conf.ngfw.fip_slb_ip_pool
        super(ngfwL3NATAgentWithStateReport, self)._report_state()


def main():
    conf = cfg.CONF
    conf.register_opts(ngfwL3NATAgent.OPTS)
    conf.register_opts(l3_ha_agent.OPTS)
    conf.register_opts(ngfw_plugin.OPTS, "ngfw")
    config.register_interface_driver_opts_helper(conf)
    config.register_use_namespaces_opts_helper(conf)
    config.register_agent_state_opts_helper(conf)
    config.register_root_helper(conf)
    conf.register_opts(interface.OPTS)
    conf.register_opts(external_process.OPTS)
    common_config.init(sys.argv[1:])
    config.setup_logging()
    server = neutron_service.Service.create(
        binary='neutron-ngfw-agent',
        topic=topics.L3_AGENT,
        report_interval=cfg.CONF.AGENT.report_interval,
        manager='neutron.services.firewall.agents.ngfw.ngfw_router.'
                'ngfwL3NATAgentWithStateReport')
    service.launch(server).wait()
