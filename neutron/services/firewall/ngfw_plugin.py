# Copyright 2013 Big Switch Networks, Inc.
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

from oslo.config import cfg
import traceback
from neutron.common import exceptions as exc
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.db.firewall import firewall_db
from neutron.openstack.common import log as logging
from neutron.services.firewall import fwaas_plugin
import copy
import netaddr
from oslo.serialization import jsonutils
from neutron import context
from neutron.db import agents_db
from neutron.db import common_db_mixin as base_db
from neutron.common import constants as l3_constants
from neutron.extensions import firewall
import re
import json


LOG = logging.getLogger(__name__)

OPTS = [
    cfg.ListOpt('vpn_ip_pool',
                default=[],
                help=_("vpn public ip pool."
                       "Comma-separated list of <ip_min>:<ip_max> tuples")),
    cfg.ListOpt('fip_slb_ip_pool',
                default=[],
                help=_("fip/slb public ip pool."
                       "Comma-separated list of <ip_min>:<ip_max> tuples")),
    cfg.ListOpt('vsys_ranges',
                default=[],
                help=_("ngfw vsys ranges."
                       "Comma-separated list of <vsys_min>:<vsys_max> tuples")),
    cfg.ListOpt('vlan_ranges',
                default=[],
                help=_("vlan connectted with ngfw."
                       "Comma-separated list of <vlan_min>:<vlan_max> tuples")),
    cfg.IntOpt('addr_set_capacity',
               default=1000,
               help=_('the address number of one address set')), 
    cfg.IntOpt('ngfw_agent_count',
               default=1,
               help=_('the total count of ngfw-agent')),
    cfg.IntOpt('ngfw_agent_label',
               default=0,
               help=_('the label of ngfw-agent')),                                                                         
]

PLUGIN_UTILS_TYPE_VPN = 'vpn'
PLUGIN_UTILS_TYPE_FIP_SLB = 'fip_slb'


class NGFWAgentUtils():
    def __init__(self, vpn_ip=None, fip_slb=None, vsys=None, vlan=None,agent_label = 0,agent_count = 1):
        self.vpn_ip_pool = []
        self.fip_slb_ip_pool = []
        self.vsys_ranges = []
        self.vlan_ranges = []
        
        self.param={'vpn_ip':None, 'fip_slb':None, 'vsys':None, 'vlan':None,'agent_label' : 0,'agent_count' : 1}
        if vpn_ip or fip_slb or vsys or vlan:
            self.param['vpn_ip']=vpn_ip
            self.param['fip_slb']=fip_slb
            self.param['vsys']=vsys
            self.param['vlan']=vlan
            self.param['agent_count']= agent_count
            self.param['agent_label']= agent_label
        else:
            cfg.CONF.register_opts(OPTS, "ngfw")
            self.param['vpn_ip']=cfg.CONF.ngfw.vpn_ip_pool
            self.param['fip_slb']=cfg.CONF.ngfw.fip_slb_ip_pool
            self.param['vsys']=cfg.CONF.ngfw.vsys_ranges
            self.param['vlan']=cfg.CONF.ngfw.vlan_ranges
            self.param['agent_count']=cfg.CONF.ngfw.ngfw_agent_count
            self.param['agent_label']=cfg.CONF.ngfw.ngfw_agent_label
        self.initialize()

    def _parse_ranges(self, cfg_ranges, current_range):
        if not cfg_ranges:
            return        
        for entry in cfg_ranges:
            entry = entry.strip()
            try:
                tun_min, tun_max = entry.split(':')
                tun_min = int(tun_min)
                tun_max = int(tun_max)
                if tun_min > tun_max:
                    tunnel_range = tun_max, tun_min
                else:
                    tunnel_range = tun_min, tun_max
            except ValueError as ex:
                raise exc.NeutronException(error=ex)
            
            current_range.append(tunnel_range)
        LOG.info(_("ranges: %(range)s"), {'range': current_range})    

    def _parse_ip_ranges(self, cfg_ranges, current_range):
        if not cfg_ranges:
            return        
        for entry in cfg_ranges:
            entry = entry.strip()
            try:
                cidr=netaddr.IPNetwork(entry)
            except ValueError as ex:
                raise exc.NeutronException(error=ex)
            
            current_range.append(entry)
        LOG.info(_("ranges: %(range)s"), {'range': current_range})  
            
    def initialize(self):
        try:
            self._parse_ip_ranges(self.param['vpn_ip'], self.vpn_ip_pool)
            self._parse_ip_ranges(self.param['fip_slb'], self.fip_slb_ip_pool)
            self._parse_ranges(self.param['vsys'], self.vsys_ranges)
            self._parse_ranges(self.param['vlan'], self.vlan_ranges)                                  
        except exc.NeutronException:
            LOG.exception(_("Failed to parse ngfw cfg. "
                            "Service terminated!"))
            raise SystemExit()
        self._check_param_value()

    def _check_param_value(self):
        base_num = 0
        for entry in self.vpn_ip_pool:
            base_num = base_num + len(netaddr.IPNetwork(entry))
        
        check_num = 0
        for entry in self.vsys_ranges:
            check_num = check_num + (entry[1] - entry[0]) + 1
        if check_num != base_num:
            LOG.error(_("_check_param_value Failed!"))
            raise SystemExit()
        
        check_num = 0            
        for entry in self.vlan_ranges:
            check_num = check_num + (entry[1] - entry[0]) + 1
        if check_num != base_num:
            LOG.error(_("_check_param_value Failed!"))
            raise SystemExit()

        if self.param['agent_label'] >= self.param['agent_count']:
            LOG.error(_("_check_param_value Failed!"))
            raise SystemExit()
    
class NGFWPluginUtils(agents_db.AgentDbMixin, base_db.CommonDbMixin):
    def _check_ip_in_ip_pool(self, public_ip, ip_pool):
        LOG.debug(_("enter _check_ip_in_ip_pool, public_ip is: %s, ip_pool is: %s" % (public_ip, ip_pool)))
        if public_ip is None:
            return False
        
        if '/' in public_ip:
            public_ip = netaddr.IPNetwork(public_ip)
        
        for entry in ip_pool:
            if entry:
                cidr=netaddr.IPNetwork(entry)
                if public_ip in cidr:
                    return True        
        return False
    
    def _check_whether_public_ip(self, src_ip, dst_ip):
        ip_list = [src_ip, dst_ip]
        for ip in ip_list:
            if self._check_ip_in_ip_pool(ip, ['100.64/10']):
                continue
            return ip
        return None
    
    def get_proper_agent_by_ip(self, type, public_ip):
        ctx = context.get_admin_context()
        list_agents = self.get_agents(ctx, filters={'agent_type': [l3_constants.AGENT_TYPE_L3]})
        LOG.debug(_("list_agents is: %s" % list_agents))        

        for agent in list_agents:
            configuration = agent['configurations']
            vpn_ip_pool = configuration.get('vpn_ip_pool', None)
            fip_slb_ip_pool = configuration.get('fip_slb_ip_pool', None)
            vsys_ranges = configuration.get('vsys_ranges', None)
            vlan_ranges = configuration.get('vlan_ranges', None)
            agentUtil = NGFWAgentUtils(vpn_ip_pool, fip_slb_ip_pool, vsys_ranges, vlan_ranges)

            if type == PLUGIN_UTILS_TYPE_VPN:
                ip_pool = agentUtil.vpn_ip_pool
            elif type == PLUGIN_UTILS_TYPE_FIP_SLB:
                ip_pool = agentUtil.fip_slb_ip_pool
            else:
                ip_pool = None

            rest = self._check_ip_in_ip_pool(public_ip, ip_pool)
            if rest:
                return (agent['id'], configuration)
       
        return (None, None)            

    def check_whether_my_label(self, label):
        if label == cfg.CONF.ngfw.ngfw_agent_label:
            return True
        else:
            return False

    def is_ip(self, ip_str):
        ip = str(ip_str)
        pattern = r"^(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9])\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[0-9])$"
        p = re.compile(pattern)
        if p.match(ip):
            return True
        else:
            return False

            
class NGFWFirewallAgentApi(fwaas_plugin.FirewallAgentApi):
    """Plugin side of plugin to agent RPC API."""

    API_VERSION = '1.0'

    def __init__(self, topic, host):
        super(NGFWFirewallAgentApi, self).__init__(topic, self.API_VERSION)
        self.plugutil = NGFWPluginUtils()
        self.host = host

    def _get_ngfw_agents(self, context, firewall):
        list_agents = self.plugutil.get_agents(context, filters={'agent_type': [l3_constants.AGENT_TYPE_L3]})
        LOG.debug(_("get ngfw agent,list_agents is: %s" % list_agents))
        agent_to_send = []
        for agent in list_agents:
            binary = agent['binary']
            if binary == 'neutron-ngfw-agent':
                agent_to_send.append(agent)
        return agent_to_send

    def create_firewall(self, context, firewall):
        agents = self._get_ngfw_agents(context, firewall)
        for agent in agents:
            agent_host = agent['host']
            self.cast(
                context,
                self.make_msg('create_firewall', firewall=firewall, host=self.host),
                topic='%s.%s' % (self.topic, agent_host)
            )

    def update_firewall(self, context, firewall):
        agents = self._get_ngfw_agents(context, firewall)
        for agent in agents:
            agent_host = agent['host']
            self.cast(
                context,
                self.make_msg('update_firewall', firewall=firewall, host=self.host),
                topic='%s.%s' % (self.topic, agent_host)
            )

    def delete_firewall(self, context, firewall):
        agents = self._get_ngfw_agents(context, firewall)
        for agent in agents:
            agent_host = agent['host']
            self.cast(
                context,
                self.make_msg('delete_firewall', firewall=firewall, host=self.host),
                topic='%s.%s' % (self.topic, agent_host)
            )


class NGFWFirewallPlugin(fwaas_plugin.FirewallPlugin):

    """Implementation of the Neutron Firewall Service Plugin.

    This class manages the workflow of FWaaS request/response.
    Most DB related works are implemented in class
    firewall_db.Firewall_db_mixin.
    """
    supported_extension_aliases = ["fwaas", "fwaasrouterinsertion"]

    def __init__(self):
        """Do the initialization for the firewall service plugin here."""
        
        self.endpoints = [fwaas_plugin.FirewallCallbacks(self)]

        self.conn = n_rpc.create_connection(new=True)
        self.conn.create_consumer(
            topics.FIREWALL_PLUGIN, self.endpoints, fanout=False)
        self.conn.consume_in_threads()

        self.agent_rpc = NGFWFirewallAgentApi(
            topics.L3_AGENT,
            cfg.CONF.host
        )

        self.pluginutils = NGFWPluginUtils()

    def _check_firewall_rule(self, context, firewall_rule):
        fwr = firewall_rule['firewall_rule']
        LOG.info(_("firewall rule is: %s" % fwr))
        try:
            if ( not fwr.has_key("mode") ) or ( "normal" == fwr["mode"] ):
                return
            
            elif "mix" == fwr["mode"]:
                rule_profile = json.loads( fwr["rule_profile"] )
                rule_profile_sesurity_zone = rule_profile["security-zone"]
                match_rule = False

                #in
                if "untrust" == rule_profile_sesurity_zone["source-zone"] and \
                    "trust" == rule_profile_sesurity_zone["destination-zone"]:
                    match_rule = True
                    LOG.info(_("firewall in rule, judge destination ip."))    
                    ret = self.pluginutils.get_proper_agent_by_ip(PLUGIN_UTILS_TYPE_FIP_SLB, fwr['destination_ip_address'])
                    if (None, None) == ret:
                        LOG.error(_("destination ip: %s is not public ip" % fwr['destination_ip_address']))
                        raise firewall.FirewallRuleDestinationIpNotPublicIp()
                    
                #out
                if "trust" == rule_profile_sesurity_zone["source-zone"] and \
                    "untrust" == rule_profile_sesurity_zone["destination-zone"]:
                    match_rule = True
                    LOG.info(_("firewall out rule. judge source ip."))    
                    ret = self.pluginutils.get_proper_agent_by_ip(PLUGIN_UTILS_TYPE_FIP_SLB, fwr['source_ip_address'])
                    if (None, None) == ret:
                        LOG.error(_("source ip: %s is not public ip" % fwr['source_ip_address']))
                        raise firewall.FirewallRuleSourceIpNotPublicIp()
                
                if not match_rule:
                    raise firewall.FirewallRuleInvalid()   
            
            elif "profile" == fwr["mode"]:
                if not fwr.get('rule_profile'):
                    raise firewall.FirewallRuleModeProfileNotMatch()
                ret1 = (None, None)
                ret2 = (None, None)
                if fwr.has_key('source_ip_address') and fwr['source_ip_address']:
                    ret1 = self.pluginutils.get_proper_agent_by_ip(PLUGIN_UTILS_TYPE_FIP_SLB, fwr['source_ip_address'])
                    if ret1 == (None, None):
                        raise firewall.FirewallRuleInvalid()
                if fwr.has_key('destination_ip_address') and fwr['destination_ip_address']:
                    ret2 = self.pluginutils.get_proper_agent_by_ip(PLUGIN_UTILS_TYPE_FIP_SLB, fwr['destination_ip_address'])
                    if ret2 == (None, None):
                        raise firewall.FirewallRuleInvalid()
                if ( (None, None) != ret1 and (None, None) != ret2 ):
                    LOG.error(_("both source ip and destination ip is public ip"))
                    raise firewall.FirewallRuleInvalid()

                try:
                    rule_profile = json.loads(fwr["rule_profile"])
                except:
                    LOG.error(_('create traffic policy error, rule_profile is illeagal'))
                    raise firewall.FirewallRuleInvalid()
                if rule_profile.get('traffic-policy'):
                    if not rule_profile.get('traffic-policy').get('add-body'):
                        LOG.error(_('create traffic policy error, traffic-policy has no add-body'))
                        raise firewall.FirewallRuleInvalid()
                else:
                    LOG.error(_('create traffic policy error, no traffic-policy in rule_profile'))
                    raise firewall.FirewallRuleInvalid()
            else:
                raise firewall.FirewallRuleInvalid()
                
        except:
               LOG.error(_("ERROR, traceback:%s" % traceback.format_exc() ))
               raise firewall.FirewallRuleInvalid() 


    def create_firewall_rule(self, context, firewall_rule):
        self._check_firewall_rule(context, firewall_rule)
        return super(NGFWFirewallPlugin, self).create_firewall_rule(context, firewall_rule)

    def update_firewall_rule(self, context, id, firewall_rule):
        firewall_temp = {'firewall_rule':{}}
        firewall_rule_temp = firewall_temp['firewall_rule']
        fwr_db = self._get_firewall_rule(context, id)
        if fwr_db["mode"]:
            firewall_rule_temp.update({"mode":fwr_db["mode"]})
        if fwr_db["rule_profile"]:
            firewall_rule_temp.update({"rule_profile":fwr_db["rule_profile"]})
        if fwr_db["source_ip_address"]:
            firewall_rule_temp.update({"source_ip_address":fwr_db["source_ip_address"]})
        if fwr_db["destination_ip_address"]:
            firewall_rule_temp.update({"destination_ip_address":fwr_db["destination_ip_address"]})
        firewall_rule_temp.update(firewall_rule['firewall_rule'])
        self._check_firewall_rule(context, firewall_temp)
        return super(NGFWFirewallPlugin, self).update_firewall_rule(context, id, firewall_rule)            

