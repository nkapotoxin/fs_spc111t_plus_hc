#!/usr/bin/env python
# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2011 Nicira Networks, Inc.
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

import hashlib
import signal
from neutron.agent.linux import utils
from neutron.openstack.common import jsonutils
from neutron.common import exceptions

from six import moves
from neutron.plugins.common import constants as p_const
from neutron.plugins.openvswitch.common import constants

import sys
import time
import platform

import eventlet
eventlet.monkey_patch()

from oslo.config import cfg
from neutron.agent.linux import polling

from neutron.agent.linux import ip_lib
from neutron.agent.linux import evs_lib
from neutron.agent import rpc as agent_rpc
from neutron.common import config as logging_config
from neutron.common import constants as q_const
from neutron.common import topics
from neutron.common import utils as q_utils
from neutron import context
from neutron.extensions import securitygroup as ext_sg
from neutron.openstack.common import log as logging
from neutron.openstack.common import loopingcall
from neutron.agent.common import config


from neutron.common import rpc as n_rpc
from neutron.agent.linux import interface
from neutron.agent.linux import external_process
from neutron.common import config as common_config

from neutron.openstack.common import service
from neutron import service as neutron_service
from neutron.services.servicechain import constants as sc_constants
from neutron.services.servicechain.common import sc_ovs_lib
from neutron.agent.linux import ip_lib
from neutron.openstack.common import jsonutils
from neutron.agent.linux import ovs_lib


LOG = logging.getLogger(__name__)


SERVICE_CHAIN_TABLE = 41
SERVICE_FUNCTION_INSTANCE_GROUP_TABLE = 42
SERVICE_FUNCTION_INSTANCE_TABLE = 43
RESTART_TABLE = 24
Agent_Start_Report_Retry_Interval = 2


class DeviceListRetrievalError(exceptions.NeutronException):
    message = _("Unable to retrieve port details for devices: %(devices)s "
                "because of error: %(error)s")


class ServiceChainPluginApi(n_rpc.RpcProxy):
    
    BASE_RPC_API_VERSION = '1.0'

    def __init__(self, topic, host):
        super(ServiceChainPluginApi, self).__init__(
            topic=topic, default_version=self.BASE_RPC_API_VERSION)
        self.host = host

        
    def update_portflows_status(self, context, host, chain_id, ports_id_status):
        self.cast(context,
                  self.make_msg('update_portflows_status', 
                                host=host,
                                chain_id=chain_id,
                                ports_id_status=ports_id_status),
                  topic=self.topic)

    def get_portflows_by_host_portid(self, context, host, port_id, status=None):
        return self.call(context, 
                          self.make_msg('get_portflows_by_host_portid', host=host, port_id=port_id),
                          topic=self.topic)
        
    def get_instance_classifier_by_host_portid(self, context, host, port_id):
        return self.call(context, 
                          self.make_msg('get_instance_classifier_by_host_portid', host=host, port_id=port_id),
                          topic=self.topic)        
        

class ServiceChainAgent(n_rpc.RpcCallback):
    # history
    #   1.0 Initial version
    #   1.1 Support Security Group RPC
    #   1.2 user space SERVICECHAIN
    
    DEFAULT_BRIDGE_MAPPINGS = []
    
    OPTS= [
        cfg.ListOpt('bridge_mappings',
                       default=DEFAULT_BRIDGE_MAPPINGS,
                       help=_("List of <physical_network>:<bridge>"))]    

    agent_opts = [
        cfg.IntOpt('polling_interval', default=2,
                   help=_("The number of seconds the agent will wait between "
                          "polling for local device changes.")),
        cfg.BoolOpt('minimize_polling',
                    default=True,
                    help=_("Minimize polling by monitoring ovsdb for interface "
                           "changes."))
        ]
    
    RPC_API_VERSION = '1.2'

    def __init__(self, integ_ebr, bridge_mappings, root_helper, polling_interval,
                 minimize_polling=False,
                 ovsdb_monitor_respawn_interval=(
                     constants.DEFAULT_OVSDBMON_RESPAWN)):
        '''Constructor.

        :param integ_ebr: name of the integration bridge.
        :param bridge_mappings: mappings from physical network name to bridge.
        :param root_helper: utility to use when running shell cmds.
        :param polling_interval: interval (seconds) to poll DB.
        '''
        super(ServiceChainAgent, self).__init__()
        self.root_helper = root_helper
        self.run_daemon_loop = True
        self.use_call = True          

        self.agent_state = {
            'binary': 'neutron-servicechain-agent',
            'host': cfg.CONF.host,
            'topic': ('%s.%s' % (sc_constants.SERVICECHAIN_AGENT_TOPIC, cfg.CONF.host)),
            'configurations': {'bridge_mappings': bridge_mappings},
            'agent_type': sc_constants.AGENT_TYPE_SERVICECHAIN,
            'start_flag': True}

        self.int_br_device_count = 0
        self.host = cfg.CONF.host

        self.setup_rpc(cfg.CONF.host)             
        self.integ_ebr = evs_lib.EVSBridge(integ_ebr, self.root_helper)             
        
        self.updated_ports = set()
        self.polling_interval = polling_interval
        self.iter_num = 0
        
        self.agent_restart = True
        

        self.bridge_mappings = bridge_mappings
                
        if bridge_mappings:        
            self.integ_ebr.add_flow(table=RESTART_TABLE, priority=0,
                                    actions="drop")     
        self.ovsdb_monitor_respawn_interval = ovsdb_monitor_respawn_interval
        self.minimize_polling = minimize_polling      

    def _report_state(self):
        self.agent_state.get('configurations')['devices'] = (
            self.int_br_device_count)
        try:
            self.state_rpc.report_state(self.context,
                                        self.agent_state,
                                        self.use_call)
            self.agent_state.pop('start_flag', None)
            self.use_call = False
        except Exception:
            LOG.exception(_("Failed reporting state!"))

    def setup_rpc(self, host):
        self.agent_id = 'servicechain_agent_%s' % platform.node()
        self.plugin_rpc = ServiceChainPluginApi(sc_constants.SERVICECHAIN_TOPIC, host) 


        self.topic = sc_constants.SERVICECHAIN_AGENT_TOPIC
   
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.PLUGIN)

        self.context = context.get_admin_context_without_session()
        self.dispatcher = [self]
        consumers = [[topics.PORT, topics.UPDATE],
                     [topics.NETWORK, topics.DELETE],
                     ['port_flows','add',cfg.CONF.host],
                     ['port_flows','delete',cfg.CONF.host],
                     ['port_type','set',cfg.CONF.host],
                     ['port_type','clear',cfg.CONF.host]]
        
        
        self.connection = agent_rpc.create_consumers(self.dispatcher,
                                                     self.topic,
                                                     consumers)
        report_interval = cfg.CONF.AGENT.report_interval
        if report_interval:
            heartbeat = loopingcall.FixedIntervalLoopingCall(
                self._report_state)
            heartbeat.start(interval=report_interval)
        

    def port_update(self, context, **kwargs):
        port = kwargs.get('port')
        self.updated_ports.add(port['id'])

    def create_rpc_dispatcher(self):
        return n_rpc.PluginRpcDispatcher([self])


    def scan_ports(self, registered_ports, updated_ports = None):
        cur_ports = self.integ_ebr.get_vif_port_set(q_const.QEP_VSWITCH_PREFIX)
        self.int_br_device_count = len(cur_ports)
        port_info = {'current': cur_ports}
        
        if updated_ports is None:
            updated_ports = set()

        if updated_ports:
            updated_ports &= cur_ports
            if updated_ports:
                port_info['updated'] = updated_ports        
        if cur_ports == registered_ports:
            return port_info

        port_info['added'] = cur_ports - registered_ports
        port_info['removed'] = registered_ports - cur_ports
        return port_info


    def _port_info_has_changes(self, port_info):
        return (port_info.get('added') or
                port_info.get('removed') or
                port_info.get('updated'))

    def treat_devices_added_updated(self, devices, ovs_restarted):  

        resync_a = False
        skipped_devices = []

        self.add_ports_id_flow(devices, ovs_restarted)
                          
        return resync_a,skipped_devices
    

    def treat_devices_removed(self, devices):
      
        self.delete_ports_id_flow(devices)
        return False
        

    def process_network_ports(self, port_info, ovs_restarted):
        resync_a = False
        resync_b = False

        devices_added_updated = (port_info.get('added', set()) |
                                 port_info.get('updated', set()))
        if devices_added_updated:
            try:
                LOG.debug(_("process_network_ports,devices_added_updated:%s"),devices_added_updated)
                resync_a, skipped_devices = self.treat_devices_added_updated(devices_added_updated, ovs_restarted)
                port_info['current'] = (port_info['current'] -
                                        set(skipped_devices))
            except DeviceListRetrievalError:
                LOG.exception(_("process_network_ports - iteration:%d - "
                                "failure while retrieving port details "
                                "from server"), self.iter_num)
                resync_a = True
        if 'removed' in port_info and port_info['removed']:

            resync_b = self.treat_devices_removed(port_info['removed'])
        return (resync_a | resync_b)

    def check_ovs_restart(self):       
        canary_flow = self.integ_ebr.dump_flows_for_table(RESTART_TABLE)
        return not canary_flow
    
    def _agent_has_updates(self, polling_manager):
        return (polling_manager.is_polling_required or
                self.updated_ports) 

    def rpc_loop(self, polling_manager=None):     
        if not polling_manager:
            polling_manager = polling.AlwaysPoll()

        sync = True
        ports = set()
        updated_ports_copy = set()
        ovs_restarted = False
                
        while self.run_daemon_loop:
            if self.use_call == True:
                time.sleep(Agent_Start_Report_Retry_Interval)
                continue
            try:
                start = time.time()
                if sync:
                    LOG.info(_("Agent out of sync with plugin! Should br synchronized!"))
                    ports.clear()
                    sync = False
                    polling_manager.force_polling()	
                                       
                try:
                    
                    if not self.bridge_mappings:
                        LOG.debug(_("Bridge mapping is not configured!"))
                        elapsed = (time.time() - start)
                        if (elapsed < self.polling_interval):
                            time.sleep(self.polling_interval - elapsed)
                        continue
                                    
                    #check if ovs-vswitchd restart
                    ovs_restarted = self.check_ovs_restart()
                    
                    if self._agent_has_updates(polling_manager) or ovs_restarted: 
                                    
                        updated_ports_copy = self.updated_ports
                        self.updated_ports = set()
                    
                        reg_ports = (set() if ovs_restarted else ports)
                        if ovs_restarted:
                            self.integ_ebr.add_flow(table=RESTART_TABLE, priority=0,
                                                     actions="drop")                          
                        
                        port_info = self.scan_ports(reg_ports, updated_ports_copy)
                    
                        if self._port_info_has_changes(port_info):
                            LOG.debug(_("Starting to process devices in:%s"),
                                      port_info)
                            # If treat devices fails - must resync with plugin
                            sync = self.process_network_ports(port_info, ovs_restarted)                       
                        ports = port_info['current']
                        polling_manager.polling_completed()
                except Exception:
                    LOG.exception(_("Error while processing VIF ports"))
                    # Put the ports back in self.updated_port
                    self.updated_ports |= updated_ports_copy                    
                    sync = True 
            except Exception:
                LOG.exception(_("Error in agent event loop"))
                sync = True
            # sleep till end of polling interval
            elapsed = (time.time() - start)
            if (elapsed < self.polling_interval):
                time.sleep(self.polling_interval - elapsed)
            else:
                LOG.debug(_("Loop iteration exceeded interval "
                            "(%(polling_interval)s vs. %(elapsed)s)!"),
                          {'polling_interval': self.polling_interval,
                           'elapsed': elapsed})
            self.iter_num = self.iter_num + 1

    def _handle_sigterm(self, signum, frame):
        LOG.debug("Agent caught SIGTERM, quitting daemon loop.")
        self.run_daemon_loop = False            

    
    def daemon_loop(self):
        with polling.get_polling_manager(
            self.minimize_polling,
            self.root_helper,
            self.ovsdb_monitor_respawn_interval) as pm:
            LOG.debug("daemon_loop,pm=%s" % pm)
            self.rpc_loop(polling_manager=pm)

        

    #you may want to set the type from 'notrans' to 'trans', so we should delete the old flows
    def set_port_type(self, context, **kwargs):        
        try:

            ports_info = kwargs['ports_info']
            LOG.debug("set_port_type received, ports_info= %s" %(ports_info))  
            for port_info in ports_info:
                port_name = self.integ_ebr.get_port_name_by_id(port_info['port_id']) 
                if not port_name:
                    LOG.debug("set_port_type continue, port_name= %s is not exsist" %(port_name))
                    continue  
                policy_bridge_name = evs_lib.get_bridge_for_iface(self.root_helper, port_name)        
                policy_bridge = evs_lib.EVSBridge(policy_bridge_name, self.root_helper)
                if port_name:
                    port_name_tap = policy_bridge.get_port_ofport(port_name)
                    port_name_patch_name = port_name.replace('tap','qvp')                     
                    port_name_patch = policy_bridge.get_port_ofport(port_name_patch_name)                    
                    
                    #we should delete the flows before we set them, otherwise when instance is changed from 
                    #notrans to trans #we could not delete the '0x0806' flows
                    policy_bridge.delete_flows(in_port = port_name_tap) 
                    policy_bridge.delete_flows(in_port = port_name_patch, dl_dst=port_info['dst_mac']) 
                    policy_bridge.delete_flows(in_port = port_name_patch, dl_dst='00:00:00:00:00:00/00:01:00:00:00:00')
                    policy_bridge.delete_flows(in_port = port_name_patch, dl_dst='00:01:00:00:00:00/00:01:00:00:00:00')  
                    policy_bridge.delete_flows(in_port = port_name_patch, dl_type='0x0806')                   
                
                if port_info['sc_type'] == 'dl_src':
                    type = 'trans'                                
                else:                   
                    type = 'notrans' 
                    policy_bridge.add_sc_flow(priority=10000, in_port=port_name_patch, dl_type='0x0806', actions="NORMAL") 

  
                                 
                policy_bridge.add_sc_flow(priority=9000, in_port=port_name_tap, actions="NORMAL")                                   
                policy_bridge.add_sc_flow(priority=10, in_port=port_name_patch, \
                                          dl_dst="00:00:00:00:00:00/00:01:00:00:00:00",actions='drop')
                policy_bridge.add_sc_flow(priority=10, in_port=port_name_patch, \
                                          dl_dst="00:01:00:00:00:00/00:01:00:00:00:00",actions='drop')
                    
                if int(port_info['sf_port_id']) >= 20000:
                    policy_bridge.add_sc_flow(priority=10000, in_port=port_name_patch,  \
                                              dl_dst=port_info['dst_mac'], actions='resubmit(,1)')   
                    policy_bridge.add_sc_flow(table=1, priority=1, actions="NORMAL")                           
                else:
                    policy_bridge.add_sc_flow(priority=10000, in_port=port_name_patch,\
                                              dl_dst=port_info['dst_mac'], actions="NORMAL")                                               
        
                sc_ovs_lib.set_sc_port_type(port_name, type,
                                            int(port_info['sf_port_id']), self.root_helper) 
        except Exception as e:                 
            LOG.error(_("set_port_type failed, except by %s"), e)                 
            
    def clear_port_type(self, context, **kwargs):           
        try:   
            ports_info = kwargs['ports_info']
            LOG.debug("clear_port_type received, ports_info= %s" %(ports_info))             
            for port_info in ports_info:
                port_name = self.integ_ebr.get_port_name_by_id(port_info['port_id'])   
                if not port_name:
                    LOG.debug("clear_port_type continue, port_name= %s is not exsist" %(port_name))
                    continue                 
                sc_ovs_lib.clear_sc_port_type(port_name, 'default', self.root_helper) 

                policy_bridge_name = evs_lib.get_bridge_for_iface(self.root_helper, port_name)        
                policy_bridge = evs_lib.EVSBridge(policy_bridge_name, self.root_helper)    

                port_name_tap = policy_bridge.get_port_ofport(port_name)
                port_name_patch_name = port_name.replace('tap','qvp')                     
                port_name_patch = policy_bridge.get_port_ofport(port_name_patch_name)
                policy_bridge.delete_flows(in_port = port_name_tap) 
                policy_bridge.delete_flows(in_port = port_name_patch, dl_dst='00:00:00:00:00:00/00:01:00:00:00:00')
                policy_bridge.delete_flows(in_port = port_name_patch, dl_dst='00:01:00:00:00:00/00:01:00:00:00:00')  
                policy_bridge.delete_flows(in_port = port_name_patch, dl_type='0x0806')              
                
        except Exception as e: 
            LOG.error(_("clear_port_type failed, except by %s"), e)   

    #the group_flow: if the chain is U2N, sf_port_list={0:100} when chain is N2U, sf_port_list={0:100} it must equal to the before
    #when the classifier has the flows like(the instance must has the same flows):  
    #table=43 sf_port_id=0, pair_sf_port_id=1, dl_vlan=1, fault_policy=default, dl_dst=fa:16:3e:ea:84:99, usr_dl_dst=fa:16:3e:ea:84:99
    #table=43 sf_port_id=1, pair_sf_port_id=0, dl_vlan=1, fault_policy=default, dl_dst=fa:16:3e:69:bf:91    
    #only classifier has this flow: sf_port_id=20000, pair_sf_port_id=20000, dl_vlan=0, fault_policy=default, dl_dst=00:00:00:00:00:00       
    def treat_add_port_flow_opt(self, portflow, ports_id_status):
        try:                                             
            port_name = self.integ_ebr.get_port_name_by_id(portflow['in_port_uuid'])
            policy_bridge_name = evs_lib.get_bridge_for_iface(self.root_helper, port_name)        
            policy_bridge = evs_lib.EVSBridge(policy_bridge_name, self.root_helper)                
            
            sf_port_list = {}
            direct = int(portflow['chain_direction'])
            tap_port_tag = 0
            
            in_port_pair = portflow['in_port_pair']
            
            net_dl_dst_date_pair = None
            user_dl_dst_date_pair =None
            #when the instance do the scale_in actions we should delete the port_table
            #if the group only has that instance we should delete the group_table

            if portflow.get('history_portlist', None):
                LOG.debug("treat_add_port_flow_opt received, history_portlist= %s" %portflow['history_portlist'])
                if portflow['history_portlist'].get('group_id',None) or portflow['history_portlist'].get('group_id', None) == 0:
                    if portflow['history_portlist']['group_id'] != portflow['group_id'] and \
                        portflow['history_portlist']['group_id'] != -1:   
                        policy_bridge.delete_flows(table = SERVICE_FUNCTION_INSTANCE_GROUP_TABLE, group_id = \
                                                   portflow['history_portlist']['group_id'])
                        
                if portflow['history_portlist'].get('old_port_list',None):
                    for port_to_delete in portflow['history_portlist']['old_port_list']:
                        policy_bridge.delete_flows(table = SERVICE_FUNCTION_INSTANCE_TABLE, sf_port_id = int(port_to_delete))
                        policy_bridge.delete_flows(table = SERVICE_FUNCTION_INSTANCE_TABLE, sf_port_id = \
                                                   int(portflow['history_portlist']['old_port_list'][port_to_delete]))

            #if the instance is inactive, we needn't to set the flows, but we should make sure it is active 
            #to make sure the chain is active
            inactive_flag = False
            if portflow.get('instance_state', None) == 'inactive':
                inactive_flag = True

            if portflow['in_port'] >= 20000:
                policy_bridge.add_flow(table = SERVICE_FUNCTION_INSTANCE_TABLE, sf_port_id = portflow['in_port'],
                            fault_policy = 'default', pair_sf_port_id = portflow['in_port'], actions="NORMAL")
            else:
                if direct == 1:
                    if in_port_pair['udmac']:
                        user_dl_dst_date_pair = in_port_pair['udmac']
                    if in_port_pair['ndmac']:
                        net_dl_dst_date_pair = in_port_pair['ndmac']                                                                      
                else:
                    if in_port_pair['udmac']:
                        net_dl_dst_date_pair = in_port_pair['udmac']
                    if in_port_pair['ndmac']:
                        user_dl_dst_date_pair = in_port_pair['ndmac'] 
    
                if net_dl_dst_date_pair:
                    policy_bridge.add_flow(table = SERVICE_FUNCTION_INSTANCE_TABLE, sf_port_id = portflow['in_port'],
                                fault_policy = in_port_pair['fault_policy'], dl_vlan=tap_port_tag,
                                pair_sf_port_id = in_port_pair['pair_in_port'],
                                dl_dst = portflow['outer_dl_src'], user_dl_dst = net_dl_dst_date_pair,
                                actions="NORMAL")                       
                else:  
                    policy_bridge.add_flow(table = SERVICE_FUNCTION_INSTANCE_TABLE, sf_port_id = portflow['in_port'],
                                fault_policy = in_port_pair['fault_policy'], dl_vlan=tap_port_tag,
                                pair_sf_port_id = in_port_pair['pair_in_port'],
                                dl_dst = portflow['outer_dl_src'],actions="NORMAL")    
                    
                if user_dl_dst_date_pair:
                    policy_bridge.add_flow(table = SERVICE_FUNCTION_INSTANCE_TABLE, sf_port_id = in_port_pair['pair_in_port'],
                                fault_policy = in_port_pair['fault_policy'], dl_vlan=tap_port_tag,
                                pair_sf_port_id = portflow['in_port'],
                                dl_dst = in_port_pair['pair_outer_dl_src'], user_dl_dst = user_dl_dst_date_pair,
                                actions="NORMAL")                       
                else:  
                    policy_bridge.add_flow(table = SERVICE_FUNCTION_INSTANCE_TABLE, sf_port_id = in_port_pair['pair_in_port'],
                                fault_policy = in_port_pair['fault_policy'], dl_vlan=tap_port_tag,
                                pair_sf_port_id = portflow['in_port'],
                                dl_dst = in_port_pair['pair_outer_dl_src'], actions="NORMAL")    
           
            if portflow['breakout_dl_src']:
                policy_bridge.add_flow(table = SERVICE_CHAIN_TABLE, chain_id = portflow['chain_id'],  
                                in_port = portflow['in_port'], breakout_dl_src = portflow['breakout_dl_src'], dl_vlan=0,
                                breakout_dl_dst = portflow['breakout_dl_dst'], actions="NORMAL")                  

            else:
                if portflow.get('chain_id', None) or portflow.get('chain_id', None) == 0:
                    policy_bridge.add_flow(table = SERVICE_CHAIN_TABLE, chain_id = portflow['chain_id'],direct=direct,  
                                    in_port = portflow['in_port'], outer_dl_src = portflow['outer_dl_src'], dl_vlan=0,
                                    group_id = portflow['group_id'], actions="goto_table:42")
                    sf_port_list = {}      
                
                if portflow.get('sf_port_list', None):   
                    no_active_instance_flag = 0
                    for sf_port in portflow['sf_port_list']: 
                        sf_port_key = sf_port.keys()[0]
                        if sf_port[sf_port_key]['fault_policy'] == 'default':
                            no_active_instance_flag = 1
                            break
   
                    for sf_port in portflow['sf_port_list']:     
                        sf_port_key = sf_port.keys()[0]  
                        
                        if sf_port[sf_port_key].get('state', None) == 'inactive':
                            continue
                        
                        tap_port_tag_next_hop = 0
                                                        
                        user_dl_dst_date = None
                        net_dl_dst_date = None
                        in_port_group = None
                                                        
                        if direct == 1:
                            if sf_port[sf_port_key]['udmac']:
                                user_dl_dst_date = sf_port[sf_port_key]['udmac'] 
                            if sf_port[sf_port_key]['ndmac']:
                                net_dl_dst_date = sf_port[sf_port_key]['ndmac']     
                            in_port_group = int(sf_port_key)                                                             
                        else:
                            if sf_port[sf_port_key]['udmac']:
                                net_dl_dst_date = sf_port[sf_port_key]['udmac'] 
                            if sf_port[sf_port_key]['ndmac']:
                                user_dl_dst_date = sf_port[sf_port_key]['ndmac'] 
                            in_port_group = sf_port[sf_port_key]['pair_sf_port_id']
            
                        LOG.debug("treat_add_port_flow_opt, here has net_dl_dst_date=%s and user_dl_dst_date=%s" %\
                                  (net_dl_dst_date,user_dl_dst_date))
                        
                        if user_dl_dst_date:
                            policy_bridge.add_flow(table = SERVICE_FUNCTION_INSTANCE_TABLE, sf_port_id = int(sf_port_key),
                                                fault_policy = sf_port[sf_port_key]['fault_policy'],dl_vlan=tap_port_tag_next_hop,
                                                pair_sf_port_id = sf_port[sf_port_key]['pair_sf_port_id'],
                                                dl_dst = sf_port[sf_port_key]['dl_dst'], user_dl_dst = user_dl_dst_date,
                                                actions="NORMAL")                       
                        else:  
                            policy_bridge.add_flow(table = SERVICE_FUNCTION_INSTANCE_TABLE, sf_port_id = int(sf_port_key),
                                                fault_policy = sf_port[sf_port_key]['fault_policy'],dl_vlan=tap_port_tag_next_hop,
                                                pair_sf_port_id = sf_port[sf_port_key]['pair_sf_port_id'],
                                                dl_dst = sf_port[sf_port_key]['dl_dst'], actions="NORMAL")    
                            
                        if net_dl_dst_date:
                            policy_bridge.add_flow(table=SERVICE_FUNCTION_INSTANCE_TABLE, sf_port_id=sf_port[sf_port_key]['pair_sf_port_id'],
                                                fault_policy = sf_port[sf_port_key]['fault_policy'],dl_vlan=tap_port_tag_next_hop,
                                                pair_sf_port_id = int(sf_port_key),
                                                dl_dst = sf_port[sf_port_key]['dl_dst_pair'], user_dl_dst = net_dl_dst_date,
                                                actions="NORMAL")                    
                        else:  
                            policy_bridge.add_flow(table=SERVICE_FUNCTION_INSTANCE_TABLE, sf_port_id=sf_port[sf_port_key]['pair_sf_port_id'],
                                                fault_policy = sf_port[sf_port_key]['fault_policy'],dl_vlan=tap_port_tag_next_hop,
                                                pair_sf_port_id = int(sf_port_key),
                                                dl_dst = sf_port[sf_port_key]['dl_dst_pair'], actions="NORMAL")      

                        if inactive_flag == False:
                            if no_active_instance_flag == 1 and sf_port[sf_port_key]['fault_policy'] != 'default':
                                sf_port_list[in_port_group] = 0    
                            else:
                                sf_port_list[in_port_group] = int(sf_port[sf_port_key]['sf_port_weight'])                      

                if sf_port_list:                    
                    sf_port_string = str(sf_port_list)
                    sf_port_change = sf_port_string.replace(',', '/')
                    sf_port_change_no_empty = sf_port_change.replace(' ', '')
                    
                    if portflow['hash_policy'] == 'LBM_SIP':
                        hash_policy_group = 'layer3_SIP'
                    elif portflow['hash_policy'] == 'LBM_DIP':
                        hash_policy_group = 'layer3_DIP'
                    elif portflow['hash_policy'] == 'LBM_5TUPLE':
                        hash_policy_group = 'layer34'
                                        
                    policy_bridge.add_flow(table = SERVICE_FUNCTION_INSTANCE_GROUP_TABLE, \
                                           group_id = portflow['group_id'], hash_policy = hash_policy_group, \
                                           sf_port_list = sf_port_change_no_empty, actions="goto_table:43")
                                
            ports_id_status_temp = []
            ports_id_status_temp.append(portflow['in_port_uuid'])
            ports_id_status_temp.append(portflow['chain_id'])
            ports_id_status_temp.append(sc_constants.STATUS_ACTIVE)
            ports_id_status.append(ports_id_status_temp)
        except Exception as e:     
            ports_id_status_temp = []
            ports_id_status_temp.append(portflow['in_port_uuid'])
            ports_id_status_temp.append(portflow['chain_id'])
            ports_id_status_temp.append(sc_constants.STATUS_ERROR)
            ports_id_status.append(ports_id_status_temp)                      
            LOG.error(_("add_port_flows failed, except by %s"), e) 
            
    
    #if index(sf_port_id and group) in port_flows we should not delete the sf_port_flow or sf_group_flow
    #if index(sf_port_id) in port_flows we should not delete the sf_port_flow or sf_group_flow                           
    def treat_delete_port_flow_opt(self, portflow, ports_id_status):
        try:                               
            LOG.debug("treat_delete_port_flow_opt, portflow= %s" %(portflow))
            port_name = self.integ_ebr.get_port_name_by_id(portflow['in_port_uuid'])                
            policy_bridge_name = evs_lib.get_bridge_for_iface(self.root_helper, port_name)        
            policy_bridge = evs_lib.EVSBridge(policy_bridge_name, self.root_helper)  
            
            policy_bridge.delete_flows(table = SERVICE_CHAIN_TABLE, in_port = portflow['in_port'], \
                                       chain_id = portflow['chain_id'])
                
            if portflow.get('group_id', None) or portflow.get('group_id', None) == 0:
                if not portflow.get('group_count', None) or int(portflow.get('group_count', None)) <= 1 :                
                    policy_bridge.delete_flows(table = SERVICE_FUNCTION_INSTANCE_GROUP_TABLE, \
                                               group_id = portflow['group_id'])
            
            if not portflow.get('group_count', None) or (portflow.get('sf_port_list', None) and int(portflow.get('group_count', None)) <= 1):
                for sf_port in portflow['sf_port_list']:                                          
                    policy_bridge.delete_flows(table = SERVICE_FUNCTION_INSTANCE_TABLE, \
                                               sf_port_id = int(sf_port.keys()[0]))
                    policy_bridge.delete_flows(table = SERVICE_FUNCTION_INSTANCE_TABLE, sf_port_id = \
                                               int(sf_port[sf_port.keys()[0]]['pair_sf_port_id']))
            if (not portflow.get('group_count', None) or int(portflow.get('group_count', None)) <= 1) and \
                (not portflow.get('himeself_count', None) or int(portflow.get('himeself_count', None))<=1):
                #and int(portflow.get('group_count', None)) != -1
                policy_bridge.delete_flows(table = SERVICE_FUNCTION_INSTANCE_TABLE, sf_port_id = \
                                           int(portflow['in_port_pair']['pair_in_port']))
                policy_bridge.delete_flows(table = SERVICE_FUNCTION_INSTANCE_TABLE, \
                                           sf_port_id = int(portflow['in_port']))
            
            ports_id_status_temp = []
            ports_id_status_temp.append(portflow['in_port_uuid'])
            ports_id_status_temp.append(portflow['chain_id'])
            ports_id_status_temp.append(sc_constants.STATUS_ACTIVE)
            ports_id_status.append(ports_id_status_temp) 
                
        except Exception as e:             
            ports_id_status_temp = []
            ports_id_status_temp.append(portflow['in_port_uuid'])
            ports_id_status_temp.append(portflow['chain_id'])
            ports_id_status_temp.append(sc_constants.STATUS_ERROR)
            ports_id_status.append(ports_id_status_temp)                      
            LOG.error(_("delete_port_flows failed, except by %s"), e) 


    #when restart the service_chain-agent(restart the ovs or reboot or restart evs_agent) we should 
    #delete all the service_chain flows and recovery the flows who still in db
    #if the port in port_flows we will recovery the port_flows and "prevent broadcast flows"
    #if the port in just in classifier we will recovery the "prevent broadcast flows"
    def add_ports_id_flow(self, ports_id, ovs_restarted):            
        try: 

            LOG.debug("add_port_id_flows received, ports_id=%s,ovs_restarted=%s,agent_restart=%s" \
                      %(ports_id,ovs_restarted,self.agent_restart)) 
            

            if self.agent_restart == True or ovs_restarted == True:  
                LOG.debug("add_ports_id_flow, servicechain-agent restart ")  
                self.integ_ebr.delete_flows(table = SERVICE_CHAIN_TABLE)
                self.integ_ebr.delete_flows(table = SERVICE_FUNCTION_INSTANCE_GROUP_TABLE)
                self.integ_ebr.delete_flows(table = SERVICE_FUNCTION_INSTANCE_TABLE)                              
                self.agent_restart = False            
                
            ports_id_status = []                           
            chain_id = 0                 
            for port_id in ports_id:  
                port_name = self.integ_ebr.get_port_name_by_id(port_id)  
                if not port_name:
                    LOG.debug("add_ports_id_flow restart continue, port_name= %s is not exsist" %(port_name))  
                    continue                      
                policy_bridge_name = evs_lib.get_bridge_for_iface(self.root_helper, port_name)        
                policy_bridge = evs_lib.EVSBridge(policy_bridge_name, self.root_helper)
                
                #even if the flow does not '0x0806' we will skip it
                port_name_tap = policy_bridge.get_port_ofport(port_name)
                port_name_patch_name = port_name.replace('tap','qvp')                     
                port_name_patch = policy_bridge.get_port_ofport(port_name_patch_name)
                                
                #here we got the mac_addr like: '"xx:xx:xx:xx"'
                port_mac = sc_ovs_lib.get_mac_by_port_name(self.root_helper, port_name)[1:-1]  
                                    
                policy_bridge.delete_flows(in_port = port_name_tap) 
                policy_bridge.delete_flows(in_port = port_name_patch, dl_dst=port_mac) 
                policy_bridge.delete_flows(in_port = port_name_patch, dl_dst='00:00:00:00:00:00/00:01:00:00:00:00')
                policy_bridge.delete_flows(in_port = port_name_patch, dl_dst='00:01:00:00:00:00/00:01:00:00:00:00')  
                policy_bridge.delete_flows(in_port = port_name_patch, dl_type='0x0806')  

                                                          
                port_all_chains_flows_list = None
                instance_classifier = None
                                               
                port_all_chains_flows_list = self.plugin_rpc.get_portflows_by_host_portid(self.context,
                                                               self.host, port_id, "port_flow")

                instance_classifier = self.plugin_rpc.get_instance_classifier_by_host_portid(self.context,
                                                               self.host, port_id)                                                        
                                                        
                if port_all_chains_flows_list or instance_classifier:                                            
               
                    if port_all_chains_flows_list:
                        for port_one_chain_flow in port_all_chains_flows_list:
                            self.treat_add_port_flow_opt(port_one_chain_flow, ports_id_status) 
                    
                    type = None

                    if instance_classifier:
                        if instance_classifier.keys()[0] == 'instance':
                            instance_type = instance_classifier.values()[0]['classification_type']
                            if instance_type == 'dl_src':
                                type = 'trans'
                            elif instance_type == '5tuple':
                                type = 'notrans'
                                
                            if port_id == instance_classifier.values()[0]['user_side_port']:
                                in_port = instance_classifier.values()[0]['user_side_sf_port_id']
                            elif port_id == instance_classifier.values()[0]['network_side_port']:
                                in_port = instance_classifier.values()[0]['network_side_sf_port_id']

                            sc_ovs_lib.set_sc_port_type(port_name, type,
                                                        int(in_port), self.root_helper) 
                            policy_bridge.add_sc_flow(priority=10000, in_port=port_name_patch, \
                                                      dl_dst=port_mac, actions="NORMAL")                                                                                                                      
                        elif instance_classifier.keys()[0] == 'classifiers':
                             
                            classifier_type = instance_classifier.values()[0]['classification_type']

                            if classifier_type == 'dl_src':
                                type = 'trans'
                            elif classifier_type == '5tuple':
                                type = 'notrans'
                                                                
                            ports_id = instance_classifier.values()[0]['list_ports']
                            
                            port = jsonutils.loads(ports_id)[port_id]
                            sc_ovs_lib.set_sc_port_type(port_name, type,
                                                            int(port), self.root_helper)  
                            policy_bridge.add_sc_flow(priority=10000, in_port=port_name_patch,  \
                                              dl_dst=port_mac, actions='resubmit(,1)')  
                            policy_bridge.add_sc_flow(table=1, priority=1, actions="NORMAL")                                  
                                                                   
                    if type == 'notrans':                   
                        policy_bridge.add_sc_flow(priority=10000, in_port=port_name_patch, \
                                                  dl_type='0x0806', actions="NORMAL")                   
                    policy_bridge.add_sc_flow(priority=9000, in_port=port_name_tap, actions="NORMAL")                                   
                    policy_bridge.add_sc_flow(priority=10, in_port=port_name_patch, \
                                              dl_dst="00:00:00:00:00:00/00:01:00:00:00:00",actions='drop')
                    policy_bridge.add_sc_flow(priority=10, in_port=port_name_patch, \
                                              dl_dst="00:01:00:00:00:00/00:01:00:00:00:00",actions='drop')
                                   
                    self.plugin_rpc.update_portflows_status(self.context,
                                                            self.host, chain_id, ports_id_status)   
                LOG.debug("restart, new port_id=%s,%s,%s,%s" %(port_id,policy_bridge,port_name_patch_name,port_name_patch))
                                                
        except Exception as e:                        
            LOG.error(_("add_port_id_flows failed, except by %s"), e) 
                                    
            
    def add_port_flows(self, context, **kwargs):   
    
        try:                 
            ports_id_status = []
            portflows = kwargs['port_flows']
            LOG.debug("add_port_flows received,  portflows= %s" %(portflows))             
        
            chain_id = 0
            
            if portflows:
                for portflow in portflows:
                    self.treat_add_port_flow_opt(portflow, ports_id_status)
    
            self.plugin_rpc.update_portflows_status(self.context,
                                                self.host,
                                                chain_id,
                                                ports_id_status)         
        except Exception as e:                  
            LOG.error(_("add_port_flows failed, except by %s"), e)           
            
                            
    def delete_ports_id_flow(self, ports_id):
        
        try:            
            LOG.debug("delete_port_id_flows received, ports_id= %s" %(ports_id))  
            ports_id_status = []
            
            chain_id = 0
            count = 0 
            if  ports_id:
                for port_id in ports_id:     
                    count = count + 1           
                    portflow = self.plugin_rpc.get_portflows_by_host_portid(self.context,
                                                                   self.host,
                                                                   port_id,
                                                                   sc_constants.STATUS_ACTIVE)
                    if portflow:
                        self.treat_delete_port_flow_opt(portflow, ports_id_status)

            self.plugin_rpc.update_portflows_status(self.context,
                                                self.host,
                                                chain_id,
                                                ports_id_status)                 
        except Exception as e:          
            LOG.error(_("delete_port_id_flows failed, except by %s"), e)  
                        
    def delete_port_flows(self, context, **kwargs):
     
        try:    
                   
            ports_id_status = []
            portflows = kwargs['port_flows']
            LOG.debug("delete_port_flows received,  portflows= %s" %(portflows))

            count = 0 
            chain_id = 0
            
            if portflows:
                for portflow in portflows:
                    count = count + 1  
                    self.treat_delete_port_flow_opt(portflow, ports_id_status)
    
            LOG.debug("delete_port_flows received, count= %s" %(count)) 
            self.plugin_rpc.update_portflows_status(self.context,
                                                self.host,
                                                chain_id,
                                                ports_id_status)                 
        except Exception as e:    
            LOG.error(_("delete_port_flows failed, except by %s"), e)  
                       

def create_agent_config_map(config):
    try:
        bridge_mappings = q_utils.parse_mappings(config.servicechain.bridge_mappings)
    except ValueError as e:
        raise ValueError(_("Parsing bridge_mappings failed: %s.") % e)

    kwargs = dict(
        integ_ebr="ebr-int",
        bridge_mappings=bridge_mappings,
        root_helper=config.AGENT.root_helper,
        polling_interval=config.AGENT.polling_interval,
        minimize_polling=config.AGENT.minimize_polling,
    )

    return kwargs


def main():

    
    cfg.CONF.register_opts(ip_lib.OPTS)
    common_config.init(sys.argv[1:])
    common_config.setup_logging()
    
           
    cfg.CONF.register_opts(ServiceChainAgent.OPTS,'servicechain')
    cfg.CONF.register_opts(ServiceChainAgent.agent_opts, "AGENT") 
    config.register_root_helper(cfg.CONF)   
    config.register_agent_state_opts_helper(cfg.CONF)

        
    
    
    cfg.CONF(project='neutron')

    try:
        agent_config = create_agent_config_map(cfg.CONF)
    except ValueError as e:
        LOG.error(_('%s ServiceChain-Agent terminated!'), e)
        sys.exit(1)

    plugin = ServiceChainAgent(**agent_config)
    signal.signal(signal.SIGTERM, plugin._handle_sigterm)

    # Start everything.
    LOG.info(_("ServiceChain-Agent initialized successfully, now running... "))
    plugin.daemon_loop()
    sys.exit(0)


if __name__ == "__main__":
    main()

