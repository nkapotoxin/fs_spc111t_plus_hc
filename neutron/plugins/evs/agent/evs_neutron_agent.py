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

import signal
import hashlib
import re
from neutron.agent.linux import utils
from neutron.openstack.common import jsonutils
from neutron.common import exceptions

from six import moves
from neutron.plugins.common import constants as p_const

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
from neutron.plugins.evs.common import config  # nova


from neutron.common import rpc as n_rpc
from neutron.agent.linux import interface
from neutron.agent.linux import external_process
from neutron.common import config as common_config
from neutron.plugins.openvswitch.common import constants


LOG = logging.getLogger(__name__)

# A placeholder for dead vlans.
DEAD_VLAN_TAG = str(q_const.MAX_VLAN_TAG + 1)
Agent_Start_Report_Retry_Interval = 2



EVS_FLOW_TABLE = 1

DPDK_TYPE = "dpdk"

class DeviceListRetrievalError(exceptions.NeutronException):
    message = _("Unable to retrieve port details for devices: %(devices)s "
                "because of error: %(error)s")

class Port(object):
    """Represents a neutron port.

    Class stores port data in a ORM-free way, so attributres are
    still available even if a row has been deleted.
    """

    def __init__(self, p):
        self.id = p.id
        self.network_id = p.network_id
        self.device_id = p.device_id
        self.admin_state_up = p.admin_state_up
        self.status = p.status

    def __eq__(self, other):
        '''Compare only fields that will cause us to re-wire.'''
        try:
            return (self and other
                    and self.id == other.id
                    and self.admin_state_up == other.admin_state_up)
        except Exception:
            return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(self.id)

class LocalVLANMapping:
    def __init__(self, vlan, network_type, physical_network, segmentation_id,
                 vif_ports=None):
        if vif_ports is None:
            vif_ports = {}
        self.vlan = vlan
        self.network_type = network_type
        self.physical_network = physical_network
        self.segmentation_id = segmentation_id
        self.vif_ports = vif_ports


    def __str__(self):
        return ("lv-id = %s type = %s phys-net = %s phys-id = %s" %
                (self.vlan, self.network_type, self.physical_network,
                 self.segmentation_id))

class EVSPluginApi(agent_rpc.PluginApi):
    pass

class VLANPolicyBridge(evs_lib.EVSBridge):
    """Extends EVSBridge for Trunkport."""
    def configure(self, name, root_helper, integ_ebr):
        self.name = name
        self.root_helper = root_helper
        self.integ_ebr = integ_ebr

        self.vlan_port_name = q_const.QVP_PATCH_PORT_PREFIX + name[3:]
        self.integ_ebr_port_name = q_const.QVE_PATCH_PORT_PREFIX + name[3:]

        self.create(DPDK_TYPE)

        ports = self.get_port_name_list()

        if self.vlan_port_name not in ports:
            self.add_patch_port(
                self.vlan_port_name, self.integ_ebr_port_name)

        self.vlan_ofport = self.get_port_ofport(self.vlan_port_name)

        ports = self.integ_ebr.get_port_name_list()

        if self.integ_ebr_port_name not in ports:
            self.integ_ebr.add_patch_port(
                self.integ_ebr_port_name, self.vlan_port_name)

        self.integ_ebr_ofport = self.get_port_ofport(
            self.integ_ebr_port_name)

        cur_vlan_flows = self._get_flows(self, self.vlan_ofport)
        for (integ_ebr_vid, record_vid)  in cur_vlan_flows:
            self.delete_flows(
                          in_port=self.vlan_ofport,
                          dl_vlan=integ_ebr_vid
                          )
            self.delete_flows(table=EVS_FLOW_TABLE,
                          in_port=self.vlan_ofport,
                          dl_vlan=integ_ebr_vid
                          )
        
        self.add_flow(priority=2,
                      in_port=self.vlan_ofport,
                      actions="drop")
        self.add_flow(table=EVS_FLOW_TABLE,
                      priority=2,
                      in_port=self.vlan_ofport,
                      actions="drop")
        
        self.integ_ebr.delete_flows(in_port=self.integ_ebr_ofport)
        self.integ_ebr.add_flow(priority=2,
                             in_port=self.integ_ebr_ofport,
                             actions="drop")

    def cleanup_bridge(self):
        LOG.debug(_("Cleanup bridge %s"), self.integ_ebr_ofport)
        self.integ_ebr.delete_port(self.integ_ebr_port_name)
        self.integ_ebr.delete_flows(in_port=self.integ_ebr_ofport)

    def _get_flows(self, br, of_port):
        flow_list = br.run_ofctl("dump-flows", []).split("\n")[1:]

        p1 = re.compile('in_port=(\d+),dl_vlan=(\d+).*mod_vlan_vid:(\d+)')
        p2 = re.compile('in_port=(\d+),dl_vlan=(\d+).*strip_vlan')

        f = set()
        for l in flow_list:
            m = p1.search(l)
            if m:
                in_port = m.group(1)
                f_vid = int(m.group(2))
                t_vid = int(m.group(3))
                if(in_port == of_port):
                    f.add((f_vid, t_vid))
            m = p2.search(l)
            if m:
                in_port = m.group(1)
                f_vid = int(m.group(2))
                t_vid = "Untagged"
                if(in_port == of_port):
                    f.add((f_vid, t_vid))

        return f

    def init_flow_check(self):
        self.current_flows = self._get_flows(self,
                                             self.vlan_ofport)
        self.new_flows = set()

    def init_integ_ebr_flow_check(self):
        self.current_integ_ebr_flows = self._get_flows(self.integ_ebr,
                                                    self.integ_ebr_ofport)

        self.new_integ_ebr_flows = set()
    
    def _set_mapping(self, vm_flow_vid, integ_ebr_vid, record_vid, action):
        self.new_integ_ebr_flows.add((record_vid, integ_ebr_vid))
        if (record_vid, integ_ebr_vid) not in self.current_integ_ebr_flows:
            self.integ_ebr.add_flow(
                priority=3, in_port=self.integ_ebr_ofport,
                dl_vlan=vm_flow_vid,
                actions="mod_vlan_vid:%s,normal" % integ_ebr_vid)
        else:
            LOG.debug(_("Flow already in place: %s"), (record_vid, integ_ebr_vid))

        self.new_flows.add((integ_ebr_vid, record_vid))
        if (integ_ebr_vid, record_vid) not in self.current_flows:
            self.add_flow(priority=3,
                          in_port=self.vlan_ofport,
                          dl_vlan=integ_ebr_vid,
                          actions=action)
            self.add_flow(table=EVS_FLOW_TABLE,
                          priority=3,
                          in_port=self.vlan_ofport,
                          dl_vlan=integ_ebr_vid,
                          actions=action)
        else:
            LOG.debug(_("Flow already in place: %s"), (integ_ebr_vid, record_vid))

    def set_mapping(self, vm_vid, integ_ebr_vid):
        if vm_vid is None:
            self._set_mapping(0xffff, integ_ebr_vid, "Untagged",
                              "strip_vlan,normal")
        else:
            self._set_mapping(vm_vid, integ_ebr_vid, vm_vid,
                              "mod_vlan_vid:%s,normal" % vm_vid)

    def remove_flows(self, vid, local_vlan):
        self.integ_ebr.delete_flows(in_port=self.integ_ebr_ofport,
                                 dl_vlan=vid)

        self.delete_flows(in_port=self.vlan_ofport,
                      dl_vlan=local_vlan)

    def remove_extra_flows(self):
        remove = self.current_flows - self.new_flows
        integ_ebr_remove = self.current_integ_ebr_flows - self.new_integ_ebr_flows
        for f in remove:
            if f[0] == 'Untagged':
                pass
            else:
                self.delete_flows(in_port=self.vlan_ofport,
                                  dl_vlan=f[0])
        for f in integ_ebr_remove:
            if f[0] == 'Untagged':
                pass
            else:
                self.integ_ebr.delete_flows(in_port=self.integ_ebr_ofport,
                                         dl_vlan=f[0])

    def set_trunk(self, integ_ebr_vid):
        self.integ_ebr.add_flow(
            priority=3, in_port=self.integ_ebr_ofport,
            actions="push_vlan:0x8100,mod_vlan_vid:%s,normal" % integ_ebr_vid)
        self.add_flow(priority=3,
                      in_port=self.vlan_ofport,
                      dl_vlan=integ_ebr_vid,
                      actions="strip_vlan,normal")
        self.add_flow(table=EVS_FLOW_TABLE,
                      priority=3,
                      in_port=self.vlan_ofport,
                      dl_vlan=integ_ebr_vid,
                      actions="strip_vlan,normal")


class EVSNeutronAgent(n_rpc.RpcCallback):
    '''Implements EVS-based  VLANs  networks.
    '''

    # history
    #   1.0 Initial version
    #   1.1 Support Security Group RPC
    #   1.2 user space EVS
    #   1.3 vlantrunk
    
    RPC_API_VERSION = '1.3'

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
        super(EVSNeutronAgent, self).__init__()
        self.root_helper = root_helper
        self.available_local_vlans = set(moves.xrange(q_const.MIN_VLAN_TAG,
                                                      q_const.MAX_VLAN_TAG))
        self.run_daemon_loop = True
        self.use_call = True        

        self.agent_state = {
            'binary': 'neutron-evs-agent',
            'host': cfg.CONF.host,
            'topic': q_const.AGENT_TYPE_EVS,
            'configurations': {'bridge_mappings': bridge_mappings},
            'agent_type': q_const.AGENT_TYPE_EVS,
            'start_flag': True}

        # Keep track of integ_ebr's device count for use by _report_state()
        self.integ_ebr_device_count = 0

        self.setup_rpc()
        #set local vlan map  
        self.local_vlan_map = {}                
        #setup integration bridge ebr-int   
        self.integ_ebr = evs_lib.EVSBridge(integ_ebr, self.root_helper)
        self.integ_ebr_name = integ_ebr
        self.is_hugemem_configured = False 
        
        #ebr-int exists if bridge_mappings is configured
        if bridge_mappings:
            self.setup_integration_ebr()
        self.bridge_mappings = bridge_mappings
    
        self.updated_ports = set()
        
        #add for vlan trunk
        self.trunk_backlog = list()
        self.trunk_subports = dict()
        
        #all brpcy_bridges
        self.brpcy_bridges = {}
        
        #setup physical bridge which create by cps
        if self.bridge_mappings and self.is_hugemem_configured:
            self.setup_physical_bridges(bridge_mappings)

        self.polling_interval = polling_interval
        self.iter_num = 0
        self.ovsdb_monitor_respawn_interval = ovsdb_monitor_respawn_interval
        self.minimize_polling = minimize_polling


    def _report_state(self):
        # How many devices are likely used
        self.agent_state.get('configurations')['devices'] = (
            self.integ_ebr_device_count)
        try:
            self.state_rpc.report_state(self.context,
                                        self.agent_state,
                                        self.use_call)
            self.agent_state.pop('start_flag', None)
            self.use_call = False
        except Exception:
            LOG.exception(_("Failed reporting state!"))

    def setup_rpc(self):
        self.agent_id = 'evs_agent_%s' % platform.node()
        self.topic = topics.AGENT
        self.plugin_rpc = EVSPluginApi(topics.PLUGIN)
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.PLUGIN)

        # RPC network init
        self.context = context.get_admin_context_without_session()
        # Handle updates from service
        self.dispatcher = [self]
        # Define the listening consumers for the agent
        consumers = [[topics.PORT, topics.UPDATE],
                     [topics.NETWORK, topics.DELETE],
                     [topics.TRUNKPORT, topics.UPDATE]]

        
        self.connection = agent_rpc.create_consumers(self.dispatcher,
                                                     self.topic,
                                                     consumers)
        report_interval = cfg.CONF.AGENT.report_interval
        if report_interval:
            heartbeat = loopingcall.FixedIntervalLoopingCall(
                self._report_state)
            heartbeat.start(interval=report_interval)

    def get_net_uuid(self, vif_id):
        for network_id, vlan_mapping in self.local_vlan_map.iteritems():
            if vif_id in vlan_mapping.vif_ports:
                return network_id

    def trunkports_updated(self, context, **kwargs):
        for port in kwargs['trunkport_ids']:
            self.updated_ports.add(port)

    def network_delete(self, context, **kwargs):
        #The network may not be defined on this agent
        LOG.debug(_("network_delete received"))
        network_id = kwargs.get('network_id')
        lvm = self.local_vlan_map.get(network_id)
        if lvm:
            self.reclaim_local_vlan(network_id)
        else:
            LOG.debug(_("Network %s not used on agent."), network_id)
        LOG.debug(_("Delete %s"), network_id)
        

    def port_update(self, context, **kwargs):
        port = kwargs.get('port')
        # Put the port identifier in the updated_ports set.
        # Even if full port details might be provided to this call,
        # they are not used since there is no guarantee the notifications
        # are processed in the same order as the relevant API requests
        self.updated_ports.add(port['id'])


    def provision_local_vlan(self, net_uuid, network_type, physical_network,
                             segmentation_id):
        '''Provisions a local VLAN.

        :param net_uuid: the uuid of the network associated with this vlan.
        :param network_type: the network type ( 'vlan', 'flat', 'local')
        :param physical_network: the physical network for 'vlan' or 'flat'
        :param segmentation_id: the VID for 'vlan' 
        '''

        # On a restart or crash of OVS, the network associated with this VLAN
        # will already be assigned, so check for that here before assigning a
        # new one.
        bridges = set()
        lvm = self.local_vlan_map.get(net_uuid)
        if lvm:
            lvid = lvm.vlan
        else:
            if not self.available_local_vlans:
                LOG.error(_("No local VLAN available for net-id=%s"), net_uuid)
                return
            lvid = self.available_local_vlans.pop()
            self.local_vlan_map[net_uuid] = LocalVLANMapping(lvid,
                                                             network_type,
                                                             physical_network,
                                                             segmentation_id)
        LOG.info(_("Assigning %(vlan_id)s as local vlan for "
                   "net-id=%(net_uuid)s"),
                 {'vlan_id': lvid, 'net_uuid': net_uuid})

        if network_type == p_const.TYPE_FLAT:
            if physical_network in self.phys_brs:
                # outbound
                br = self.phys_brs[physical_network]
                bridges.add(br)
                br.add_flow(priority=4,
                            in_port=self.phys_ofports[physical_network],
                            dl_vlan=lvid,
                            actions="strip_vlan,normal")
                # inbound
                self.integ_ebr.add_flow(
                    priority=3,
                    in_port=self.int_ofports[physical_network],
                    dl_vlan=0xffff,
                    actions="mod_vlan_vid:%s,normal" % lvid)
            else:
                LOG.error(_("Cannot provision flat network for "
                            "net-id=%(net_uuid)s - no bridge for "
                            "physical_network %(physical_network)s"),
                          {'net_uuid': net_uuid,
                           'physical_network': physical_network})
        elif network_type == p_const.TYPE_VLAN:
            if physical_network in self.phys_brs:
                # outbound
                br = self.phys_brs[physical_network]
                br.add_flow(priority=4,
                            in_port=self.phys_ofports[physical_network],
                            dl_vlan=lvid,
                            actions="mod_vlan_vid:%s,normal" % segmentation_id)
                # inbound
                self.integ_ebr.add_flow(priority=3,
                                     in_port=self.
                                     int_ofports[physical_network],
                                     dl_vlan=segmentation_id,
                                     actions="mod_vlan_vid:%s,normal" % lvid)
            else:
                LOG.error(_("Cannot provision VLAN network for "
                            "net-id=%(net_uuid)s - no bridge for "
                            "physical_network %(physical_network)s"),
                          {'net_uuid': net_uuid,
                           'physical_network': physical_network})
        elif network_type == p_const.TYPE_LOCAL:
            # no flows needed for local networks
            pass
        else:
            LOG.error(_("Cannot provision unknown network type "
                        "%(network_type)s for net-id=%(net_uuid)s"),
                      {'network_type': network_type,
                       'net_uuid': net_uuid})
        return bridges

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

        if lvm.network_type == p_const.TYPE_FLAT:
            if lvm.physical_network in self.phys_brs:
                # outbound
                br = self.phys_brs[lvm.physical_network]
                br.delete_flows(in_port=self.phys_ofports[lvm.physical_network],
                                dl_vlan=lvm.vlan)
                # inbound
                self.integ_ebr.delete_flows(in_port=self.int_ofports[lvm.
                                                                     physical_network],
                                dl_vlan=0xffff)
        elif lvm.network_type == p_const.TYPE_VLAN:
            if lvm.physical_network in self.phys_brs:
                # outbound
                br = self.phys_brs[lvm.physical_network]
                br.delete_flows(in_port=self.phys_ofports[lvm.
                                                          physical_network],
                                dl_vlan=lvm.vlan)
                # inbound
                self.integ_ebr.delete_flows(in_port=self.int_ofports[lvm.physical_network],
                                dl_vlan=lvm.segmentation_id)
        elif lvm.network_type == p_const.TYPE_LOCAL:
            # no flows needed for local networks
            pass
        else:
            LOG.error(_("Cannot reclaim unknown network type "
                        "%(network_type)s for net-id=%(net_uuid)s"),
                      {'network_type': lvm.network_type,
                       'net_uuid': net_uuid})

        self.available_local_vlans.add(lvm.vlan)


    def port_unbound(self, vif_id, net_uuid = None):
        '''Unbind port.

        Removes corresponding local vlan mapping object if this is its last
        VIF.

        :param vif_id: the id of the vif
        :param net_uuid: the net_uuid this port is associated with.
        '''
        if net_uuid is None:
            net_uuid = self.get_net_uuid(vif_id)

        if not self.local_vlan_map.get(net_uuid):
            LOG.info(_('port_unbound(): net_uuid %s not in local_vlan_map'),
                     net_uuid)
            return

        lvm = self.local_vlan_map[net_uuid]

        lvm.vif_ports.pop(vif_id, None)

        if not lvm.vif_ports:
            self.reclaim_local_vlan(net_uuid)

    def port_bound_qep_br(self, port, net_uuid,
                   network_type, physical_network,
                   segmentation_id, fixed_ips, device_owner,
                   ovs_restarted, port_to_brpcy_name):
        '''Bind port to net_uuid/lsw_id and install flow for inbound traffic
        to vm.
        
        :param port: a evslib.VifPort object.
        :param net_uuid: the net_uuid this port is to be associated with.
        :param network_type: the network type ('gre', 'vlan', 'flat', 'local')
        :param physical_network: the physical network for 'vlan' or 'flat'
        :param segmentation_id: the VID for 'vlan' or tunnel ID for 'tunnel'
        :param fixed_ips: the ip addresses assigned to this port
        :param device_owner: the string indicative of owner of this port
        :param ovs_restarted: indicates if this is called for an OVS restart.
        :param port_to_brpcy_name: indicates qep bridge
        '''
        if net_uuid not in self.local_vlan_map or ovs_restarted:
            self.provision_local_vlan(net_uuid, network_type,
                                      physical_network, segmentation_id)
        lvm = self.local_vlan_map[net_uuid]
        lvm.vif_ports[port.vif_id] = port
        
        # Do not bind a port if it's already bound
        qep_br = self.brpcy_bridges.get(port_to_brpcy_name)
        if qep_br and ip_lib.device_exists(port_to_brpcy_name, self.root_helper):
            cur_tag = qep_br.db_get_val("Port", port.port_name, "tag")                
            if cur_tag != str(lvm.vlan):
                qep_br.set_db_attribute("Port", port.port_name, "tag",
                                             str(lvm.vlan))
                if port.ofport != -1:
                    qep_br.delete_flows(in_port=port.ofport)
        else:
            LOG.error(_("qep_br %s doesn't exist " % port_to_brpcy_name))

    def port_bound(self, port, net_uuid,
                   network_type, physical_network,
                   segmentation_id, fixed_ips, device_owner,
                   ovs_restarted):
        '''Bind port to net_uuid/lsw_id and install flow for inbound traffic
        to vm.
        
        :param port: a evslib.VifPort object.
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
                                      physical_network, segmentation_id)
        lvm = self.local_vlan_map[net_uuid]
        lvm.vif_ports[port.vif_id] = port
        
        # Do not bind a port if it's already bound
        cur_tag = self.integ_ebr.db_get_val("Port", port.port_name, "tag")                
        if cur_tag != str(lvm.vlan):
            self.integ_ebr.set_db_attribute("Port", port.port_name, "tag",
                                         str(lvm.vlan))
            if port.ofport != -1:
                self.integ_ebr.delete_flows(in_port=port.ofport)

    def port_dead_qep_br(self, port, port_to_brpcy_name):
        '''Once a port has no binding, put it on the "dead vlan".

        :param port: a evs_lib.VifPort object.
        '''
        # Don't kill a port if it's already dead
        qep_br = self.brpcy_bridges.get(port_to_brpcy_name)
        if qep_br and ip_lib.device_exists(port_to_brpcy_name, self.root_helper):        
            cur_tag = qep_br.db_get_val("Port", port.port_name, "tag")
            if cur_tag != DEAD_VLAN_TAG:
                qep_br.set_db_attribute("Port", port.port_name, "tag",
                                             DEAD_VLAN_TAG)
                qep_br.add_flow(priority=2, in_port=port.ofport,
                                 actions="drop")
        else:
            LOG.error(_("qep_br %s doesn't exist " % port_to_brpcy_name)) 

    def port_dead(self, port):
        '''Once a port has no binding, put it on the "dead vlan".

        :param port: a evs_lib.VifPort object.
        '''
        # Don't kill a port if it's already dead
        cur_tag = self.integ_ebr.db_get_val("Port", port.port_name, "tag")
        if cur_tag != DEAD_VLAN_TAG:
            self.integ_ebr.set_db_attribute("Port", port.port_name, "tag",
                                         DEAD_VLAN_TAG)
            self.integ_ebr.add_flow(priority=2, in_port=port.ofport,
                                 actions="drop")

    def setup_integration_ebr(self):
        '''Setup the integration bridge.

        Create integration ebr-int and remove all existing flows.

        :returns: None
        '''
        # Ensure the integration bridge is created.
        # ovs_lib.OVSBridge.create() will run
        # ovs-vsctl -- --may-exist add-br BRIDGE_NAME
        # which does nothing if bridge already exists.
        self.integ_ebr.create(DPDK_TYPE)
        
        #check hugemem is configured or not
        if not ip_lib.device_exists(self.integ_ebr_name, self.root_helper):
                LOG.error(_("Bridge %(bridge)s does not exist "
                            " because of hugemem is not configured!"),
                          {'bridge': self.integ_ebr_name})                
                self.is_hugemem_configured = False
                return
        cur_tag = self.integ_ebr.db_get_val("Port", self.integ_ebr_name, "tag")
        if cur_tag != "4095":
            self.integ_ebr.set_db_attribute("Port", self.integ_ebr_name, "tag", "4095")

        self.is_hugemem_configured = True

        self.integ_ebr.set_secure_mode()
        self.integ_ebr.remove_all_flows()
        self.integ_ebr.add_flow(priority=1, actions="normal")
        # Add a canary flow to integ_ebr to track OVS restarts
        self.integ_ebr.add_flow(table=q_const.CANARY_TABLE, priority=0,
                             actions="drop")

    def setup_brpcy_bridge(self, brpcy_bridge_name):
        '''Setup the brpcy bridge.

        Create brpcy bridge and remove all existing flows.

        :param bridge_name: the name of the brpcy bridge.
        :returns: None
        '''
        brpcy_bridge = self.brpcy_bridges[brpcy_bridge_name]
        brpcy_bridge.create(DPDK_TYPE)
        brpcy_bridge.add_flow(priority=1, actions="normal")

    def get_peer_name(self, prefix, name):
        """Construct a peer name based on the prefix and name.

        The peer name can not exceed the maximum length allowed for a linux
        device. Longer names are hashed to help ensure uniqueness.
        """
        if len(prefix + name) <= q_const.DEVICE_NAME_MAX_LEN:
            return prefix + name
        # We can't just truncate because bridges may be distinguished
        # by an ident at the end. A hash over the name should be unique.
        # Leave part of the bridge name on for easier identification
        hashlen = 6
        namelen = q_const.DEVICE_NAME_MAX_LEN - len(prefix) - hashlen
        new_name = ('%(prefix)s%(truncated)s%(hash)s' %
                    {'prefix': prefix, 'truncated': name[0:namelen],
                     'hash': hashlib.sha256(name).hexdigest()[0:hashlen]})
        LOG.warning(_("Creating an interface named %(name)s exceeds the "
                      "%(limit)d character limitation. It was shortened to "
                      "%(new_name)s to fit."),
                    {'name': name, 'limit': q_const.DEVICE_NAME_MAX_LEN,
                     'new_name': new_name})
        return new_name

    def setup_physical_bridges(self, bridge_mappings):
        '''Setup the physical network bridges.

        Creates physical network bridges and links them to the patch port

        :param bridge_mappings: map physical network names to bridge names.
        '''
        self.phys_brs = {}
        self.int_ofports = {}
        self.phys_ofports = {}
   
        for physical_network, bridge in bridge_mappings.iteritems():
            LOG.info(_("Mapping physical network %(physical_network)s to "
                       "bridge %(bridge)s"),
                     {'physical_network': physical_network,
                      'bridge': bridge})
            # setup physical bridge
            if not ip_lib.device_exists(bridge, self.root_helper):
                LOG.error(_("Bridge %(bridge)s for physical network "
                            "%(physical_network)s does not exist. "),
                          {'physical_network': physical_network,
                           'bridge': bridge})
                return

            br = evs_lib.EVSBridge(bridge, self.root_helper)
            br.remove_all_flows()
            br.add_flow(priority=1, actions="NORMAL")
            self.phys_brs[physical_network] = br
            
            # interconnect physical and integration bridges using patchs
            int_if_name = self.get_peer_name(q_const.PEER_INTEGRATION_PREFIX,
                                             bridge)
            phys_if_name = self.get_peer_name(q_const.PEER_PHYSICAL_PREFIX,
                                              bridge)

            self.integ_ebr.delete_port(int_if_name)
            br.delete_port(phys_if_name)

            # Create patch ports without associating them in order to block
            # untranslated traffic before association
            int_ofport = self.integ_ebr.add_patch_port(
                int_if_name, q_const.NONEXISTENT_PEER)
            phys_ofport = br.add_patch_port(
                phys_if_name, q_const.NONEXISTENT_PEER)

            self.int_ofports[physical_network] = int_ofport
            self.phys_ofports[physical_network] = phys_ofport

            # block all untranslated traffic between bridges
            self.integ_ebr.add_flow(priority=2, in_port = int_ofport,
                                 actions="drop")
            br.add_flow(priority=2, in_port=phys_ofport, 
                        actions="drop")

            # associate patch ports to pass traffic
            self.integ_ebr.set_db_attribute('Interface', int_if_name,
                                         'options:peer', phys_if_name)
            br.set_db_attribute('Interface', phys_if_name,
                                'options:peer', int_if_name)

    def treat_vif_port_qep_br(self, vif_port, port_id, network_id, network_type,
                       physical_network, segmentation_id, admin_state_up,
                       fixed_ips, device_owner, ovs_restarted, port_to_brpcy_name):
        # When this function is called for a port, the port should have
        # an OVS ofport configured, as only these ports were considered
        # for being treated. If that does not happen, it is a potential
        # error condition of which operators should be aware
        if not vif_port.ofport:
            LOG.warn(_("VIF port: %s has no ofport configured, and might not "
                       "be able to transmit"), vif_port.vif_id)

        if vif_port:
            if admin_state_up:
                self.port_bound_qep_br(vif_port, network_id, network_type,
                                physical_network, segmentation_id,
                                fixed_ips, device_owner, ovs_restarted,
                                port_to_brpcy_name)
            else:
                self.port_dead_qep_br(vif_port, port_to_brpcy_name)
        else:
            LOG.debug(_("No VIF port for port %s defined on agent."), port_id)

    def update_trunk_subports(self, reg_trunk_subports,
                              cur_trunk_subports):
        reg_subports = set(reg_trunk_subports.keys())
        cur_subports = set(cur_trunk_subports.keys())

        added = cur_subports - reg_subports
        removed = reg_subports - cur_subports

        port_info = {}
        if added:
            port_info['added'] = {}
            for port in added:
                port_info['added'][port] = cur_trunk_subports[port]

        if removed:
            port_info['removed'] = {}
            for port in removed:
                port_info['removed'][port] = reg_trunk_subports[port]

        return port_info

    def treat_trunk_port(self, port, details, vlan_policy_bridge, ovs_restarted):
        '''Treat trunk type port.
        If trunk port is newly added, first set port trunk mode, and then
        put its subports info trunk_backlog for later.
        If trunk port is updated, just compute added or removed subports
        '''
        
        vlan_policy_bridge.init_flow_check()
        vlan_policy_bridge.init_integ_ebr_flow_check()

        current_subports = details['trunk_networks']
        if port.vif_id not in self.trunk_subports:
            net_uuid = details['network_id']
            network_type = details['network_type']
            physical_network = details['physical_network']
            segmentation_id = details['segmentation_id']

            if net_uuid not in self.local_vlan_map or ovs_restarted:
                self.provision_local_vlan(net_uuid, network_type,
                                      physical_network, segmentation_id)
            lvm = self.local_vlan_map[net_uuid]
            lvm.vif_ports[port.vif_id] = port

            vlan_policy_bridge.set_mapping(None, lvm.vlan)
            
            vlan_policy_bridge.set_db_attribute("Port", port.port_name,
                                                "vlan_mode",
                                                'trunk')
        port_info = self.update_trunk_subports(
                                        self.trunk_subports.get(port.vif_id, {}),
                                        current_subports)
        self.trunk_subports[port.vif_id] = current_subports
        if port_info:
            port_info['port_id'] = port.vif_id
            port_info['br'] = vlan_policy_bridge
            port_info['ovs_restarted'] = ovs_restarted
            self.trunk_backlog.append(port_info)

    def treat_trunk_subports_added(self, trunk_subports, vlan_bridge, ovs_restarted):
        c = 0
        start = time.time()
        while trunk_subports and c != 20 :
            subport_id = trunk_subports.keys()[0]
            ext_net = trunk_subports.pop(subport_id)
            net_uuid = ext_net['net_id']

            if net_uuid not in self.local_vlan_map or ovs_restarted:
                self.provision_local_vlan(net_uuid,
                                          ext_net['network_type'],
                                          ext_net['physical_network'],
                                          ext_net['segmentation_id'])

            lvm = self.local_vlan_map[net_uuid]
            lvm.vif_ports[subport_id] = evs_lib.VifPort('',-1,
                                                subport_id,'',vlan_bridge.name)

            if ip_lib.device_exists(vlan_bridge.name, self.root_helper):
                vlan_bridge.set_mapping(ext_net['vid'], lvm.vlan)

            c += 1

        LOG.debug(_("treat_trunk_subports_added - iteration: %(iter_num)d"
                    "%(num_current)d devices currently available. "
                    "Time elapsed: %(elapsed).3f"),
                  {'iter_num': self.iter_num,
                   'num_current': c,
                   'elapsed': time.time() - start})
            

    def treat_trunk_subports_removed(self, trunk_subports, vlan_bridge):
        c = 0
        start = time.time()

        while trunk_subports and c != 20 :
            subport_id = trunk_subports.keys()[0]
            ext_net = trunk_subports.pop(subport_id)
            net_uuid = ext_net['net_id']
            #delete flows
            if not self.local_vlan_map.get(net_uuid):
                LOG.error(_('delete subport_flows failed. Net_uuid %s'
                            ' not in local_vlan_map'),
                         net_uuid)
                continue

            lvm = self.local_vlan_map[net_uuid]
            if ip_lib.device_exists(vlan_bridge.name, self.root_helper):
                vlan_bridge.remove_flows(ext_net['vid'], lvm.vlan)
            #reclaim local vlan
            self.port_unbound(subport_id, net_uuid)
            

            c += 1

        LOG.debug(_("treat_trunk_subports_removed - iteration: %(iter_num)d"
                    "%(num_current)d devices currently available. "
                    "Time elapsed: %(elapsed).3f"),
                  {'iter_num': self.iter_num,
                   'num_current': c,
                   'elapsed': time.time() - start})

             
    def trunk_work(self):
        port_info = self.trunk_backlog[0]
        vlan_bridge = port_info['br']
        #vswitchd restart
        ovs_restarted = port_info.get('ovs_restarted', False)
        
        if port_info.get('added'):
            self.treat_trunk_subports_added(port_info['added'], vlan_bridge,
                                            ovs_restarted)

        if port_info.get('removed'):
            self.treat_trunk_subports_removed(port_info['removed'], vlan_bridge)

        if not port_info.get('added') and not port_info.get('removed'):
            self.trunk_backlog.pop(0)
 
    def treat_vif_port(self, vif_port, port_id, network_id, network_type,
                       physical_network, segmentation_id, admin_state_up,
                       fixed_ips, device_owner, ovs_restarted):
        # When this function is called for a port, the port should have
        # an OVS ofport configured, as only these ports were considered
        # for being treated. If that does not happen, it is a potential
        # error condition of which operators should be aware
        if not vif_port.ofport:
            LOG.warn(_("VIF port: %s has no ofport configured, and might not "
                       "be able to transmit"), vif_port.vif_id)

        if vif_port:
            if admin_state_up:
                self.port_bound(vif_port, network_id, network_type,
                                physical_network, segmentation_id,
                                fixed_ips, device_owner, ovs_restarted)
            else:
                self.port_dead(vif_port)
        else:
            LOG.debug(_("No VIF port for port %s defined on agent."), port_id)



    def check_changed_vlans(self, registered_ports):
        """Return ports which have lost their vlan tag.

        The returned value is a set of port ids of the ports concerned by a
        vlan tag loss.
        """
        port_tags = self.integ_ebr.get_port_tag_dict()
        for reg_port in registered_ports:
            port_to_brpcy_name = q_const.QEP_VSWITCH_PREFIX + reg_port[:11]
            if self.brpcy_bridges.get(port_to_brpcy_name) and ip_lib.device_exists(port_to_brpcy_name, self.root_helper):
                qep_port_tags = self.brpcy_bridges[port_to_brpcy_name].get_port_tag_dict()
                port_tags.update(qep_port_tags)

        changed_ports = set()
        for lvm in self.local_vlan_map.values():
            for port in registered_ports:
                if (
                    port in lvm.vif_ports
                    and lvm.vif_ports[port].port_name in port_tags
                    and port_tags[lvm.vif_ports[port].port_name] != lvm.vlan
                    ):
                    LOG.info(
                        _("Port '%(port_name)s' has lost "
                            "its vlan tag '%(vlan_tag)d'!"),
                        {'port_name': lvm.vif_ports[port].port_name,
                         'vlan_tag': lvm.vlan}
                    )
                    changed_ports.add(port)
        return changed_ports

    def scan_ports(self, registered_ports, updated_ports = None):
        cur_ports = self.integ_ebr.get_vif_port_set(q_const.QEP_VSWITCH_PREFIX)
        self.integ_ebr_device_count = len(cur_ports)
        port_info = {'current': cur_ports}
        # FIXME(salv-orlando): It's not really necessary to return early
        # if nothing has changed.
        if updated_ports is None:
            updated_ports = set()
        
        updated_ports.update(self.check_changed_vlans(registered_ports))
        if updated_ports:
            # Some updated ports might have been removed in the
            # meanwhile, and therefore should not be processed.
            # In this case the updated port won't be found among
            # current ports.
            updated_ports &= cur_ports
            if updated_ports:
                port_info['updated'] = updated_ports        
        if cur_ports == registered_ports:
            # No added or removed ports to set, just return here
            return port_info

        port_info['added'] = cur_ports - registered_ports
        # Remove all the known ports not found on the integration bridge
        port_info['removed'] = registered_ports - cur_ports
        return port_info


    def _port_info_has_changes(self, port_info):
        return (port_info.get('added') or
                port_info.get('removed') or
                port_info.get('updated'))

    def treat_devices_added_updated(self, devices, ovs_restarted):
        """
        Devices contain tapXXXXXXXXX-XX which is plugged in EVS vSwitch 
            :qepXXXXXXXXX-XX
            :ebr-int
        """
        resync = False
        skipped_devices = []
        try:
            devices_details_list = self.plugin_rpc.get_devices_details_list(
                self.context,
                devices,
                self.agent_id,
                cfg.CONF.host)
        except Exception as e:
                LOG.debug(_("Unable to get port details for "
                            "%(device)s: %(e)s"),
                          {'devices': devices, 'e': e})                
                resync = True
        for details in devices_details_list:
            device = details['device']
            LOG.debug("Processing port: %s", device)
            port = self.integ_ebr.get_vif_port_by_id(device, q_const.QEP_VSWITCH_PREFIX)
       
            if not port:
                # The port disappeared and cannot be processed
                LOG.info(_("Port %s was not found on the integration bridge or brpcy bridge"
                           "and will therefore not be processed"), device)
                skipped_devices.append(device)
                continue

            if 'port_id' in details:
                LOG.info(_("Port %(device)s updated. Details: %(details)s"),
                         {'device': device, 'details': details})
                
                #get brpcy_name of device[len(q_const.QEP_VSWITCH_PREFIX):] 
                port_to_brpcy_name = q_const.QEP_VSWITCH_PREFIX + device[:11]
                if port.switch.startswith(q_const.QEP_VSWITCH_PREFIX) \
                    and not ip_lib.device_exists(port_to_brpcy_name, self.root_helper):
                        LOG.error(_("Brpcy bridge %(port_to_brpcy_name)s for brpcy port %(port_name)s doesn't exist "),
                                  {'port_name': port.port_name,
                                   'port_to_brpcy_name': port_to_brpcy_name})
                        continue               
                
                #should decide the trunk_type of port
                if details.get('trunk_type') == 'trunk':           
                    if not self.brpcy_bridges.get(port_to_brpcy_name):
                        br = VLANPolicyBridge(port_to_brpcy_name, self.root_helper)
                        br.configure(port_to_brpcy_name, self.root_helper,
                                     self.integ_ebr)                                                     
                        self.brpcy_bridges[port_to_brpcy_name] = br
                    self.treat_trunk_port(port, details, self.brpcy_bridges[port_to_brpcy_name],
                                          ovs_restarted)                                        
                else:
                    #port directly plug in ebr-int
                    if not port.switch.startswith(q_const.QEP_VSWITCH_PREFIX):
                        self.treat_vif_port(port, details['port_id'],
                                            details['network_id'],
                                            details['network_type'],
                                            details['physical_network'],
                                            details['segmentation_id'],
                                            details['admin_state_up'],
                                            details['fixed_ips'],
                                            details['device_owner'],
                                            ovs_restarted
                                            )
                    else:
                        self.brpcy_bridges[port_to_brpcy_name] = evs_lib.EVSBridge(port_to_brpcy_name, self.root_helper)
                        self.setup_brpcy_bridge(port_to_brpcy_name)                        
                        #set tag for tap device plugged in qep br
                        self.treat_vif_port_qep_br(port, details['port_id'],
                                            details['network_id'],
                                            details['network_type'],
                                            details['physical_network'],
                                            details['segmentation_id'],
                                            details['admin_state_up'],
                                            details['fixed_ips'],
                                            details['device_owner'],
                                            ovs_restarted,
                                            port_to_brpcy_name
                                            )                   
                if details.get('admin_state_up'):
                    LOG.debug(_("Setting status for %s to UP"), device)
                    self.plugin_rpc.update_device_up(
                        self.context, device, self.agent_id, cfg.CONF.host)
                else:
                    LOG.debug(_("Setting status for %s to DOWN"), device)
                    self.plugin_rpc.update_device_down(
                        self.context, device, self.agent_id, cfg.CONF.host)
                LOG.info(_("Configuration for device %s completed."), device)            
            else:
                LOG.warn(_("Device %s not defined on plugin"), device)
                br_name = port.switch
                if br_name.startswith(q_const.QEP_VSWITCH_PREFIX) \
                    and port.ofport != -1:
                        self.port_dead_qep_br(port, br_name)
                elif br_name == self.integ_ebr_name \
                    and port.ofport != -1:
                        self.port_dead(port)

                        
        return resync, skipped_devices

    def remove_trunk_port(self, port_id, vlan_bridge):
        LOG.debug(_("Remove trunk port %s."), port_id)
        if self.trunk_subports.has_key(port_id):
            trunk_subports = self.trunk_subports.pop(port_id)
            port_info = self.update_trunk_subports(trunk_subports, {})
            if port_info:
                port_info['port_id'] = port_id
                port_info['br'] = vlan_bridge
                self.trunk_backlog.append(port_info)

    def treat_devices_removed(self, devices):
        resync = False
        for device in devices:
            LOG.info(_("Attachment %s removed"), device)
            
            #consider trunk port tag device
            port_to_brpcy_name = q_const.QEP_VSWITCH_PREFIX + device[:11]
            if port_to_brpcy_name in self.brpcy_bridges.keys():
                self.remove_trunk_port(device, self.brpcy_bridges[port_to_brpcy_name])
                self.brpcy_bridges.pop(port_to_brpcy_name)
            
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
            self.port_unbound(device)
        return resync

    def process_network_ports(self, port_info, ovs_restarted):
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
                resync_a, skipped_devices = self.treat_devices_added_updated(devices_added_updated, ovs_restarted)
                LOG.debug(_("process_network_ports - iteration:%(iter_num)d -"
                            "treat_devices_added completed. "
                            "Skipped %(num_skipped)d devices of "
                            "%(num_current)d devices currently available. "
                            "Time elapsed: %(elapsed).3f"),
                          {'iter_num': self.iter_num,
                           'num_skipped': len(skipped_devices),
                           'num_current': len(port_info['current']),
                           'elapsed': time.time() - start})
                port_info['current'] = (port_info['current'] -
                                        set(skipped_devices))
            except DeviceListRetrievalError:
                # Need to resync as there was an error with server
                # communication.
                LOG.exception(_("process_network_ports - iteration:%d - "
                                "failure while retrieving port details "
                                "from server"), self.iter_num)
                resync_a = True
        if 'removed' in port_info and port_info['removed']:
            start = time.time()
            resync_b = self.treat_devices_removed(port_info['removed'])
            LOG.debug(_("process_network_ports - iteration:%(iter_num)d -"
                        "treat_devices_removed completed in %(elapsed).3f"),
                      {'iter_num': self.iter_num,
                       'elapsed': time.time() - start})
        # If one of the above operations fails => resync with plugin
        return (resync_a | resync_b)

    def check_ovs_restart(self):
        # Check for the canary flow
        canary_flow = self.integ_ebr.dump_flows_for_table(q_const.CANARY_TABLE)
        return not canary_flow


    def check_hugemem_configured(self):
        return ip_lib.device_exists(self.integ_ebr_name, self.root_helper)
    
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
                LOG.debug(_("Agent rpc_loop - iteration:%d started"),
                            self.iter_num)
                if sync:
                    LOG.info(_("Agent out of sync with plugin! Should br synchronized!"))
                    ports.clear()
                    self.trunk_subports = {} 
                    self.brpcy_bridges = {}
                    sync = False         
                    polling_manager.force_polling()
                
                if not self.bridge_mappings:
                    LOG.debug(_("Bridge mapping is not configured!"))
                    elapsed = (time.time() - start)
                    if (elapsed < self.polling_interval):
                        time.sleep(self.polling_interval - elapsed)
                    continue
                
                self.is_hugemem_configured = self.check_hugemem_configured()
                if not self.is_hugemem_configured:
                    LOG.error(_("Huge memory is not configured "
                                " or vswitchd is abnormal."))
                    elapsed = (time.time() - start)
                    if (elapsed < self.polling_interval):
                        time.sleep(self.polling_interval - elapsed)
                    
                    
                    #check hugemem_configured or not as openvswitch restarted
                    hugemem_configured_rel = self.check_hugemem_configured()
                    if not hugemem_configured_rel:
                        continue
                    else:
                        self.is_hugemem_configured = True
                
                #check if ovs-vswitchd restart
                ovs_restarted = self.check_ovs_restart()
                
                
                if ovs_restarted:
                    self.setup_integration_ebr()
                    self.setup_physical_bridges(self.bridge_mappings)
                    #vswitchd restart
                    self.trunk_subports = {} 
                    self.brpcy_bridges = {}
                             
                if self._agent_has_updates(polling_manager) or ovs_restarted:                       
                    try:
                        LOG.debug(_("Agent rpc_loop - iteration:%(iter_num)d - "
                                    "starting polling. Elapsed:%(elapsed).3f"),
                                  {'iter_num': self.iter_num,
                                   'elapsed': time.time() - start})
                        updated_ports_copy = self.updated_ports
                        self.updated_ports = set()
    
                        reg_ports = (set() if ovs_restarted else ports)
                        
                        port_info = self.scan_ports(reg_ports, updated_ports_copy)
                        
                        if self._port_info_has_changes(port_info):
                            LOG.debug(_("Starting to process devices in:%s"),
                                      port_info)
                            # If treat devices fails - must resync with plugin
                            sync = self.process_network_ports(port_info, ovs_restarted)                       
                            LOG.debug(_("Agent rpc_loop - iteration:%(iter_num)d -"
                                        "ports processed. Elapsed:%(elapsed).3f"),
                                        {'iter_num': self.iter_num,
                                        'elapsed': time.time() - start})
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
            

            try:
                if self.trunk_backlog:
                    LOG.debug(_("Trunk backlog: %s"), self.trunk_backlog)
                    self.trunk_work()
            except Exception:
                LOG.exception(_("Error while processing backlog ports"))
                # Put the ports back in self.updated_port
                self.trunk_subports = {} 
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
    
    def daemon_loop(self):
        with polling.get_polling_manager(
            self.minimize_polling,
            self.root_helper,
            self.ovsdb_monitor_respawn_interval) as pm:
            LOG.debug("daemon_loop,pm=%s" % pm)
            self.rpc_loop(polling_manager=pm)
            
    def _handle_sigterm(self, signum, frame):
        LOG.debug("Agent caught SIGTERM, quitting daemon loop.")
        self.run_daemon_loop = False            



def create_agent_config_map(config):
    """Create a map of agent config parameters.

    :param config: an instance of cfg.CONF
    :returns: a map of agent configuration parameters
    """
    try:
        bridge_mappings = q_utils.parse_mappings(config.EVS.bridge_mappings)
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
    
    cfg.CONF(project='neutron')

    try:
        agent_config = create_agent_config_map(cfg.CONF)
    except ValueError as e:
        LOG.error(_('%s Agent terminated!'), e)
        sys.exit(1)

    plugin = EVSNeutronAgent(**agent_config)
    
    signal.signal(signal.SIGTERM, plugin._handle_sigterm)

    # Start everything.
    LOG.info(_("Agent initialized successfully, now running... "))
    plugin.daemon_loop()
    sys.exit(0)


if __name__ == "__main__":
    main()


