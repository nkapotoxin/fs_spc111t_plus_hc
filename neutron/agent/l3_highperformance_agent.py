# Copyright 2012 VMware, Inc.  All rights reserved.
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
#

import sys

import datetime
import eventlet
eventlet.monkey_patch()

from oslo.config import cfg
from oslo import messaging
import Queue

from neutron.agent.common import config
from neutron.agent.linux import external_process
from neutron.agent.linux import ip_lib
from neutron.agent import rpc as agent_rpc
from neutron.common import config as common_config
from neutron.common import constants as l3_constants
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.common import utils as common_utils
from neutron import context
from neutron import manager
from neutron.openstack.common import excutils
from neutron.openstack.common.gettextutils import _LW
from neutron.openstack.common import log as logging
from neutron.openstack.common import loopingcall
from neutron.openstack.common import periodic_task
from neutron.openstack.common import service
from neutron.openstack.common import timeutils
from neutron.plugins.common import constants as p_const
from neutron import service as neutron_service

LOG = logging.getLogger(__name__)

RPC_LOOP_INTERVAL = 1
# Lower value is higher priority
PRIORITY_RPC = 0
PRIORITY_SYNC_ROUTERS_TASK = 1
DELETE_ROUTER = 1

HA_DEFAULT_PRIORITY = 50

ROUTE_INFO = ['destination','nexthop']
SUBNET_INFO = ['vni', 'mac_address', 'cidr']
EXT_NET_INFO = ['vlan', 'ip_address']


class L3PluginApi(n_rpc.RpcProxy):
    """Agent side of the l3 agent RPC API."""

    BASE_RPC_API_VERSION = '1.0'

    def __init__(self, topic, host):
        super(L3PluginApi, self).__init__(
            topic=topic, default_version=self.BASE_RPC_API_VERSION)
        self.host = host

    def get_dvr_base_mac(self, context):
        return self.call(context,
                         self.make_msg('get_dvr_base_mac'))

    def get_routers(self, context, router_ids=None):
        """Make a remote process call to retrieve the sync data for routers."""
        return self.call(context,
                         self.make_msg('sync_highperformance_routers', host=self.host,
                                       router_ids=router_ids))

    def get_service_plugin_list(self, context):
        """Make a call to get the list of activated services."""
        return self.call(context,
                         self.make_msg('get_service_plugin_list'),
                         topic=self.topic,
                         version='1.3')

class L3DataEngineApi(n_rpc.RpcProxy):
    
    BASE_RPC_API_VERSION = '1.0'
    
    def __init__(self, topic, context):
        super(L3DataEngineApi, self).__init__(
            topic=topic, default_version=self.BASE_RPC_API_VERSION)
        self.context = context
    
    def router_interface_add(self, data):    
        return self.fanout_cast(
            self.context,
            self.make_msg('router_interface_add', data=data),
            topic=self.topic
        )

    def router_interface_delete(self, data):    
        return self.fanout_cast(
            self.context,
            self.make_msg('router_interface_delete', data=data),
            topic=self.topic
        )

    def router_route_add(self, data):    
        return self.fanout_cast(
            self.context,
            self.make_msg('router_route_add', data=data),
            topic=self.topic
        )

    def router_route_delete(self, data):    
        return self.fanout_cast(
            self.context,
            self.make_msg('router_route_delete', data=data),
            topic=self.topic
        )
        
    def router_gateway_add(self, data):    
        return self.fanout_cast(
            self.context,
            self.make_msg('router_gateway_add', data=data),
            topic=self.topic
        )
    
    def router_gateway_delete(self, data):    
        return self.fanout_cast(
            self.context,
            self.make_msg('router_gateway_delete', data=data),
            topic=self.topic
        )

    def arp_flows_add(self, data):
        return self.fanout_cast(
            self.context,
            self.make_msg('arp_flows_add', data=data),
            topic=self.topic
        )

    def arp_flows_delete(self, data):
        return self.fanout_cast(
            self.context,
            self.make_msg('arp_flows_delete', data=data),
            topic=self.topic
        )
    
    def delete_all_flows(self, data=None):
        return self.fanout_cast(
            self.context,
            self.make_msg('delete_all_flows', data=data),
            topic=self.topic
        )


class L3DataEngineCallback(n_rpc.RpcCallback):
    
    RPC_API_VERSION = '1.0'

    def __init__(self, manager):
        self.manager = manager
        self.ha_priority = HA_DEFAULT_PRIORITY
        self.ha_prioritys = {}

    def get_routers(self, context):
        return self.manager.get_routers(context)

    def report_state(self, context, data):
        self.manager.virtual_ip = data['virtual_ip']
        self.manager.virtual_mac = data['virtual_mac']

    def get_init_info(self, context, data):
        if not data:
            return
        if data not in self.ha_prioritys:
            self.ha_prioritys[data] = self.ha_priority
            self.ha_priority += 100
        keepalive_priority = self.ha_prioritys[data]
        dvr_base_mac = self.manager.dvr_base_mac
        prefix = []
        flag = False
        for ch in dvr_base_mac[ : : -1]:
            if ch == ':':
                prefix.append(ch)
            else:
                if flag:
                    prefix.append('f')
                else:
                    if ch == '0':
                        prefix.append('0')
                    else:
                        flag = True
                        prefix.append('f')
        
        prefix.reverse()
        prefix = ''.join(prefix)
        
        dvr_mac_info = dvr_base_mac + '/' + prefix
        return cfg.CONF.local_ip, dvr_mac_info, keepalive_priority


class RouterInfo():

    def __init__(self, router_id, router):
        self.router_id = router_id
        self.ex_gw_port = None
        self.snat_ports = []
        # Invoke the setter for establishing initial SNAT action
        self.router = router
        self.routes = []
        # DVR Data

    @property
    def router(self):
        return self._router

    @router.setter
    def router(self, value):
        self._router = value
        if not self._router:
            return


class RouterUpdate(object):
    """Encapsulates a router update

    An instance of this object carries the information necessary to prioritize
    and process a request to update a router.
    """
    def __init__(self, router_id, priority,
                 action=None, router=None, timestamp=None):
        self.priority = priority
        self.timestamp = timestamp
        if not timestamp:
            self.timestamp = timeutils.utcnow()
        self.id = router_id
        self.action = action
        self.router = router

    def __lt__(self, other):
        """Implements priority among updates

        Lower numerical priority always gets precedence.  When comparing two
        updates of the same priority then the one with the earlier timestamp
        gets procedence.  In the unlikely event that the timestamps are also
        equal it falls back to a simple comparison of ids meaning the
        precedence is essentially random.
        """
        if self.priority != other.priority:
            return self.priority < other.priority
        if self.timestamp != other.timestamp:
            return self.timestamp < other.timestamp
        return self.id < other.id


class ExclusiveRouterProcessor(object):
    """Manager for access to a router for processing

    This class controls access to a router in a non-blocking way.  The first
    instance to be created for a given router_id is granted exclusive access to
    the router.

    Other instances may be created for the same router_id while the first
    instance has exclusive access.  If that happens then it doesn't block and
    wait for access.  Instead, it signals to the master instance that an update
    came in with the timestamp.

    This way, a thread will not block to wait for access to a router.  Instead
    it effectively signals to the thread that is working on the router that
    something has changed since it started working on it.  That thread will
    simply finish its current iteration and then repeat.

    This class keeps track of the last time that a router data was fetched and
    processed.  The timestamp that it keeps must be before when the data used
    to process the router last was fetched from the database.  But, as close as
    possible.  The timestamp should not be recorded, however, until the router
    has been processed using the fetch data.
    """
    _masters = {}
    _router_timestamps = {}

    def __init__(self, router_id):
        self._router_id = router_id

        if router_id not in self._masters:
            self._masters[router_id] = self
            self._queue = []

        self._master = self._masters[router_id]

    def _i_am_master(self):
        return self == self._master

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        if self._i_am_master():
            del self._masters[self._router_id]

    def _get_router_data_timestamp(self):
        return self._router_timestamps.get(self._router_id,
                                           datetime.datetime.min)

    def fetched_and_processed(self, timestamp):
        """Records the data timestamp after it is used to update the router"""
        new_timestamp = max(timestamp, self._get_router_data_timestamp())
        self._router_timestamps[self._router_id] = new_timestamp

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
                if self._get_router_data_timestamp() < update.timestamp:
                    yield update


class RouterProcessingQueue(object):
    """Manager of the queue of routers to process."""
    def __init__(self):
        self._queue = Queue.PriorityQueue()

    def add(self, update):
        self._queue.put(update)

    def each_update_to_next_router(self):
        """Grabs the next router from the queue and processes

        This method uses a for loop to process the router repeatedly until
        updates stop bubbling to the front of the queue.
        """
        next_update = self._queue.get()

        with ExclusiveRouterProcessor(next_update.id) as rp:
            # Queue the update whether this worker is the master or not.
            rp.queue_update(next_update)

            # Here, if the current worker is not the master, the call to
            # rp.updates() will not yield and so this will essentially be a
            # noop.
            for update in rp.updates():
                yield (rp, update)

class LocalVLANMapping:
    def __init__(self, network_type, physical_network, segmentation_id,
                 vif_ports=None):
        if vif_ports is None:
            vif_ports = {}
        self.network_type = network_type
        self.physical_network = physical_network
        self.segmentation_id = segmentation_id
        self.vif_ports = vif_ports

    def __str__(self):
        return ("type = %s phys-net = %s phys-id = %s" %
                (self.network_type, self.physical_network,
                 self.segmentation_id))


class L2populationRpcCallback(n_rpc.RpcCallback):
    
    def __init__(self, manager):
        self.manager = manager

    def add_fdb_entries(self, context, fdb_entries, host=None):
        LOG.debug('add_fdb_entries received')
        if not host or host == cfg.CONF.host:
            self.manager.fdb_add(context, fdb_entries)

    def remove_fdb_entries(self, context, fdb_entries, host=None):
        LOG.debug('remove_fdb_entries received')
        if not host or host == cfg.CONF.host:
            self.manager.fdb_remove(context, fdb_entries)

    def update_fdb_entries(self, context, fdb_entries, host=None):
        LOG.debug('update_fdb_entries received')
        if not host or host == cfg.CONF.host:
            self.manager.fdb_update(context, fdb_entries)


class L2HighNeutronAgent(object):

    OPTS = [
        cfg.StrOpt('local_ip', default='',
                   help=_("Local IP address of VXLAN tunnel endpoints.")),
        cfg.ListOpt('bridge_mappings',
                   default=[],
                   help=_("List of <physical_network>:<bridge>. "
                           "Deprecated for ofagent.")),
        cfg.BoolOpt('l2_population', default=True,
                    help=_("Use ML2 l2population mechanism driver to learn "
                           "remote MAC and IPs and improve tunnel scalability.")),
        cfg.BoolOpt('arp_responder', default=False,
                    help=_("Enable local ARP responder if it is supported. "
                           "Requires OVS 2.1 and ML2 l2population driver. "
                           "Allows the switch (when supporting an overlay) "
                           "to respond to an ARP request locally without "
                           "performing a costly ARP broadcast into the overlay.")),
        cfg.ListOpt('l2pop_network_types', default=['vxlan'],
                    help=_("L2pop network types supported by the agent."))
    ]

    def __init__(self):
        LOG.debug(_('L2HighNeutronAgent init is STARTING'))
        self.conf = cfg.CONF
        try:
            self.bridge_mappings = common_utils.parse_mappings(self.conf.bridge_mappings)
        except ValueError as e:
            raise ValueError(_("Parsing bridge_mappings failed: %s.") % e)
        self.context = context.get_admin_context_without_session()
        self.agent_id = 'ovs-agent-%s' % self.conf.host
        self.l2_plugin_rpc = agent_rpc.PluginApi(topics.PLUGIN)
        self.l2_state_rpc = agent_rpc.PluginReportStateAPI(topics.PLUGIN)
        self._set_l2_rpc_consumers()
        self.use_call = True
        self.local_vlan_map = {}
        self.tunnel_types = [p_const.TYPE_VXLAN]
        self.l2_pop = self.conf.l2_population
        self.local_ip = self.conf.local_ip
        self.arp_responder_enabled = self.conf.arp_responder and self.l2_pop
        self.l2pop_network_types = self.conf.l2pop_network_types or self.tunnel_types
        self.l2_agent_state = {
            'binary': 'neutron-openvswitch-agent',
            'host': self.conf.host,
            'topic': l3_constants.L2_AGENT_TOPIC,
            'configurations': {
                   'bridge_mappings': self.bridge_mappings,
                   'tunnel_types': self.tunnel_types,
                   'tunneling_ip': self.local_ip.split('/')[0],
                   'l2_population': self.l2_pop,
                   'l2pop_network_types': self.l2pop_network_types,
                   'arp_responder_enabled':self.arp_responder_enabled,
                   'enable_distributed_routing': True
            },
            'agent_type': l3_constants.AGENT_TYPE_OVS,
            'start_flag': True}
        LOG.debug(_('RPC l2_state_report heartbeat start'))

    def _set_l2_rpc_consumers(self):
        self.endpoints = [L2populationRpcCallback(self)]
        # Define the listening consumers for the agent
        consumers = [[topics.L2POPULATION, topics.UPDATE, self.conf.host]]
        self.connection = agent_rpc.create_consumers(self.endpoints,
                                                     topics.AGENT,
                                                     consumers)

    def _l2_report_state(self):
        try:
            self.l2_state_rpc.report_state(self.context,
                                           self.l2_agent_state,
                                           self.use_call)
            self.use_call = False
            self.l2_agent_state.pop('start_flag', None)
        except Exception:
            LOG.exception(_("Failed Report state"))

    def l2pop_report_router_port_up(self, ports):
        LOG.debug(_('RPC l2pop_report_router_port_up is CALLED'))
        devices = []
        for port in ports:
            devices.append(port.get('id'))

        devices_details_list = self.l2_plugin_rpc.get_devices_details_list(self.context,
                                                                           devices,
                                                                           self.agent_id,
                                                                           self.conf.host)

        for details in devices_details_list:
            device = details['device']
            LOG.debug("Processing port: %s", device)
            if 'port_id' in details:
                LOG.info(_("Port %(device)s updated. Details: %(details)s"),
                         {'device': device, 'details': details})
                self.treat_vif_port(details,
                                    details['network_id'],
                                    details['network_type'],
                                    details['physical_network'],
                                    details['segmentation_id'],
                                    details['admin_state_up'],
                                    details['fixed_ips'],
                                    details['device_owner'])
                if details.get('admin_state_up'):
                    LOG.debug(_("Setting status for %s to UP"), device)
                    self.l2_plugin_rpc.update_device_up(
                        self.context, device, self.agent_id, self.conf.host)
                else:
                    LOG.debug(_("Setting status for %s to DOWN"), device)
                    self.l2_plugin_rpc.update_device_down(
                        self.context, device, self.agent_id, self.conf.host)
                LOG.info(_("Configuration for device %s completed."), device)
            else:
                LOG.warn(_("Device %s not defined on plugin"), device)

    def l2pop_report_router_port_down(self, ports):
        LOG.debug(_('RPC l2pop_report_router_port_down is CALLED'))
        for port in ports:
            LOG.info(_("Attachment %s removed"), port.get('id'))
            try:
                details = self.l2_plugin_rpc.update_device_down(self.context,
                                                                port.get('id'),
                                                                self.agent_id,
                                                                self.conf.host)
                self.port_unbound(port.get('mac_address'), port.get('network_id'))
            except Exception as e:
                LOG.debug(_("port_removed failed for %(device)s: %(e)s"),
                          {'device': port.get('id'), 'e': e})
                continue
            if details['exists']:
                LOG.info(_("Port %s updated."), port.get('id'))
            else:
                LOG.debug(_("Device %s not defined on plugin"), port.get('id'))

    def treat_vif_port(self, port, network_id, network_type,
                       physical_network, segmentation_id, admin_state_up,
                       fixed_ips, device_owner):
        # When this function is called for a port, the port should have
        # an OVS ofport configured, as only these ports were considered
        # for being treated. If that does not happen, it is a potential
        # error condition of which operators should be aware

        if admin_state_up:
            self.port_bound(port, network_id, network_type,
                            physical_network, segmentation_id,
                            fixed_ips, device_owner)

    def port_bound(self, port, net_uuid,
                   network_type, physical_network,
                   segmentation_id, fixed_ips, device_owner):
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
        if net_uuid not in self.local_vlan_map:
            self.provision_local_vlan(net_uuid, network_type,
                                      physical_network, segmentation_id)
        lvm = self.local_vlan_map[net_uuid]
        lvm.vif_ports[port['mac_address']] = port

    def port_unbound(self, port_mac=None, net_uuid=None):
        '''Unbind port.

        Removes corresponding local vlan mapping object if this is its last
        VIF.

        :param vif_id: the id of the vif
        :param net_uuid: the net_uuid this port is associated with.
        '''
        if not net_uuid or not self.local_vlan_map.get(net_uuid):
            LOG.info(_('port_unbound(): net_uuid %s not in local_vlan_map'),
                     net_uuid)
            return

        lvm = self.local_vlan_map[net_uuid]

        if not port_mac and port_mac in lvm.vif_ports:
            lvm.vif_ports.pop(port_mac, None)

        if not lvm.vif_ports:
            self.reclaim_local_vlan(net_uuid)

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

    def provision_local_vlan(self, net_uuid, network_type, physical_network,
                             segmentation_id):
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
        if not lvm:
            self.local_vlan_map[net_uuid] = LocalVLANMapping(network_type,
                                                             physical_network,
                                                             segmentation_id)

        LOG.info(_("Assigning net-id=%(net_uuid)s"),{'net_uuid': net_uuid})

    def get_agent_ports(self, fdb_entries, local_vlan_map):
        for network_id, values in fdb_entries.items():
            lvm = local_vlan_map.get(network_id)
            if lvm is None:
                continue
            agent_ports = values.get('ports')
            yield (lvm, agent_ports)

    def fdb_add(self, context, fdb_entries):
        LOG.debug("fdb_add received")
        for lvm, agent_ports in self.get_agent_ports(fdb_entries,
                                                     self.local_vlan_map):

            LOG.debug("the add lvm is %s, the agent_ports is %s" % (lvm, agent_ports))
            if lvm.network_type not in self.tunnel_types:
                continue

            add_other_mac_ips = {}
            if len(agent_ports):
                for agent_ip, ports in agent_ports.items():
                    mac_ip_map = {}
                    for port in ports:
                        if port == l3_constants.FLOODING_ENTRY:
                            continue
                        mac_ip_map[port[0]] = [port[1]]
                    for mac_address, ips in mac_ip_map.items():
                        if lvm.vif_ports.get(mac_address):
                            continue
                        add_other_mac_ips[mac_address] = {'vm_ip':ips,
                                                          'vm_mac': mac_address,
                                                          'vtep_ip': agent_ip,
                                                          'vni': lvm.segmentation_id}
                LOG.debug("the add_other_mac_ips is %s" % add_other_mac_ips)
                if add_other_mac_ips:
                    self.dataengine_rpc.arp_flows_add(add_other_mac_ips)

    def fdb_remove(self, context, fdb_entries):
        LOG.debug("fdb_remove received")
        for lvm, agent_ports in self.get_agent_ports(fdb_entries,
                                                     self.local_vlan_map):

            LOG.debug("the remove lvm is %s, the agent_ports is %s" % (lvm, agent_ports))
            remove_other_mac_ips = {}
            if len(agent_ports):
                for agent_ip, ports in agent_ports.items():

                    for port in ports:
                        local_port = lvm.vif_ports.pop(port[0], None)
                        if local_port:
                            continue
                        remove_other_mac_ips[port[0]] = {'vm_ip':port[1],
                                                         'vm_mac': port[0],
                                                         'vtep_ip': agent_ip,
                                                         'vni': lvm.segmentation_id}
                LOG.debug("the remove_other_mac_ips is %s" % remove_other_mac_ips)
                if remove_other_mac_ips:
                    self.dataengine_rpc.arp_flows_delete(remove_other_mac_ips)

    def fdb_update(self, context, fdb_entries):
        LOG.debug("fdb_update received")
        pass


class L3NATAgent(manager.Manager, L2HighNeutronAgent):
    """Manager for L3NatAgent"""

    RPC_API_VERSION = '1.2'

    OPTS = [
        cfg.StrOpt('agent_mode', default='dvr_snat',
                   help=_("The working mode for the agent. Allowed modes are: "
                          "'legacy' - this preserves the existing behavior "
                          "where the L3 agent is deployed on a centralized "
                          "networking node to provide L3 services like DNAT, "
                          "and SNAT. Use this mode if you do not want to "
                          "adopt DVR. 'dvr' - this mode enables DVR "
                          "functionality and must be used for an L3 agent "
                          "that runs on a compute host. 'dvr_snat' - this "
                          "enables centralized SNAT support in conjunction "
                          "with DVR.  This mode must be used for an L3 agent "
                          "running on a centralized node (or in single-host "
                          "deployments, e.g. devstack)")),
        cfg.StrOpt(
            'agent_index',
            default='',
            help=_('The index of L3 high-performance agent')
        )
    ]

    def __init__(self, host, conf=None):
        super(L3NATAgent, self).__init__()
        if conf:
            self.conf = conf
        else:
            self.conf = cfg.CONF
        self.router_info = {}
        self.virtual_ip = ''
        self.virtual_mac = ''
        self.context = context.get_admin_context_without_session()
        self.plugin_rpc = L3PluginApi(topics.L3PLUGIN, host)
        self.dvr_base_mac = self.plugin_rpc.get_dvr_base_mac(self.context)
        self._setup_dataenigine_rpc()
        self.dataengine_rpc.delete_all_flows()
        self.fullsync = True

        # Get the list of service plugins from Neutron Server
        # This is the first place where we contact neutron-server on startup
        # so retry in case its not ready to respond.
        retry_count = 5
        while True:
            retry_count = retry_count - 1
            try:
                self.neutron_service_plugins = (
                    self.plugin_rpc.get_service_plugin_list(self.context))
            except n_rpc.RemoteError as e:
                with excutils.save_and_reraise_exception() as ctx:
                    ctx.reraise = False
                    LOG.warning(_LW('l3-agent cannot check service plugins '
                                    'enabled at the neutron server when '
                                    'startup due to RPC error. It happens '
                                    'when the server does not support this '
                                    'RPC API. If the error is '
                                    'UnsupportedVersion you can ignore this '
                                    'warning. Detail message: %s'), e)
                self.neutron_service_plugins = None
            except messaging.MessagingTimeout as e:
                with excutils.save_and_reraise_exception() as ctx:
                    if retry_count > 0:
                        ctx.reraise = False
                        LOG.warning(_LW('l3-agent cannot check service '
                                        'plugins enabled on the neutron '
                                        'server. Retrying. '
                                        'Detail message: %s'), e)
                        continue
            break

        self._queue = RouterProcessingQueue()
        
    def _setup_dataenigine_rpc(self):
        self.dataengine_rpc = L3DataEngineApi(
            '%s-%s' % (topics.L3_DATAENGINE, self.conf.agent_index),
            self.context)
                
        self.conn = n_rpc.create_connection(new=True)
        endpoints = [L3DataEngineCallback(self)]
        self.conn.create_consumer('%s-%s' % (topics.L3_HIGTPERFORMANCE_AGNET,
                                             self.conf.agent_index),
                                  endpoints)
        self.conn.consume_in_threads()  

    def _router_added(self, router_id, router):
        ri = RouterInfo(router_id, router)
        self.router_info[router_id] = ri

    def _router_removed(self, router_id):
        ri = self.router_info.get(router_id)
        if ri is None:
            LOG.warn(_("Info for router %s were not found. "
                       "Skipping router removal"), router_id)
            return

        ri.router['gw_port'] = None
        ri.router[l3_constants.INTERFACE_KEY] = []
        ri.router[l3_constants.FLOATINGIP_KEY] = []
        self.process_router(ri)

        del self.router_info[router_id]
        
    def _get_engine_routes(self, routes, ex_gw_port):
        engine_routes = []
        default_route = False
        for route in routes:
            engine_routes.append({'nw_dst_cidr': route['destination'],
                                   'next_hop': route['nexthop']})
            if route['destination'] == '0.0.0.0/0':
                default_route = True
        
        if not default_route and ex_gw_port:
            engine_routes.append(self._get_default_route(ex_gw_port))
        
        return engine_routes

    def _get_default_route(self, ex_gw_port):
        gateway_ip = ex_gw_port['subnet']['gateway_ip']
        return {'nw_dst_cidr': 'default',
                'next_hop': gateway_ip}

    def _get_engine_subnets(self, snat_ports):
        engine_subnets = []
        for snat_port in snat_ports:
            engine_subnets.append({'vni': snat_port['vni'],
                                    'sg_mac': snat_port['mac_address'],
                                    'cidr': snat_port['subnet']['cidr']})
        return engine_subnets

    @common_utils.exception_logger()
    def process_router(self, ri):
        data = {}
        data['router_id'] = ri.router_id

        ex_gw_port = self._get_ex_gw_port(ri)
        
        if ex_gw_port:
            def _gateway_ports_equal(port1, port2):
                def _get_filtered_dict(d, ignore):
                    return dict((k, v) for k, v in d.iteritems()
                                if k not in ignore)

                keys_to_ignore = set(['binding:host_id'])
                port1_filtered = _get_filtered_dict(port1, keys_to_ignore)
                port2_filtered = _get_filtered_dict(port2, keys_to_ignore)
                return port1_filtered == port2_filtered

            if not ri.ex_gw_port:
                self.gateway_set(ri)
            elif not _gateway_ports_equal(ex_gw_port, ri.ex_gw_port):
                self.gateway_clear(ri)
                self.gateway_set(ri)

            # Process static routes for router
            self.routes_updated(ri)
            self.interface_updated(ri)

            ri.ex_gw_port = ex_gw_port
            ri.snat_ports = ri.router.get(l3_constants.SNAT_ROUTER_INTF_KEY, [])
            ri.routes = ri.router['routes']
        else:
            if ri.ex_gw_port:
                self.gateway_clear(ri)

    def _get_ex_gw_port(self, ri):
        return ri.router.get('gw_port')

    def router_deleted(self, context, router_id):
        """Deal with router deletion RPC message."""
        LOG.debug(_('Got router deleted notification for %s'), router_id)
        update = RouterUpdate(router_id, PRIORITY_RPC, action=DELETE_ROUTER)
        self._queue.add(update)

    def add_arp_entry(self, context, payload):
        """Add arp entry into router namespace.  Called from RPC."""
        pass

    def del_arp_entry(self, context, payload):
        """Delete arp entry from router namespace.  Called from RPC."""
        pass

    def routers_updated(self, context, routers):
        """Deal with routers modification and creation RPC message."""
        LOG.debug(_('Got routers updated notification :%s'), routers)
        if routers:
            # This is needed for backward compatibility
            if isinstance(routers[0], dict):
                routers = [router['id'] for router in routers]
            for id in routers:
                update = RouterUpdate(id, PRIORITY_RPC)
                self._queue.add(update)

    def router_removed_from_agent(self, context, payload):
        LOG.debug(_('Got router removed from agent :%r'), payload)
        router_id = payload['router_id']
        update = RouterUpdate(router_id, PRIORITY_RPC, action=DELETE_ROUTER)
        self._queue.add(update)

    def router_added_to_agent(self, context, payload):
        LOG.debug(_('Got router added to agent :%r'), payload)
        self.routers_updated(context, payload)

    def _process_routers(self, routers, all_routers=False):
        pool = eventlet.GreenPool()

        # if routers are all the routers we have (They are from router sync on
        # starting or when error occurs during running), we seek the
        # routers which should be removed.
        # If routers are from server side notification, we seek them
        # from subset of incoming routers and ones we have now.
        if all_routers:
            prev_router_ids = set(self.router_info)
        else:
            prev_router_ids = set(self.router_info) & set(
                [router['id'] for router in routers])
        cur_router_ids = set()
        for r in routers:
            cur_router_ids.add(r['id'])
            if r['id'] not in self.router_info:
                self._router_added(r['id'], r)
            ri = self.router_info[r['id']]
            ri.router = r
            pool.spawn_n(self.process_router, ri)
        # identify and remove routers that no longer exist
        for router_id in prev_router_ids - cur_router_ids:
            pool.spawn_n(self._router_removed, router_id)
        pool.waitall()

    def _process_router_update(self):
        for rp, update in self._queue.each_update_to_next_router():
            LOG.debug("Starting router update for %s", update.id)
            router = update.router
            if update.action != DELETE_ROUTER and not router:
                try:
                    update.timestamp = timeutils.utcnow()
                    routers = self.plugin_rpc.get_routers(self.context,
                                                          [update.id])
                except Exception:
                    msg = _("Failed to fetch router information for '%s'")
                    LOG.exception(msg, update.id)
                    self.fullsync = True
                    continue

                if routers:
                    router = routers[0]

            if not router:
                self._router_removed(update.id)
                continue

            self._process_routers([router])
            LOG.debug("Finished a router update for %s", update.id)
            rp.fetched_and_processed(update.timestamp)

    def _process_routers_loop(self):
        LOG.debug("Starting _process_routers_loop")
        pool = eventlet.GreenPool(size=8)
        while True:
            pool.spawn_n(self._process_router_update)

    @periodic_task.periodic_task
    def periodic_sync_routers_task(self, context):
        self._sync_routers_task(context)

    def _sync_routers_task(self, context):
        LOG.debug(_("Starting _sync_routers_task - fullsync:%s"),
                  self.fullsync)
        if not self.fullsync:
            return

        # Capture a picture of namespaces *before* fetching the full list from
        # the database.  This is important to correctly identify stale ones.
        prev_router_ids = set(self.router_info)

        try:
            timestamp = timeutils.utcnow()
            routers = self.plugin_rpc.get_routers(
                context)

            LOG.debug(_('Processing :%r'), routers)
            for r in routers:
                update = RouterUpdate(r['id'],
                                      PRIORITY_SYNC_ROUTERS_TASK,
                                      router=r,
                                      timestamp=timestamp)
                self._queue.add(update)
            self.fullsync = False
            LOG.debug(_("_sync_routers_task successfully completed"))
        except n_rpc.RPCException:
            LOG.exception(_("Failed synchronizing routers due to RPC error"))
            self.fullsync = True
        except Exception:
            LOG.exception(_("Failed synchronizing routers"))
            self.fullsync = True
        else:
            # Resync is not necessary for the cleanup of stale namespaces
            curr_router_ids = set([r['id'] for r in routers])

            # Two kinds of stale routers:  Routers for which info is cached in
            # self.router_info and the others.  First, handle the former.
            for router_id in prev_router_ids - curr_router_ids:
                update = RouterUpdate(router_id,
                                      PRIORITY_SYNC_ROUTERS_TASK,
                                      timestamp=timestamp,
                                      action=DELETE_ROUTER)
                self._queue.add(update)
            # delete router_info

    def after_start(self):
        eventlet.spawn_n(self._process_routers_loop)
        self._sync_routers_task(self.context)
        LOG.info(_("L3 agent started"))

    def routes_updated(self, ri):
        LOG.debug("Enter routes updated function")
        data = {}
        data['id'] = ri.router_id
        data['subnets'] = self._get_engine_subnets(ri.router.get(l3_constants.SNAT_ROUTER_INTF_KEY, []))
        ex_gw_port = self._get_ex_gw_port(ri)
        data['ext_net_info'] = {
            'vlan': ex_gw_port['vlan'],
            'ip': ex_gw_port['fixed_ips'][0]['ip_address']
        }
        new_routes = ri.router['routes']
        old_routes = ri.routes
        adds, removes = common_utils.diff_list_of_dict(old_routes,
                                                       new_routes)

        if removes:
            data['routes'] = self._get_engine_routes(removes, ex_gw_port)
            self.dataengine_rpc.router_route_delete(data)
        
        if adds:
            data['routes'] = self._get_engine_routes(adds, ex_gw_port)
            self.dataengine_rpc.router_route_add(data)
    
    def interface_updated(self, ri):
        ex_gw_port = self._get_ex_gw_port(ri)
        data = {}
        data['id'] = ri.router_id
        data['routes'] = self._get_engine_routes(ri.router['routes'], ex_gw_port)
        data['ext_net_info'] = {
            'vlan': ex_gw_port['vlan'],
            'ip': ex_gw_port['fixed_ips'][0]['ip_address']
        }

        # Update ex_gw_port and enable_snat on the router info cache
        snat_ports = ri.router.get(l3_constants.SNAT_ROUTER_INTF_KEY, [])
        existing_port_ids = set([p['id'] for p in ri.snat_ports])
        current_port_ids = set([p['id'] for p in snat_ports
                                if p['admin_state_up']])
        new_ports = [p for p in snat_ports if
                     p['id'] in current_port_ids and
                     p['id'] not in existing_port_ids]
        old_ports = [p for p in ri.snat_ports if
                     p['id'] not in current_port_ids]
        
        if new_ports:
            data['subnets'] = self._get_engine_subnets(new_ports)
            self.dataengine_rpc.router_interface_add(data)
            self.l2pop_report_router_port_up(new_ports)
        
        if old_ports:
            data['subnets'] = self._get_engine_subnets(old_ports)
            self.dataengine_rpc.router_interface_delete(data)
            self.l2pop_report_router_port_down(old_ports)

    def gateway_set(self, ri):
        ex_gw_port = self._get_ex_gw_port(ri)
        data = {}
        data['router_id'] = ri.router_id
        data['routes'] = [self._get_default_route(ex_gw_port)]
        data['subnets'] = self._get_engine_subnets(ri.router.get(l3_constants.SNAT_ROUTER_INTF_KEY, []))
        data['ext_net_info'] = {
            'vlan': ex_gw_port['vlan'],
            'ip': ex_gw_port['fixed_ips'][0]['ip_address']
        }

        self.dataengine_rpc.router_gateway_add(data)
        self.l2pop_report_router_port_up([ex_gw_port])

    def gateway_clear(self, ri):
        ex_gw_port = ri.ex_gw_port
        data = {}
        data['router_id'] = ri.router_id
        data['routes'] = self._get_engine_routes(ri.routes, ex_gw_port)
        data['subnets'] = self._get_engine_subnets(ri.snat_ports)
        data['ext_net_info'] = {
            'vlan': ex_gw_port['vlan'],
            'ip': ex_gw_port['fixed_ips'][0]['ip_address']
        }
        self.dataengine_rpc.router_gateway_delete(data)
        self.l2pop_report_router_port_down([ex_gw_port])
        self.l2pop_report_router_port_down(ri.snat_ports)
        ri.ex_gw_port = None
        ri.snat_ports = []
        ri.routes = []

    def get_routers(self, context):
        ret = []
        for ri in self.router_info.values():
            ex_gw_port = self._get_ex_gw_port(ri)
            if ex_gw_port:
                data = {}
                data['router_id'] = ri.router_id
                data['routes'] = self._get_engine_routes(ri.router['routes'], ex_gw_port)
                data['subnets'] = self._get_engine_subnets(ri.router.get(l3_constants.SNAT_ROUTER_INTF_KEY, []))
                data['ext_net_info'] = {
                    'vlan': ex_gw_port['vlan'],
                    'ip': ex_gw_port['fixed_ips'][0]['ip_address']
                }

                ret.append(data)
                if ri.router.get(l3_constants.SNAT_ROUTER_INTF_KEY, []):
                    self.l2pop_report_router_port_up(ri.router.get(l3_constants.SNAT_ROUTER_INTF_KEY))
        return ret


class L3NATAgentWithStateReport(L3NATAgent):

    def __init__(self, host, conf=None):
        super(L3NATAgentWithStateReport, self).__init__(host=host, conf=conf)
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.PLUGIN)
        self.agent_state = {
            'binary': 'neutron-l3-agent' + cfg.CONF.agent_index,
            'host': host,
            'topic': topics.L3_AGENT,
            'configurations': {
                'agent_mode': self.conf.agent_mode,
            },
            'start_flag': True,
            'agent_type': l3_constants.AGENT_TYPE_L3}
        report_interval = cfg.CONF.AGENT.report_interval
        self.use_call = True
        if report_interval:
            self.heartbeat = loopingcall.FixedIntervalLoopingCall(
                self._report_state)
            self.heartbeat.start(interval=report_interval)

    def _report_state(self):
        LOG.debug(_("Report state task started"))
        num_ex_gw_ports = 0
        router_infos = self.router_info.values()
        num_routers = len(router_infos)
        for ri in router_infos:
            ex_gw_port = self._get_ex_gw_port(ri)
            if ex_gw_port:
                num_ex_gw_ports += 1

        configurations = self.agent_state['configurations']
        configurations['routers'] = num_routers
        configurations['ex_gw_ports'] = num_ex_gw_ports
        configurations['virtual_ip'] = self.virtual_ip
        configurations['virtual_mac'] = self.virtual_mac
        try:
            self.state_rpc.report_state(self.context, self.agent_state,
                                        self.use_call)
            self.agent_state.pop('start_flag', None)
            self.use_call = False
            LOG.debug(_("Report state task successfully completed"))
        except AttributeError:
            # This means the server does not support report_state
            LOG.warn(_("Neutron server does not support state report."
                       " State report for this agent will be disabled."))
            self.heartbeat.stop()
            return
        except Exception:
            LOG.exception(_("Failed reporting state!"))
        
        self._l2_report_state()


    def agent_updated(self, context, payload):
        """Handle the agent_updated notification event."""
        self.fullsync = True
        LOG.info(_("agent_updated by server side %s!"), payload)


def _register_opts(conf):
    conf.register_opts(L3NATAgent.OPTS)
    conf.register_opts(L2HighNeutronAgent.OPTS)
    config.register_agent_state_opts_helper(conf)
    conf.register_opts(external_process.OPTS)
    config.register_root_helper(conf)



def main(manager='neutron.agent.l3_highperformance_agent.L3NATAgentWithStateReport'):
    _register_opts(cfg.CONF)
    common_config.init(sys.argv[1:])
    config.setup_logging()
    server = neutron_service.Service.create(
        binary='neutron-l3-agent',
        topic=topics.L3_AGENT,
        report_interval=cfg.CONF.AGENT.report_interval,
        manager=manager)
    service.launch(server).wait()

