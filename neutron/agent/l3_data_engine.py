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

import copy
import datetime
import eventlet
import json
import os
import socket
import struct
import sys
import time

eventlet.monkey_patch()

from oslo.config import cfg
import Queue

from neutron.agent.common import config
from neutron.agent.linux import external_process
from neutron.agent.linux import interface
from neutron.agent.linux import ovs_lib
from neutron.agent.linux import utils
from neutron.agent import rpc as agent_rpc
from neutron.common import config as common_config
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.common import utils as uts
from neutron import context
from neutron import manager
from neutron.openstack.common import log as logging
from neutron.openstack.common import loopingcall
from neutron.openstack.common import periodic_task
from neutron.openstack.common import service
from neutron.openstack.common import timeutils
from neutron import service as neutron_service

LOG = logging.getLogger(__name__)

RPC_LOOP_INTERVAL = 1
# Lower value is higher priority
PRIORITY_RPC = 0
PRIORITY_SYNC_ROUTERS_TASK = 1

# Various tables for br-gw flows
GW_ROOT = 0
GW_ARP_IP_REC = 2
GW_LEARN_FROM_ARP = 5
GW_FILTER = 7
GW_MARK_MOD = 8
GW_ARP_RESPONSE = 15
GW_DST_MAC_MOD = 17
GW_DROP = 30

# Various tables for br-tun flows
TUN_ROOT = 0
TUN_VLAN_MOD = 3
TUN_DVR_REC = 9
TUN_ROUTE_DISPATCH = 12
TUN_SRC_MAC_MOD = 18
TUN_DST_MAC_MOD = 20

# Protocol name constants
IP = 'ip'
ARP = 'arp'

# Network Type constants
TYPE_VXLAN = 'vxlan'

# Port names
TUN_PEER_PATCH_PORT = 'pt'
GW_PEER_PATCH_PORT = 'pg'
PHY_TO_GW_PATCH_PORT = 'pcps'
GW_TO_PHY_PATCH_PORT = 'pgw'
TUN_VTEP_PORT = 'vxlan-l3-engine'
VTEP_DEV = 'tunnel_bearing'

# keepalived info
KEEPALIVED_CFG = '/etc/keepalived/keepalived.conf'
KEEPALIVED_CFG_FILE = '/etc/keepalived'
MASTER_SCRIPT_PATH = '/etc/neutron/neutron-l3-data-engine/notify_master.sh'
BACKUP_SCRIPT_PATH = '/etc/neutron/neutron-l3-data-engine/notify_backup.sh'
FAULT_SCRIPT_PATH = '/etc/neutron/neutron-l3-data-engine/notify_fault.sh'
PORTS_FILE = '/usr/bin/ports_info'
NETWORKS_FILE = "/etc/huawei/fusionsphere/cps.network-client/cfg/cps.network-client.cfg"
keepalived_cfg_head = "! Configuration File for keepalived\n\n"

# ha info
KEEPALIVED_STATE_FILE = '/etc/keepalived/state'
MASTER = 'master'
SLAVE = 'backup'


class L3AgentApi(n_rpc.RpcProxy):
    """Agent side of the l3 agent RPC API.

    API version history:
        1.0 - Initial version.
        1.1 - Floating IP operational status updates
        1.2 - DVR support: new L3 plugin methods added.
              - get_ports_by_subnet
              - get_agent_gateway_port
              Needed by the agent when operating in DVR/DVR_SNAT mode
        1.3 - Get the list of activated services

    """

    BASE_RPC_API_VERSION = '1.0'

    def __init__(self, topic, host):
        super(L3AgentApi, self).__init__(
            topic=topic, default_version=self.BASE_RPC_API_VERSION)
        self.host = host

    def get_routers(self, context):
        """Make a remote process call to retrieve the sync data for routers."""
        return self.call(context,
                         self.make_msg('get_routers'))

    def get_init_info(self, context, data):
        """Call the plugin update floating IPs's operational status."""
        return self.call(context,
                         self.make_msg('get_init_info', data=data))

    def report_state(self, context, data):
        return self.call(context,
                         self.make_msg('report_state', data=data))


class RouterUpdate(object):
    """Encapsulates a router update

    An instance of this object carries the information necessary to prioritize
    and process a request to update a router.
    """
    def __init__(self, router_id, priority, data,
                 action=None, router=None, timestamp=None):
        self.priority = priority
        self.timestamp = timestamp
        if not timestamp:
            self.timestamp = timeutils.utcnow()
        self.id = router_id
        self.data = data
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


class KeepalivedProcess(object):
    def __init__(self, root_helper, local_ip, priority, conf=None):
        self.conf = conf
        self.virtual_router_id = self.conf.agent_index
        self.physical_bridge = self.conf.physical_bridge
        self.virtual_ip = self.conf.virtual_ip
        self.virtual_mac = self.conf.virtual_mac
        self.root_helper = root_helper
        self.local_vtep_ip = local_ip
        self.vtep_dev = VTEP_DEV
        self.vip_dev = self.conf.gateway_bridge
        self.priority = priority
        LOG.debug(_("agent priority is %s"), self.priority)

    def create_keepalived_cfg(self):
        try:
            config_file = KEEPALIVED_CFG
            cmd = ["rm", config_file]
            utils.execute(cmd, root_helper=self.root_helper)
        except Exception, e:
            LOG.error(_("except info:%s"), e)

        cmd = ["chown","openstack:openstack", KEEPALIVED_CFG_FILE]
        utils.execute(cmd, root_helper=self.root_helper)

        LOG.info(_("begin create keep alived cfg file"))

        msg = keepalived_cfg_head

        tmp = "vrrp_sync_group VG_%s {\n" % self.virtual_router_id
        msg += tmp

        tmp = "    group {\n"
        msg += tmp
        tmp = "        VR_%s\n" % self.virtual_router_id
        msg += tmp
        tmp = "    }\n"
        msg += tmp

        tmp = "    notify_master %s\n" % MASTER_SCRIPT_PATH
        msg += tmp
        tmp = "    notify_backup %s\n" % BACKUP_SCRIPT_PATH
        msg += tmp
        tmp = "    notify_fault %s\n" % FAULT_SCRIPT_PATH
        msg += tmp

        tmp = "}\n\n"
        msg += tmp

        tmp = "global_defs {\n"
        msg += tmp
        tmp = "    router_id LVS_DEVEL\n"
        msg += tmp
        tmp = "}\n\n"
        msg += tmp

        tmp = "vrrp_instance VR_%s {\n" % self.virtual_router_id
        msg += tmp
        tmp = "    state BACKUP\n"
        msg += tmp
        tmp = "    nopreempt\n"
        msg += tmp
        tmp = "    interface %s\n" % self.physical_bridge
        msg += tmp
        tmp = "    priority %s\n" % self.priority
        msg += tmp
        tmp = "    virtual_router_id %s\n" % self.virtual_router_id
        msg += tmp
        tmp = "    advert_int 1\n"
        msg += tmp
        tmp = "    virtual_ipaddress {\n"
        msg += tmp
        tmp = "        %s dev %s \n" % (self.local_vtep_ip, self.vtep_dev)
        msg += tmp
        tmp = "        %s dev %s \n" % (self.virtual_ip, self.vip_dev)
        msg += tmp
        tmp = "    }\n"
        msg += tmp
        tmp = "}\n"
        msg += tmp

        utils.replace_file(config_file, msg)

    def start_keepalived(self):
        cmd = ["chown","openstack:openstack", MASTER_SCRIPT_PATH]
        utils.execute(cmd, root_helper=self.root_helper)
        cmd = ["chmod","750", MASTER_SCRIPT_PATH]
        utils.execute(cmd, root_helper=self.root_helper)

        cmd = ["chown","openstack:openstack", BACKUP_SCRIPT_PATH]
        utils.execute(cmd, root_helper=self.root_helper)
        cmd = ["chmod","750", BACKUP_SCRIPT_PATH]
        utils.execute(cmd, root_helper=self.root_helper)

        cmd = ["chown","openstack:openstack", FAULT_SCRIPT_PATH]
        utils.execute(cmd, root_helper=self.root_helper)
        cmd = ["chmod","750", FAULT_SCRIPT_PATH]
        utils.execute(cmd, root_helper=self.root_helper)

        cmd = ["service", "keepalived", "restart"]
        utils.execute(cmd, root_helper=self.root_helper)


class L3DataEngine(manager.Manager):
    """Manager for L3NatAgent

        API version history:
        1.0 initial Version
        1.1 changed the type of the routers parameter
            to the routers_updated method.
            It was previously a list of routers in dict format.
            It is now a list of router IDs only.
            Per rpc versioning rules,  it is backwards compatible.
        1.2 - DVR support: new L3 agent methods added.
              - add_arp_entry
              - del_arp_entry
              Needed by the L3 service when dealing with DVR
    """
    RPC_API_VERSION = '1.2'

    # Update router actions
    ROUTER_INTERFACE_ADD = "router_interface_add"
    ROUTER_INTERFACE_DELETE = "router_interface_delete"
    ROUTER_ROUTE_ADD = "router_route_add"
    ROUTER_ROUTE_DELETE = "router_route_delete"
    ROUTER_GATEWAY_ADD = "router_gateway_add"
    ROUTER_GATEWAY_DELETE = "router_gateway_delete"
    ARP_FLOWS_ADD = "arp_flows_add"
    ARP_FLOW_DELETE = "arp_flows_delete"
    DELETE_ALL_FLOWS = "delete_all_flows"

    OPTS = [
        cfg.StrOpt('gateway_bridge', default='br-gw',
                   help=_("Name of bridge uesd for gateway")),
        cfg.StrOpt('tunnel_bridge', default='br-tun',
                   help=_("Name of bridge used for tunnel")),
        cfg.StrOpt('physical_bridge', default='brcps',
                   help=_("Name of bridge used for physical network")),
        cfg.StrOpt('external_physical_port', default='',
                   help=_("A physical ethernet added to gateway_bridge")),
        cfg.StrOpt('virtual_ip', default='169.254.192.2/24',
                   help=_("Virtual ip address")),
        cfg.StrOpt('virtual_mac', default='',
                   help=_("Virtual mac address")),
        cfg.StrOpt('agent_index', default='',
                   help=_("The index of l3 high-performance agent")),
        cfg.StrOpt('vlan_ranges', default='',
                   help=_("The ext net vlan ranges of l3 high-performance agent"))
    ]

    def __init__(self, host, conf=None):
        if conf:
            self.conf = conf
        else:
            self.conf = cfg.CONF
        self.root_helper = config.get_root_helper(self.conf)

        self.local_ip = ""
        self.dvr_base_mac = ""
        self.ha_state = SLAVE
        self.tunnel_ofport = -1
        self.patch_gw_ofport = -1
        self.patch_tun_ofport = -1
        self.physical_ofport = -1
        self.patch_gw_brcps_ofport = -1
        self.patch_brcps_gw_ofport = -1

        self.tun_br = ovs_lib.OVSBridge(self.conf.tunnel_bridge, self.root_helper)
        self.gw_br = ovs_lib.OVSBridge(self.conf.gateway_bridge, self.root_helper)
        self.phy_br = ovs_lib.OVSBridge(self.conf.physical_bridge, self.root_helper)

        self.setup_tunnel_br()
        self.setup_gateway_br()

        self.context = context.get_admin_context_without_session()
        self.agent_rpc = L3AgentApi(
            '%s-%s' % (topics.L3_HIGTPERFORMANCE_AGNET,
                       self.conf.agent_index),
            host)

        self.fullsync = True
        self.routersync = True
        self.sync_progress = False

        # dvr data
        self.agent_gateway_port = {}
        self.extra_route_map = {}

        self._queue = RouterProcessingQueue()
        super(L3DataEngine, self).__init__()

    def delete_all_flows(self, context, data):
        LOG.debug(_("rpc:delete_all_flows"))
        update = RouterUpdate(None, PRIORITY_SYNC_ROUTERS_TASK, data, action=self.DELETE_ALL_FLOWS)
        self._queue.add(update)

    def router_interface_add(self, context, data):
        LOG.debug(_("rpc:router_interface_add %s"), data)
        router_id = data.get("router_id")
        update = RouterUpdate(router_id, PRIORITY_RPC, data, action=self.ROUTER_INTERFACE_ADD)
        self._queue.add(update)

    def router_interface_delete(self, context, data):
        LOG.debug(_("rpc:router_interface_delete %s"), data)
        router_id = data.get("router_id")
        update = RouterUpdate(router_id, PRIORITY_RPC, data, action=self.ROUTER_INTERFACE_DELETE)
        self._queue.add(update)

    def router_route_add(self, context, data):
        LOG.debug(_("rpc:router_route_add %s"), data)
        router_id = data.get("router_id")
        update = RouterUpdate(router_id, PRIORITY_RPC, data, action=self.ROUTER_ROUTE_ADD)
        self._queue.add(update)

    def router_route_delete(self, context, data):
        LOG.debug(_("rpc:router_route_delete %s"), data)
        router_id = data.get("router_id")
        update = RouterUpdate(router_id, PRIORITY_RPC, data, action=self.ROUTER_ROUTE_DELETE)
        self._queue.add(update)

    def router_gateway_add(self, context, data):
        LOG.debug(_("rpc:router_gateway_add %s"), data)
        router_id = data.get("router_id")
        update = RouterUpdate(router_id, PRIORITY_RPC, data, action=self.ROUTER_GATEWAY_ADD)
        self._queue.add(update)

    def router_gateway_delete(self, context, data):
        LOG.debug(_("rpc:router_gateway_delete %s"), data)
        router_id = data.get("router_id")
        update = RouterUpdate(router_id, PRIORITY_RPC, data, action=self.ROUTER_GATEWAY_DELETE)
        self._queue.add(update)

    def arp_flows_add(self, context, data):
        LOG.debug(_("rpc:arp_flows_add %s"), data)
        router_id = None
        update = RouterUpdate(router_id, PRIORITY_RPC, data, action=self.ARP_FLOWS_ADD)
        self._queue.add(update)

    def arp_flows_delete(self, context, data):
        LOG.debug(_("rpc:arp_flows_delete %s"), data)
        router_id = None
        update = RouterUpdate(router_id, PRIORITY_RPC, data, action=self.ARP_FLOW_DELETE)
        self._queue.add(update)

    def _delete_all_flows(self):
        LOG.debug(_("delete all flows begin"))
        self.fullsync = True
        self.routersync = False
        self._sync_routers_task(self.context)
        self.routersync = True

    def _router_interface_add(self, data):
        LOG.debug(_("router interface add begin: %s"), data)
        ext_net = data.get("ext_net_info")
        subnets = data.get("subnets")
        subnet = subnets[0]
        routes = data.get("routes")

        # table3
        self.tun_br.add_flow(table=TUN_VLAN_MOD,
                             priority=1,
                             tun_id=subnet.get("vni"),
                             dl_dst=subnet.get("sg_mac"),
                             actions="mod_vlan_vid:%s,load:%s->OXM_OF_METADATA[],resubmit(,%s)" %
                                     (ext_net.get("vlan"), self._ip_to_hex(ext_net.get("ip")),
                                      TUN_DVR_REC))
        # table18
        for route in routes:
            next_hop = route.get("next_hop")
            if route.get("nw_dst_cidr") == "default":
                continue

            self.tun_br.add_flow(table=TUN_SRC_MAC_MOD,
                                 priority=2,
                                 proto=IP,
                                 dl_vlan=ext_net.get("vlan"),
                                 nw_dst=subnet.get("cidr"),
                                 nw_src=route.get("nw_dst_cidr"),
                                 pkt_mark=self._ip_to_hex(next_hop),
                                 actions="load:%s->OXM_OF_METADATA[],mod_dl_src:%s,resubmit(,%s)" %
                                         (hex(subnet.get("vni")), subnet.get("sg_mac"), TUN_DST_MAC_MOD))

    def _router_interface_delete(self, data):
        LOG.debug(_("router interface delete begin: %s"), data)
        ext_net = data.get("ext_net_info")
        subnets = data.get("subnets")
        subnet = subnets[0]
        routes = data.get("routes")

        # table3
        self.tun_br.delete_flows(table=TUN_VLAN_MOD,
                                 tun_id=subnet.get("vni"),
                                 dl_dst=subnet.get("sg_mac"))
        # table18
        for route in routes:
            next_hop = route.get("next_hop")
            self.tun_br.delete_flows(table=TUN_SRC_MAC_MOD,
                                     proto=IP,
                                     dl_vlan=ext_net.get("vlan"),
                                     nw_dst=subnet.get("cidr"),
                                     nw_src=route.get("nw_dst_cidr"),
                                     pkt_mark=self._ip_to_hex(next_hop))

        # table20 remove vm_ip_mac which belong to this subnet
        self.tun_br.delete_flows(table=TUN_DST_MAC_MOD,
                                 metadata=hex(subnet.get("vni")))

    def _router_route_add(self, data):
        LOG.debug(_("router route add begin: %s"), data)
        ext_net = data.get("ext_net_info")
        subnets = data.get("subnets")
        routes = data.get("routes")

        for route in routes:
            if route.get("nw_dst_cidr") == "default":
                continue

            # table12
            self.tun_br.add_flow(table=TUN_ROUTE_DISPATCH,
                                 priority=2,
                                 proto=IP,
                                 nw_dst=route.get("nw_dst_cidr"),
                                 dl_vlan=ext_net.get("vlan"),
                                 metadata=self._ip_to_hex(ext_net.get("ip")),
                                 actions="load:%s->NXM_NX_PKT_MARK[],output:%s" %
                                         (self._ip_to_hex(route.get("next_hop")), self.patch_tun_ofport))
            # table18
            for subnet in subnets:
                self.tun_br.add_flow(table=TUN_SRC_MAC_MOD,
                                     priority=2,
                                     proto=IP,
                                     dl_vlan=ext_net.get("vlan"),
                                     nw_dst=subnet.get("cidr"),
                                     nw_src=route.get("nw_dst_cidr"),
                                     pkt_mark=self._ip_to_hex(route.get("next_hop")),
                                     actions="load:%s->OXM_OF_METADATA[],mod_dl_src:%s,resubmit(,%s)" %
                                             (hex(subnet.get("vni")), subnet.get("sg_mac"), TUN_DST_MAC_MOD))

    def _router_route_delete(self, data):
        LOG.debug(_("router route delete begin: %s"), data)
        ext_net = data.get("ext_net_info")
        subnets = data.get("subnets")
        routes = data.get("routes")
        for route in routes:
            if route.get("nw_dst_cidr") == "default":
                continue

            # table12
            self.tun_br.delete_flows(table=TUN_ROUTE_DISPATCH,
                                     proto=IP,
                                     nw_dst=route.get("nw_dst_cidr"),
                                     dl_vlan=ext_net.get("vlan"),
                                     metadata=self._ip_to_hex(ext_net.get("ip")))
            # table18
            for subnet in subnets:
                self.tun_br.delete_flows(table=TUN_SRC_MAC_MOD,
                                         proto=IP,
                                         dl_vlan=ext_net.get("vlan"),
                                         nw_dst=subnet.get("cidr"),
                                         nw_src=route.get("nw_dst_cidr"),
                                         pkt_mark=self._ip_to_hex(route.get("next_hop")))

    def _router_gateway_add(self, data):
        LOG.debug(_("router gateway add begin: %s"), data)
        ext_net = data.get("ext_net_info")
        routes = data.get("routes")
        route = routes[0]
        subnets = data.get("subnets")

        # table3 & table18
        for subnet in subnets:
            self.tun_br.add_flow(table=TUN_VLAN_MOD,
                                 priority=1,
                                 tun_id=subnet.get("vni"),
                                 dl_dst=subnet.get("sg_mac"),
                                 actions="mod_vlan_vid:%s,load:%s->OXM_OF_METADATA[],resubmit(,%s)" %
                                         (ext_net.get("vlan"), self._ip_to_hex(ext_net.get("ip")),
                                          TUN_DVR_REC))

            if route.get("nw_dst_cidr") == "default":
                continue
            self.tun_br.add_flow(table=TUN_SRC_MAC_MOD,
                                 priority=1,
                                 proto=IP,
                                 dl_vlan=ext_net.get("vlan"),
                                 nw_dst=subnet.get("cidr"),
                                 nw_src=route.get("nw_dst_cidr"),
                                 pkt_mark=self._ip_to_hex(route.get("next_hop")),
                                 actions="load:%s->OXM_OF_METADATA[],mod_dl_src:%s,resubmit(,%s)" %
                                         (hex(subnet.get("vni")), subnet.get("sg_mac"), TUN_DST_MAC_MOD))

    def _router_gateway_delete(self, data):
        LOG.debug(_("router gateway delete begin: %s"), data)
        ext_net = data.get("ext_net_info")
        routes = data.get("routes")
        subnets = data.get("subnets")

        for subnet in subnets:
            # table3
            self.tun_br.delete_flows(table=TUN_VLAN_MOD,
                                     tun_id=subnet.get("vni"),
                                     dl_dst=subnet.get("sg_mac"))
            # table18
            for route in routes:
                if route.get("nw_dst_cidr") == "default":
                    continue
                self.tun_br.delete_flows(table=TUN_SRC_MAC_MOD,
                                         proto=IP,
                                         dl_vlan=ext_net.get("vlan"),
                                         nw_dst=subnet.get("cidr"),
                                         nw_src=route.get("nw_dst_cidr"),
                                         pkt_mark=self._ip_to_hex(route.get("next_hop")))
            # table20 remove vm_ip_mac which belong to this subnet
            self.tun_br.delete_flows(table=TUN_DST_MAC_MOD,
                                     metadata=hex(subnet.get("vni")))

    def _arp_flows_add(self, data):
        LOG.debug(_("arp flows add begin: %s"), data)
        if not data:
            return

        for single_data in data.values():
            ips = single_data.get("vm_ip")
            vni = single_data.get("vni")
            dl_dst = single_data.get("vm_mac")
            remote_ip = single_data.get("vtep_ip")

            for nw_dst in ips:
                # table20
                self.tun_br.add_flow(table=TUN_DST_MAC_MOD,
                                     priority=2,
                                     proto=IP,
                                     nw_dst=nw_dst,
                                     metadata=hex(vni),
                                     actions="strip_vlan,mod_dl_dst:%s,set_tunnel:%s,"
                                             "set_field:%s->tun_dst,set_field:%s->tun_src,output:%s" %
                                             (dl_dst, vni, remote_ip, self._strip_ip_mask(self.local_ip),
                                              self.tunnel_ofport))

    def _arp_flows_delete(self, data):
        LOG.debug(_("arp flows delete begin: %s"), data)
        for single_data in data.values():
            nw_dst = single_data.get("vm_ip")
            vni = single_data.get("vni")

            # table20
            self.tun_br.delete_flows(table=TUN_DST_MAC_MOD,
                                     proto=IP,
                                     nw_dst=nw_dst,
                                     metadata=hex(vni))

    def _process_router_update(self):
        for rp, update in self._queue.each_update_to_next_router():
            LOG.debug(_("Starting router update for %s"), update.id)
            data = update.data
            action = update.action
            if action == self.DELETE_ALL_FLOWS:
                self._delete_all_flows()
            elif action == self.ROUTER_INTERFACE_ADD:
                self._router_interface_add(data)
            elif action == self.ROUTER_INTERFACE_DELETE:
                self._router_interface_delete(data)
            elif action == self.ROUTER_ROUTE_ADD:
                self._router_route_add(data)
            elif action == self.ROUTER_ROUTE_DELETE:
                self._router_route_delete(data)
            elif action == self.ROUTER_GATEWAY_ADD:
                self._router_gateway_add(data)
            elif action == self.ROUTER_GATEWAY_DELETE:
                self._router_gateway_delete(data)
            elif action == self.ARP_FLOWS_ADD:
                self._arp_flows_add(data)
            elif action == self.ARP_FLOW_DELETE:
                self._arp_flows_delete(data)

            LOG.debug(_("Finished a router update for %s"), update.id)

    def _process_routers_loop(self):
        LOG.debug(_("Starting _process_routers_loop"))
        pool = eventlet.GreenPool(size=8)
        while True:
            pool.spawn_n(self._process_router_update)

    def _router_ids(self):
        if not self.conf.use_namespaces:
            return [self.conf.router_id]

    def periodic_sync_ha_task(self, context):
        while True:
            self._sync_ha_task(context)
            time.sleep(1)

    def _check_keepalived_process(self):
        cmd = ["service", "keepalived", "status"]
        try:
            status = utils.execute(cmd, root_helper=self.root_helper)
        except Exception:
            status = ''
        
        if 'running' not in status:
            LOG.debug(_('Keepalived is not running'))
            cmd = ['ps', '-ewwf', '|', 'grep', '/usr/sbin/keepalived', 
                   '|', 'grep', '-v', 'grep', '|', 'awk', '\'{print $2}\'']
            try:
                output = os.popen(' '.join(cmd))
                pids = output.read()
            except Exception:
                LOG.exception(_('Excute %s failed'), cmd)
                return

            pids = pids.split('\n')
            for pid in pids:
                if pid:
                    LOG.debug(_('Try to kill unactive keepalived process: %s'), pid)
                    try:
                        cmd = ['kill', '-9', pid]
                        utils.execute(cmd, root_helper=self.root_helper)
                    except Exception:
                        LOG.error(_('Kill keepalived process: %s failed'), pid)
            cmd = ["service", "keepalived", "restart"]
            utils.execute(cmd, root_helper=self.root_helper)
            
    def _sync_ha_task(self, context):
        try:
            before = timeutils.utcnow()
            LOG.debug(_("Sync ha task begin: %s"), before)

            br_gw = self.conf.gateway_bridge
            cmd = ['cat', KEEPALIVED_STATE_FILE]
            state = utils.execute(cmd, root_helper=self.root_helper)
            
            self._check_keepalived_process()
            
            if state == MASTER:
                if self.ha_state == SLAVE:
                    LOG.debug(_("HA mode change to MASTER"))
                    self.ha_state = MASTER

                # add table2 flow
                cmd = ["ovs-ofctl", "dump-flows", br_gw, "table=%s,%s" % (GW_ARP_IP_REC, IP)]
                flows = utils.execute(cmd, root_helper=self.root_helper)
                if "ip" not in flows:
                    self.gw_br.add_flow(table=GW_ARP_IP_REC,
                                        priority=1,
                                        proto=IP,
                                        actions="resubmit(,%s)" % GW_FILTER)
                # del table15 flow
                cmd = ["ovs-ofctl", "dump-flows", br_gw, "table=%s" % GW_ARP_RESPONSE]
                flows = utils.execute(cmd, root_helper=self.root_helper)
                if "priority=2 actions=drop" in flows:
                    cmd = ["ovs-ofctl", "--strict", "del-flows", br_gw, "table=%s,priority=2" % GW_ARP_RESPONSE]
                    utils.execute(cmd, root_helper=self.root_helper)

                # set port ip
                cmd = ["ip", "-f", "inet", "addr", "show", br_gw]
                ip = utils.execute(cmd, root_helper=self.root_helper)
                match = " " + self.conf.virtual_ip + " "
                if match not in ip:
                    cmd = ["ifconfig", br_gw, self.conf.virtual_ip]
                    utils.execute(cmd, root_helper=self.root_helper)
                cmd = ["ip", "-f", "inet", "addr", "show", VTEP_DEV]
                ip = utils.execute(cmd, root_helper=self.root_helper)
                match = " " + self.local_ip + " "
                if match not in ip:
                    cmd = ["ifconfig", VTEP_DEV, self.local_ip]
                    utils.execute(cmd, root_helper=self.root_helper)

                # set ip rule & table
                ports_info = self._load_json_file(PORTS_FILE)
                gateway_ip = self._get_gateway_ip(ports_info)
                networks_info = self._load_json_file(NETWORKS_FILE)
                subnet = self._get_subnet(networks_info)
                vtep_ip = self._strip_ip_mask(self.local_ip)

                LOG.debug(_("gateway_ip is %s, subnet is %s"), gateway_ip, subnet)
                if gateway_ip:
                    cmd = ["ip", "rule"]
                    ip_rules = utils.execute(cmd, root_helper=self.root_helper)
                    match = "from %s lookup %s" % (vtep_ip, VTEP_DEV)
                    if match not in ip_rules:
                        cmd = ["ip", "rule", "add", "from", vtep_ip, "table", VTEP_DEV]
                        utils.execute(cmd, root_helper=self.root_helper)
                    cmd = ["ip", "route", "show", "table", VTEP_DEV]
                    ip_routes = utils.execute(cmd, root_helper=self.root_helper)
                    match = "default via %s dev %s" % (gateway_ip, VTEP_DEV)
                    if match not in ip_routes:
                        cmd = ["ip", "route", "add", "default", "via", gateway_ip, "dev", VTEP_DEV, "table", VTEP_DEV]
                        utils.execute(cmd, root_helper=self.root_helper)
                    match = "%s dev %s  scope link" % (subnet, VTEP_DEV)
                    if match not in ip_routes:
                        LOG.debug(_("add subnet gateway"))
                        cmd = ["ip", "route", "add", subnet, "dev", "tunnel_bearing",
                               "scope", "link", "table", VTEP_DEV]
                        utils.execute(cmd, root_helper=self.root_helper)
                else:
                    cmd = ["ip", "rule"]
                    ip_rules = utils.execute(cmd, root_helper=self.root_helper)
                    match = "from %s lookup %s" % (vtep_ip, VTEP_DEV)
                    if match in ip_rules:
                        cmd = ["ip", "rule", "del", "from", vtep_ip, "lookup", VTEP_DEV]
                        utils.execute(cmd, root_helper=self.root_helper)
            elif state == SLAVE:
                if self.ha_state == MASTER:
                    LOG.debug(_("HA mode change to SLAVE"))
                    self.ha_state = SLAVE

                # del table2 flow
                cmd = ["ovs-ofctl", "dump-flows", br_gw, "table=%s,%s" % (GW_ARP_IP_REC, IP)]
                flows = utils.execute(cmd, root_helper=self.root_helper)
                if "ip" in flows:
                    self.gw_br.delete_flows(table=GW_ARP_IP_REC,
                                            proto=IP)
                # add table15 flow
                cmd = ["ovs-ofctl", "dump-flows", br_gw, "table=%s" % GW_ARP_RESPONSE]
                flows = utils.execute(cmd, root_helper=self.root_helper)
                if "priority=2 actions=drop" not in flows:
                    self.gw_br.add_flow(table=GW_ARP_RESPONSE,
                                        priority=2,
                                        actions="DROP")

                # clear port ip
                cmd = ["ip", "-f", "inet", "addr", "show", br_gw]
                ip = utils.execute(cmd, root_helper=self.root_helper)
                if ip:
                    cmd = ["ifconfig", br_gw, 0]
                    utils.execute(cmd, root_helper=self.root_helper)
                cmd = ["ip", "-f", "inet", "addr", "show", VTEP_DEV]
                ip = utils.execute(cmd, root_helper=self.root_helper)
                if ip:
                    cmd = ["ifconfig", VTEP_DEV, 0]
                    utils.execute(cmd, root_helper=self.root_helper)
            else:
                LOG.exception(_("Unknown HA role"))
                return

            after = timeutils.utcnow()
            LOG.debug(_("Time used: %s"), after - before)
        except Exception:
            LOG.exception(_("Failed to sync ha task"))

    @periodic_task.periodic_task
    def periodic_sync_routers_task(self, context):
        self._sync_routers_task(context)

    def _sync_routers_task(self, context):
        LOG.debug(_("Starting _sync_routers_task - fullsync:%s"),
                  self.fullsync)
        if not self.fullsync:
            return

        try:
            self.local_ip, self.dvr_base_mac, self.priority = self.agent_rpc.get_init_info(context, uts.get_hostname())
            LOG.debug(_("sync task:local_ip is %s, dvr_base_mac is %s, priority is %s"),
                      self.local_ip, self.dvr_base_mac, self.priority)

            # rebuild default flows
            self.tun_br.remove_all_flows()
            self.gw_br.remove_all_flows()
            self.setup_tunnel_flows()
            self.setup_gateway_flows()
            self.setup_default_flows()

            try:
                self.keepalived_pro = KeepalivedProcess(self.root_helper, self.local_ip, self.priority, conf=self.conf)
                self.keepalived_pro.create_keepalived_cfg()
                self.keepalived_pro.start_keepalived()
            except Exception, e:
                LOG.error(_("start keepalived failed : %s"), e)

            if self.routersync:
                timestamp = timeutils.utcnow()

                # l3_agent will send vm_ip_mac while get_routers
                routers = self.agent_rpc.get_routers(context)
                LOG.debug(_('Processing :%r'), routers)
                for r in routers:
                    if not r.get("ext_net_info"):
                        continue

                    subnets = r.get("subnets")
                    for subnet in subnets:
                        temp = copy.deepcopy(r)
                        temp["subnets"] = [subnet]

                        update = RouterUpdate(r.get("router_id"),
                                              PRIORITY_SYNC_ROUTERS_TASK,
                                              temp,
                                              action=self.ROUTER_INTERFACE_ADD,
                                              timestamp=timestamp)
                        self._queue.add(update)

                    routes = r.get("routes")
                    for route in routes:
                        temp = copy.deepcopy(r)
                        temp["routes"] = [route]
                        temp["subnets"] = []

                        update = RouterUpdate(r.get("router_id"),
                                              PRIORITY_SYNC_ROUTERS_TASK,
                                              temp,
                                              action=self.ROUTER_ROUTE_ADD,
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

    @staticmethod
    def _ip_to_hex(ip):
        return str(hex(struct.unpack("!I", socket.inet_aton(ip))[0])).replace("L", "")

    @staticmethod
    def _mac_to_hex(mac):
        return "0x" + mac.upper().replace(":", "")

    @staticmethod
    def _strip_ip_mask(cidr):
        return cidr.split("/").pop(0)

    @staticmethod
    def _get_subnet(networks_info):
        subnet = ''
        sysintfnws = networks_info['sysintfnw']
        for sysintf in sysintfnws:
            if sysintf.get('name') == VTEP_DEV:
                subnet = sysintf.get('subnet')
                break
        return subnet

    @staticmethod
    def _get_gateway_ip(ports_info):
        gateway_ip = ''
        system_inf = ports_info['systemIntfInfo']
        internal_data = system_inf.get('tunnel_bearing', None)
        if internal_data:
            gateway_ip = internal_data.get('gateway', '')
        return gateway_ip

    @staticmethod
    def _load_json_file(filename):
        json_file = open(filename)
        try:
            json_dict = json.load(json_file)
        except Exception, e:
            LOG.error("exception occured when parser the json file, %s " % e)
            json_dict = {}
        json_file.close()
        return json_dict

    def after_start(self):
        eventlet.spawn_n(self._process_routers_loop)
        eventlet.spawn_n(self.periodic_sync_ha_task, self.context)
        self._sync_routers_task(self.context)
        LOG.info(_("L3 data engine started"))

    def setup_tunnel_br(self):
        LOG.debug(_("setup tunnel bridge begin"))
        self.tun_br.create()
        self.tunnel_ofport = \
            self.tun_br.add_tunnel_port(TUN_VTEP_PORT, "flow", "flow", TYPE_VXLAN)

    def setup_gateway_br(self):
        LOG.debug(_("setup gateway bridge begin"))
        self.gw_br.create()
        self.patch_gw_brcps_ofport = \
            self.gw_br.add_patch_port(GW_TO_PHY_PATCH_PORT, PHY_TO_GW_PATCH_PORT)
        self.patch_brcps_gw_ofport = \
            self.phy_br.add_patch_port(PHY_TO_GW_PATCH_PORT, GW_TO_PHY_PATCH_PORT)
        self.patch_gw_ofport = \
            self.gw_br.add_patch_port(GW_PEER_PATCH_PORT, TUN_PEER_PATCH_PORT)
        self.patch_tun_ofport = \
            self.tun_br.add_patch_port(TUN_PEER_PATCH_PORT, GW_PEER_PATCH_PORT)

        if int(self.patch_gw_brcps_ofport) < 0 or int(self.patch_brcps_gw_ofport) < 0:
            LOG.error(_("Failed to create gw-brcps patch port."))

        if int(self.patch_gw_ofport) < 0 or int(self.patch_tun_ofport) < 0:
            LOG.error(_("Failed to create gw-tun patch port"))

    def setup_tunnel_flows(self):
        # add-flows for br-tun
        LOG.debug(_("setup tunnel bridge default flows begin"))
        self.tun_br.add_flow(priority=0,
                             in_port=self.tunnel_ofport,
                             actions="drop")
        self.tun_br.add_flow(priority=1,
                             in_port=self.patch_tun_ofport,
                             actions="resubmit(,%s)" % TUN_SRC_MAC_MOD)
        self.tun_br.add_flow(table=TUN_VLAN_MOD,
                             priority=0,
                             proto=ARP,
                             actions="resubmit(,%s)" % TUN_DVR_REC)
        self.tun_br.add_flow(table=TUN_DVR_REC,
                             priority=0,
                             actions="drop")
        self.tun_br.add_flow(table=TUN_ROUTE_DISPATCH,
                             priority=0,
                             actions="drop")

    def setup_gateway_flows(self):
        # add-flows for br-gw
        LOG.debug(_("setup gateway bridge default flows begin"))
        self.gw_br.add_flow(priority=1,
                            in_port=self.patch_gw_ofport,
                            actions="resubmit(,%s)" % GW_DST_MAC_MOD)
        self.gw_br.add_flow(priority=1,
                            in_port=self.patch_gw_brcps_ofport,
                            actions="resubmit(,%s)" % GW_ARP_IP_REC)
        self.gw_br.add_flow(table=GW_ARP_IP_REC,
                            priority=2,
                            proto=ARP,
                            actions="load:%s->OXM_OF_METADATA[32..63],resubmit(,%s)"
                                    % (hex(int(self.patch_gw_ofport)), GW_LEARN_FROM_ARP))
        self.gw_br.add_flow(table=GW_ARP_IP_REC,
                            priority=1,
                            proto=IP,
                            actions="resubmit(,%s)" % GW_FILTER)
        self.gw_br.add_flow(table=GW_FILTER,
                            priority=0,
                            actions="drop")
        self.gw_br.add_flow(table=GW_ARP_RESPONSE,
                            priority=0,
                            actions="drop")
        self.gw_br.add_flow(table=GW_DROP,
                            priority=0,
                            actions="drop")
        self.gw_br.add_flow(table=GW_FILTER,
                            priority=1,
                            dl_dst=self.conf.virtual_mac,
                            actions="resubmit(,%s)" % GW_MARK_MOD)
        self.gw_br.add_flow(table=GW_ARP_RESPONSE,
                            priority=1,
                            proto=ARP,
                            actions="move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],"
                                    "mod_dl_src:%s,"
                                    "load:0x2->NXM_OF_ARP_OP[],"
                                    "move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],"
                                    "move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],"
                                    "load:%s->NXM_NX_ARP_SHA[],"
                                    "move:OXM_OF_METADATA[0..31]->NXM_OF_ARP_SPA[],"
                                    "IN_PORT" %
                                    (self.conf.virtual_mac, self._mac_to_hex(self.conf.virtual_mac)))

        learn17from5 = ("table=%s,"
                        "priority=2,"
                        "NXM_NX_PKT_MARK[]=NXM_OF_ARP_SPA[],"
                        "NXM_OF_VLAN_TCI[]=NXM_OF_VLAN_TCI[],"
                        "load:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],"
                        "load:%s->NXM_OF_ETH_SRC[],"
                        "load:%s->NXM_NX_PKT_MARK[],"
                        "output:NXM_OF_IN_PORT[]" %
                        (GW_DST_MAC_MOD, self._mac_to_hex(self.conf.virtual_mac), hex(0)))
        learn8from5 = ("table=%s,"
                       "priority=2,"
                       "NXM_OF_VLAN_TCI[]=NXM_OF_VLAN_TCI[],"
                       "NXM_OF_ETH_SRC[]=NXM_OF_ETH_SRC[],"
                       "load:NXM_OF_ARP_SPA[]->NXM_NX_PKT_MARK[],"
                       "output:OXM_OF_METADATA[32..63]" % GW_MARK_MOD)
        self.gw_br.add_flow(table=GW_LEARN_FROM_ARP,
                            priority=2,
                            proto=ARP,
                            arp_tpa=self._strip_ip_mask(self.conf.virtual_ip),
                            actions="learn(%s),"
                                    "learn(%s),"
                                    "move:NXM_OF_ARP_TPA[]->OXM_OF_METADATA[0..31],resubmit(,%s)" %
                                    (learn17from5, learn8from5, GW_ARP_RESPONSE))
        self.gw_br.add_flow(table=GW_LEARN_FROM_ARP,
                            priority=1,
                            proto=ARP,
                            actions="learn(%s),"
                                    "learn(%s),"
                                    "resubmit(,%s)" %
                                    (learn17from5, learn8from5, GW_DROP))

    def setup_default_flows(self):
        LOG.debug(_("setup default flows begin"))
        # table0
        self.tun_br.add_flow(priority=1,
                             in_port=self.tunnel_ofport,
                             tun_dst=self._strip_ip_mask(self.local_ip),
                             actions="resubmit(,%s)" % TUN_VLAN_MOD)
        # table9
        self.tun_br.add_flow(table=TUN_DVR_REC,
                             priority=1,
                             dl_src=self.dvr_base_mac,
                             actions="resubmit(,%s)" % TUN_ROUTE_DISPATCH)


class L3DataEngineWithStateReport(L3DataEngine):

    def __init__(self, host, conf=None):
        super(L3DataEngineWithStateReport, self).__init__(host=host, conf=conf)
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.PLUGIN)
        self.agent_state = {
            'virtual_ip': self.conf.virtual_ip,
            'virtual_mac': self.conf.virtual_mac
        }
        report_interval = cfg.CONF.AGENT.report_interval
        if report_interval:
            self.heartbeat = loopingcall.FixedIntervalLoopingCall(
                self._report_state)
            self.heartbeat.start(interval=report_interval)

    def _report_state(self):
        LOG.debug(_("Report state task started"))
        try:
            self.agent_rpc.report_state(self.context, self.agent_state)
            LOG.debug(_("Report state task successfully completed"))
        except Exception:
            LOG.exception(_("Failed reporting state!"))
            self.fullsync = True

    def agent_updated(self, context, payload):
        """Handle the agent_updated notification event."""
        self.fullsync = True
        LOG.info(_("agent_updated by server side %s!"), payload)


def _register_opts(conf):
    conf.register_opts(L3DataEngine.OPTS)
    config.register_interface_driver_opts_helper(conf)
    config.register_use_namespaces_opts_helper(conf)
    config.register_agent_state_opts_helper(conf)
    config.register_root_helper(conf)
    conf.register_opts(interface.OPTS)
    conf.register_opts(external_process.OPTS)


def main(manager='neutron.agent.l3_data_engine.L3DataEngineWithStateReport'):
    _register_opts(cfg.CONF)
    common_config.init(sys.argv[1:])
    config.setup_logging()
    server = neutron_service.Service.create(
        binary='neutron-l3-data-engine',
        topic='%s-%s' % (topics.L3_DATAENGINE,
                         cfg.CONF.agent_index),
        report_interval=cfg.CONF.AGENT.report_interval,
        manager=manager)
    service.launch(server).wait()

