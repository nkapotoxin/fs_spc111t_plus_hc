'''
Created on 2014-5-23
'''

import sys

import datetime
import eventlet
eventlet.monkey_patch()

import netaddr
import os
from oslo.config import cfg
from oslo import messaging
import Queue
import random
import socket
import time

from neutron.agent.common import config
from neutron.agent import l3_ha_agent
from neutron.agent.linux import external_process
from neutron.agent.linux import interface
from neutron.agent.linux import ip_lib
from neutron.agent import rpc as agent_rpc
from neutron.common import config as common_config
from neutron.common import constants as l3_constants
from neutron.common import ipv6_utils
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
from neutron.openstack.common import jsonutils
from neutron import service as neutron_service
from neutron.services.firewall.agents.l3reference import firewall_l3_proxy

from neutron.plugins.l2_proxy.agent import neutron_proxy_context
from neutron.plugins.l2_proxy.agent import clients
from neutronclient.common import exceptions

LOG = logging.getLogger(__name__)
NS_PREFIX = 'qrouter-'
INTERNAL_DEV_PREFIX = 'qr-'
EXTERNAL_DEV_PREFIX = 'qg-'
SNAT_INT_DEV_PREFIX = 'sg-'
FIP_NS_PREFIX = 'fip-'
SNAT_NS_PREFIX = 'snat-'
FIP_2_ROUTER_DEV_PREFIX = 'fpr-'
ROUTER_2_FIP_DEV_PREFIX = 'rfp-'
FIP_EXT_DEV_PREFIX = 'fg-'
FIP_LL_SUBNET = '169.254.30.0/23'
# Route Table index for FIPs
FIP_RT_TBL = 16
# Rule priority range for FIPs
FIP_PR_START = 32768
FIP_PR_END = FIP_PR_START + 40000
RPC_LOOP_INTERVAL = 1
FLOATING_IP_CIDR_SUFFIX = '/32'
# Lower value is higher priority
PRIORITY_RPC = 0
PRIORITY_SYNC_ROUTERS_TASK = 1
DELETE_ROUTER = 1

AGENTS_SCHEDULER_OPTS = [
    cfg.IntOpt('dhcp_agents_per_network', default=2,
               help=_('Number of DHCP agents scheduled to host a network.')),
]

class L3PluginApi(n_rpc.RpcProxy):
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
        super(L3PluginApi, self).__init__(
            topic=topic, default_version=self.BASE_RPC_API_VERSION)
        self.host = host

    def get_routers(self, context, router_ids=None):
        """Make a remote process call to retrieve the sync data for routers."""
        return self.call(context,
                         self.make_msg('sync_routers', host=self.host,
                                       router_ids=router_ids))

    def get_external_network_id(self, context):
        """Make a remote process call to retrieve the external network id.

        @raise n_rpc.RemoteError: with TooManyExternalNetworks as
                                  exc_type if there are more than one
                                  external network
        """
        return self.call(context,
                         self.make_msg('get_external_network_id',
                                       host=self.host))

    def update_floatingip_statuses(self, context, router_id, fip_statuses):
        """Call the plugin update floating IPs's operational status."""
        return self.call(context,
                         self.make_msg('update_floatingip_statuses',
                                       router_id=router_id,
                                       fip_statuses=fip_statuses),
                         version='1.1')

    def get_ports_by_subnet(self, context, subnet_id):
        """Retrieve ports by subnet id."""
        return self.call(context,
                         self.make_msg('get_ports_by_subnet', host=self.host,
                                       subnet_id=subnet_id),
                         topic=self.topic,
                         version='1.2')

    def get_agent_gateway_port(self, context, fip_net):
        """Get or create an agent_gateway_port."""
        return self.call(context,
                         self.make_msg('get_agent_gateway_port',
                                       network_id=fip_net, host=self.host),
                         topic=self.topic,
                         version='1.2')

    def get_service_plugin_list(self, context):
        """Make a call to get the list of activated services."""
        return self.call(context,
                         self.make_msg('get_service_plugin_list'),
                         topic=self.topic,
                         version='1.3')
    
    def update_router_extern_ip_map(self, context, router_id, gateway_ip):
        """update router and extern ip mapping"""
        return self.call(context,
                         self.make_msg('update_router_extern_ip_map',
                                       router_id=router_id, host=self.host,
                                       gateway_ip=gateway_ip),
                         topic=self.topic,
                         version='1.2')

    def get_extra_routes_by_subnet(self, context, router_id, subnet_id, gw_port_id=None):
        """get extra routes for router by subnet id"""
        return self.call(context,
                         self.make_msg('get_extra_routes_by_subnet',
                                       router_id=router_id, host=self.host,
                                       subnet_id=subnet_id,
                                       gw_port_id=gw_port_id),
                         topic=self.topic,
                         version='1.2')

    def get_network_binding_host(self, context, router_id, networks):
        """get network binding host by network id"""
        return self.call(context,
                         self.make_msg('get_network_binding_host',
                                       networks=networks, host=self.host,
                                        router_id=router_id),
                         topic=self.topic,
                         version='1.2')

class LinkLocalAddressPair(netaddr.IPNetwork):
    def __init__(self, addr):
        super(LinkLocalAddressPair, self).__init__(addr)

    def get_pair(self):
        """Builds an address pair from the first and last addresses. """
        return (netaddr.IPNetwork("%s/%s" % (self.network, self.prefixlen)),
                netaddr.IPNetwork("%s/%s" % (self.broadcast, self.prefixlen)))


class LinkLocalAllocator(object):
    """Manages allocation of link local IP addresses.

    These link local addresses are used for routing inside the fip namespaces.
    The associations need to persist across agent restarts to maintain
    consistency.  Without this, there is disruption in network connectivity
    as the agent rewires the connections with the new IP address assocations.

    Persisting these in the database is unnecessary and would degrade
    performance.
    """
    def __init__(self, state_file, subnet):
        """Read the file with previous allocations recorded.

        See the note in the allocate method for more detail.
        """
        self.state_file = state_file
        subnet = netaddr.IPNetwork(subnet)

        self.allocations = {}

        self.remembered = {}
        for line in self._read():
            key, cidr = line.strip().split(',')
            self.remembered[key] = LinkLocalAddressPair(cidr)

        self.pool = set(LinkLocalAddressPair(s) for s in subnet.subnet(31))
        self.pool.difference_update(self.remembered.values())

    def allocate(self, key):
        """Try to allocate a link local address pair.

        I expect this to work in all cases because I expect the pool size to be
        large enough for any situation.  Nonetheless, there is some defensive
        programming in here.

        Since the allocations are persisted, there is the chance to leak
        allocations which should have been released but were not.  This leak
        could eventually exhaust the pool.

        So, if a new allocation is needed, the code first checks to see if
        there are any remembered allocations for the key.  If not, it checks
        the free pool.  If the free pool is empty then it dumps the remembered
        allocations to free the pool.  This final desparate step will not
        happen often in practice.
        """
        if key in self.remembered:
            self.allocations[key] = self.remembered.pop(key)
            return self.allocations[key]

        if not self.pool:
            # Desparate times.  Try to get more in the pool.
            self.pool.update(self.remembered.values())
            self.remembered.clear()
            if not self.pool:
                # More than 256 routers on a compute node!
                raise RuntimeError(_("Cannot allocate link local address"))

        self.allocations[key] = self.pool.pop()
        self._write_allocations()
        return self.allocations[key]

    def release(self, key):
        self.pool.add(self.allocations.pop(key))
        self._write_allocations()

    def _write_allocations(self):
        current = ["%s,%s\n" % (k, v) for k, v in self.allocations.items()]
        remembered = ["%s,%s\n" % (k, v) for k, v in self.remembered.items()]
        current.extend(remembered)
        self._write(current)

    def _write(self, lines):
        with open(self.state_file, "w") as f:
            f.writelines(lines)

    def _read(self):
        if not os.path.exists(self.state_file):
            return []
        with open(self.state_file) as f:
            return f.readlines()


class CascadedRouterInfo():
    def __init__(self, router):
        self.router = router
        self.router_port = []

class RouterInfo(l3_ha_agent.RouterMixin):

    def __init__(self, router_id, root_helper, use_namespaces, router,
                 use_ipv6=False):
        self.router_id = router_id
        self.cascaded_router_id = None
        self.extern_extra_routes = {}
        self.extra_routes_is_update = False
        self.local_internal_ports = []
        self.cascaded_router = None
        self.cascaded_extern_net_id = None
        self.cascaded_gateway_subnets = {'tunnel_subnet_id': None,
                                        'extern_subnet_id': None}
        self.ex_gw_port = None
        self._snat_enabled = None
        self._snat_action = None
        self.internal_ports = []
        self.snat_ports = []
        self.floating_ips = set()
        self.floating_ips_dict = {}
        self.root_helper = root_helper
        # Invoke the setter for establishing initial SNAT action
        self.router = router
        self.routes = []
        # DVR Data
        self.dist_fip_count = 0

        super(RouterInfo, self).__init__()

    @property
    def router(self):
        return self._router

    @router.setter
    def router(self, value):
        self._router = value
        if not self._router:
            return
        # enable_snat by default if it wasn't specified by plugin
        self._snat_enabled = self._router.get('enable_snat', True)
        # Set a SNAT action for the router
        if self._router.get('gw_port'):
            self._snat_action = ('add_rules' if self._snat_enabled
                                 else 'remove_rules')
        elif self.ex_gw_port:
            # Gateway port was removed, remove rules
            self._snat_action = 'remove_rules'

    def perform_snat_action(self, snat_callback, *args):
        # Process SNAT rules for attached subnets
        if self._snat_action:
            snat_callback(self, self._router.get('gw_port'),
                          *args, action=self._snat_action)
        self._snat_action = None


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


class L3NATAgent(firewall_l3_proxy.FWaaSL3AgentRpcCallback,
                 l3_ha_agent.AgentMixin,
                 manager.Manager):
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

    OPTS = [
        cfg.StrOpt('agent_mode', default='legacy',
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
        cfg.StrOpt('external_network_bridge', default='br-ex',
                   help=_("Name of bridge used for external network "
                          "traffic.")),
        cfg.StrOpt('router_id', default='',
                   help=_("If namespaces is disabled, the l3 agent can only"
                          " configure a router that has the matching router "
                          "ID.")),
        cfg.BoolOpt('handle_internal_only_routers',
                    default=True,
                    help=_("Agent should implement routers with no gateway")),
        cfg.StrOpt('gateway_external_network_id', default='',
                   help=_("UUID of external network for routers implemented "
                          "by the agents.")),
        cfg.StrOpt('nexthop_over_tunneling',
                   default="none",
                   help=_('The mode for nexthop over tunneling '
                          'The Allowed values are:none or gre')),
        cfg.BoolOpt('is_notify_l2proxy', default=False,
                    help=_("is_notify_l2proxy, default value is False, "
                           "means it will not notify l2proxy when creating"
                           " router ports")),
        cfg.StrOpt('l2proxy_sock_path', default='/var/l2proxysock',
                   help=_("socket path when query ports from nova_proxy")),
        cfg.IntOpt('pagination_limit', default=2,
                   help=_("list ports pagination limit, if value is -1,"
                          "means no pagination")),
        cfg.StrOpt('cascaded_extern_subnet_cidr',
                   default='100.64.1.0/24',
                   help=_("cascaded_extern_subnet_cidr")),
        cfg.StrOpt('cascaded_start_extern_ip',
                   default='100.64.1.2',
                   help=_("cascaded_start_extern_ip")),
        cfg.StrOpt('cascaded_end_extern_ip',
                   default='100.64.1.254',
                   help=_("cascaded_end_extern_ip")),
        cfg.StrOpt('cascaded_extern_network_type',
                   default='flat',
                   help=_("cascaded_extern_net_type")),
        cfg.StrOpt('cascaded_extern_physical_network',
                   default='external',
                   help=_("cascaded_extern_physical_net")),
        cfg.StrOpt('proxy_router_distributed', default='False',
                   help=_("Setting the 'proxy_router_distributed' flag "
                          "to 'False' will default to the creation "
                            "of distributed tenant routers in cascaded.")),
        cfg.BoolOpt('is_public_cloud', default=False,
                   help=_("Setting True when its public_cloud sense")),
        cfg.StrOpt('internal_relay_network_name',
               default='default',
               help=_('Allow the port has duplicate floatingips')),
        cfg.StrOpt('proxy_router_enable_snat', default='',
                   help=_("Setting the 'proxy_router_enable_snat' flag "
                          "to 'False' will default to the creation "
                            "of router in cascaded."))
    ]

    AGENT_OPTS = [
        cfg.StrOpt('region_name', default=None,
                   help=_("cascading neutron_region name to use")),
        cfg.StrOpt('neutron_region_name', default=None,
                   help=_("cascaded neutron_region name to use")),
        cfg.StrOpt('neutron_admin_auth_url',
                   default='http://127.0.0.1:35357/v2.0',
                   help=_("keystone auth url to use")),
        cfg.StrOpt('neutron_admin_user',
                   help=_("access neutron user name to use"),
                   secret=True),
        cfg.StrOpt('neutron_admin_tenant_name',
                   help=_("access neutron tenant to use"),
                   secret=True),
        cfg.BoolOpt('auth_insecure',
            default=False,
            help=_("Turn off verification of the certificate for"
                   " ssl")),
        cfg.StrOpt('admin_password',
                   help=_("access neutron password to use"),
                   secret=True),
    ]

    def __init__(self, host, conf=None):
        if conf:
            self.conf = conf
        else:
            self.conf = cfg.CONF
        self.root_helper = config.get_root_helper(self.conf)
        self.router_info = {}

        self._check_config_params()
        self.context = context.get_admin_context_without_session()
        self.plugin_rpc = L3PluginApi(topics.L3PLUGIN, host)
        self.fullsync = True
        self.sync_progress = False

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


        self.cascaded_router_map = {}  #key is the casacaded router_name  as same as cascading router_id
        self.network_map = {}  #key is the casacaded network_name  as same as cascading network_id
        self.subnet_map = {}
        self.csd_router_port_map = {}
        self.cascaded_extern_net_id = None
        self.l2proxy_sock_path = self.conf.l2proxy_sock_path
        self.csg_client = clients.CascadeNeutronClient(clients.CASCADING)
        self.csd_client = clients.CascadeNeutronClient(clients.CASCADED)
        #must after csg_client and csd_client init
        self.cache_object_map_info()
        self._queue = RouterProcessingQueue()
        super(L3NATAgent, self).__init__(conf=self.conf)

        self.target_ex_net_id = None
        self.use_ipv6 = ipv6_utils.is_enabled()

    def _check_config_params(self):
        """Check items in configuration files.

        Check for required and invalid configuration items.
        The actual values are not verified for correctness.
        """
        if not self.conf.interface_driver:
            msg = _('An interface driver must be specified')
            LOG.error(msg)
            raise SystemExit(1)

        if not self.conf.use_namespaces and not self.conf.router_id:
            msg = _('Router id is required if not using namespaces.')
            LOG.error(msg)
            raise SystemExit(1)

    def _fetch_external_net_id(self, force=False):
        """Find UUID of single external network for this agent."""
        if self.conf.gateway_external_network_id:
            return self.conf.gateway_external_network_id

        # L3 agent doesn't use external_network_bridge to handle external
        # networks, so bridge_mappings with provider networks will be used
        # and the L3 agent is able to handle any external networks.
        if not self.conf.external_network_bridge:
            return

        if not force and self.target_ex_net_id:
            return self.target_ex_net_id

        try:
            self.target_ex_net_id = self.plugin_rpc.get_external_network_id(
                self.context)
            return self.target_ex_net_id
        except n_rpc.RemoteError as e:
            with excutils.save_and_reraise_exception() as ctx:
                if e.exc_type == 'TooManyExternalNetworks':
                    ctx.reraise = False
                    msg = _(
                        "The 'gateway_external_network_id' option must be "
                        "configured for this agent as Neutron has more than "
                        "one external network.")
                    raise Exception(msg)

    def _router_added(self, router_id, router):
        ri = RouterInfo(router_id, self.root_helper,
                        self.conf.use_namespaces, router,
                        use_ipv6=self.use_ipv6)
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
        #hyp delete fip_agent_gw_port and ext_gw_port when the router delete
        if self.conf.is_public_cloud:
            req_props = {'device_id': router_id}
            ports_ret = self.csg_client('list_ports', **req_props)
            if ports_ret and ports_ret['ports'] and len(ports_ret['ports']):
                for port in ports_ret['ports']:
                    bodyResponse = self.csg_client('delete_port', port['id'])
                    LOG.debug(_('TRICIRCLE delete port, Response:%s'), str(bodyResponse))

    def get_one_compute_port(self, ri, port):
        # Get DVR ports for subnet
        if 'id' not in port['subnet'] or ri.router['distributed'] is False:
            return

        subnet_ports = (
            self.plugin_rpc.get_ports_by_subnet(self.context,
                                                port['subnet']['id']))
        LOG.debug(_('DVR: subnet_ports: %s'), subnet_ports)

        for p in subnet_ports:
            # TODO: check for multiple subnets on port case
            if ('compute' in  p['device_owner'] and
                    p['binding:host_id'] == self.conf.host and
                    p['binding:profile']):
                return p

    def _set_subnet_arp_info(self, ri, port):
        """Set ARP info retrieved from Plugin for existing ports."""
        if 'id' not in port['subnet'] or not ri.router['distributed']:
            return
        subnet_id = port['subnet']['id']
        subnet_ports = (
            self.plugin_rpc.get_ports_by_subnet(self.context,
                                                subnet_id))

        for p in subnet_ports:
            if (p['device_owner'] not in (
                l3_constants.DEVICE_OWNER_ROUTER_INTF,
                l3_constants.DEVICE_OWNER_DVR_INTERFACE)):
                for fixed_ip in p['fixed_ips']:
                    self._update_arp_entry(ri, fixed_ip['ip_address'],
                                           p['mac_address'],
                                           subnet_id, 'add')

    def _set_subnet_info(self, port):
        ips = port['fixed_ips']
        if not ips:
            raise Exception(_("Router port %s has no IP address") % port['id'])
        if len(ips) > 1:
            LOG.error(_("Ignoring multiple IPs on router port %s"),
                      port['id'])
        prefixlen = netaddr.IPNetwork(port['subnet']['cidr']).prefixlen
        port['ip_cidr'] = "%s/%s" % (ips[0]['ip_address'], prefixlen)

    def create_cascaded_router(self, ri, external_gateway_info=None):

        distributed = ri.router['distributed']
        router_name = self._get_cascaded_router_name(ri.router['id'])
        req_props = {'name': router_name,
                     'tenant_id': ri.router['tenant_id']}
        if not self.conf.proxy_router_distributed:
            req_props['distributed'] = distributed or False
        else:
            req_props['distributed'] = self.conf.proxy_router_distributed

        if(external_gateway_info):
            req_props["external_gateway_info"] = external_gateway_info

        router_ret = self.csd_client('create_router', {'router': req_props})
        if(not router_ret or
           (router_ret and (not router_ret.get('router')))):
            LOG.debug(_("cascaded router created failed, "
                        "router name:%s"), router_name)
            return
        LOG.debug(_('TRICIRCLE create router, Response:%s'), str(router_ret))
        self.cascaded_router_map[router_name] = CascadedRouterInfo(router_ret['router'])
        return router_ret['router']['id']

    def delete_cascaded_router_sync(self, router_id, csd_router_id):
        try:
            self.delete_cascaded_router(router_id, csd_router_id)
        except Exception, e:
            LOG.error("TRICIRCLE delete router failed, clean csd router and try again")
            self._delete_cascaded_floating_ips_by_router_id(csd_router_id)
            self._delete_cascaded_interface_port(router_id, csd_router_id)
            try:
                self.delete_cascaded_router(router_id, csd_router_id)
            except Exception, e:
                LOG.error("TRICIRCLE delete router failed again")



    def delete_cascaded_router(self, router_id, csd_router_id):

        self.csd_client('delete_router', csd_router_id)
        LOG.debug(_('TRICIRCLE delete router,router_id:%s,cascaded_router_id:'
                    '%s'), str(router_id), str(csd_router_id))
        csd_router_name = self.get_router_name(router_id)
        csd_router = self.cascaded_router_map.get(csd_router_name, None)
        if(not csd_router):
            LOG.error('TRICIRCLE Get router failed when delete_cascaded_router'
                      ' %s, router %s', csd_router_id, router_id)
            return
        if(len(csd_router.router_port) == 0):
            self.cascaded_router_map.pop(csd_router_name)
        else:
            LOG.warn(_('TRICIRCLE The router %s still has some router ports '
                       '[%s]'), csd_router_name, csd_router.router_port)

    def clear_router_port_cache(self, router_id, port_id):
        csd_router_name = self.get_router_name(router_id)
        csd_port_name = self.get_router_port_name(port_id)
        csd_router = self.cascaded_router_map.get(csd_router_name, None)
        if(not csd_router):
            LOG.error('TRICIRCLE get router failed when remove interface %s '
                      ' from router %s', router_id, port_id)
            return
        csd_port = self.csd_router_port_map.pop(csd_port_name, None)
        if(not csd_port):
            LOG.error('TRICIRCLE get cascaded router port failed when remove'
                      ' interface %s from router %s', router_id, port_id)
            return
        if(csd_port['id'] in csd_router.router_port):
            csd_router.router_port.remove(csd_port['id'])

    def list_cascaded_network_by_name(self, name):
        search_opts = {'name': name}
        cascaded_net = self.csd_client('list_networks', **search_opts)
        return cascaded_net

    def list_cascading_network_by_id(self, id):
        search_opts = {'id': id}
        cascaded_net = self.csg_client('list_networks', **search_opts)
        return cascaded_net

    def get_network_req(self, network):
        req_network = {'network': {
                       'admin_state_up': network['admin_state_up'],
                       'name': self._get_cascaded_network_name(network['id']),
                       'tenant_id': network['tenant_id'],
                       'router:external': network['router:external'],
                       'shared': network['shared'],
                       }}
        if network['provider:network_type'] in ['vxlan', 'gre']:
            req_provider = {
                'provider:network_type': network['provider:network_type'],
                'provider:segmentation_id': network['provider:segmentation_id']}
        elif network['provider:network_type'] == 'flat':
            req_provider = {
                'provider:network_type': network['provider:network_type'],
                'provider:physical_network': network['provider:physical_network']}
        elif network['provider:network_type'] == 'local':
            req_provider = {
                'provider:network_type': network['provider:network_type']}
        else:
            req_provider = {
                'provider:network_type': network['provider:network_type'],
                'provider:physical_network': network['provider:physical_network'],
                'provider:segmentation_id': network['provider:segmentation_id']}
        req_network['network'].update(req_provider)
        return req_network

    def create_cascaded_network(self, cascading_net_id):
        network_ret = self.list_cascading_network_by_id(cascading_net_id)
        if(not network_ret or
           (network_ret and (not network_ret.get('networks')))):
            LOG.debug(_("cascading network list failed, "
                        "network id:%s"), cascading_net_id)
            return
        network_req = self.get_network_req(network_ret['networks'][0])

        try:
            bodyResponse = self.csd_client('create_network', network_req)
            LOG.debug(_('TRICIRCLE Create network, Response:%s'),
                      str(bodyResponse))
            return bodyResponse

        except exceptions.Conflict:
            LOG.debug(_('TRICIRCLE create network Conflicted, so list'))
            name = self.get_network_name(cascading_net_id)
            csd_net_ret = self.list_cascaded_network_by_name(name)
            if(not csd_net_ret or
                   (csd_net_ret and (not csd_net_ret.get('networks')))):
                LOG.debug(_("TRICIRCLE Cascading network list failed, name:%s, "
                            "try to delete conflict network"), name)
                if self.delete_cascaded_conflict_network(network_req):
                    LOG.debug(_("TRICIRCLE Create network again"))
                    try:
                        bodyResponse = self.csd_client('create_network', network_req)
                        LOG.debug(_('TRICIRCLE Create network, Response:%s'),
                                  str(bodyResponse))
                        return bodyResponse
                    except Exception:
                        with excutils.save_and_reraise_exception():
                            LOG.error(_('TRICIRCLE Create network failed!Request:%s'), network_req)
                        return None
                return None
            LOG.debug(_('TRICIRCLE list network, Response:%s'),
                                str(csd_net_ret))
            return {u'network': csd_net_ret['networks'][0]}
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_('TRICIRCLE Create network failed!Request:%s'), network_req)
            return None

    def delete_cascaded_conflict_network(self, cas_network):
        cas_network = cas_network['network']
        network_req = {}
        if cas_network.get('provider:network_type', None):
            network_req['provider:network_type'] = cas_network.get('provider:network_type')
        if cas_network.get('provider:segmentation_id', None):
            network_req['provider:segmentation_id'] = cas_network.get('provider:segmentation_id')
        if cas_network.get('provider:physical_network', None):
            network_req['provider:physical_network'] = cas_network.get('provider:physical_network')
        if not network_req['provider:segmentation_id']:
            LOG.debug(_("network has no provider:segmentation_id, can't delete conflict network"))
            return False
        cad_network_ret = self.csd_client('list_networks', **network_req)
        if (not cad_network_ret) or (cad_network_ret and not cad_network_ret.get('networks')):
            LOG.debug(_("cannot find conflict network for cas_network_id: %s"), cas_network['id'])
            return False
        cad_networks = cad_network_ret.get('networks')
        LOG.debug("find conflict networks: %s, delete them", cad_networks)
        for cad_network in cad_networks:
            self.delete_cascaded_network_by_id(cad_network['id'])
        return True

    def delete_cascaded_network_by_id(self, network_id):
        """
        add by data consistency, if modify, modify delete_cascaded_network_by_id in l2_proxy.py too
        """
        subnets_ret = self.list_cascaded_subnet_by_network_id(network_id)
        if subnets_ret and len(subnets_ret.get('subnets')) > 0:
            for subnet in subnets_ret.get('subnets'):
                subnet_id = subnet['id']
                ports_ret = self.list_cascaded_port_by_subnet_id(subnet_id)
                if ports_ret and len(ports_ret.get('ports')) > 0:
                    for port in ports_ret.get('ports'):
                        if port['device_owner'] in [l3_constants.DEVICE_OWNER_DVR_INTERFACE,
                                                    l3_constants.DEVICE_OWNER_ROUTER_SNAT,
                                                    l3_constants.DEVICE_OWNER_AGENT_GW,
                                                    l3_constants.DEVICE_OWNER_ROUTER_INTF]:
                            LOG.info(_("Subnet %s is bound on a router"), subnet_id)
                            router_id = port['device_id']
                            self.delete_interface_for_cascaded_router_sync(router_id, subnet_id)
                            if self.validate_router_port_name(port.get('name')):
                                self.clear_router_port_cache(router_id, port.get('name').split('@')[1])
                        else:
                            try:
                                self.csd_client('delete_port', port['id'])
                                LOG.debug(_("Port %s was deleted successfully."), port['id'])
                            except Exception as e:
                                LOG.error('Delete cascaded port %s failed! Exception:%s',
                                          port['id'], str(e))
                                continue

                try:
                    self.csd_client('delete_subnet', subnet_id)
                    LOG.debug(_("Subnet %s was deleted successfully."), subnet_id)
                except Exception as e:
                    LOG.error('Delete cascaded subnet %s failed! Exception:%s',
                              subnet_id, str(e))
                    continue
        for i in range(l3_constants.DESTROY_RETRY):
            try:
                self.csd_client('delete_network', network_id)
                LOG.debug(_("Network %s was deleted successfully."), network_id)
                break
            except Exception as e:
                LOG.error('Delete cascaded network %s failed! Exception:%s',
                          network_id, str(e))
                continue

    def get_cascaded_network_id(self, csg_network_id):
        cascaded_net_name = self.get_network_name(csg_network_id)
        cascaded_network = self.network_map.get(cascaded_net_name)
        if cascaded_network  and not self.conf.is_public_cloud:
            LOG.debug(_("TRICIRCLE cascaded network is get, "
                        "network:%s"), cascaded_network)
            return cascaded_network['id']
        network_ret = self.list_cascaded_network_by_name(cascaded_net_name)
        if(network_ret and network_ret.get('networks')):
            if(len(network_ret['networks']) > 1):
                LOG.warn(_('TRICIRCLE There exist more than one network in'
                           ' cascaded neutron, all network:%s'), network_ret)
            cascaded_network = network_ret['networks'][0]
            self.network_map[cascaded_net_name] = cascaded_network
            LOG.debug(_("TRICIRCLE cascaded network is listed, "
                        "network:%s"), cascaded_network)
            return cascaded_network['id']
        return None

    def get_cascaded_network(self, csg_network_id):
        cascaded_net_name = self.get_network_name(csg_network_id)
        cascaded_network = self.network_map.get(cascaded_net_name)
        if cascaded_network:
            LOG.debug(_("TRICIRCLE cascaded network is get, "
                        "network:%s"), cascaded_network)
            return cascaded_network
        network_ret = self.list_cascaded_network_by_name(cascaded_net_name)
        if(network_ret and network_ret.get('networks')):
            if(len(network_ret['networks']) > 1):
                LOG.warn(_('TRICIRCLE There exist more than one network in'
                           ' cascaded neutron, all network:%s'), network_ret)
            cascaded_network = network_ret['networks'][0]
            self.network_map[cascaded_net_name] = cascaded_network
            LOG.debug(_("TRICIRCLE cascaded network is listed, "
                        "network:%s"), cascaded_network)
            return cascaded_network
        return None

    def get_or_create_cascaded_net(self, csg_network_id):
        '''get cascaded net_id from cascaded neutron or create network'''
        '''if not exists in cascaded neutron'''
        csd_network = self.get_cascaded_network(csg_network_id)
        if(csd_network):
            return csd_network

        cascaded_net_name = self.get_network_name(csg_network_id)
        network_ret = self.create_cascaded_network(cascaded_net_name[8:])
        if(not network_ret or
           (network_ret and (not network_ret.get('network')))):
            LOG.error(_("TRICIRCLE cascaded network created failed, "
                        "network name:%s"), cascaded_net_name)
            return
        cascaded_net = network_ret.get('network')
        self.network_map[cascaded_net_name] = cascaded_net
        return cascaded_net

    def list_cascaded_port_by_subnet_id(self, id):
        search_opts = {'fixed_ips': 'subnet_id=%s' % id}
        cascaded_ports = self.csd_client('list_ports', **search_opts)
        return cascaded_ports

    def list_cascaded_subnet_by_network_id(self, id):
        search_opts = {'network_id': [id]}
        cascaded_subnet = self.csd_client('list_subnets', **search_opts)
        return cascaded_subnet

    def list_cascaded_subnet_by_name(self, name):
        search_opts = {'name': name}
        cascaded_subnet = self.csd_client('list_subnets', **search_opts)
        return cascaded_subnet

    def list_cascading_subnet_by_name(self, sub_name):
        search_opts = {'name': sub_name}
        cascading_subnet = self.csg_client('list_subnets', **search_opts)
        return cascading_subnet

    def list_cascading_subnet_by_id(self, sub_id):
        search_opts = {'id': sub_id}
        cascading_subnet = self.csg_client('list_subnets', **search_opts)
        return cascading_subnet

    def get_subnet_req(self, subnet):
        csg_network_id = subnet['network_id']
        csd_network_id = self.get_cascaded_network_id(csg_network_id)
        if(not csd_network_id):
            LOG.error(_("TRICIRCLE cascaded network get failed, "
                        "csg network id:%s"), csg_network_id)
            return
        subnet_req = {'subnet': {
                      'name': self._get_cascaded_subnet_name(subnet['id']),
                      'cidr': subnet['cidr'],
                      'enable_dhcp': False,
                      'allocation_pools': subnet['allocation_pools'],
                      'host_routes': subnet['host_routes'],
                      'dns_nameservers': subnet['dns_nameservers'],
                      'gateway_ip': subnet['gateway_ip'],
                      'ip_version': subnet['ip_version'],
                      'network_id': csd_network_id,
                      'tenant_id': subnet['tenant_id']}}
        return subnet_req

    def create_cascaded_subnet(self, cascading_subnet_id, cascaded_sub_name):
        subnet_ret = self.list_cascading_subnet_by_id(cascading_subnet_id)
        if(not subnet_ret or
           (subnet_ret and (not subnet_ret.get('subnets')))):
            LOG.debug(_("TRICIRCLE cascading subnet list failed, "
                        "subnet id:%s"), cascading_subnet_id)
            return

        subnet_req = self.get_subnet_req(subnet_ret['subnets'][0])

        try:
            bodyResponse = self.csd_client('create_subnet', subnet_req)
            LOG.debug(_('TRICIRCLE Create subnet, Response:%s'),
                      str(bodyResponse))
            try:
                subnet_ret = self.list_cascaded_subnet_by_name(cascaded_sub_name)
                if(len(subnet_ret['subnets']) > 1):
                    subs = []
                    for subnet in subnet_ret['subnets']:
                        if subnet.get('id') == bodyResponse['subnet'].get('id'):
                            self.csd_client('delete_subnet', subnet.get('id'))
                            subs.append(subnet)

                    final_sub = [sub for sub in subnet_ret['subnets'] if sub not in subs]
                    return {u'subnet': final_sub[0]}
            except Exception as e:
                LOG.error('Delete cascaded subnet %s failed! Exception:%s',
                              bodyResponse.get('subnet'), str(e))
            return bodyResponse

        except exceptions.BadRequest:
            LOG.debug(_('TRICIRCLE create subnet failed, so list!'))
            name = self.get_subnet_name(cascading_subnet_id)
            csd_sub_ret = self.list_cascaded_subnet_by_name(name)
            if(not csd_sub_ret or
                   (csd_sub_ret and (not csd_sub_ret.get('subnets')))):
                LOG.debug(_("TRICIRCLE Cascading subnet list failed, name:%s"), name)
                return None
            LOG.debug(_('TRICIRCLE list subnet, Response:%s'),
                                str(csd_sub_ret))
            return {u'subnet': csd_sub_ret['subnets'][0]}
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_('TRICIRCLE Create subnet failed! Request:%s'), subnet_req)
            return None

    def get_cascaded_subnet(self, csg_subnet_id):
        cascaded_sub_name = self.get_subnet_name(csg_subnet_id)
        cascaded_subnet = self.subnet_map.get(cascaded_sub_name)
        if cascaded_subnet:
            LOG.debug(_("TRICIRCLE cascaded subnet is get, "
                        "subnet:%s"), cascaded_subnet)
            return cascaded_subnet
        subnet_ret = self.list_cascaded_subnet_by_name(cascaded_sub_name)
        if(subnet_ret and subnet_ret.get('subnets')):
            if(len(subnet_ret['subnets']) > 1):
                LOG.warn(_('TRICIRCLE There exist more than one subnet in'
                           ' cascaded neutron, all subnet:%s'), subnet_ret)
            cascaded_subnet = subnet_ret['subnets'][0]
            self.subnet_map[cascaded_sub_name] = cascaded_subnet
            LOG.debug(_("TRICIRCLE cascaded subnet is listed, "
                        "subnet:%s"), cascaded_subnet)
            return cascaded_subnet
        return None

    def get_or_create_cascaded_subnet(self, csg_subnet_id):
        cascaded_subnet = self.get_cascaded_subnet(csg_subnet_id)
        if cascaded_subnet:
            return cascaded_subnet
        cascaded_sub_name = self.get_subnet_name(csg_subnet_id)
        subnet_ret = self.create_cascaded_subnet(csg_subnet_id, cascaded_sub_name)
        if(not subnet_ret or
           (subnet_ret and (not subnet_ret.get('subnet')))):
            LOG.error(_("TRICIRCLE cascaded subnet created failed, "
                        "cascading subnet id:%s"), cascaded_sub_name)
            return

        cascaded_subnet = subnet_ret.get('subnet')
        self.subnet_map[cascaded_sub_name] = cascaded_subnet
        return cascaded_subnet

    def get_network_name(self, network_id):
        return ('network@' + network_id)

    def get_subnet_name(self, subnet_id):
        return ('subnet@' + subnet_id)

    def get_router_name(self, router_id):
        return ('router@' + router_id)

    def get_router_port_name(self, port_id):
        return ('router_port@' + port_id)

    def get_or_create_cascaded_router_port(self, cascaded_net_id, port):
        cascaded_port_name = self.get_router_port_name(port['id'])
        cascaded_port = self.csd_router_port_map.get(cascaded_port_name)
        if cascaded_port:
            LOG.debug(_("TRICIRCLE cascaded router port is get, "
                        "port:%s"), cascaded_port)
            return cascaded_port['id']

        mac_address = port['mac_address']
        ip_address = port['fixed_ips'][0]['ip_address']
        tenant_id = port['tenant_id']
        profile = {'cascading_port_id': port['id']}
        name = self.get_router_port_name(port['id'])
        req_props = {'network_id': cascaded_net_id,
                     'name': name,
                     'admin_state_up': True,
                     'fixed_ips': [{'ip_address': ip_address}],
                     'mac_address': mac_address,
                     'binding:profile': profile,
                     'device_owner': l3_constants.DEVICE_OWNER_DVR_INTERFACE
                     }
        if tenant_id:
            req_props['tenant_id'] = tenant_id

        port_ret = self.csd_client('create_port', {'port': req_props})
        if(not port_ret or
                (port_ret and (not port_ret.get('port')))):
            LOG.error(_("ERR:router port created failed, "
                        "ip_address:%s, mac_address:%s"),
                      ip_address, mac_address)
            return

        LOG.debug(_('TRICIRCLE create router port, Response:%s'),
                  str(port_ret))
        cascaded_port = port_ret['port']
        self.csd_router_port_map[cascaded_port_name] = cascaded_port
        return port_ret['port'].get('id')

    def delete_cascaded_router_port(self, cascaded_port_id):
        try:
            bodyResponse = self.csd_client('delete_port', cascaded_port_id)
            LOG.debug(_('TRICIRCLE delete port, Response:%s'), str(bodyResponse))
            return bodyResponse
        except Exception, e:
            LOG.error(_("TRICIRCLE delete port: %s failed: %s"), cascaded_port_id, e)

    def validate_network_name(self, name):
        if(name):
            return True
        return False

    def validate_subnet_name(self, name):
        if(name):
            return True
        return False

    def validate_router_name(self, name):
        if(name and name.startswith('router@')):
            return True
        return False

    def validate_router_port_name(self, name):
        if(name and name.startswith('router_port@')):
            return True
        return False

    def get_params_limit(self):
        pagination_limit = self.conf.pagination_limit
        if(pagination_limit > 0):
            params = {'limit': pagination_limit}
        else:
            params = None
        return params

    def cache_network_map(self):
        params_limit = self.get_params_limit()
        if(params_limit):
            net_ret = self.csd_client('list_networks', params_limit)
        else:
            net_ret = self.csd_client('list_networks')
        if(not net_ret or
                (net_ret and (not net_ret.get('networks')))):
            LOG.error(_("ERR:cascaded networks list failed!"))
            return
        net_info = net_ret.get('networks')
        for net in net_info:
            if(not self.validate_network_name(net['name'])):
                continue
            self.network_map[net['name']] = net

    def cache_subnet_map(self):
        params_limit = self.get_params_limit()
        if(params_limit):
            subnet_ret = self.csd_client('list_subnets', params_limit)
        else:
            subnet_ret = self.csd_client('list_subnets')
        if(not subnet_ret or
                (subnet_ret and (not subnet_ret.get('subnets')))):
            LOG.error(_("ERR:cascaded subnets list failed!"))
            return
        subnet_info = subnet_ret.get('subnets')
        for subnet in subnet_info:
            if(not self.validate_subnet_name(subnet['name'])):
                continue
            self.subnet_map[subnet['name']] = subnet

    def cache_router_map(self):

        params_limit = self.get_params_limit()
        if(params_limit):
            router_ret = self.csd_client('list_routers', params_limit)
        else:
            router_ret = self.csd_client('list_routers')
        if(not router_ret or
                (router_ret and (not router_ret.get('routers')))):
            return
        routers_info = router_ret.get('routers')
        for router in routers_info:
            if(not self.validate_router_name(router['name'])):
                continue
            self.cascaded_router_map[router['name']] = CascadedRouterInfo(router)

    def cache_router_port_map(self):

        params_limit = self.get_params_limit()
        if(params_limit):
            port_ret = self.csd_client('list_ports', params_limit)
        else:
            port_ret = self.csd_client('list_ports')
        if(not port_ret or
                (port_ret and (not port_ret.get('ports')))):
            LOG.error(_("TRICIRCLE:cascaded ports list failed!"))
            return
        ports_info = port_ret.get('ports')
        associated_router_port = {}
        for port in ports_info:
            if(not self.validate_router_port_name(port['name'])):
                continue
            self.csd_router_port_map[port['name']] = port
            if(port['device_id']):
                router_id = port['device_id']
                p_list = associated_router_port.get(router_id, [])
                p_list.append(port['id'])
                associated_router_port[router_id] = p_list
        for router_id, port_list in associated_router_port.items():
            router_exists = False
            for csd_name, csd_router_info in self.cascaded_router_map.items():
                if(csd_router_info.router['id'] == router_id):
                    router_exists = True
                    csd_router_info.router_port.extend(port_list)
            if(not router_exists):
                LOG.error(_("TRICIRCLE:cascaded ports %s has been associated "
                            "to router %s, but not find router in "
                            "cascaded_router_map!"), port_list, router_id)

    def print_all_object_map(self):
        LOG.debug(_('TRICIRCLE network_map: %s'), str(self.network_map))
        LOG.debug(_('TRICIRCLE subnet_map: %s'), str(self.subnet_map))
        LOG.debug(_('TRICIRCLE csd_router_port_map: %s'),
                  str(self.csd_router_port_map))
        csd_router_map = {}
        for csd_router_name, router_info in self.cascaded_router_map.items():
            csd_router_map[csd_router_name] = {'router': router_info.router,
                                               'router_port': router_info.router_port}
        LOG.debug(_('TRICIRCLE cascaded_router_map: %s'),
                  str(csd_router_map))

    def cache_object_map_info(self):
        self.cache_network_map()
        self.cache_subnet_map()
        self.cache_router_map()
        self.cache_router_port_map()
        self.print_all_object_map()

    def notify_l2_proxy(self, action, cascaded_port_id):
        if(not self.conf.is_notify_l2proxy):
            return

        retry = 3
        while retry:
            try:
                retry = retry - 1
                port_data = {"ports": {action: [cascaded_port_id]}}
                port_data_str = jsonutils.dumps(port_data)
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.connect(self.l2proxy_sock_path)
                sock.send(str(port_data_str))
                sock.close()
                LOG.debug(_('TRICIRCLE Notify the router port info %s to l2proxy!'),
                          port_data_str)
                break
            except socket.error as e:
                LOG.error(_('TRICIRCLE Notify the router port occur exception! %s'), e)
                time.sleep(1)

    def add_interface_for_cascaded_router(self, router_id,
                                          cascaded_router_id,
                                          cascaded_subnet_id,
                                          cascaded_port_id):
        router_name = self.get_router_name(router_id)
        csd_rouer_info = self.cascaded_router_map.get(router_name)
        if(not csd_rouer_info):
            LOG.error(_('TRICIRCLE add router interface failed, can not get '
                        'cascaded router, router_name :%s'), str(router_name))
            return

        if(cascaded_port_id in csd_rouer_info.router_port):
            LOG.debug(_('TRICIRCLE router %s has been added interface %s'),
                      csd_rouer_info.router['id'], str(cascaded_port_id))
            return

        req_props = {'port_id': cascaded_port_id}
        ret = self.csd_client('add_interface_router', cascaded_router_id, req_props)
        csd_rouer_info.router_port.append(cascaded_port_id)
        LOG.debug(_("TRICIRCLE Add interface for cascaded router, router:"
                    "%s, cascaded_subnet_id:%s, cascaded_port_id:%s, Ret:%s"),
                  cascaded_router_id, cascaded_subnet_id,
                  cascaded_port_id, str(ret))
        self.notify_l2_proxy("add", cascaded_port_id)

    def _delete_router_routes_for_interface(self, csd_router, subnet_cidr):
        subnet_cidr = netaddr.IPNetwork(subnet_cidr)
        extra_routes = csd_router.get('routes')
        final_routes = [route for route in extra_routes
                        if not netaddr.all_matching_cidrs(route['nexthop'], [subnet_cidr])]
        req_props = {"routes": final_routes}
        LOG.debug("update router: %s", req_props)
        self.csd_client('update_router', csd_router.get('id'), {'router': req_props})
        if self.validate_router_name(csd_router.get('name')):
            csg_router_id = csd_router.get('name').split('@')[1]
            ri = self.router_info.get(csg_router_id)
            if ri:
                ri.routes = final_routes
                LOG.debug("final_routes: %s", ri.routes)

    def delete_interface_for_cascaded_router_sync(self, cascaded_router_id, cascaded_subnet_id):
        """
        add for data consistency, if modify, modify function clear_cascaded_port_for_subnet in l2_proxy.py too
        """
        try:
            self.delete_interface_for_cascaded_router(cascaded_router_id, cascaded_subnet_id)
        except Exception, e:
            LOG.error(_("Disassociate subnet %s from router %s failed: %s, try to delete FIP & rotes and try again"),
                      cascaded_subnet_id, cascaded_router_id, e)
            self._delete_cascaded_floating_ips_by_subnet_id(cascaded_subnet_id)
            router_ret = self.csd_client('show_router', cascaded_router_id)
            if not router_ret or not router_ret.get('router'):
                return
            subnet_ret = self.csd_client('show_subnet', cascaded_subnet_id)
            cidr = subnet_ret.get('subnet', {}).get('cidr')
            if cidr:
                LOG.debug(_("Update Router routes to delete router_interface"))
                self._delete_router_routes_for_interface(router_ret.get('router'), cidr)
            self.delete_interface_for_cascaded_router(cascaded_router_id, cascaded_subnet_id)

    def delete_interface_for_cascaded_router(self, cascaded_router_id,
                                             cascaded_subnet_id):

        req_props = {'subnet_id': cascaded_subnet_id}
        ret = self.csd_client('remove_interface_router', cascaded_router_id, req_props)
        LOG.debug(_('TRICIRCLE Disassociate subnet %s from router %s, Ret:'
                    '%s'), cascaded_subnet_id, cascaded_router_id, str(ret))
        return

    def get_cascaded_router_gateway_ip(self, router_id):
        search_opts = {'device_id': router_id,
                       'device_owner': 'network:router_gateway'}

        port_ret = self.csd_client('list_ports', **search_opts)

        if(not port_ret or
           (port_ret and (not port_ret.get('ports')))):
            LOG.debug(_("cascaded router gateway_ip get failed, "
                        "router id:%s"), router_id)
            return
        port = port_ret['ports']
        if(len(port) == 0):
            return
        for fixed_ip in port[0]['fixed_ips']:
            if fixed_ip['subnet_id'] == self.cascaded_gateway_subnets.get('tunnel_subnet_id'):
                return fixed_ip['ip_address']
        return None

    def create_fip_gw_port_in_csd_and_csg(self, port_ret, cascading_fip, cascaded_net_id):
        #hyp create cascaded floatingip_host_gateway_port by vm port
        if self.conf.is_public_cloud:
            vm_port_host_id = port_ret.get('ports')[0]['binding:host_id']
            
            #get cascading fip_gw_port if is not exist then create 
            csg_fip_gw_port_exist = False
            req_props = {'name': 'fip_gw_port@' + vm_port_host_id}
            port_ret = self.csg_client('list_ports', **req_props).get('ports')
            if port_ret:
                port_ret = port_ret[0]
                csg_fip_gw_port_exist = True
            
            if not csg_fip_gw_port_exist:
                #get cascading internal_relay_subnet by host
                req_props = {'name' : self.conf.host}
                subnet_ret = self.csg_client('list_subnets', **req_props).get('subnets')
                subnet_id = subnet_ret[0].get('id', None)
                subnet_network_id = subnet_ret[0].get('network_id', None)
                
                #create vm host fip gateway port in cascading
                req_props = {'tenant_id': cascading_fip['tenant_id'],
                             'network_id': subnet_network_id,
                             'name': 'fip_gw_port@' + vm_port_host_id,
                             'admin_state_up': True,
                             'device_id' : cascading_fip['router_id'],
                             'device_owner' : 'network:floatingip_agent_gateway',
                             'fixed_ips': [{'subnet_id': subnet_id}],
                             }
                port_ret = self.csg_client('create_port', {'port': req_props}).get('port')
            fip_gw_ip_address = port_ret.get('fixed_ips')[0].get('ip_address')
            fip_gw_mac_address = port_ret.get('mac_address')
            fip_gw_ip_id = port_ret.get('id')
            
            
            #get cascaded l3_agent id by vm port host_id as device_id
            req_props = {'host' : vm_port_host_id, 'binary': 'neutron-l3-agent'}
            agent_ret = self.csd_client('list_agents', **req_props).get('agents')
            if not agent_ret:
                LOG.error('agent not exsit')
                return 
            agent_id = agent_ret[0].get('id', None)
            
            #get cascaded fip_gw_port if is not exist then create 
            csd_fip_gw_port_exist = False
            req_props = {'device_id': agent_id, 'device_owner':'network:floatingip_agent_gateway', 'network_id': cascaded_net_id}
            port_ret = self.csd_client('list_ports', **req_props).get('ports')
            if port_ret:
                csd_fip_gw_port_exist = True
            if not csd_fip_gw_port_exist:
                #create vm host fip gateway port in cascaded
                req_props = {'name': 'port@' + fip_gw_ip_id,
                             'binding:host_id' :vm_port_host_id,
                             'admin_state_up': True,
                             'fixed_ips': [{'ip_address': fip_gw_ip_address}],
                             'mac_address': fip_gw_mac_address,
                             #fip_gw_port constants
                             'network_id': cascaded_net_id,
                             'device_owner' : 'network:floatingip_agent_gateway',
                             'device_id' : agent_id
                             }
                try:
                    port_ret = self.csd_client('create_port', {'port': req_props})
                except Exception, e:
                    LOG.error(_("create fip_gw_port failed:%s, clean csd FIP and try again"), e)
                    self.clean_cascaded_floatingip(cascaded_net_id, fip_gw_ip_address)
                    req_filters = {'mac_address': fip_gw_mac_address}
                    self.delete_cascaded_ports(req_filters)
                    port_ret = self.csd_client('create_port', {'port': req_props})
                if not port_ret:
                    LOG.error('create fip_gw_port failed in csd')

    def delete_cascaded_ports(self, filters):
        port_ret = self.csd_client('list_ports', **filters)
        if port_ret and len(port_ret.get('ports')) > 0:
            ports = port_ret.get('ports')
            port_name = str(ports[0]['name'])
            if (len(port_name) > 36 and port_name.startswith("port@"))\
                or port_name == l3_constants.REMOTE_PORT_KEY:
                self._destroy_port(ports[0]['id'])

    def _destroy_port(self, port_id):
        if not port_id:
            LOG.error(_("No port id is specified, cannot destroy port"))
            return
        for retry in range(l3_constants.DESTROY_RETRY):
            try:
                body_response = self.csd_client('delete_port', port_id)
                LOG.debug(_('destroy port, Response:%s'), str(body_response))
                return body_response
            except Exception as e:
                LOG.error('Delete port %s failed! Exception:%s',
                          port_id, str(e))
                continue
        return

    def create_cascaded_external_net_for_gateway(self):
        #get cascading_internal_relay_network
        csg_network_ret = self.get_cascading_network_by_name(self.conf.internal_relay_network_name)
        if(not csg_network_ret):
            LOG.error(_("TRICIRCLE get cascading_network failed, "
                        "network name:%s"), self.conf.internal_relay_network_name)
            return
        cascading_fip_net = csg_network_ret.get('id', None)
        
        #create cascaded_internal_network
        network_ret = self.get_or_create_cascaded_net(cascading_fip_net)
        if not network_ret:
            LOG.error(_("TRICIRCLE cascaded network created failed, "
                        "network name:%s"), cascading_fip_net)
            return
        
        #get cascading_internal_subnet id 
        cascaded_net = network_ret
        cascading_subnet = self.list_cascading_subnet_by_name(self.conf.host)
        if(not cascading_subnet or
           (cascading_subnet and (not cascading_subnet.get('subnets')))):
            LOG.error(_("TRICIRCLE get cascading subnet failed, "
                        "cascading subnet name: %s"), self.conf.host)
            return
        cascading_subnet_id = cascading_subnet.get('subnets')[0].get('id', None)
        #create cascaded_external subnet for specified
        subnet_ret = self.get_or_create_cascaded_subnet(cascading_subnet_id)
        if not subnet_ret:
            LOG.error(_("TRICIRCLE cascaded subnet created failed, "
                        "cascading subnet id:%s"), cascading_subnet_id)
            return
        return cascaded_net.get('id', None)
    
    def set_cascaded_router_gw_by_cascading_ip(self, ri, cascaded_net_id):
        #set tenant router gateway on csd
        enable_snat = 'False'
        if self.conf.proxy_router_enable_snat:
            enable_snat = self.conf.proxy_router_enable_snat
        router_name = self._get_cascaded_router_name(ri.router['id'])
        router_ret = self.csd_client('list_routers', **{'name': router_name}).get('routers')
        if router_ret and len(router_ret):
            router_external_gateway_info = router_ret[0].get('external_gateway_info', None)
            if not router_external_gateway_info:
                router_id = router_ret[0].get('id')
                tenant_id = router_ret[0].get('tenant_id')
                #get fix_ip in internal_raley_network by host(like az2.dc1)
                req_props = {'name' : self.conf.host}
                subnet_ret = self.csg_client('list_subnets', **req_props).get('subnets')
                subnet_ret_id = subnet_ret[0].get('id', None)
                gw_relay_net_id = subnet_ret[0].get('network_id', None)
                if not gw_relay_net_id:
                    LOG.error(_('Set router gw in csd faild , cannot get gw_relay_net by host is (%s)'), self.conf.host)
                    return
                #get fix_ip for set gw port ip in csd
                req_props = {'network_id': gw_relay_net_id,
                             'name': 'ext_gw_port@' + cascaded_net_id,
                             'device_id' : router_id,
                             'device_owner' : router_name,
                             'fixed_ips': [{'subnet_id': subnet_ret_id}],
                             'admin_state_up': True
                             }
                if tenant_id:
                    req_props['tenant_id'] = tenant_id
                #create gateway port in csg for getting is fix_ip 
                port_ret = self.csg_client('create_port', {'port': req_props}).get('port')
                extern_ip_address = port_ret.get('fixed_ips')[0].get('ip_address')
                LOG.debug(_('add gateway by specified fix_ip(%s)  for router(%s) '), extern_ip_address, router_id)
                            
                req_props = {"external_gateway_info": {
                             "network_id": cascaded_net_id,
                             "enable_snat":enable_snat,
                             "external_fixed_ips":
                             [{"ip_address": extern_ip_address}]}}
                
                try:
                    self.csd_client('update_router', router_id, {'router': req_props})
                except Exception, e:
                    LOG.error(_("update router failed: %s, clean cascaded FIP and try again"), e)
                    self.clean_cascaded_floatingip(cascaded_net_id, extern_ip_address)
                    try:
                        self.csd_client('update_router', router_id, {'router': req_props})
                    except:
                        LOG.debug(_('set gateway info by specified fix_ip(%s) failed'),extern_ip_address)
                        try:
                            self.csd_client('delete_port', port_ret['id'])
                            LOG.debug(_("Delete port %s successfully."), port_ret['id'])
                        except Exception as e:
                            LOG.error('Delete cascaded port %s failed! Exception:%s',
                                      port_ret['id'], e)
        else:
            LOG.debug(_('Router(%s) is deleted already'), router_name)                          
        
    def update_extra_routes_for_cascaded_router(self, router_id, extra_routes, snat_ports=None):

        LOG.debug("The extra_routes is %s, and the sg_ports is %s"
                  % (extra_routes, snat_ports))
        routes = []
        if snat_ports:
            for d in extra_routes.keys():
                routes.extend([
                    {
                        'destination': d,
                        'nexthop': sg['fixed_ips'][0]['ip_address']
                    } for sg in snat_ports
                ])

        req_props = {"routes": routes}

        try:
            router_ret = self.csd_client('update_router', router_id,
                                                      {'router': req_props})
            if(not router_ret or
               (router_ret and (not router_ret.get('router')))):
                LOG.debug(_("cascaded router update failed, "
                            "router id:%s"), router_id)
                return
        except:
            LOG.error(_("cascaded router update failed, "
                            "router id:%s"), router_id)
            return

        LOG.debug(_('update router, Response:%s'), str(router_ret))
        return router_ret['router']['id']

    def get_or_create_cascaded_router(self, existing_port_ids,
                                      internal_ports, ri):
        if(len(existing_port_ids) == 0 and len(internal_ports) > 0 and
           not ri.cascaded_router_id):
            cascaded_name = self.get_router_name(ri.router['id'])
            cascaded_router = self.cascaded_router_map.get(cascaded_name, None)
            if(cascaded_router and cascaded_router.router):
                ri.cascaded_router_id = cascaded_router.router['id']
                LOG.debug(_('TRICIRCLE get router:%s'), str(cascaded_router))
                return

            router_id = self.create_cascaded_router(ri)
            if(not router_id):
                LOG.error(_('ERR: can not create cascaded router: router@%s'),
                          router_id)
                return
            ri.cascaded_router_id = router_id

    def _update_extern_extra_routes_for_snat(self, ri, ex_gw_port, snat_ports):
       if self.conf.nexthop_over_tunneling == 'gre' and snat_ports:
            snat_networks = dict((s['network_id'], s['subnet']['cidr']) for s in snat_ports)
            network_binding = self.plugin_rpc.get_network_binding_host(self.context, ri.router_id,
                                                                       snat_networks.keys())
            for n in network_binding.keys():
                next_hop = network_binding[n]
                dest_cidr = snat_networks[n]
                ri.extern_extra_routes[dest_cidr] = next_hop
                ri.extra_routes_is_update = True

            if ri.router['gw_port_host'] != self.host:
                network_binding = self.plugin_rpc.get_network_binding_host(self.context, ri.router_id,
                                                   [ex_gw_port['network_id']])
                if network_binding:
                    ri.extern_extra_routes[ex_gw_port['subnet']['cidr']] = network_binding[ex_gw_port['network_id']]
                    ri.extra_routes_is_update = True

    def _delete_extra_routes_for_snat(self, ri):
        if self.conf.nexthop_over_tunneling == 'gre' and ri.ex_gw_port['binding:host_id'] != self.host and \
            ri.extern_extra_routes.has_key(ri.ex_gw_port['subnet']['cidr']):
            ri.extern_extra_routes.pop(ri.ex_gw_port['subnet']['cidr'])
            ri.extra_routes_is_update = True

    def _update_extern_extra_routes(self, ri, port, ex_gw_port):
        if self.conf.nexthop_over_tunneling == 'gre':
            extra_routes = self.plugin_rpc.get_extra_routes_by_subnet(
                self.context,
                ri.router['id'],
                port['fixed_ips'][0]['subnet_id'],
                ex_gw_port and ex_gw_port['id'])
            LOG.debug(_("Cascade Info, new ports, extra_routes:%s from  "
                        "plugin_rpc.get_extra_routes_by_subnet"), extra_routes)
            if('not_bound_network' in extra_routes):
                return False
            if ('big2Layer' not in extra_routes and
                    'local_network' not in extra_routes):
                next_hop = extra_routes[0][0]
                dest_cidr = extra_routes[0][1]
                if(not next_hop):
                    return False
                ri.extern_extra_routes[dest_cidr] = next_hop
                ri.extra_routes_is_update = True
                ri.internal_ports.append(port)
                return False

        return True

    def _delete_extern_extra_routes(self, ri, port, ex_gw_port):
        if self.conf.nexthop_over_tunneling == 'gre':
            extra_routes = self.plugin_rpc.get_extra_routes_by_subnet(
                self.context,
                ri.router['id'],
                port['fixed_ips'][0]['subnet_id'],
                ex_gw_port and ex_gw_port['id'])
            LOG.debug(_("Cascade Info, old ports, extra_routes:%s from  "
                        "plugin_rpc.get_extra_routes_by_subnet"), extra_routes)
            if('not_bound_network' in extra_routes):
                return False
            if ('big2Layer' not in extra_routes and
                    'local_network' not in extra_routes):
                next_hop = extra_routes[0][0]
                dest_cidr = extra_routes[0][1]
                ri.extern_extra_routes.pop(dest_cidr, None)
                ri.extra_routes_is_update = True
                ri.internal_ports.remove(port)
                return False

        return True

    def _get_cascaded_router_name(self, id):
        return ('router@' + id)

    def _get_cascaded_network_name(self, id):
        return ('network@' + id)

    def _get_cascaded_subnet_name(self, id):
        return ('subnet@' + id)

    def _get_cascaded_port_name(self, id):
        return ('port@' + id)

    @common_utils.exception_logger()
    def process_router(self, ri):
        #TODO(mrsmith) - we shouldn't need to check here
        if 'distributed' not in ri.router:
            ri.router['distributed'] = False

        ex_gw_port = self._get_ex_gw_port(ri)
        internal_ports = ri.router.get(l3_constants.INTERFACE_KEY, [])
        snat_ports = ri.router.get(l3_constants.SNAT_ROUTER_INTF_KEY, [])
        existing_port_ids = set([p['id'] for p in ri.internal_ports])
        current_port_ids = set([p['id'] for p in internal_ports
                                if p['admin_state_up']])
        new_ports = [p for p in internal_ports if
                     p['id'] in current_port_ids and
                     p['id'] not in existing_port_ids]
        old_ports = [p for p in ri.internal_ports if
                     p['id'] not in current_port_ids]
        LOG.debug(_("process_router: internal_ports: %s"), internal_ports)
        LOG.debug(_("process_router: existing_port_ids: %s"), existing_port_ids)
        LOG.debug(_("process_router: current_port_ids: %s"), current_port_ids)
        LOG.debug(_("process_router: new_ports: %s"), new_ports)
        LOG.debug(_("process_router: old_ports: %s"), old_ports)

        cascaded_router = self._get_cascaded_router(ri)
        if cascaded_router:
            ri.cascaded_router_id = cascaded_router['id']

        for p in old_ports:
            try:
                LOG.debug("process_router: start delete interface: cas_subnet:%s, port_id:%s",
                          p['fixed_ips'][0]['subnet_id'], p['id'])
                if not self._delete_extern_extra_routes(ri, p, ex_gw_port):
                    LOG.debug("process_router: _delete_extern_extra_routes return False, delete failed ")
                    continue

                cascaded_subnet_id = self.get_cascaded_subnet(
                                              p['fixed_ips'][0]['subnet_id'])['id']
                if(not cascaded_subnet_id):
                    LOG.error(_('ERR: can not delete interface for cascaded'
                                ' router, not find cascaded_subnet_id!'))
                    continue
                self.delete_interface_for_cascaded_router_sync(ri.cascaded_router_id,
                                                            cascaded_subnet_id)
                self.clear_router_port_cache(ri.router['id'], p['id'])
                ri.internal_ports.remove(p)
                ri.local_internal_ports.remove(p)
            except Exception, e:
                LOG.error(_("delete interface %s failed: %s"), p, e)

        for p in new_ports:
            try:
                if not self._update_extern_extra_routes(ri, p, ex_gw_port):
                    continue

                local_existing_port_ids = set([pt['id']
                                               for pt in ri.local_internal_ports])
                self.get_or_create_cascaded_router(local_existing_port_ids,
                                                   internal_ports, ri)
                cascaded_net = self.get_or_create_cascaded_net(p['network_id'])
                cascaded_net_id = cascaded_net['id']
                if not cascaded_net_id:
                    LOG.error(_('ERR: can not get cascaded net_id from port'
                                ' %s by get_or_create_cascaded_net_id!'), p)
                    continue
                cascaded_subnet_id = self.get_or_create_cascaded_subnet(
                                        p['fixed_ips'][0]['subnet_id'])['id']
                if not cascaded_subnet_id:
                    LOG.error(_('ERR: can not get cascaded subnet_id from port'
                                ' %s by get_or_create_cascaded_subnet_id!'), p)
                    continue
                #modify by data consistency, clean cascaded router port if create port failed
                cascaded_port_id = None
                try:
                    cascaded_port_id = self.get_or_create_cascaded_router_port(cascaded_net_id, p)
                    if not cascaded_port_id:
                        raise Exception
                except Exception, e:
                    LOG.warn(_("create rotuer port failed: %s, try to clean cascaded router port"), e)
                    router = ri.router
                    self._delete_cascaded_illegal_interface(router['id'], router.get(l3_constants.INTERFACE_KEY, []),
                                                            ri.internal_ports)
                    req_props_list = {'network_id': cascaded_net_id,
                                     'fixed_ips': "ip_address=" + p['fixed_ips'][0]['ip_address'],
                                     }
                    cad_router_ports = self.csd_client('list_ports', **req_props_list)
                    if cad_router_ports and cad_router_ports.get('ports'):
                        for cad_router_port in cad_router_ports.get('ports'):
                            self.delete_cascaded_router_port(cad_router_port['id'])
                    cascaded_port_id = self.get_or_create_cascaded_router_port(cascaded_net_id, p)
                if not cascaded_port_id:
                    continue
                p['cascaded_port_id'] = cascaded_port_id
                if not ri.cascaded_router_id:
                    LOG.error(_('ERR: can not create cascaded router port from'
                                'port %s by create_cascaded_router_port!'), p)
                    self.delete_cascaded_router_port(cascaded_port_id)
                    continue
                #modify by data consistency, delete illegal router interface if add interface failed
                try:
                    self.add_interface_for_cascaded_router(ri.router['id'],
                                                           ri.cascaded_router_id,
                                                           cascaded_subnet_id,
                                                           cascaded_port_id)
                except Exception, e:
                    LOG.error(_("add interface for cascaded router failed: %s, "
                                "csg_router: %s, csd_router: %s, csd_subnet: %s, csd_port: %s, "
                                "clean cascaded router interface and try again")
                              , e, ri.router['id'], ri.cascaded_router_id, cascaded_subnet_id, cascaded_port_id)
                    router = ri.router
                    self._delete_cascaded_illegal_interface(router['id'], router.get(l3_constants.INTERFACE_KEY, []),
                                                            ri.internal_ports)
                    try:
                        self.add_interface_for_cascaded_router(ri.router['id'],
                                                               ri.cascaded_router_id,
                                                               cascaded_subnet_id,
                                                               cascaded_port_id)
                    except Exception, e:
                        LOG.error(_("add interface for cascaded router failed again: %s, "
                                    "csg_router: %s, csd_router: %s, csd_subnet: %s, csd_port: %s")
                                  , e, ri.router['id'], ri.cascaded_router_id, cascaded_subnet_id, cascaded_port_id)
                        self.delete_cascaded_router_port(cascaded_port_id)
                        raise e
                ri.internal_ports.append(p)
                ri.local_internal_ports.append(p)
            except Exception, e:
                LOG.error(_("add interface %s failed: %s"), p, e)

        # Process external gateway
        try:
            ex_gw_port_id = (ex_gw_port and ex_gw_port['id'] or
                             ri.ex_gw_port and ri.ex_gw_port['id'])

            ext_port_exists = False
            if ex_gw_port_id and not ri.ex_gw_port:
                ext_port_exists = self._check_external_port_exists(
                                        ri.router_id, ex_gw_port_id)
            elif ex_gw_port_id and ri.ex_gw_port:
                ext_port_exists = True

            if ex_gw_port:
                def _gateway_ports_equal(port1, port2):
                    def _get_filtered_dict(d, ignore):
                        return dict((k, v) for k, v in d.iteritems()
                                    if k not in ignore)

                    keys_to_ignore = set(['binding:host_id'])
                    port1_filtered = _get_filtered_dict(port1, keys_to_ignore)
                    port2_filtered = _get_filtered_dict(port2, keys_to_ignore)
                    return port1_filtered == port2_filtered

                self._set_subnet_info(ex_gw_port)
                if (not ri.ex_gw_port or (ri.router['distributed'] and
                            not ext_port_exists)) or (not _gateway_ports_equal(ex_gw_port, ri.ex_gw_port) or \
                            (ri.router['gw_port_host'] is None and ext_port_exists) or \
                            (ri.enable_snat != ri.router.get('enable_snat'))):
                    self._update_extern_extra_routes_for_snat(ri, ex_gw_port, snat_ports)
                    self.external_gateway_added(ri, ex_gw_port)
            elif not ex_gw_port and ri.ex_gw_port:
                self._delete_extra_routes_for_snat(ri)
                self.external_gateway_removed(ri)
        except Exception, e:
            LOG.error(_("process external gateway failed: %s"), e)

        # Process static routes for router
        try:
            self.routes_updated(ri)
        except Exception, e:
            LOG.error(_("process static routes failed: %s"), e)

        # Process floatingip
        fip_statuses = {}
        existing_floating_ips = ri.floating_ips
        try:
            if ex_gw_port and self.conf.agent_mode == 'dvr_snat' and ri.router['gw_port_host'] == self.host:
                cascading_floating_ips = self.get_cascading_floating_ips(ri)
                cascaded_floating_ips = self.get_cascaded_floating_ips(ri.cascaded_router_id)

                cas_fip = []
                cad_fip = []
                #handle floating_ips
                for cascading_fip in cascading_floating_ips:
                    for fip in cascaded_floating_ips:
                        if fip['fixed_ip_address'] == cascading_fip['fixed_ip_address'] \
                            and fip['floating_ip_address'] == cascading_fip['floating_ip_address']:
                            fip_statuses[cascading_fip['id']] = fip['status']
                            cas_fip.append(cascading_fip)
                            cad_fip.append(fip)
                            break

                LOG.debug("cas_fip is %s", cas_fip)
                for fip_port in cas_fip:
                    cascading_floating_ips.remove(fip_port)

                LOG.debug("cad_fip is %s", cad_fip)
                for fip_port in cad_fip:
                    cascaded_floating_ips.remove(fip_port)

                #delete floating_ip
                for fip in cascaded_floating_ips:
                    floating_ip_ret = self.csd_client('delete_floatingip', fip['id'])
                    LOG.debug(_('delete cascaded_floatingip for %s, Response:%s') % 
                              (fip['id'], str(floating_ip_ret)))

                #add floating_ip
                ext_net_map = {}
                for cascading_fip in cascading_floating_ips:
                    try:
                        cascaded_net_id = ext_net_map.get(cascading_fip['floating_network_id'], None)
                        if not cascaded_net_id:
                            cascaded_net = self.get_cascaded_network_by_cascading(cascading_fip['floating_network_id'])
                            if cascaded_net:
                                cascaded_net_id = cascaded_net['id']
                            else:
                                fip_statuses[cascading_fip['id']] = l3_constants.FLOATINGIP_STATUS_ERROR
                                LOG.error(_("cascaded ext_net for %s get failed"), cascading_fip['floating_network_id'])
                                continue
                        ext_net_map[cascading_fip['floating_network_id']] = cascaded_net_id
                        
                        if self.host != cascading_fip['host']:
                            result = self._create_cascaded_fip_with_no_port(cascading_fip, cascaded_net_id, ri)
                        else:
                            result = self._create_cascaded_fip_with_port(cascading_fip, cascaded_net_id)
                        if result:
                            fip_statuses[cascading_fip['id']] = l3_constants.FLOATINGIP_STATUS_ACTIVE
                        else:
                            fip_statuses[cascading_fip['id']] = l3_constants.FLOATINGIP_STATUS_ERROR
                    except Exception, e:
                        fip_statuses[cascading_fip['id']] = l3_constants.FLOATINGIP_STATUS_ERROR
                        LOG.error(_("create cascaded floatingip for %s failed: %s"),
                                      cascading_fip, e)
                        continue

            #handler the dvr mode router
            elif self.conf.agent_mode == 'dvr' and self.conf.is_public_cloud:
                cascaded_floating_ips = self.get_cascaded_floating_ips(ri.cascaded_router_id)
                cascading_floating_ips = self.get_floating_ips(ri)

                pc_cas_fip = []
                pc_cad_fip = []
                #handle floating_ips
                for cascading_fip in cascading_floating_ips:
                    for fip in cascaded_floating_ips:
                        if fip['fixed_ip_address'] == cascading_fip['fixed_ip_address'] \
                            and fip['floating_ip_address'] == cascading_fip['floating_ip_address']:
                            fip_statuses[cascading_fip['id']] = fip['status']
                            pc_cas_fip.append(cascading_fip)
                            pc_cad_fip.append(fip)
                            break

                LOG.debug("pc_cas_fip is %s", pc_cas_fip)
                for fip_port in pc_cas_fip:
                    cascading_floating_ips.remove(fip_port)

                LOG.debug("pc_cad_fip is %s", pc_cad_fip)
                for fip_port in pc_cad_fip:
                    cascaded_floating_ips.remove(fip_port)

                #delete floating_ip
                for fip in cascaded_floating_ips:
                    floating_ip_ret = self.csd_client('delete_floatingip', fip['id'])
                    LOG.debug(_('delete cascaded_floatingip for %s, Response:%s') % 
                             (fip['id'], str(floating_ip_ret)))

                #add floating_ip
                ext_net_map = {}
                for cascading_fip in cascading_floating_ips:
                    try:
                        cascaded_net_id = ext_net_map.get(cascading_fip['floating_network_id'], None)
                        if not cascaded_net_id:
                            cascaded_net = self.get_cascaded_network_by_cascading_name(self.conf.internal_relay_network_name)
                            if cascaded_net:
                                cascaded_net_id = cascaded_net['id']
                            elif self.conf.is_public_cloud and not cascaded_net:
                                #hyp create exteranl_relay_work in csd for tenant_router set gateway
                                cascaded_net_id = self.create_cascaded_external_net_for_gateway()
                            else:
                                fip_statuses[cascading_fip['id']] = l3_constants.FLOATINGIP_STATUS_ERROR
                                LOG.error(_("cascaded ext_net for %s get failed"), cascading_fip['floating_network_id'])
                                continue
                            
                        # hyp set tenant router gateway on csd
                        self.set_cascaded_router_gw_by_cascading_ip(ri, cascaded_net_id)

                        ext_net_map[cascading_fip['floating_network_id']] = cascaded_net_id
                        result = self._create_cascaded_fip_with_port(cascading_fip, cascaded_net_id)
                        if result:
                            fip_statuses[cascading_fip['id']] = l3_constants.FLOATINGIP_STATUS_ACTIVE
                        else:
                            fip_statuses[cascading_fip['id']] = l3_constants.FLOATINGIP_STATUS_ERROR
                    except Exception, e:
                        fip_statuses[cascading_fip['id']] = l3_constants.FLOATINGIP_STATUS_ERROR
                        LOG.error(_("create cascaded floatingip for %s failed: %s"),
                                      cascading_fip, e)
                        continue
                    # Update floating IP status on the neutron server
                    self.plugin_rpc.update_floatingip_statuses(
                        self.context, ri.router_id, fip_statuses)
                    
                # Identify floating IPs which were disabled
                ri.floating_ips = set(fip_statuses.keys())
                for fip_id in existing_floating_ips - ri.floating_ips:
                    fip_statuses[fip_id] = l3_constants.FLOATINGIP_STATUS_DOWN
                # Update floating IP status on the neutron server
                self.plugin_rpc.update_floatingip_statuses(
                    self.context, ri.router_id, fip_statuses)

        except Exception, e:
            # TODO(salv-orlando): Less broad catching
            # All floating IPs must be put in error state
            for fip in ri.router.get(l3_constants.FLOATINGIP_KEY, []):
                fip_statuses[fip['id']] = l3_constants.FLOATINGIP_STATUS_ERROR
            LOG.error(_("process floatingip failed: %s"), e)

        try:
            if ex_gw_port and self.conf.agent_mode == 'dvr_snat' and ri.router['gw_port_host'] == self.host:
                # Identify floating IPs which were disabled
                ri.floating_ips = set(fip_statuses.keys())
                for fip_id in existing_floating_ips - ri.floating_ips:
                    fip_statuses[fip_id] = l3_constants.FLOATINGIP_STATUS_DOWN
                # Update floating IP status on the neutron server
                self.plugin_rpc.update_floatingip_statuses(
                    self.context, ri.router_id, fip_statuses)
        except Exception, e:
            LOG.error(_("update fip  failed: %s"), e)

        try:
            if ri.cascaded_router_id:
                self.update_extra_routes_for_cascaded_router(
                    ri.cascaded_router_id,
                    ri.extern_extra_routes,
                    ri.router.get(l3_constants.SNAT_ROUTER_INTF_KEY, []))
                ri.extra_routes_is_update = False
        except Exception, e:
            LOG.error(_("update cascaded_router %s failed: %s"), ri.cascaded_router_id, e)

        # Update ex_gw_port and enable_snat on the router info cache
        ri.ex_gw_port = ex_gw_port
        ri.snat_ports = snat_ports
        ri.enable_snat = ri.router.get('enable_snat')

        # Process if delete router
        try:
            LOG.info("local_internal_ports:%s, cascaded_router_id:%s, ex_gw_port:%s, gw_port_host:%s" % (
                len(ri.local_internal_ports), ri.cascaded_router_id, ri.ex_gw_port, ri.router.get('gw_port_host')
            ))
            if(len(ri.local_internal_ports) == 0 and ri.cascaded_router_id and
                   (not ri.ex_gw_port or ri.router.get('gw_port_host') != self.host)):
                ri.internal_ports = []
                ri.local_internal_ports = []
                ri.extern_extra_routes = {}
                ri.routes = []

                ri.extra_routes_is_update = False
                self.delete_cascaded_router_sync(ri.router['id'], ri.cascaded_router_id)
                if self.conf.nexthop_over_tunneling == 'gre':
                    self.plugin_rpc.update_router_extern_ip_map(self.context,
                                                                ri.router['id'],
                                                                None)
                ri.cascaded_router_id = None
        except Exception, e:
            LOG.error(_("process whether delete router failed: %s"), e)

    def clean_cascaded_floatingip(self, csd_network_id, csd_fip_ip):
        filters = {'floating_network_id': csd_network_id,
                   'floating_ip_address': csd_fip_ip}
        floating_ips_ret = self.csd_client('list_floatingips', **filters)
        if floating_ips_ret and floating_ips_ret.get('floatingips'):
            for fip in floating_ips_ret.get('floatingips'):
                try:
                    self.csd_client('delete_floatingip', fip['id'])
                except Exception, e:
                    LOG.error(_("Delete floatingip failed: %s"), e)

    def _create_floatingip_sync(self, floating_ip):
        try:
            floating_ip_ret = self.csd_client('create_floatingip', {'floatingip': floating_ip})
            if (not floating_ip_ret) or not floating_ip_ret.get('floatingip'):
                raise Exception
            return floating_ip_ret
        except Exception, e:
            LOG.error(_("Create floatingip failed: %s, clean cascaded floatingip and try again"), e)
            self.clean_cascaded_floatingip(floating_ip['floating_network_id'], floating_ip['floating_ip_address'])
            floating_ip_ret = self.csd_client('create_floatingip', {'floatingip': floating_ip})
            return floating_ip_ret

    def _create_cascaded_fip_with_no_port(self, cascading_fip, cascaded_net_id, ri):
        try:
            floating_ip = {'floating_network_id': cascaded_net_id,
                           'tenant_id': cascading_fip['tenant_id'],
                           'floating_ip_address': cascading_fip['floating_ip_address']
                          }
            # create_floatingip
            floating_ip_ret = self._create_floatingip_sync(floating_ip)
            if (not floating_ip_ret) or not floating_ip_ret.get('floatingip'):
                return False
            else:
                cascaded_floating_ip = floating_ip_ret.get('floatingip')
                req_props = {'fixed_ips': 'ip_address=%s' % cascaded_floating_ip.get('floating_ip_address'),
                             'network': cascaded_net_id}
                # search floatingip_port
                port_ret = self.csd_client('list_ports', **req_props)
                if not port_ret or not port_ret.get('ports'):
                    self.csd_client('delete_floatingip', floating_ip_ret.get('floatingip')['id'])
                    return False
                else:
                    #update floatingip ,write router_id into floatingip
                    floating_port = port_ret.get('ports')[0]
                    port_props = {'name': ri.router['id']}
                    port_ret = self.csd_client('update_port', floating_port.get('id'), \
                                               {'port': port_props})
                    if not port_ret or not port_ret.get('port'):
                        self.csd_client('delete_floatingip', floating_ip_ret.get('floatingip')['id'])
                        return False

            floating_ip = {'fixed_ip_address': cascading_fip['fixed_ip_address']}

            floating_ip_ret = self.csd_client('update_floatingip', floating_ip_ret.get('floatingip')['id'], \
                                              {'floatingip': floating_ip})
            if not floating_ip_ret or not floating_ip_ret.get('floatingip'):
                self.csd_client('delete_floatingip', floating_ip_ret.get('floatingip')['id'])
                LOG.error(_("update cascaded floatingip for %s failed, Response is %s") % 
                          (floating_ip_ret, str(floating_ip_ret)))
                return False
            return True
        except Exception:
            LOG.error(_("create cascaded floatingip with no port_id for %s failed, Response is %s") % 
                        (floating_ip_ret, str(floating_ip_ret)))
            self.csd_client('delete_floatingip', floating_ip_ret.get('floatingip')['id'])
            return False


    def _create_cascaded_fip_with_port(self, cascading_fip, cascaded_net_id):
        floating_ip = {'floating_network_id': cascaded_net_id,
               'tenant_id': cascading_fip['tenant_id'],
               'fixed_ip_address': cascading_fip['fixed_ip_address'],
               'floating_ip_address': cascading_fip['floating_ip_address']
              }
        search_opts = {'name': 'port@' + cascading_fip['port_id']}
        port_ret = self.csd_client('list_ports', **search_opts)
        if not port_ret or not port_ret.get('ports'):
            LOG.error(_("cascaded port for %s get failed"), cascading_fip['port_id'])
            return False
        floating_ip['port_id'] = port_ret.get('ports')[0]['id']
        
        #hyp create floatingip_agent_gateway port 
        self.create_fip_gw_port_in_csd_and_csg(port_ret, cascading_fip, cascaded_net_id)
        
        floating_ip_ret = self._create_floatingip_sync(floating_ip)
        if not floating_ip_ret or not floating_ip_ret.get('floatingip'):
            LOG.error(_("create cascaded floatingip for %s failed, Response is %s") % 
                      (floating_ip_ret, str(floating_ip_ret)))
            return False
        return True


    def _get_ex_gw_port(self, ri):
        return ri.router.get('gw_port')

    def _check_external_port_exists(self, router_id, port_id):
        """Return True if external gateway port is present."""
        router_ret = self.csd_client('list_routers', **{'name': self._get_cascaded_router_name(router_id)})
        if(not router_ret or
                (router_ret and (not router_ret.get('routers')))):
            return False
        routers_info = router_ret.get('routers')
        LOG.debug("_check_external_port_exists routers_info:%s " % routers_info)
        if len(routers_info) and not routers_info[0].get('external_gateway_info'):
            return False

        return True

    def get_internal_port(self, ri, subnet_id):
        """Return internal router port based on subnet_id."""
        router_ports = ri.router.get(l3_constants.INTERFACE_KEY, [])
        for port in router_ports:
            fips = port['fixed_ips']
            for f in fips:
                if f['subnet_id'] == subnet_id:
                    return port

    def get_internal_device_name(self, port_id):
        return (INTERNAL_DEV_PREFIX + port_id)[:self.driver.DEV_NAME_LEN]

    def get_external_device_name(self, port_id):
        return (EXTERNAL_DEV_PREFIX + port_id)[:self.driver.DEV_NAME_LEN]

    def get_fip_ext_device_name(self, port_id):
        return (FIP_EXT_DEV_PREFIX + port_id)[:self.driver.DEV_NAME_LEN]

    def get_snat_int_device_name(self, port_id):
        return (SNAT_INT_DEV_PREFIX + port_id)[:self.driver.DEV_NAME_LEN]

    def get_snat_ns_name(self, router_id):
        return (SNAT_NS_PREFIX + router_id)

    def get_snat_interfaces(self, ri):
        return ri.router.get(l3_constants.SNAT_ROUTER_INTF_KEY, [])

    def get_floating_ips(self, ri):
        """Filter Floating IPs to be hosted on this agent."""
        floating_ips = ri.router.get(l3_constants.FLOATINGIP_KEY, [])
        if ri.router['distributed']:
            floating_ips = [i for i in floating_ips if i['host'] == self.host]
        return floating_ips

    def get_cascading_floating_ips(self, ri):
        return ri.router.get(l3_constants.FLOATINGIP_KEY, [])

    def get_cascaded_floating_ips(self, cascaded_router_id):
        filters = {'router_id': cascaded_router_id}
        floating_ips_ret = self.csd_client('list_floatingips', **filters)
        if (not floating_ips_ret) or (floating_ips_ret and not floating_ips_ret.get('floatingips')):
            return []
        else:
            return floating_ips_ret.get('floatingips')

    def get_cascaded_floating_ips_by_port(self, port_id):
        filters = {'port_id': port_id}
        floating_ips_ret = self.csd_client('list_floatingips', **filters)
        if (not floating_ips_ret) or (floating_ips_ret and not floating_ips_ret.get('floatingips')):
            return []
        else:
            return floating_ips_ret.get('floatingips')

    def get_cascaded_network_by_cascading(self, cascading_network_id):

        filters = {'name': 'network@' + cascading_network_id}
        network_ret = self.csd_client('list_networks', **filters)
        if (not network_ret) or (network_ret and not network_ret.get('networks')):
            return
        else:
            return network_ret.get('networks')[0]
        
    def get_cascading_network_by_name(self, cascading_network_name):

        filters = {'name': cascading_network_name}
        network_ret = self.csg_client('list_networks', **filters)
        if (not network_ret) or (network_ret and not network_ret.get('networks')):
            return
        else:
            return network_ret.get('networks')[0]
        
    def get_cascaded_network_by_cascading_name(self, cascading_network_name):

        filters = {'name': cascading_network_name}
        network_ret = self.csg_client('list_networks', **filters)
        if (not network_ret) or (network_ret and not network_ret.get('networks')):
            return
        else:
            filters = {'name': 'network@' + network_ret.get('networks')[0].get('id')}
            network_ret = self.csd_client('list_networks', **filters)
            if (not network_ret) or (network_ret and not network_ret.get('networks')):
                return
            else:
                return network_ret.get('networks')[0]

    def _map_internal_interfaces(self, ri, int_port, snat_ports):
        """Return the SNAT port for the given internal interface port."""
        fixed_ip = int_port['fixed_ips'][0]
        subnet_id = fixed_ip['subnet_id']
        match_port = [p for p in snat_ports if
                      p['fixed_ips'][0]['subnet_id'] == subnet_id]
        if match_port:
            return match_port[0]
        else:
            LOG.error(_('DVR: no map match_port found!'))


    def _get_cascaded_router(self, ri):

        router_ret = self.csd_client('list_routers', **{'name': self._get_cascaded_router_name(ri.router['id'])})

        if len(router_ret['routers']):
            return router_ret['routers'][0]

        return None

    def _get_cascaded_router_interface(self, cad_router_id, distributed):
        if distributed:
            filter = {'device_id': cad_router_id,
                      'device_owner': l3_constants.DEVICE_OWNER_DVR_INTERFACE}
            ports_ret = self.csd_client('list_ports', **filter)
            if ports_ret and ports_ret.get('ports'):
                return ports_ret.get('ports')
        else:
            filter = {'device_id': cad_router_id,
                      'device_owner': l3_constants.DEVICE_OWNER_ROUTER_INTF}
            ports_ret = self.csd_client('list_ports', **filter)
            if ports_ret and ports_ret.get('ports'):
                return ports_ret.get('ports')
        return []

    def _get_cascaded_router_port(self, cad_router_id):
        filter = {'device_id': cad_router_id}
        ports_ret = self.csd_client('list_ports', **filter)
        if ports_ret and ports_ret.get('ports'):
            return ports_ret.get('ports')
        return []

    def _delete_cascaded_illegal_interface(self, csg_router_id, cas_router_interfaces, existing_rouer_interfaces=[]):
        router_int = cas_router_interfaces + existing_rouer_interfaces
        cad_router_names = list(set([self.get_router_port_name(p.get('id')) for p in router_int]))
        cad_router = None
        router_ret = self.csd_client('list_routers', **{'name': self._get_cascaded_router_name(csg_router_id)})
        if len(router_ret['routers']):
            cad_router = router_ret['routers'][0]
        if cad_router:
            cad_router_interfaces = self._get_cascaded_router_interface(cad_router['id'], cad_router[
                'distributed'])
            for cad_router_interface in cad_router_interfaces:
                if cad_router_interface.get('name') not in cad_router_names:
                    self.delete_interface_for_cascaded_router_sync(cad_router.get('id'),
                                                              cad_router_interface['fixed_ips'][0]['subnet_id'])
                    if self.validate_router_port_name(cad_router_interface.get('name')):
                        self.clear_router_port_cache(csg_router_id, cad_router_interface.get('name').split("@")[1])

    def _delete_cascaded_interface_port(self, router_id, csd_router_id):
        cad_router_ports = self._get_cascaded_router_port(csd_router_id)
        for cad_router_port in cad_router_ports:
            if cad_router_port.get('device_owner') in [l3_constants.DEVICE_OWNER_DVR_INTERFACE,
                                                       l3_constants.DEVICE_OWNER_ROUTER_INTF]:
                try:
                    self.delete_interface_for_cascaded_router_sync(csd_router_id,
                                                              cad_router_port['fixed_ips'][0]['subnet_id'])
                    if self.validate_router_port_name(cad_router_port.get('name')):
                        self.clear_router_port_cache(router_id, cad_router_port.get('name').split("@")[1])
                    LOG.debug(_("Delete router_interface %s successfully."), cad_router_port['id'])
                except Exception, e:
                    LOG.error(_("Delete router_interface %s failed: %s"), cad_router_port['id'], e)
            else:
                try:
                    self.csd_client('delete_port', cad_router_port['id'])
                    LOG.debug(_("Delete port %s successfully."), cad_router_port['id'])
                except Exception as e:
                    LOG.error('Delete cascaded port %s failed! Exception:%s',
                              cad_router_port['id'], e)

    def _delete_cascaded_floating_ips_by_subnet_id(self, csd_subnet_id):
        req_props_list = {'fixed_ips': "subnet_id=" + csd_subnet_id}
        csd_ports = self.csd_client('list_ports', **req_props_list)
        if not csd_ports or not csd_ports.get('ports'):
            return
        csd_ports = csd_ports.get('ports')
        for csd_port in csd_ports:
            fips = self.get_cascaded_floating_ips_by_port(csd_port.get('id'))
            for fip in fips:
                try:
                    floating_ip_ret = self.csd_client('delete_floatingip', fip['id'])
                    LOG.debug(_('delete cascaded_floatingip for %s, Response:%s') % 
                              (fip.get('id'), str(floating_ip_ret)))
                except Exception, e:
                    LOG.error(_("delete cascaded_floatingip for %s, failed: %s"), fip.get('id'), e)

    def _delete_cascaded_floating_ips_by_router_id(self, csd_router_id):
        csd_floating_ips = self.get_cascaded_floating_ips(csd_router_id)
        for csd_floating_ip in csd_floating_ips:
            try:
                floating_ip_ret = self.csd_client('delete_floatingip', csd_floating_ip['id'])
                LOG.debug(_('delete cascaded_floatingip for %s, Response:%s') % 
                          (csd_floating_ip['id'], str(floating_ip_ret)))
            except Exception, e:
                LOG.error(_("delete cascaded_floatingip failed: %s"), e)


    def _get_cascaded_gateway_subnets(self, ri, network_id):
        if ri.cascaded_gateway_subnets.get('tunnel_subnet_id') \
            and ri.cascaded_gateway_subnets.get('extern_subnet_id'):
            return ri.cascaded_gateway_subnets

        external_net_id = self.conf.gateway_external_network_id
        if external_net_id:
            req_props = {'name': external_net_id,
                         'router:external': True}
            net_ret = self.csd_client('list_networks', **req_props)
            subnet_ids = net_ret.get('networks', [])[0].get('subnets')
            for subnet_id in subnet_ids:
                subnet_ret = self.csd_client('show_subnet', subnet_id)
                cidr = subnet_ret.get('subnet', {}).get('cidr')
                if cidr == self.conf.cascaded_extern_subnet_cidr:
                    ri.cascaded_gateway_subnets['tunnel_subnet_id'] = subnet_id
                else:
                    ri.cascaded_gateway_subnets['extern_subnet_id'] = subnet_id
        else:
            LOG.error('[_get_cascaded_gateway_subnets] Must be specify gateway_external_network_id in l3_proxy.ini')

        return ri.cascaded_gateway_subnets

    def external_gateway_removed(self, ri):
        #(TODO)it's invoked when remove gateway every router, Maybe can improved.
        if (not ri.router['distributed'] or
                self.conf.agent_mode != 'dvr_snat'):
            return
        LOG.info('[_external_gateway_removed] remove external gateway port. router:(%s)' % ri.router['id'])

        external_net_id = self.conf.gateway_external_network_id
        if external_net_id:
            cascaded_ext_net_name = self._get_cascaded_network_name(external_net_id)
            req_props = {'name': cascaded_ext_net_name,
                         'router:external': True}
            net_ret = self.csd_client('list_networks', **req_props)
            if not net_ret or not net_ret['networks']:
                LOG.debug(_('Can not find external network(%s) on cascaded'), cascaded_ext_net_name)
                return

            router_name = self._get_cascaded_router_name(ri.router['id'])

            #check router exist
            router_ret = self.csd_client('list_routers', **{'name': router_name}).get('routers')
            if router_ret and len(router_ret):
                router_id = router_ret[0].get('id')
                self.csd_client('remove_gateway_router', router_id)
            else:
                LOG.debug(_('Router(%s) is deleted already'), router_name)
        else:
            LOG.error('[_external_gateway_removed] Must be specify gateway_external_network_id in l3_proxy.ini')

    def external_gateway_added(self, ri, ex_gw_port):
        if (not ri.router['distributed'] or self.conf.agent_mode != 'dvr_snat' or
                ri.router['gw_port_host'] != self.host):
            return
        LOG.info('[external_gateway_added] add external gateway port. ex_gw_port:(%s)' % ex_gw_port)

        external_net_id = self.conf.gateway_external_network_id
        if external_net_id:
            #get subnet_id from cascaded by cascading cidr
            external_subnet_id = ex_gw_port['subnet']['id']
            external_subnet_cidr = ex_gw_port['subnet']['cidr']
            req_props = {'cidr' : external_subnet_cidr}
            subnet_ret = self.csd_client('list_subnets', **req_props)
            if subnet_ret and subnet_ret['subnets'] and len(subnet_ret['subnets']):
                cascaded_ext_subnet_id = subnet_ret['subnets'][0]['id']
                cascaded_ext_subnet_name = subnet_ret['subnets'][0]['name']
                cascaded_ext_net_id = subnet_ret['subnets'][0]['network_id']

                if cascaded_ext_subnet_name != ('subnet@' + external_subnet_id):
                    subnet_ret = self.csd_client('update_subnet', cascaded_ext_subnet_id,
                                                              {'subnet': {'name': 'subnet@' + external_subnet_id}})
                    if not subnet_ret or not subnet_ret.get('subnet'):
                        LOG.error("update_subnet(%s) failed in cascaded." % cascaded_ext_subnet_id)
                        return

                network_ret = self.csd_client('update_network', cascaded_ext_net_id,
                                                          {'network': {'name': 'network@' + external_net_id}})
                if not network_ret or not network_ret.get('network'):
                    LOG.error("update_network(%s) failed in cascaded." % external_net_id)
                    return
            else:
                LOG.error("Can not find subnet by cidr(%s) in cascaded." % external_subnet_cidr)
                return

            extern_ip_address = ex_gw_port['fixed_ips'][0].get('ip_address')
            enable_snat = ri.router.get('external_gateway_info', {}).get('enable_snat', True)
            router_name = self._get_cascaded_router_name(ri.router['id'])

            if self.conf.proxy_router_enable_snat:
                enable_snat = self.conf.proxy_router_enable_snat

            req_props = {"external_gateway_info": {
                             "network_id": cascaded_ext_net_id,
                             "enable_snat":enable_snat,
                             "external_fixed_ips":
                                 [{"subnet_id": cascaded_ext_subnet_id, "ip_address": extern_ip_address}]}}

            #check router, update if router exist, otherwise create it.
            router_ret = self.csd_client('list_routers', **{'name': router_name}).get('routers')
            if router_ret and len(router_ret):
                router_id = router_ret[0].get('id')
                ri.cascaded_router_id = router_id
                external_gateway_info = router_ret[0].get('external_gateway_info', {}) or {}
                if (cascaded_ext_net_id == external_gateway_info.get('network_id')) and \
                        (enable_snat == external_gateway_info.get('enable_snat')) and \
                        ([{"subnet_id": cascaded_ext_subnet_id, "ip_address": extern_ip_address}] == \
                             external_gateway_info.get('external_fixed_ips')):
                    LOG.debug("It's has external gateway(%s) already in cascaded." % cascaded_ext_net_id)
                    return

                router_ret = self.csd_client('update_router', router_id, {'router': req_props})
                if router_ret and router_ret.get('router'):
                    ri.cascaded_router_id = router_ret.get('router', {}).get('id')
                else:
                    LOG.error(_('Update router failed by external network(%s) on cascaded'), str(cascaded_ext_net_id))
                    return
            else:
                router_id = self.create_cascaded_router(ri, req_props['external_gateway_info'])
                if router_id:
                    ri.cascaded_router_id = router_id
                else:
                    LOG.error(_('Create router failed by external network(%s) on cascaded'), str(cascaded_ext_net_id))
                    return
        else:
            LOG.error('[external_gateway_added] Must be specify gateway_external_network_id in l3_proxy.ini')


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
        if (self.conf.external_network_bridge and
            not ip_lib.device_exists(self.conf.external_network_bridge)):
            LOG.error(_("The external network bridge '%s' does not exist"),
                      self.conf.external_network_bridge)
            return

        target_ex_net_id = self._fetch_external_net_id()
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
            # If namespaces are disabled, only process the router associated
            # with the configured agent id.
            if (not self.conf.use_namespaces and
                r['id'] != self.conf.router_id):
                continue
            ex_net_id = (r['external_gateway_info'] or {}).get('network_id')
            if not ex_net_id and not self.conf.handle_internal_only_routers:
                continue
            if (target_ex_net_id and ex_net_id and
                ex_net_id != target_ex_net_id):
                # Double check that our single external_net_id has not changed
                # by forcing a check by RPC.
                if (ex_net_id != self._fetch_external_net_id(force=True)):
                    continue
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

    def _router_ids(self):
        if not self.conf.use_namespaces:
            return [self.conf.router_id]

    def sync_routers(self, routers):
        try:
            csd_routers_name = [self.get_router_name(r['id']) for r in routers]
            csd_routers_info = self.csd_client('list_routers')
            if csd_routers_info and len(csd_routers_info.get('routers')) > 0:
                for csd_router in csd_routers_info.get('routers'):
                    if self.validate_router_name(csd_router['name']) and csd_router['name'] not in csd_routers_name:
                        self.delete_cascaded_router_sync(csd_router['name'].split('@')[1], csd_router['id'])
            for csg_router in routers:
                if csg_router['id'] not in self.router_info:
                    self._delete_cascaded_illegal_interface(csg_router['id'], csg_router.get(l3_constants.INTERFACE_KEY, []))
                else:
                    ri = self.router_info[csg_router['id']]
                    router = ri.router
                    self._delete_cascaded_illegal_interface(router['id'], router.get(l3_constants.INTERFACE_KEY, []),
                                                            ri.internal_ports)
        except Exception, e:
            LOG.error(_("sync_routers exception: %s"), e)

    @periodic_task.periodic_task
    def periodic_sync_routers_task(self, context):
        LOG.debug("periodic_sync_routers_task")
        self._cascaded_clean_task(context)
        self._sync_routers_task(context)

    def _sync_routers_task(self, context):
        if self.services_sync:
            super(L3NATAgent, self).process_services_sync(context)
        LOG.debug(_("Starting _sync_routers_task - fullsync:%s"),
                  self.fullsync)
        if not self.fullsync:
            return

        prev_router_ids = set(self.router_info)

        try:
            router_ids = self._router_ids()
            timestamp = timeutils.utcnow()
            routers = self.plugin_rpc.get_routers(
                context, router_ids)

            LOG.debug(_('Processing :%r'), routers)
            self.sync_routers(routers)
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

    def after_start(self):
        eventlet.spawn_n(self._process_routers_loop)
        self._sync_routers_task(self.context)
        LOG.info(_("L3 agent started"))

    def routes_updated(self, ri):
        new_routes = ri.router['routes']

        old_routes = ri.routes
        adds, removes = common_utils.diff_list_of_dict(old_routes, new_routes)
        LOG.debug(_("routes_updated: new_routes:%s, old_routes:%s, adds:%s, removes:%s"), new_routes, old_routes,
                  adds, removes)
        if adds or removes:
            ri.routes = new_routes
            ri.extern_extra_routes = {}
            for routes in new_routes:
                ri.extern_extra_routes[routes['destination']] = routes['nexthop']

            ri.extra_routes_is_update = True

    def check_cascaded_service_ready(self):
        for retry in range(l3_constants.GET_RETRY):
            try:
                neutron_extensions = self.csd_client('list_extensions')
                if neutron_extensions:
                    return True
            except Exception:
                if retry == (l3_constants.GET_RETRY - 1):
                    self.fullsync = True
                    return False


class L3NATAgentWithStateReport(L3NATAgent):

    def __init__(self, host, conf=None):
        super(L3NATAgentWithStateReport, self).__init__(host=host, conf=conf)
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.PLUGIN)
        self.agent_state = {
            'binary': 'neutron-l3-proxy',
            'host': host,
            'topic': topics.L3_AGENT,
            'configurations': {
                'agent_mode': self.conf.agent_mode,
                'use_namespaces': self.conf.use_namespaces,
                'router_id': self.conf.router_id,
                'handle_internal_only_routers':
                self.conf.handle_internal_only_routers,
                'external_network_bridge': self.conf.external_network_bridge,
                'gateway_external_network_id':
                self.conf.gateway_external_network_id,
                'interface_driver': self.conf.interface_driver},
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
        num_interfaces = 0
        num_floating_ips = 0
        router_infos = self.router_info.values()
        num_routers = len(router_infos)
        for ri in router_infos:
            ex_gw_port = self._get_ex_gw_port(ri)
            if ex_gw_port:
                num_ex_gw_ports += 1
            num_interfaces += len(ri.router.get(l3_constants.INTERFACE_KEY,
                                                []))
            num_floating_ips += len(ri.router.get(l3_constants.FLOATINGIP_KEY,
                                                  []))
        configurations = self.agent_state['configurations']
        configurations['routers'] = num_routers
        configurations['ex_gw_ports'] = num_ex_gw_ports
        configurations['interfaces'] = num_interfaces
        configurations['floating_ips'] = num_floating_ips
        try:
            csd_neutron_ready = super(L3NATAgentWithStateReport, self).check_cascaded_service_ready()
            if csd_neutron_ready:
                self.state_rpc.report_state(self.context, self.agent_state,
                                            self.use_call)
                self.agent_state.pop('start_flag', None)
                self.use_call = False
                LOG.debug(_("Report state task successfully completed"))
            else:
                LOG.error(_("Cascaded neutron service error!"))
        except AttributeError:
            # This means the server does not support report_state
            LOG.warn(_("Neutron server does not support state report."
                       " State report for this agent will be disabled."))
            self.heartbeat.stop()
            return
        except Exception:
            LOG.exception(_("Failed reporting state!"))

    def agent_updated(self, context, payload):
        """Handle the agent_updated notification event."""
        self.fullsync = True
        LOG.info(_("agent_updated by server side %s!"), payload)


def _register_opts(conf):
    conf.register_opts(L3NATAgent.OPTS)
    conf.register_opts(L3NATAgent.AGENT_OPTS, 'AGENT')
    conf.register_opts(l3_ha_agent.OPTS)
    config.register_interface_driver_opts_helper(conf)
    config.register_use_namespaces_opts_helper(conf)
    config.register_agent_state_opts_helper(conf)
    config.register_root_helper(conf)
    conf.register_opts(interface.OPTS)
    conf.register_opts(external_process.OPTS)
    conf.register_opts(AGENTS_SCHEDULER_OPTS)

def main(manager='neutron.agent.l3_proxy.L3NATAgentWithStateReport'):
    _register_opts(cfg.CONF)
    common_config.init(sys.argv[1:])
    config.setup_logging()
    server = neutron_service.Service.create(
        binary='neutron-l3-proxy',
        topic=topics.L3_AGENT,
        report_interval=cfg.CONF.AGENT.report_interval,
        manager=manager)
    service.launch(server).wait()
    
if __name__ == "__main__":
    sys.exit(main())

