import eventlet
import os
import socket
import time

from oslo.config import cfg

from neutron.agent.common import config
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.common import utils as n_utils
from neutron import context
from neutron.openstack.common import log as logging
from neutron.openstack.common import timeutils
from neutron.plugins.common import constants
from neutron.services.firewall.agents.ngfw import ngfw_api
from neutron.services.firewall.agents.ngfw import ngfw_utils
from neutron.services.loadbalancer.agent import agent_device_driver
from neutron.services.loadbalancer import constants as lb_const
from neutron.services.loadbalancer.drivers.haproxy_integration import cfg as hacfg

LOG = logging.getLogger(__name__)
DRIVER_NAME = 'haproxy_int'
IN_BYTES = 0
OUT_BYTES = 1

STATE_PATH_DEFAULT = '$state_path/lbaas'
USER_GROUP_DEFAULT = 'nogroup'
OPTS = [
    cfg.StrOpt(
        'loadbalancer_state_path',
        default=STATE_PATH_DEFAULT,
        help=_('Location to store config and state files'),
        deprecated_opts=[cfg.DeprecatedOpt('loadbalancer_state_path',
                                           group='DEFAULT')],
    ),
    cfg.StrOpt(
        'user_group',
        default=USER_GROUP_DEFAULT,
        help=_('The user group'),
        deprecated_opts=[cfg.DeprecatedOpt('user_group', group='DEFAULT')],
    ),
    cfg.StrOpt(
        'cluster_name',
        default='',
        help=_('The name of Lbaas proxy cluster')
    ),
    cfg.IntOpt(
        'proxy_down_time',
        default=60,
        help=_("Seconds to regard the proxy is down; "
               "should be at least twice report_interval, "
               "to be sure the proxy is down for good."),
    ),
    cfg.ListOpt(
        'external_networks',
        default=[],
        help=_("CIDR of External networks"),
    ),
]
cfg.CONF.register_opts(OPTS, 'haproxy_int')


class LbaasProxyApi(n_rpc.RpcProxy):
    """Agent side of the Agent to Proxy RPC API."""

    API_VERSION = '1.0'

    def __init__(self, topic, context):
        super(LbaasProxyApi, self).__init__(topic, self.API_VERSION)
        self.topic = topic
        self.context = context

    def send_haproxy_config_data(self, data):
        return self.fanout_cast(
            self.context,
            self.make_msg('refresh_device', data=data),
            topic=self.topic
        )


class LbassProxyCallback(n_rpc.RpcCallback):
    """Callback for Lb proxy RPC in agent implementations."""
    
    RPC_API_VERSION = '1.0'
    START_TIME = timeutils.utcnow()
    
    def __init__(self, manager):
        self.manager = manager
    
    def update_stats(self, context, stats):
        return self.manager.update_stats(stats)   
    
    def get_haproxy_config_data(self, context):
        return self.manager.get_haproxy_config_data()       
    
    def report_state(self, context, data):
        if not data['ip'] or data['status'] == 'DOWN':
            return
        
        report_time = data['time']
        report_time = timeutils.parse_strtime(report_time)
        
        if self.START_TIME > report_time:
            LOG.debug(_("Message with invalid timestamp received"))
        else:
            ip = data['ip']
            if ip not in self.manager.proxy_ips:
                self.manager.proxy_ips[ip] = {}
                self.manager.proxy_ips[ip]['flag'] = False 
            self.manager.proxy_ips[ip]['time'] = report_time


class NGFWClient(object):
    
    def __init__(self):
        self.rest = ngfw_api.ngfwRestAPI()

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
    
    def clear_static_route(self, static_route):
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
    
    def make_static_route(self, static_route):
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
            return False
        LOG.debug(_('_make_static_route success.'))
        return True 

          
class HaproxyIntDriver(agent_device_driver.AgentDeviceDriver):
    def __init__(self, conf, plugin_rpc):
        self.conf = conf
        self.root_helper = config.get_root_helper(conf)
        self.state_path = conf.haproxy_int.loadbalancer_state_path
        self.external_networks = self.conf.haproxy_int.external_networks
        
        self.ngfw_client = NGFWClient()
        self.plugin_rpc = plugin_rpc
        self.pools_stats = {}
        self.cfg_data = {}
        self.proxy_ips = {}
        self._set_proxy_info()
        self.last_process_time = 0
        self.last_rpc_time = 0
        self.last_collect_time = 0
        self.context = context.get_admin_context_without_session()
        self._setup_proxy_rpc()
    
    @classmethod
    def get_name(cls):
        return DRIVER_NAME

    def _setup_proxy_rpc(self):
        self.proxy_rpc = LbaasProxyApi(
            '%s-%s' % (topics.LOADBALANCER_INTEGRATION, self.conf.haproxy_int.cluster_name),
            self.context
        )     
                
        self.conn = n_rpc.create_connection(new=True)
        endpoints = [LbassProxyCallback(self)]
        self.conn.create_consumer('%s-%s' % (topics.LOADBALANCER_INTEGRATION_PROXY, 
                                             self.conf.haproxy_int.cluster_name), 
                                  endpoints)
        self.conn.consume_in_threads()  

    def _clear_old_external_networks(self):
        if self.removed_external_networks:
            LOG.debug(_('remove static route of external networks: %s'),
                      self.removed_external_networks)
            static_route = {
                 "priority":"60",
                 "description":"SLB static route"
            }
            deleted_external_networks = set()
            for external_network in self.removed_external_networks:
                strs = external_network.split('/')
                static_route["ip_address"] = strs[0]
                static_route["mask_length"] = strs[1]
                success = True
                for ip in self.old_ips:
                    static_route["next_hop_address"]= ip
                    success &= self.ngfw_client.clear_static_route(static_route)
                    if not success:
                        break
                if success:
                    deleted_external_networks.add(external_network)

            self.removed_external_networks -= deleted_external_networks

    def _process_static_route(self, ip, info):
        heart_beat_time = info['time']
        flag = info['flag']
        static_route = {
             "next_hop_address": ip,
             "priority":"60",
             "description":"SLB static route"
         }
        if timeutils.is_older_than(heart_beat_time,
                                   self.conf.haproxy_int.proxy_down_time):
            for external_network in self.external_networks:
                strs = external_network.split('/')
                static_route["ip_address"] = strs[0]
                static_route["mask_length"] = strs[1]
                success = self.ngfw_client.clear_static_route(static_route)
                if not success:
                    LOG.warn(_('Failed to remove static route to proxy %s'), ip)
                    return
                    
            del self.proxy_ips[ip]
            LOG.debug(_('Remove static route to proxy %s'), ip)
        else:
            if not flag:
                for external_network in self.external_networks:
                    strs = external_network.split('/')
                    static_route["ip_address"] = strs[0]
                    static_route["mask_length"] = strs[1]
                    success = self.ngfw_client.make_static_route(static_route)
                    if not success:
                        LOG.warn(_('Failed to add static route to proxy %s'), ip)
                        return
                    
                info['flag'] = True
                LOG.debug(_('Add static route to proxy %s'), ip)

    def process_static_routes(self):
        pool = eventlet.GreenPool()
        pool.spawn_n(self._clear_old_external_networks)
        for ip, info in self.proxy_ips.items():
            self._process_static_route(ip, info)
            pool.spawn_n(self._process_static_route, ip, info)
        pool.waitall()
   
    def _set_proxy_info(self):
        self.old_ips, old_external_networks = self.plugin_rpc.get_proxy_info()
        init_time = timeutils.utcnow()
        
        for ip in self.old_ips:
            self.proxy_ips[ip] = {'time': init_time,
                                  'flag': False}
        
        self.removed_external_networks = set(old_external_networks) -\
                                    set(self.external_networks)
        
    def get_proxy_info(self):
        return {
            'proxy_ips': [ip for ip in self.proxy_ips],
            'external_networks': self.external_networks,
            'removed_external_networks': list(self.removed_external_networks)
        }

    def update(self, logical_config):
        if not 'vip' in logical_config:
            return
        
        pool_id = logical_config['pool']['id']
        if not pool_id in self.pools_stats:
            self.pools_stats[pool_id] = {}
            self.pools_stats[pool_id]['members'] = {}
        for member in logical_config['members']:
            if member['id'] not in self.pools_stats[pool_id]['members']:
                self.pools_stats[pool_id]['members'][member['id']] = {}

        self.cfg_data[pool_id] = hacfg.get_config_data(logical_config)
        self.last_rpc_time = time.time()

    create = update
    
    @n_utils.synchronized('update_stats')
    def update_stats(self, stats):
        for pool_id, pool_stats in stats.items():
            if pool_id in self.pools_stats:
                local_stats = self.pools_stats[pool_id]
                if len(self.pools_stats[pool_id]) == 1:
                    local_stats.update(pool_stats)
                else: 
                    for k in hacfg.STATS_MAP.iterkeys():
                        local_stats[k] = pool_stats[k]
                    if 'members' in pool_stats:
                        for member_id, member_stats in pool_stats['members'].items():
                            if member_id in local_stats['members']:
                                local_stats['members'][member_id] = member_stats
        
    def send_haproxy_config_data(self):
        if self.last_rpc_time > self.last_process_time:
            LOG.debug(_('Start make new requests go into effect'))
            self.last_process_time = time.time()
            data = self.get_haproxy_config_data()
            self.proxy_rpc.send_haproxy_config_data(data)
                 
    def get_haproxy_config_data(self):
        sock_path = self._get_state_file_path('sock')
        user_group = self.conf.haproxy_int.user_group
        
        data = []
        for pool_data in self.cfg_data.itervalues():
            data.append(pool_data)

        config_data = hacfg.save_config(data, sock_path, user_group)
        return config_data
    
    def _get_state_file_path(self, kind, ensure_state_dir=True):
        """Returns the file name for a given kind of config file."""
        conf_dir = os.path.abspath(os.path.normpath(self.state_path))
        if ensure_state_dir:
            if not os.path.isdir(conf_dir):
                os.makedirs(conf_dir, 0o755)
        return os.path.join(conf_dir, kind)
    
    @n_utils.synchronized('haproxy-int-driver')
    def undeploy_instance(self, pool_id):
        if pool_id in self.cfg_data:
            del self.cfg_data[pool_id]
        if pool_id in self.pools_stats:
            del self.pools_stats[pool_id]
        self.last_rpc_time = time.time()
        
    def exists(self, pool_id):
        return pool_id in self.cfg_data

    def check_process(self, pool_id):
        pass
    
    def get_stats(self, pool_id):
        if pool_id in self.pools_stats and len(self.pools_stats[pool_id]) > 1:
            return self.pools_stats[pool_id]
        else:
            LOG.warn(_('Stats info is empty for pool %s'), pool_id)
            return {}
    
    @n_utils.synchronized('haproxy-int-driver')
    def deploy_instance(self, logical_config):
        # do actual deploy only if vip and pool are configured and active
        if (not logical_config or
                'vip' not in logical_config or
                (logical_config['vip']['status'] not in
                 constants.ACTIVE_PENDING_STATUSES) or
                not logical_config['vip']['admin_state_up'] or
                (logical_config['pool']['status'] not in
                 constants.ACTIVE_PENDING_STATUSES) or
                not logical_config['pool']['admin_state_up']):
            return

        self.update(logical_config)

    def _refresh_device(self, pool_id):
        logical_config = self.plugin_rpc.get_logical_device(pool_id)
        self.deploy_instance(logical_config)

    def create_vip(self, vip):
        self._refresh_device(vip['pool_id'])

    def update_vip(self, old_vip, vip):
        self._refresh_device(vip['pool_id'])

    def delete_vip(self, vip):
        self.undeploy_instance(vip['pool_id'])

    def create_listener(self, pool_id):
        self._refresh_device(pool_id)

    def delete_listener(self, pool_id):
        self._refresh_device(pool_id)

    def create_pool(self, pool):
        if pool['vip_id']:
            self._refresh_device(pool['id'])

    def update_pool(self, old_pool, pool):
        self._refresh_device(pool['id'])

    def delete_pool(self, pool):
        # delete_pool may be called before vip deletion in case
        # pool's admin state set to down
        if pool['id'] in self.pools_stats:
            del self.pools_stats[pool['id']]
        if self.exists(pool['id']):
            self.undeploy_instance(pool['id'])

    def create_member(self, member):
        self._refresh_device(member['pool_id'])

    def update_member(self, old_member, member):
        self._refresh_device(member['pool_id'])

    def delete_member(self, member):
        if member['id'] in self.pools_stats[member['pool_id']]['members']:
            del self.pools_stats[member['pool_id']]['members'][member['id']]
        self._refresh_device(member['pool_id'])

    def create_pool_health_monitor(self, health_monitor, pool_id):
        self._refresh_device(pool_id)

    def update_pool_health_monitor(self, old_health_monitor, health_monitor,
                                   pool_id):
        self._refresh_device(pool_id)

    def delete_pool_health_monitor(self, health_monitor, pool_id):
        self._refresh_device(pool_id)

    def remove_orphans(self, known_pool_ids):
        if not os.path.exists(self.state_path):
            return

        orphans = (pool_id for pool_id in os.listdir(self.state_path)
                   if pool_id not in known_pool_ids)
        for pool_id in orphans:
            if self.exists(pool_id):
                self.undeploy_instance(pool_id)
