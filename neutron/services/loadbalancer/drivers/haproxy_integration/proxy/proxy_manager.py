# Copyright 2013 New Dream Network, LLC (DreamHost)
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
import os
import socket

from oslo.config import cfg

from neutron.agent.common import config
from neutron.agent.linux import utils
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.common import utils as n_utils
from neutron import context
from neutron.openstack.common import log as logging
from neutron.openstack.common import loopingcall
from neutron.openstack.common import periodic_task
from neutron.openstack.common import timeutils
from neutron.plugins.common import constants
from neutron.services.loadbalancer import constants as lb_const
from neutron.services.loadbalancer.drivers.haproxy_integration import cfg as hacfg

LOG = logging.getLogger(__name__)

STATE_PATH_DEFAULT = '$state_path/lbaas'
OPTS = [
    cfg.StrOpt(
        'loadbalancer_state_path',
        default=STATE_PATH_DEFAULT,
        help=_('Location to store config and state files'),
    )
]


class LbassProxyApi(n_rpc.RpcProxy):

    API_VERSION = '1.0'

    def __init__(self, topic, context, host):
        super(LbassProxyApi, self).__init__(topic, self.API_VERSION)
        self.context = context
        self.host = host

    def update_stats(self, stats):
        return self.cast(
            self.context,
            self.make_msg('update_stats', stats=stats),
            topic=self.topic
        )

    def get_haproxy_config_data(self):
        return self.call(
            self.context,
            self.make_msg('get_haproxy_config_data'),
            topic=self.topic
        )
    
    def report_state(self, data):
        return self.call(
            self.context,
            self.make_msg('report_state', data=data),
            topic=self.topic
        )


class LbaasProxyManager(n_rpc.RpcCallback, periodic_task.PeriodicTasks):

    RPC_API_VERSION = '1.0'

    def __init__(self, conf):
        super(LbaasProxyManager, self).__init__()
        self.conf = conf
        self.root_helper = config.get_root_helper(conf)
        self.context = context.get_admin_context_without_session()
        self.agent_rpc = LbassProxyApi(
            '%s-%s' % (topics.LOADBALANCER_INTEGRATION_PROXY, 
                       self.conf.cluster_name),
            self.context,
            self.conf.host
        )
        self.state_path = self.conf.loadbalancer_state_path
        self.pools_config = ''
        self.needs_resync = False
        self.sync_state()

        report_interval = self.conf.report_interval
        if report_interval:
            heartbeat = loopingcall.FixedIntervalLoopingCall(
                self._report_state)
            heartbeat.start(interval=report_interval)

    def _report_state(self):
        if not self.needs_resync:
            agent_state = {
                'ip': self.conf.lbaas_proxy_ip,
                'time': timeutils.strtime(),
                'status': 'ACTIVE' if self.haproxy_active() else 'DOWN',
            }
            try:
                self.agent_rpc.report_state(agent_state)
            except Exception:
                LOG.exception(_("Failed reporting state!"))
                self.needs_resync = True
        
    def sync_state(self):
        LOG.debug('Begin to sync state')
        try:
            self.pools_config = self.agent_rpc.get_haproxy_config_data()
            self._spawn()
        except Exception:
            LOG.exception(_('Unable to sync state'))
            self.needs_resync = True  
    
    def refresh_device(self, context, data):
        LOG.debug('Begin to refresh haproxy config')
        self.pools_config = data
        self._spawn()

    def haproxy_active(self):
        socket_path = self._get_state_file_path('sock', False)
        if os.path.exists(socket_path):
            try:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.connect(socket_path)
                return True
            except socket.error:
                pass
        return False        

    def check_process(self):
        pid_path = self._get_state_file_path('pid')
        try:
            pid = [p.strip() for p in open(pid_path, 'r')]
            return  os.path.exists('/proc/' + str(pid[0]))
        except IOError:
            return False
        
    @n_utils.synchronized('proxy_manager')
    def _spawn(self):
        try:
            conf_path = self._get_state_file_path('conf')
            pid_path = self._get_state_file_path('pid')
            
            if not self.pools_config:
                kill_pids_in_file(self.root_helper, pid_path)
                return
        
            utils.replace_file(conf_path, self.pools_config)

            cmd = ['haproxy', '-f', conf_path, '-p', pid_path]
            if self.check_process():
                pid_path = self._get_state_file_path('pid')
                extra_args = ['-sf']
                extra_args.extend(p.strip() for p in open(pid_path, 'r'))
                cmd.extend(extra_args)   
                
            utils.execute(cmd, root_helper=self.root_helper) 
        except Exception:
            LOG.exception('Spawn haproxy process failed.')
            self.needs_resync = True
        
    @periodic_task.periodic_task(spacing=60)
    def check_service(self, context):
        if not self.haproxy_active():
            LOG.debug('Haproxy is inactive, begin to restart')
            self._spawn()
                
    @periodic_task.periodic_task(spacing=6)
    def collect_stats(self, context):
        if self.needs_resync:
            return
        
        socket_path = self._get_state_file_path('sock', False)
        TYPE_BACKEND_REQUEST = 2
        TYPE_SERVER_REQUEST = 4
        stats = {}
        if os.path.exists(socket_path):
            parsed_stats = self._get_stats_from_socket(
                socket_path,
                entity_type=TYPE_BACKEND_REQUEST | TYPE_SERVER_REQUEST)
            stats = self._get_pools_stats(parsed_stats)
            if stats:
                try:
                    self.agent_rpc.update_stats(stats)
                except Exception:
                    LOG.exception(_('Unable to update_stats'))
                    self.needs_resync = True
        else:
            LOG.warn(_('Stats socket not found'))

    @periodic_task.periodic_task
    def periodic_resync(self, context):
        if self.needs_resync:
            self.needs_resync = False
            self.sync_state()
                   
    def _get_pools_stats(self, parsed_stats):
        TYPE_BACKEND_RESPONSE = '1'
        TYPE_SERVER_RESPONSE = '2'
        pools_stats = {}
        for stats in parsed_stats:
            if stats.get('type') == TYPE_BACKEND_RESPONSE:
                unified_stats = dict((k, stats.get(v, ''))
                                     for k, v in hacfg.STATS_MAP.items())
                if stats.get('pxname') not in pools_stats:
                    pools_stats[stats.get('pxname')] = {}
                    pools_stats[stats.get('pxname')]['members'] = {}
                pools_stats[stats.get('pxname')].update(unified_stats)
            elif stats.get('type') == TYPE_SERVER_RESPONSE:
                res = {
                    lb_const.STATS_STATUS: (constants.INACTIVE
                                            if stats['status'] == 'DOWN'
                                            else constants.ACTIVE),
                    lb_const.STATS_HEALTH: stats['check_status'],
                    lb_const.STATS_FAILED_CHECKS: stats['chkfail']
                }
                if stats.get('pxname') not in pools_stats:
                    pools_stats[stats.get('pxname')] = {}
                    pools_stats[stats.get('pxname')]['members'] = {}
                pools_stats[stats.get('pxname')]['members'][stats['svname']] = res
        return pools_stats

    def _get_stats_from_socket(self, socket_path, entity_type):
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect(socket_path)
            s.send('show stat -1 %s -1\n' % entity_type)
            raw_stats = ''
            chunk_size = 1024
            while True:
                chunk = s.recv(chunk_size)
                raw_stats += chunk
                if not chunk:
                    break

            return self._parse_stats(raw_stats)
        except socket.error as e:
            LOG.warn(_('Error while connecting to stats socket: %s'), e)
            return {}

    def _parse_stats(self, raw_stats):
        stat_lines = raw_stats.splitlines()
        if len(stat_lines) < 2:
            return []
        stat_names = [name.strip('# ') for name in stat_lines[0].split(',')]
        res_stats = []
        for raw_values in stat_lines[1:]:
            if not raw_values:
                continue
            stat_values = [value.strip() for value in raw_values.split(',')]
            res_stats.append(dict(zip(stat_names, stat_values)))

        return res_stats
    
    def _get_state_file_path(self, kind, ensure_state_dir=True):
        """Returns the file name for a given kind of config file."""
        conf_dir = os.path.abspath(os.path.normpath(self.state_path))
        if ensure_state_dir:
            if not os.path.isdir(conf_dir):
                os.makedirs(conf_dir, 0o755)
        return os.path.join(conf_dir, kind)

def kill_pids_in_file(root_helper, pid_path):
    if os.path.exists(pid_path):
        with open(pid_path, 'r') as pids:
            for pid in pids:
                pid = pid.strip()
                try:
                    utils.execute(['kill', '-9', pid], root_helper)
                except RuntimeError:
                    LOG.exception(
                        _('Unable to kill haproxy process: %s'),
                        pid
                    )
