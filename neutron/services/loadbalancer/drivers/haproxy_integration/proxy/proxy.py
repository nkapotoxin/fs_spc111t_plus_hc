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

import sys

import eventlet
eventlet.monkey_patch()

from oslo.config import cfg

from neutron.agent.common import config
from neutron.common import config as common_config
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.openstack.common import service
from neutron.services.loadbalancer.drivers.haproxy_integration.proxy import proxy_manager as manager

OPTS = [
    cfg.IntOpt(
        'periodic_interval',
        default=10,
        help=_('Seconds between periodic task runs')
    ),
    cfg.StrOpt(
        'cluster_name',
        default='',
        help=_('The name of Lbaas proxy cluster'),
    ),
    cfg.IntOpt(
        'report_interval',
        default=20,
        help=_('Location to store config and state files'),    
    ),
    cfg.StrOpt(
        'lbaas_proxy_ip',
        default='',
        help=_('IP address of Lbaas proxy node'),
    ),
]

class LbaasProxyService(n_rpc.Service):
    def start(self):
        super(LbaasProxyService, self).start()
        self.tg.add_timer(
            cfg.CONF.periodic_interval,
            self.manager.run_periodic_tasks,
            None,
            None
        )

def main():
    cfg.CONF.register_opts(OPTS)
    cfg.CONF.register_opts(manager.OPTS)
    config.register_root_helper(cfg.CONF)

    common_config.init(sys.argv[1:])
    config.setup_logging()

    mgr = manager.LbaasProxyManager(cfg.CONF)
    svc = LbaasProxyService(
        host=cfg.CONF.host,
        topic='%s-%s' % (topics.LOADBALANCER_INTEGRATION, 
                         cfg.CONF.cluster_name),
        manager=mgr
    )
    service.launch(svc).wait()