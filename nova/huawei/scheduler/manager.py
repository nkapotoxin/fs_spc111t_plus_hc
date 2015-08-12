# Copyright (c) 2010 OpenStack Foundation
# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
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

"""
Scheduler Service
"""

import os
from oslo.config import cfg
from nova.openstack.common import log as logging
from nova.scheduler.manager import SchedulerManager
from nova.huawei import utils as h_utils

LOG = logging.getLogger(__name__)

CONF = cfg.CONF
CONF.import_opt('libvirt_snapshots_directory', 'nova.huawei.compute.manager')
compute_opts = [
    cfg.IntOpt('heartbeat_interval',
           default=30,
           help=''),
    cfg.StrOpt('monitor_file',
               default=os.path.join(CONF.libvirt_snapshots_directory,
                                    "nova-scheduler_heart.ini"),
               help='The path of file to write the monitor time.'),
]

CONF.register_opts(compute_opts, group="scheduler_monitor")

class HuaweiSchedulerManager(SchedulerManager):
    def __init__(self, scheduler_driver=None, *args, **kwargs):
        super(HuaweiSchedulerManager, self).__init__(scheduler_driver,
                                                     *args, **kwargs)

        h_utils.heartbeat_period_task(CONF.scheduler_monitor.heartbeat_interval,
                                      CONF.scheduler_monitor.monitor_file)
