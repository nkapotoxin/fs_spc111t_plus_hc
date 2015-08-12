# Copyright (c) 2012 OpenStack Foundation
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
Track resources like memory and disk for a compute host.  Provides the
scheduler with useful information about availability through the ComputeNode
model.
"""

from nova import utils
from nova.compute import resource_tracker
from nova.openstack.common import log as logging
from nova.openstack.common import jsonutils

LOG = logging.getLogger(__name__)


class HuaweiResourceTracker(resource_tracker.ResourceTracker):
    """
    HUAWEI resource tracker
    """
    def __init__(self, host, driver, nodename):
        super(HuaweiResourceTracker, self).__init__(host, driver, nodename)

    def _write_ext_resources(self, resources):
        vcpus_used = resources['vcpus_used']
        super(HuaweiResourceTracker, self)._write_ext_resources(resources)
        resources['vcpus_used'] = vcpus_used

    @utils.synchronized(resource_tracker.COMPUTE_RESOURCE_SEMAPHORE)
    def _update_available_resource(self, context, resources):
        """
        We have already get the info needed from FusionCompute, so nothing
        to do here.
        :param context:
        :param resources:
        :return:
        """

        resources['free_ram_mb'] = (resources['memory_mb'] -
                                    resources['memory_mb_used'])
        resources['free_disk_gb'] = (resources['local_gb'] -
                                     resources['local_gb_used'])

        resources['current_workload'] = 0
        resources['pci_stats'] = jsonutils.dumps([])

        metrics = self._get_host_metrics(context, self.nodename)
        resources['metrics'] = jsonutils.dumps(metrics)

        # Reset values for extended resources
        self.ext_resources_handler.reset_resources(resources, self.driver)

        self._report_final_resource_view(resources)
        self._sync_compute_node(context, resources)
