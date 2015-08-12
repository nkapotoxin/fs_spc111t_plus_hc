# Copyright (c) 2011 OpenStack Foundation
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
Manage hosts in the current zone.
"""
import copy

from nova.huawei import utils as h_utils
from nova.huawei.scheduler import filters as huawei_filters
from nova.scheduler import host_manager
from nova.scheduler import ironic_host_manager
from nova.openstack.common import jsonutils
from nova.openstack.common import log as logging
from nova.compute import task_states
from nova.compute import vm_states


LOG = logging.getLogger(__name__)


class HuaweiHostState(host_manager.HostState):
    """Mutable and immutable information tracked for a host.
    This is an attempt to remove the ad-hoc data structures
    previously used and lock down access.
    """

    def __init__(self, host, node, compute=None):
        self.physical_networks = {}
        super(HuaweiHostState, self).__init__(host, node, compute)

    def update_from_compute_node(self, compute, force_update=False):
        super(HuaweiHostState, self).update_from_compute_node(compute,
                                                              force_update)

        # get physical network info
        self.physical_networks = jsonutils.loads(
            self.stats.get("network", '{}'))

    def consume_from_instance(self, instance, filter_properties=None):
        """
        Inherit and overrider for instance booted from volume. If instance
        booted from volume, we should add the root gb.
        :param instance: the instance object
        :param filter_properties: the filter properties for filtering.
        :return:
        """

        context = filter_properties['context']
        if h_utils.is_boot_from_volume(context, instance):
            # deep copy to avoid changing original instance object.
            instance_tmp = copy.deepcopy(instance)
            instance_tmp['root_gb'] = 0
        else:
            instance_tmp = instance
        if self.numa_topology:
            cell_siblings = {}
            numa_topology = jsonutils.loads(self.numa_topology)
            cells = numa_topology.get('nova_object.data', {}).get('cells', [])
            for cell in cells:
                cell_data = cell.get('nova_object.data')
                cell_siblings[cell_data['id']] = copy.deepcopy(
                    cell_data.get('siblings', []))

        super(HuaweiHostState, self).consume_from_instance(instance_tmp)

        if self.numa_topology:
            numa_topology = jsonutils.loads(self.numa_topology)
            cells = numa_topology.get('nova_object.data', {}).get('cells', [])
            for cell in cells:
                cell_data = cell.get('nova_object.data')
                cell_data['siblings'] = cell_siblings[cell_data['id']]
            self.numa_topology = jsonutils.dumps(numa_topology)

        vm_state = instance.get('vm_state', vm_states.BUILDING)
        task_state = instance.get('task_state')
        if vm_state != vm_states.BUILDING and task_state in [
            task_states.REBUILD_SPAWNING,
            task_states.IMAGE_UPLOADING]:
            self.num_io_ops += 1

        # consume physical network resource
        physical_network_request = instance.get("stats").get("network", {})
        for phy_net in self.physical_networks.keys():
            if phy_net in physical_network_request:
                self.physical_networks[phy_net][
                    'used'] += physical_network_request[phy_net]
        LOG.debug("after consume is %s", self.physical_networks)


class HuaweiHostManager(host_manager.HostManager):
    """Huawei HostManager class."""

    def __init__(self):
        super(HuaweiHostManager, self).__init__()
        self.filter_handler = huawei_filters.HuaweiFilterHandler()

    # override the method for instance booted from volume
    def host_state_cls(self, host, node, **kwargs):
        compute = kwargs.get('compute')
        if compute and compute.get('cpu_info') == 'baremetal cpu':
            return ironic_host_manager.IronicNodeState(host, node, **kwargs)
        else:
            return HuaweiHostState(host, node, **kwargs)