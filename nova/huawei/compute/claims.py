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
Claim objects for use with resource tracking.
"""

import copy
import uuid

from nova.openstack.common import log as logging
from nova.compute import claims
from nova.huawei import utils as h_utils
from nova import conductor
from nova import exception
from nova.huawei.scheduler import utils as sched_utils
from nova import network
from nova import objects
from nova.openstack.common import jsonutils
from nova.virt import hardware

LOG = logging.getLogger(__name__)


def _get_nw_info_from_metadata(claim, metadata):
    network_api = network.API()
    for key, value in metadata.iteritems():
        key = key.strip()
        if key.startswith('vnic_info'):
            port_id = key.split(':')[1]
            port = network_api.show_port(claim.context, port_id)['port']
            if port['binding:vnic_type'] not in ['direct',
                                                 'netmap', 'macvtap']:
                continue
            bandwidth = value.strip().split(':')[1]
            nw = network_api.get(claim.context, port['network_id'])
            phy_net = nw.get('provider:physical_network')
            net_type = nw.get('provider:network_type')
            yield (phy_net, net_type, bandwidth)


def _test_bandwidth(claim):
    host = claim.tracker.host
    if not claim.tracker.pci_tracker:
        LOG.debug("pci_tracker is null.")
        return
    pci_pools = claim.tracker.pci_tracker.pci_stats.pools

    request_bandwidth = {}
    pre_request_metadata = claim.instance.get('metadata')
    if isinstance(pre_request_metadata, list):
        request_metadata = {}
        for metadata in pre_request_metadata:
            request_metadata[metadata['key']] = metadata['value']
    else:
        request_metadata = pre_request_metadata or {}
    for phy_net, __, bandwidth in _get_nw_info_from_metadata(
            claim, request_metadata):
        if phy_net in request_bandwidth:
            request_bandwidth[phy_net] += int(bandwidth)
        else:
            request_bandwidth[phy_net] = int(bandwidth)
    if len(request_bandwidth) == 0:
        return

    total_bandwidth = {}
    for pool in pci_pools:
        total_bandwidth[pool['physical_network']] = int(pool['bandwidths'])

    used_bandwidth = {}
    instance_list = conductor.API().instance_get_all_by_host(claim.context,
                                                            host)
    for instance in instance_list:
        if 'deleting' == instance.get('task_state'):
            continue
        if claim.instance.get('uuid') == instance.get('uuid'):
            continue
        metadata_dict = {}
        for metadata in instance.get('metadata', []):
            metadata_dict[metadata['key']] = metadata['value']
        for phy_net, __, bandwidth in _get_nw_info_from_metadata(
                claim, metadata_dict):
            if phy_net in used_bandwidth:
                used_bandwidth[phy_net] += int(bandwidth)
            else:
                used_bandwidth[phy_net] = int(bandwidth)

    for phy_net, bandwidth in request_bandwidth.iteritems():
        if phy_net not in total_bandwidth:
            raise exception.ComputeResourcesUnavailable(
                reason="Not Enough Bandwidth")
        free = total_bandwidth[phy_net] - used_bandwidth.get(phy_net, 0)
        if bandwidth > free:
            raise exception.ComputeResourcesUnavailable(
                reason="Not Enough Bandwidth")


class HuaweiClaim(claims.Claim):
    """A declaration that a compute host operation will require free resources.
    Claims serve as marker objects that resources are being held until the
    update_available_resource audit process runs to do a full reconciliation
    of resource usage.

    This information will be used to help keep the local compute hosts's
    ComputeNode model in sync to aid the scheduler in making efficient / more
    correct decisions with respect to host selection.
    """

    def __init__(self, context, instance, tracker, resources, overhead=None,
                 limits=None):

        super(HuaweiClaim, self).__init__(context, instance, tracker,
                                          resources, overhead=overhead,
                                          limits=limits)
        self._test_core_bind(context, instance, tracker)
        _test_bandwidth(self)

    def _test_core_bind(self, context, instance, resource_tracker):
        LOG.debug("get instance cpu bind info in _test_core_bind")
        filter_properties = {}
        inst_extra = objects.HuaweiInstanceExtra.get_by_instance_uuid(
            context, instance.uuid)
        if inst_extra:
            scheduler_hints = jsonutils.loads(
                inst_extra.scheduler_hints or '{}')
            stats = jsonutils.loads(inst_extra.stats or '{}')
        else:
            scheduler_hints = {}
            stats = {}
        filter_properties['scheduler_hints'] = scheduler_hints
        filter_properties['stats'] = stats
        pci_requests = objects.InstancePCIRequests.get_by_instance_uuid(
            context, instance['uuid'])
        if pci_requests:
            filter_properties['pci_requests'] = pci_requests

        bind_info, instance_numa, enable_ht = sched_utils.get_inst_cpu_bind_info(
            instance, resource_tracker.host, filter_properties=filter_properties)

        sched_utils.update_cpu_bind_info_to_db(bind_info, instance.uuid,
                                               instance_numa)

        if instance_numa and instance_numa['cells'][0].get('is_huawei'):
            cells = []
            for cell in instance_numa['cells']:
                cells.append(objects.InstanceNUMACell(
                    id=cell['id'], cpuset=set(cell['cpuset']),
                    memory=cell['mem']['total'],
                    pagesize=cell.get('pagesize')))

            format_inst_numa = objects.InstanceNUMATopology(cells=cells)
            self.claimed_numa_topology = format_inst_numa
            self.instance['numa_topology'] = format_inst_numa

    def _test_memory(self, resources, limit):
        if self.instance.system_metadata.get(
                'instance_type_extra_hw:mem_page_size'):
            return
        else:
            page_mem_used = 0
            host_topology = resources.get('numa_topology')
            if host_topology:
                host_topology = objects.NUMATopology.obj_from_db_obj(
                    host_topology)
                for cell in host_topology.cells:
                    for page in cell.mempages:
                        if page.size_kb != 4:
                            page_mem_used += page.size_kb * page.used / 1024
            tmp_resources = copy.deepcopy(resources)
            tmp_resources['memory_mb_used'] -= page_mem_used
            return super(HuaweiClaim, self)._test_memory(tmp_resources, limit)

    @property
    def disk_gb(self):
        """if the vm is boot from volume, just return ephemeral_gb"""
        if h_utils.is_boot_from_volume(self.context, self.instance):
            return self.instance['ephemeral_gb']
        else:
            return self.instance['root_gb'] + self.instance['ephemeral_gb']


class HuaweiRebuildClaim(HuaweiClaim):
    def __init__(self, context, instance, tracker, resources, overhead=None,
                 limits=None):
        self.pci_requests = None
        super(HuaweiRebuildClaim, self).__init__(context, instance,
                                                 tracker, resources,
                                                 overhead, limits)

    def _test_pci(self):
        pci_requests = objects.InstancePCIRequests.\
            get_by_instance_uuid_and_newness(self.context,
                                             self.instance['uuid'],
                                             False)
        new_pci_requests = self._generate_new_pci_requests(pci_requests)
        self.pci_requests = self._merge_pci_requests(pci_requests,
                                                     new_pci_requests)
        if self.pci_requests.requests:
            LOG.info("%s's pci_request is %s" % (
                self.instance['uuid'], self.pci_requests.requests))
        if new_pci_requests.requests:
            claim = self.tracker.pci_tracker.stats.support_requests(
                new_pci_requests.requests)
            if not claim:
                return _('Claim pci failed.')

    def _generate_new_pci_requests(self, pci_requests):
        requests = objects.InstancePCIRequests(requests=[])
        for pci_request in pci_requests.requests:
            request = objects.InstancePCIRequest(
                count=1,
                spec=copy.deepcopy(pci_request.spec),
                is_new=True,
                request_id=str(uuid.uuid4()))
            requests.requests.append(request)
        return requests

    def _merge_pci_requests(self, pci_requests, new_pci_requests):
        for new_pci_request in new_pci_requests.requests:
            pci_requests.requests.append(new_pci_request)
        return pci_requests


class HuaweiResizeClaim(claims.ResizeClaim):
    """Claim used for holding resources for an incoming resize/migration
    operation.
    """
    def __init__(self, context, instance, instance_type, image_meta, tracker,
                 resources, overhead=None, limits=None):
        self.pci_requests = None
        self.claimed_numa_topology = None
        self.bind_info = None
        super(HuaweiResizeClaim, self).__init__(context, instance,
                                                instance_type, image_meta,
                                                tracker, resources,
                                                overhead=overhead,
                                                limits=limits)
        _test_bandwidth(self)

    @property
    def disk_gb(self):
        """if the vm is boot from volume, just return ephemeral_gb"""
        if h_utils.is_boot_from_volume(self.context, self.instance):
            return self.instance_type['ephemeral_gb']
        else:
            return (self.instance_type['root_gb'] +
                    self.instance_type['ephemeral_gb'])

    def _test_pci(self):
        pci_requests = objects.InstancePCIRequests.\
            get_by_instance_uuid_and_newness(self.context,
                                             self.instance['uuid'],
                                             False)
        new_pci_requests = self._generate_new_pci_requests(pci_requests)
        self.pci_requests = self._merge_pci_requests(pci_requests,
                                                     new_pci_requests)
        if self.pci_requests.requests:
            LOG.info("%s's pci_request is %s" % (
                self.instance['uuid'], self.pci_requests.requests))
        if new_pci_requests.requests:
            claim = self.tracker.pci_tracker.stats.support_requests(
                new_pci_requests.requests)
            if not claim:
                return _('Claim pci failed.')

    def _test_ext_resources(self, limits):
        # add instance uuid to instance type to use and drop it after used.
        self.instance_type.update({'instance_uuid': self.instance['uuid']})
        result = super(HuaweiResizeClaim, self)._test_ext_resources(limits)
        self.instance_type.pop('instance_uuid')
        return result

    def _generate_new_pci_requests(self, pci_requests):
        requests = objects.InstancePCIRequests(requests=[])
        for pci_request in pci_requests.requests:
            request = objects.InstancePCIRequest(
                count=1,
                spec=copy.deepcopy(pci_request.spec),
                is_new=True,
                request_id=str(uuid.uuid4()))
            requests.requests.append(request)
        return requests

    def _merge_pci_requests(self, pci_requests, new_pci_requests):
        for new_pci_request in new_pci_requests.requests:
            pci_requests.requests.append(new_pci_request)
        return pci_requests

    def _test_memory(self, resources, limit):
        if self.instance_type.get('extra_specs', {})\
                .get("hw:mem_page_size"):
            return
        else:
            page_mem_used = 0
            host_topology = resources.get('numa_topology')
            if host_topology:
                host_topology = objects.NUMATopology.obj_from_db_obj(
                    host_topology)
                for cell in host_topology.cells:
                    for page in cell.mempages:
                        if page.size_kb != 4:
                            page_mem_used += page.size_kb * page.used / 1024
            tmp_resources = copy.deepcopy(resources)
            tmp_resources['memory_mb_used'] -= page_mem_used
            return super(HuaweiResizeClaim, self)._test_memory(tmp_resources,
                                                               limit)

    def _test_numa_topology(self, resources, limit):
        network_info = objects.InstanceInfoCache.get_by_instance_uuid(
            self.context, self.instance['uuid']).network_info
        self.instance['numa_topology'] = self.numa_topology or {}
        self.instance['vcpus'] = self.instance_type['vcpus']
        self.instance['memory_mb'] = self.memory_mb
        # check if cpu&mem are ok
        bind_info, instance_numa, _ = sched_utils.get_inst_cpu_bind_info(
            self.instance, self.tracker.host, network_info=network_info,
            action="resize")

        if instance_numa and instance_numa['cells'][0].get('mem'):
            cells = []
            for cell in instance_numa['cells']:
                cells.append(objects.InstanceNUMACell(
                    id=cell['id'], cpuset=set(cell['cpuset']),
                    memory=cell['mem']['total'],
                    pagesize=cell.get('pagesize')))

            format_inst_numa = objects.InstanceNUMATopology(
                cells=cells, instance_uuid=self.instance['uuid'])
            self.claimed_numa_topology = format_inst_numa
            self.bind_info = bind_info
            self.instance['numa_topology'] = format_inst_numa
        elif not instance_numa:
            return
        else:
            self.claimed_numa_topology = instance_numa
            self.bind_info = bind_info
            self.instance['numa_topology'] = instance_numa
