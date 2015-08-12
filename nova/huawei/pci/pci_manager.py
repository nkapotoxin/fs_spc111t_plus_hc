# Copyright 2013 OpenStack Foundation
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

from nova import context
from nova import exception
from nova import objects
from nova.compute import task_states
from nova.pci import pci_device
from nova.pci import pci_manager
from nova.compute import vm_states
from nova.openstack.common import log as logging

LOG = logging.getLogger(__name__)


class HuaweiPciDevTracker(pci_manager.PciDevTracker):
    def update_pci_for_migration(self, context, instance, sign=1):
        if sign == 1 and not self._is_allocated(context, instance, True):
            devs = self._claim_instance(context, instance, 'new_')
            if devs:
                self.claims[instance['uuid']] = devs + \
                    self.claims.get(instance['uuid'], [])
        if sign == -1:
            task_state = instance['task_state']
            if task_state in (task_states.RESIZE_REVERTING,):
                # revert
                self._free_migration(instance, is_new=True)
            else:
                # confirm
                self._free_migration(instance, is_new=False)

    def _claim_instance(self, context, instance, prefix=''):
        if prefix:
            is_new = True
        else:
            is_new = False
        pci_requests = objects.InstancePCIRequests.\
            get_by_instance_uuid_and_newness(
                context, instance['uuid'], is_new)
        if not pci_requests.requests:
            return None
        devs = self.stats.consume_requests(pci_requests.requests)
        if not devs:
            raise exception.PciDeviceRequestFailed(pci_requests)
        for dev in devs:
            pci_device.claim(dev, instance)
        return devs

    def _free_migration(self, instance, is_new=True):
        ctxt = context.get_admin_context()
        pci_requests = objects.InstancePCIRequests.\
            get_by_instance_uuid_and_newness(
                ctxt, instance['uuid'], is_new)
        request_ids = [r.request_id for r in pci_requests.requests]
        self._free_device_in_request(instance, request_ids)
        source_pci_requests = objects.InstancePCIRequests.\
            get_by_instance_uuid(ctxt, instance['uuid'])
        requests = []
        for request in source_pci_requests.requests:
            if request.is_new == is_new:
                continue
            request.is_new = False
            requests.append(request)
        source_pci_requests.requests = requests
        source_pci_requests.save(ctxt)

    def update_pci_for_instance(self, context, instance):
        """Update instance's pci usage information.

        The caller should hold the COMPUTE_RESOURCE_SEMAPHORE lock
        """

        uuid = instance['uuid']
        vm_state = instance['vm_state']
        task_state = instance['task_state']

        if vm_state == vm_states.DELETED:
            if self.allocations.pop(uuid, None):
                self._free_instance(instance)
            elif self.claims.pop(uuid, None):
                self._free_instance(instance)
        elif task_state == task_states.RESIZE_FINISH:
            devs = self.claims.pop(uuid, None)
            if devs:
                self._allocate_instance(instance, devs)
                self.allocations[uuid] = devs + self.allocations.get(uuid, [])
        elif task_state == task_states.RESIZE_MIGRATED:
            # will not free pci here, or might error at revert
            # and because instance's host is changed in source host.
            #
            # if dest host update resource first, will goto this branch
            # just like what you did in update_pci_for_migration.
            #
            # instance with RESIZE_MIGRATED only can be seen in dest host.
            if not self._is_allocated(context, instance, True):
                devs = self._claim_instance(context, instance, 'new_')
                if devs:
                    self.claims[instance['uuid']] = devs + \
                        self.claims.get(instance['uuid'], [])
        elif task_state == task_states.RESIZE_REVERTING:
            # instance with RESIZE_REVERTING cat be both in source&dest
            # do nothing
            return
        elif task_state == task_states.REBUILDING:
            if not self._is_allocated(context, instance, is_new=True):
                devs = self._claim_instance(context, instance, prefix="new_")
                if devs:
                    self._allocate_instance(instance, devs)
                self.allocations[uuid] = devs
        elif (uuid not in self.allocations and
              uuid not in self.claims):
            devs = self._claim_instance(context, instance)
            if devs:
                self._allocate_instance(instance, devs)
                self.allocations[uuid] = devs

    def free_pci_dev(self, context, instance, is_new=True):
        pci_requests = objects.InstancePCIRequests.\
            get_by_instance_uuid_and_newness(
                context, instance['uuid'], is_new)
        request_ids = [r.request_id for r in pci_requests.requests]

        self._free_device_in_request(instance, request_ids)

    def _is_allocated(self, context, instance, is_new):
        uuid = instance['uuid']
        # Only see pci_request.count = 1
        all_pci_request_ids = set(dev.request_id for dev in self.pci_devs
                                  if dev.status in ("claimed", "allocated") and
                                  dev.instance_uuid == uuid)
        pci_requests = objects.InstancePCIRequests.\
            get_by_instance_uuid_and_newness(
                context, instance['uuid'], is_new)
        pci_request_ids = set(req.request_id for req in pci_requests.requests)
        return pci_request_ids <= all_pci_request_ids

    def free_detached_device(self, dev, instance):
        request_ids = [dev.request_id]
        self._free_device_in_request(instance, request_ids)

    def _free_device_in_request(self, instance, request_ids):
        LOG.info("%s will free device of %s" % (instance['uuid'], request_ids))
        claim_devs = []
        devs = self.claims.pop(instance['uuid'], [])
        for dev in devs:
            if dev['status'] in ('claimed', 'allocated') and \
                dev['instance_uuid'] == instance['uuid'] and \
                    dev['request_id'] in request_ids:
                self._free_device(dev)
            else:
                claim_devs.append(dev)
        if claim_devs:
            self.claims[instance['uuid']] = claim_devs

        alloc_devs = []
        devs = self.allocations.pop(instance['uuid'], [])
        for dev in devs:
            if dev['status'] in ('claimed', 'allocated') and \
                dev['instance_uuid'] == instance['uuid'] and \
                    dev['request_id'] in request_ids:
                self._free_device(dev)
            else:
                alloc_devs.append(dev)
        if alloc_devs:
            self.allocations[instance['uuid']] = alloc_devs

    def _allocate_from_request(self, context, instance, pci_requests):
        # will not through any exception here
        # avoid to change something
        if not pci_requests.requests:
            return None
        devs = self.stats.consume_requests(pci_requests.requests)
        for dev in devs:
            pci_device.allocate(dev, instance)
        return devs
