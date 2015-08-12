# vim: tabstop=4 shiftwidth=4 softtabstop=4

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
from nova.compute import task_states
from nova.compute import vm_states


_VM_TASK_STATE_NEXT_VM_STATE_MAP = {
    task_states.SPAWNING: [vm_states.ACTIVE],
    task_states.PAUSING: [vm_states.PAUSED],
    task_states.UNPAUSING: [vm_states.ACTIVE],
    task_states.SUSPENDING: [vm_states.SUSPENDED],
    task_states.RESUMING: [vm_states.ACTIVE],
    task_states.POWERING_OFF: [vm_states.STOPPED],
    task_states.POWERING_ON: [vm_states.ACTIVE],
    task_states.RESCUING: [vm_states.RESCUED],
    task_states.UNRESCUING: [vm_states.ACTIVE],
    task_states.REBUILDING: [vm_states.ACTIVE],
    task_states.REBUILD_BLOCK_DEVICE_MAPPING: [vm_states.ACTIVE],
    task_states.REBUILD_SPAWNING: [vm_states.ACTIVE],
    task_states.MIGRATING: [vm_states.ACTIVE],
    task_states.RESTORING: [vm_states.ACTIVE],
    task_states.SHELVING: [vm_states.SHELVED, vm_states.SHELVED_OFFLOADED],
    task_states.SHELVING_IMAGE_PENDING_UPLOAD: [vm_states.SHELVED,
                                                vm_states.SHELVED_OFFLOADED],
    task_states.SHELVING_IMAGE_UPLOADING: [vm_states.SHELVED,
                                           vm_states.SHELVED_OFFLOADED],
    task_states.SHELVING_OFFLOADING: [vm_states.SHELVED_OFFLOADED],
    task_states.UNSHELVING: [vm_states.ACTIVE]
}


def expect_vm_states(task_state):
    expect_states = _VM_TASK_STATE_NEXT_VM_STATE_MAP.get(task_state, [])
    if expect_states:
        expect_states = expect_states + [vm_states.ERROR]
    return expect_states
