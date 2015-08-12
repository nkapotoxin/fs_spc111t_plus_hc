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

from nova.compute import stats as nova_stats
from nova.compute import task_states
from nova.compute import vm_states


class Stats(nova_stats.Stats):
    """Handler for updates to compute node workload stats."""

    def __init__(self):
        super(Stats, self).__init__()

    @property
    def io_workload(self):
        """Calculate an I/O based load by counting I/O heavy operations."""

        def _get(state, state_type):
            key = "num_%s_%s" % (state_type, state)
            return self.get(key, 0)

        io_workload_num = super(Stats, self).io_workload
        num_rebuild_spawnings = _get(task_states.REBUILD_SPAWNING, "task")
        num_image_uploadings = _get(task_states.IMAGE_UPLOADING, "task")

        return (io_workload_num + num_rebuild_spawnings + num_image_uploadings)
