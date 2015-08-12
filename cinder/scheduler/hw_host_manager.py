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

from cinder import db
from cinder import exception
from cinder import utils
from cinder.openstack.common import log as logging
from cinder.scheduler import host_manager

LOG = logging.getLogger(__name__)

class Hw_HostState(host_manager.HostState):
    """Mutable and immutable information tracked for a host."""

    def __init__(self, host, capabilities=None, service=None):
        super(Hw_HostState, self).__init__(host, capabilities, service)

        self.num_io_ops = 0

    def update_from_volume_capability(self, capability, service=None):
        """Update num_io_ops about a host from its volume_node info."""
        if capability:
            if self.updated and self.updated > capability['timestamp']:
                return

            self.num_io_ops = int(capability.get('io_workload', 0))
            LOG.debug(("Update the num_io_ops: %(num_io_ops)s") % {"num_io_ops" : self.num_io_ops})
            
        super(Hw_HostState, self).update_from_volume_capability(capability, service)

    def consume_from_volume(self, volume):
        """Incrementally update host state from an volume"""
        super(Hw_HostState, self).consume_from_volume(volume)
        LOG.debug(("The updated time : %s") % self.updated)
        if volume['status'] in utils.IO_OPS_LIST:
            self.num_io_ops += 1
            LOG.debug(("Update the num_io_ops: %s") % self.num_io_ops)

    def __repr__(self):
        return ("%s num_io_ops: %s" %
                (super(Hw_HostState, self).__repr__(), 
                 self.num_io_ops))


class Hw_HostManager(host_manager.HostManager):
    """HW extend HostManager class."""

    host_state_cls = Hw_HostState

    def __init__(self):
        super(Hw_HostManager, self).__init__()

