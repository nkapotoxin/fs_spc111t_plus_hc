# vim: tabstop=4 shiftwidth=4 softtabstop=4

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
HW extend volume manager
"""


import time
import traceback

from oslo.config import cfg

from cinder import context
from cinder import utils
from cinder.volume import manager as volume_manager
from cinder.openstack.common import log as logging

LOG = logging.getLogger(__name__)


class Hw_VolumeManager(volume_manager.VolumeManager):
    """Manages attachable block storage devices."""

    def update_service_capabilities(self, capabilities):
        """Update the io_workload in capabilities."""
        try:
            ctxt = context.get_admin_context()
            volumes = self.db.volume_get_all_by_host(ctxt, self.host)
            io_workload = 0
            for volume in volumes:
                if volume['status'] in utils.IO_OPS_LIST:
                    io_workload += 1
            capabilities['io_workload'] = io_workload
            LOG.debug('Calculate the io_workload result, capabilities: %s' % (capabilities))
        except Exception:
            LOG.error('Calculate the io_workload failed, exception: %s' % (traceback.format_exc()))
            pass
        
        self.last_capabilities = capabilities

