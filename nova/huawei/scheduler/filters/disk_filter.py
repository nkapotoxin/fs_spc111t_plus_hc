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

import copy
from nova.openstack.common.gettextutils import _
from nova.openstack.common import log as logging
from nova.scheduler.filters import disk_filter
from nova.huawei import utils as h_utils

LOG = logging.getLogger(__name__)


class HuaweiDiskFilter(disk_filter.DiskFilter):
    """Disk Filter with over subscription flag."""

    def host_passes(self, host_state, filter_properties):
        """Filter based on disk usage."""

        #deep copy a filter properties to avoid changing
        filter_properties_tmp = copy.deepcopy(filter_properties)

        context = filter_properties_tmp['context']
        instance = filter_properties_tmp['request_spec']['instance_properties']
        if h_utils.is_boot_from_volume(context, instance):
            # just process local disk(ephemeral and swap), so set
            # root_gb to zero
            filter_properties_tmp.get('instance_type')['root_gb'] = 0

            # if the request disk size is zero, we should return true.
            # In negative free disk size condition, the instance booted volume
            # is not create successfully.
            instance_type = filter_properties.get('instance_type')
            requested_disk = (1024 * (instance_type['ephemeral_gb']) +
                             instance_type['swap'])
            if requested_disk == 0:
                return True

        return super(HuaweiDiskFilter, self).host_passes(host_state,
                                                filter_properties_tmp)


