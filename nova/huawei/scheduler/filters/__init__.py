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
Scheduler host filters
"""

from nova import filters
from nova.scheduler import filters as base_host_filters

from nova.i18n import _
from nova.openstack.common import log as logging

LOG = logging.getLogger(__name__)


class HuaweiFilterHandler(filters.BaseFilterHandler):
    def __init__(self):
        super(HuaweiFilterHandler, self).__init__(
            base_host_filters.BaseHostFilter)

    def get_filtered_objects(self, filter_classes, objs,
                             filter_properties, index=0):
        list_objs = list(objs)

        # NOTE: tracker that trace the number of filtered compute nodes of all
        # filters
        tracker_enabled = False

        if '__tracker' in filter_properties:
            tracker_enabled = True
            tracker = filter_properties['__tracker']
            host_num = len(list_objs)
            tracker.total_host_num = host_num

        def _record_filter_return_0_hosts():
            if tracker_enabled:
                tracker[cls_name] = host_num
                tracker.filter_0_host = cls_name
                LOG.debug('traced 0 hosts filter: %s, %s',
                          cls_name, tracker[cls_name])


        LOG.debug("Starting with %d host(s)", len(list_objs))
        for filter_cls in filter_classes:
            cls_name = filter_cls.__name__
            filter = filter_cls()

            if filter.run_filter_for_index(index):
                objs = filter.filter_all(list_objs, filter_properties)

                if objs is None:
                    LOG.debug("Filter %(cls_name)s says to stop filtering",
                              {'cls_name': cls_name})
                    _record_filter_return_0_hosts()
                    return

                list_objs = list(objs)
                if not list_objs:
                    LOG.info(_("Filter %s returned 0 hosts"), cls_name)
                    _record_filter_return_0_hosts()
                    break

                LOG.debug("Filter %(cls_name)s returned "
                          "%(obj_len)d host(s)",
                          {'cls_name': cls_name, 'obj_len': len(list_objs)})

                if tracker_enabled:
                    _filtered_nodes_num = host_num - len(list_objs)
                    if _filtered_nodes_num > 0:
                        tracker[cls_name] = _filtered_nodes_num
                        LOG.debug('traced: %s, %s',
                                  cls_name, tracker[cls_name])
                    host_num = len(list_objs)

        return list_objs


def all_filters():
    """Return a list of filter classes found in this directory.

    This method is used as the default for available scheduler filters
    and should return a list of all filter classes available.
    """
    return HuaweiFilterHandler().get_all_classes()