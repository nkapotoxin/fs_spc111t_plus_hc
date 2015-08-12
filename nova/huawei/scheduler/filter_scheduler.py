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
The FilterScheduler is for creating instances locally.
You can customize this scheduler by specifying your own Host Filters and
Weighing Functions.
"""
import random

from oslo.config import cfg
from nova.compute import task_states
from nova import exception
from nova.i18n import _LE
from nova import objects
from nova.openstack.common import jsonutils
from nova.openstack.common import log as logging
from nova.scheduler import ironic_host_manager
from nova.scheduler import filter_scheduler
from nova.huawei.scheduler import utils
from nova.virt import hardware
from nova.scheduler import utils as scheduler_utils
CONF = cfg.CONF
LOG = logging.getLogger(__name__)

filter_scheduler_opts = [
    cfg.IntOpt('scheduler_host_subset_size',
               default=1,
               help='New instances will be scheduled on a host chosen '
                    'randomly from a subset of the N best hosts. This '
                    'property defines the subset size that a host is '
                    'chosen from. A value of 1 chooses the '
                    'first host returned by the weighing functions. '
                    'This value must be at least 1. Any value less than 1 '
                    'will be ignored, and 1 will be used instead')
]

CONF.register_opts(filter_scheduler_opts)


class HuaweiFilterTracker(dict):
    """Tracker that trace the number of filtered compute nodes of all
    filters"""

    def __init__(self):
        super(HuaweiFilterTracker, self).__init__()
        self.total_host_num = 0
        # record the filter return 0 host
        self.filter_0_host = None

    def to_string(self):
        sorted_result = sorted(self.iteritems(), key=lambda (_cls, _num): _num,
                               reverse=True)

        ordered_filters = ', '.join([cls for cls, num in sorted_result])
        trace = '%s returned 0 host; filtered more to less: %s' % (
            self.filter_0_host,
            ordered_filters)

        return trace


class HuaweiFilterScheduler(filter_scheduler.FilterScheduler):
    """Scheduler that can be used for filtering and weighing."""

    def __init__(self, *args, **kwargs):
        super(HuaweiFilterScheduler, self).__init__(*args, **kwargs)
        self._supports_affinity = scheduler_utils.validate_filter(
            'ServerGroupAffinityFilter')
        self._supports_anti_affinity = scheduler_utils.validate_filter(
            'ServerGroupAntiAffinityFilter')

    def _setup_instance_group(self, context, filter_properties):
        update_group_hosts = False
        scheduler_hints = filter_properties.get('scheduler_hints') or {}
        group_hint = scheduler_hints.get('group', None)
        if group_hint:
            group = objects.InstanceGroup.get_by_hint(context, group_hint)
            policies = set(('anti-affinity', 'affinity', 'legacy'))
            if any((policy in policies) for policy in group.policies):
                if ('affinity' in group.policies and
                        not self._supports_affinity):
                        msg = ("ServerGroupAffinityFilter not configured")
                        LOG.error(msg)
                        raise exception.NoValidHost(reason=msg)
                if ('anti-affinity' in group.policies and
                        not self._supports_anti_affinity):
                        msg = ("ServerGroupAntiAffinityFilter not configured")
                        LOG.error(msg)
                        raise exception.NoValidHost(reason=msg)
                update_group_hosts = True
                filter_properties.setdefault('group_hosts', set())
                user_hosts = set(filter_properties['group_hosts'])
                group_hosts = set(group.get_hosts(context))
                filter_properties['group_hosts'] = user_hosts | group_hosts
                filter_properties['group_policies'] = group.policies
        return update_group_hosts

    def select_destinations(self, context, request_spec, filter_properties):
        try:
            return super(HuaweiFilterScheduler, self).select_destinations(
                context, request_spec, filter_properties)
        except exception.NoValidHost:
            reason = ''

            if '__tracker' in filter_properties:
                LOG.debug('generate trace before raise')
                tracker = filter_properties.pop('__tracker')
                reason = ('Filter traceback: %s' % tracker.to_string())

            raise exception.NoValidHost(reason=reason)

    def _schedule(self, context, request_spec, filter_properties):
        """Returns a list of hosts that meet the required specs,
        ordered by their fitness.
        """
        elevated = context.elevated()
        instance_properties = request_spec['instance_properties']
        instance_type = request_spec.get("instance_type", None)
        instance_uuids = request_spec.get("instance_uuids", None)

        LOG.debug("[HINTS] filter_properties=%s" % filter_properties)
        # query scheduler_hints from database, and skip what in the parameters.
        if instance_uuids:
            inst_extra = objects.HuaweiInstanceExtra.get_by_instance_uuid(
                context, instance_uuids[0])
            if inst_extra:
                scheduler_hints = jsonutils.loads(
                    inst_extra.scheduler_hints or '{}')
                stats = jsonutils.loads(inst_extra.stats or '{}')
            else:
                scheduler_hints = {}
                stats = {}

            LOG.debug("[HINTS] Got scheduler_hints via db. "
                      "scheduler_hints=%s" % scheduler_hints)
            filter_properties['scheduler_hints'] = scheduler_hints
            filter_properties['stats'] = stats
            instance_properties['stats'] = stats
        try:
            update_group_hosts = self._setup_instance_group(context,filter_properties)
        except exception.InstanceGroupNotFound as e:
            # InstanceGroup has already checked in API,
            # might has been deleted when migrate/ha
            LOG.warning("ServerGroup %s doesn't exist" %
                        scheduler_hints.get('group', "None"))
            update_group_hosts = False
        config_options = self._get_configuration_options()

        filter_properties.update({'context': context,
                                  'request_spec': request_spec,
                                  'config_options': config_options,
                                  'instance_type': instance_type})

        self.populate_filter_properties(request_spec,
                                        filter_properties)

        # Find our local list of acceptable hosts by repeatedly
        # filtering and weighing our options. Each time we choose a
        # host, we virtually consume resources on it so subsequent
        # selections can adjust accordingly.

        # Note: remember, we are using an iterator here. So only
        # traverse this list once. This can bite you if the hosts
        # are being scanned in a filter or weighing function.
        hosts = self._get_all_host_states(elevated)

        selected_hosts = []
        if instance_uuids:
            num_instances = len(instance_uuids)
        else:
            num_instances = request_spec.get('num_instances', 1)
        for num in xrange(num_instances):
            #NOTE: add a tracker of filter
            tracker = HuaweiFilterTracker()
            filter_properties['__tracker'] = tracker

            # Filter local hosts based on requirements ...
            hosts = self.host_manager.get_filtered_hosts(hosts,
                                                         filter_properties,
                                                         index=num)
            if not hosts:
                # Can't get any more locally.
                break

            LOG.debug("Filtered %(hosts)s", {'hosts': hosts})

            weighed_hosts = self.host_manager.get_weighed_hosts(
                hosts,
                filter_properties)

            LOG.debug("Weighed %(hosts)s", {'hosts': weighed_hosts})

            scheduler_host_subset_size = CONF.scheduler_host_subset_size
            if scheduler_host_subset_size > len(weighed_hosts):
                scheduler_host_subset_size = len(weighed_hosts)
            if scheduler_host_subset_size < 1:
                scheduler_host_subset_size = 1

            chosen_host = random.choice(
                weighed_hosts[0:scheduler_host_subset_size])

            host_mapper = dict()
            for host in weighed_hosts:
                host_mapper[host.obj.host] = host

            if 'resize_prefer_to_same_host' in filter_properties:
                origin_host = filter_properties['resize_prefer_to_same_host']
                chosen_host = host_mapper.get(origin_host, chosen_host)

            migrate_host = filter_properties.get('migrate_host')
            if migrate_host:
                if migrate_host in host_mapper:
                    chosen_host = host_mapper.get(migrate_host)
                else:
                    # migrate_host not in filter hosts list
                    # raise NoVaildHost
                    break

            selected_hosts.append(chosen_host)

            # Now consume the resources so the filter/weights
            # will change for the next instance.
            # NOTE () adding and deleting pci_requests is a temporary
            # fix to avoid DB access in consume_from_instance() while getting
            # pci_requests. The change can be removed once pci_requests is
            # part of the instance object that is passed into the scheduler
            # APIs
            pci_requests = filter_properties.get('pci_requests')
            if pci_requests:
                instance_properties['pci_requests'] = pci_requests

            if request_spec.get('instance_type'):
                instance_properties['numa_topology'] = \
                    hardware.numa_get_constraints(instance_type, {})
            self._update_instance_topology(instance_properties, chosen_host)

            try:
                bind_info, instance_numa, __ = utils.get_inst_cpu_bind_info(
                    instance_properties, chosen_host.obj,
                    filter_properties=filter_properties)
            except exception.NovaException as ex:
                msg = ("Get cpu binding info on host %(host)s failed, the"
                       " host_numa_top is %(host_numa_top)s, "
                       "instance_properties is  %(instance_properties)s")
                params = {'host': chosen_host.obj.host,
                          'host_numa_top': chosen_host.obj.numa_topology,
                          'instance_properties': instance_properties}
                # set bind_info and instance_numa is None
                bind_info = None
                instance_numa = None
                LOG.debug(_LE(msg), params)
                LOG.debug(_LE(ex.format_message()))

            scheduler_hints = filter_properties.get('scheduler_hints', None)

            if instance_numa and instance_numa['cells'][0].get('is_huawei'):
                cells = []
                for cell in instance_numa['cells']:
                    cells.append(objects.InstanceNUMACell(
                        id=cell['id'], cpuset=set(cell['cpuset']),
                        memory=cell['mem']['total'],
                        pagesize=cell.get('pagesize')))

                format_inst_numa = objects.InstanceNUMATopology(cells=cells)
                instance_properties['numa_topology'] = format_inst_numa

            try:
                if isinstance(chosen_host.obj, ironic_host_manager.IronicNodeState):
                    chosen_host.obj.consume_from_instance(instance_properties)
                else:
                    chosen_host.obj.consume_from_instance(instance_properties,
                                                          filter_properties)
            except exception.PciDeviceRequestFailed as e:
                # pop the select chosen host in order to rollback resource in
                # memory
                LOG.warning("consume get exception: %s", e.format_message())
                rollback_hosts = [chosen_host]
                self.host_manager.force_update_host_states(context,
                                           rollback_hosts)

            if pci_requests:
                del instance_properties['pci_requests']
            if update_group_hosts is True:
                # NOTE(): Group details are serialized into a list now
                # that they are populated by the conductor, we need to
                # deserialize them
                if isinstance(filter_properties['group_hosts'], list):
                    filter_properties['group_hosts'] = set(
                        filter_properties['group_hosts'])

        self._check_fulfill_for_multiple_create(context, num_instances,
                                                selected_hosts)

        return selected_hosts
