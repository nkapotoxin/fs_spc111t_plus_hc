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
from oslo.config import cfg

from nova import exception
from nova import objects
from nova.openstack.common import log as logging
from nova.scheduler import filters
from nova.openstack.common import jsonutils

from nova.huawei.scheduler import utils

LOG = logging.getLogger(__name__)

CONF = cfg.CONF


class CpuBindFilter(filters.BaseHostFilter):
    """Filter cpu bind"""

    def host_passes(self, host_state, filter_properties):
        """CpuBindFilter

        The instance numa topology is like:
        {u'instance_uuid': u'786d1430-dfe2-4423-8522-4a5394715b32',
        u'cells': [{u'cpuset': [0],
                   u'id': 0,
                   u'memory': 256},
                   {u'cpuset': [1,2,3],
                   u'id': 1,
                   u'memory': 768 }],
        u'id': 122}
        """

        inst_prop = filter_properties['request_spec'].get(
            'instance_properties')
        inst_numa_top = inst_prop.get('numa_topology') if inst_prop else None
        # get the pagesize from instance_type
        instance_type = filter_properties['request_spec'].get(
            'instance_type', None)
        pagesize = None
        if instance_type:
            pagesize = instance_type.get('extra_specs', {}).get(
                "hw:mem_page_size", None)

        if inst_numa_top:
            inst_numa_top = utils.convert_inst_numa_topology(inst_numa_top)

        vcpus = filter_properties.get('instance_type').get('vcpus')
        mem = filter_properties.get('instance_type').get('memory_mb')

        enable_bind, enable_ht, any_mode, numa_opts = \
            utils.get_inst_affinity_mask(filter_properties)

        request_spec = filter_properties['request_spec']
        host_numa_top = copy.deepcopy(jsonutils.loads(
            host_state.numa_topology or '{}'))
        if host_numa_top and host_numa_top.get('nova_object.data'):
            host_numa_top = utils.convert_host_numa_topology(
                host_numa_top)
        elif numa_opts or enable_bind or not any_mode or pagesize:
            LOG.debug('Host %s don\'t support numa,don\'t pass',
                      host_state.host)
            LOG.debug('options:enable_bind(%s), any_mode(%s), numa_opts(%s), '
                      'pagesize(%s)'
                      % (enable_bind, any_mode, numa_opts, pagesize))
            return False
        else:
            LOG.debug('Host %s don\'t support numa, pass', host_state.host)
            return True

        context = filter_properties['context'].elevated()
        hw_instance_extras = objects.HuaweiInstanceExtra.get_by_host(
            context, host_state.host)

        instance_uuids = request_spec.get('instance_uuids', [])
        instance_uuid = instance_uuids[0] if instance_uuids else None

        if utils.is_host_numa_confict(hw_instance_extras, numa_opts,
                                      instance_uuid):
            LOG.debug('Numa instance cannot booted with non-numa '
                      'instance in host %s', host_state.host)
            return False

        if utils.is_any_node_confict(hw_instance_extras, any_mode,
                                     instance_uuid):
            LOG.debug('any-mode instance cannot booted with non-any-mode '
                      'instance in host %s', host_state.host)
            return False
        if (enable_bind, any_mode, numa_opts) == (
                False, True, 0) and not pagesize:
            LOG.debug('Cpubindfilter passed, enable_bind(%s), any_mode(%s),'
                      ' numa_opts(%s)' % (enable_bind, any_mode, numa_opts))
            return True
        if not host_state.numa_topology:
            LOG.info("No numa topology info of host: %s found, cpu bind "
                     "filter failed", host_state.host)
            return False
        # when a numa vm migrate from host1 to host2, and host1 is empty
        # if you want to forbid to create a no-numa vm in host1
        # call this function earlier
        hw_instance_extras = \
            utils._extend_hw_instance_extra(context, host_state.host)
        utils.update_numa_topo_bind_info(host_numa_top,
                                         hw_instance_extras, any_mode,
                                         instance_uuid)
        LOG.debug("CpuBindFilter trying to filter instance: %(instance_uuid)s,"
                  " with host_numa_top:%(host_numa_top)s of host:%(host)s",
                  {"instance_uuid": instance_uuid, "host_numa_top":
                      host_numa_top, "host": host_state.host})
        enable_evs = utils.get_evs_affinity(filter_properties)

        sriov_numa_id = None
        evs_numa_id = None
        if numa_opts == 2:
            try:
                sriov_numa_id = utils.get_numa_id_with_vf_request(
                    host_state, filter_properties)
            except exception.NovaException as ex:
                LOG.info(ex.format_message())
                return False
        if enable_evs:
            try:
                evs_numa_id = utils.get_specific_numa(host_state,
                                                      filter_properties)
            except exception.NovaException as error:
                # if catch the exception, the host is not suitable for creating
                # evs instances.
                LOG.debug(error.format_message())
                return False

        if sriov_numa_id and enable_evs and sriov_numa_id != evs_numa_id:
            LOG.info("Both EVS Numa and IO Numa are specified, But SRIOV"
                     "(node:%s) and EVS(node:%s) devices are not in one "
                     "numa cell." % (sriov_numa_id, evs_numa_id))
            return False
        specific_numa_id = sriov_numa_id or evs_numa_id

        try:
            if inst_numa_top and not numa_opts:
                request_spec = filter_properties.get('request_spec', {})
                instance = request_spec.get('instance_properties', {})
                fitted_inst_numas = utils.get_fitted_inst_numas(instance,
                                                                host_state)
                utils.pin_vcpu_with_inst_numa(enable_bind, enable_ht,
                                              any_mode, fitted_inst_numas,
                                              host_numa_top)
            else:
                utils.pin_vcpu(enable_bind, enable_ht, any_mode, vcpus,
                               mem, host_numa_top, numa_opts,
                               numa_id=specific_numa_id, pagesize=pagesize,
                               host_state=host_state)
        except exception.NovaException as ex:
            LOG.debug(ex.format_message())
            return False
        return True
