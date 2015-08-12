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

"""Utility methods for scheduling."""

import copy
import itertools
import six
import ast

from oslo.config import cfg
from nova import context
from nova import exception
from nova.huawei.objects import compute_node as hw_cn_obj_cls
from nova import objects
from nova.compute import task_states
from nova.compute import vm_states
from nova.openstack.common import jsonutils
from nova.openstack.common import log as logging
from nova.openstack.common.gettextutils import _
from nova.pci import pci_request
from nova.pci import pci_stats
from nova.virt import hardware
from oslo.utils import units


LOG = logging.getLogger(__name__)

interval_opts = [
    cfg.StrOpt("qemu_pin_set",
               default="",
               help="emulatorpin of numa")
]
CONF = cfg.CONF
CONF.register_opts(interval_opts)

def record_sched_ints_hw_extra(filter_properties):
    schedule_hints = filter_properties.get('scheduler_hints')
    instance_uuids = filter_properties['request_spec'].get('instance_uuids')
    context = filter_properties['context'].elevated()
    schedule_hints = jsonutils.dumps(schedule_hints)
    for instance_uuid in instance_uuids:
        objects.HuaweiInstanceExtra(instance_uuid=instance_uuid,
                                    scheduler_hints=schedule_hints). \
            create(context)


def is_host_numa_confict(hw_instance_extras, numa_opts, instance_uuid=None):
    """Means of values of numa_opts: 0: non-numa; 1:numa; 2:numa
    """
    for extra in hw_instance_extras:
        if instance_uuid == extra.instance_uuid:
            continue
        db_numaopt = int((jsonutils.loads(
            extra.scheduler_hints or '{}')).get('numaOpts', 0))
        if bool(numa_opts) != bool(db_numaopt):
            return True
    return False


def is_any_node_confict(hw_instance_extras, anyMode, instance_uuid):
    for extra in hw_instance_extras:
        db_any_mode = (jsonutils.loads(
            extra.scheduler_hints or '{}')).get('hyperThreadAffinity', 'any')
        if extra.instance_uuid != instance_uuid:
            if db_any_mode != 'any' and anyMode:
                return True
            if db_any_mode == 'any' and not anyMode:
                return True
    return False


def is_host_enable_hyperthread(numa_topo):
    siblings = numa_topo['cells'][0].get('siblings')
    return bool(siblings and len(siblings[0]) >= 2)


def update_numa_topo_bind_info(host_numa_top, hw_instance_extras, any_mode,
                               instance_uuid):
    # the initial unbound_cpu_siblings is [[3,11],[0,8],[1,9],[2,10]]
    # hw_instance_extras[0].core_bind:[{"vcpu": 0, "pcpus": [8]},
    # {"vcpu": 1, "pcpus": [10]}]
    # after the following process, get free cpus with siblings
    #  is:[[3,11],[0],[1,9],[2]]
    # cpu_bind_num is like:{0:0, 1:0, 2:0,...}
    """
        {
        u'cells': [{
            u'mem': {
                u'total': 12008,
                u'used': 1024
            },
            u'siblings': [[3,11],[0,8],[1,9],[2,10]],
            u'unbound_cpu_siblings':[[3,11],[0],[1,9],[2]],
            u'cpu_bind_num':{0:0, 1:1...}
            u'cpu_usage': 2,
            u'cpus': u'0,1,2,3,8,9,10,11',
            u'id': 0
    }"""
    admin_context = context.get_admin_context()
    instance = objects.Instance.get_by_uuid(admin_context ,instance_uuid)
    if not host_numa_top:
        return None
    for cell in host_numa_top['cells']:
        cell['cpu_bind_num'] = {}
        bind_nums = list(cell['cpus'].split(','))
        for c in bind_nums:
            if not c:
                continue
            cell['cpu_bind_num'][int(c)] = 0
    for cell in host_numa_top['cells']:
        unbound_cpu_siblings = copy.deepcopy(cell['siblings'])
        for siblings in unbound_cpu_siblings:
            for cpu in siblings[::-1]:
                if str(cpu) not in cell['cpus'].split(','):
                    siblings.remove(cpu)
        for extra in hw_instance_extras:
            if extra.instance_uuid == instance_uuid and\
                    instance.task_state != task_states.RESIZE_PREP:
                continue
            inst_core_binds = jsonutils.loads(extra.core_bind or '[]')
            pcpus = [core_bind['pcpus'] for core_bind in inst_core_binds]
            pcpus = [c for s in pcpus for c in s]
            for cpu in pcpus:
                if str(cpu) in cell['cpus'].split(','):
                    cell['cpu_bind_num'][cpu] += 1
                    if not any_mode:
                        for siblings in unbound_cpu_siblings:
                            if cpu in siblings:
                                siblings.remove(cpu)
        cell['unbound_cpu_siblings'] = unbound_cpu_siblings


def get_specific_numa(host_state, filter_properties, network_info=None,):
    admin_context = context.get_admin_context()

    phy_net_numa_mapping = get_pci_numa_mapping(
        admin_context, filter_properties,
        host_state, network_info)

    #TODO if the pci_numa_mapping is null no processing
    if len(set(phy_net_numa_mapping.values())) != 1:
        LOG.debug(_("the all physical network should in "
                    "one numa node"))
        raise exception.NovaException(_("the all physical network "
                                        "should in one numa node"))
    return phy_net_numa_mapping.values()[0]


def get_res_enough_numa(numa_topo, vcpus, mem, specified_numa=None,
                        pagesize=None):
    """

    :param numa_topo:
    :param vcpus:
    :param mem:
    :param specified_numa. a list of numa id.
    :return:
    """
    ret_cell_ids = []
    for cell in numa_topo['cells']:
        cell_free_cpu = len(
            [c for s in cell['unbound_cpu_siblings'] for c in s])
        cell_free_mem = cell['mem']['total'] - cell['mem']['used']
        cell_mem_pages = cell['mempages']
        if not pagesize:
            for page in cell_mem_pages:
                if page['size_kb'] != 4:
                    cell_free_mem = cell_free_mem - (
                        page['total'] - page['used']) * page['size_kb'] / 1024
        if mem <= cell_free_mem and vcpus <= cell_free_cpu:
            # instance uses huge page
            if pagesize:
                pagesize = int(pagesize)
                mem_kb = mem * units.Ki
                for page in cell_mem_pages:
                    if pagesize == page['size_kb'] and (
                            mem_kb % pagesize == 0) and mem_kb <= (
                        page['total'] - page['used']) * page['size_kb']:
                         ret_cell_ids.append(cell['id'])
                         break
            else:
                ret_cell_ids.append(cell['id'])

    if specified_numa is not None:
        ret_cell_ids = list(set(ret_cell_ids) & set(
            list([int(specified_numa)])))

    if not ret_cell_ids:
        raise exception.NovaException('No numa cell have enough resources'
                                      ' the numa_topology is %s'
                                      % numa_topo)
    return ret_cell_ids


def _get_bound_least_numa(host_state, host_numa_top, numa_ids):
    _get_pci_numa(host_state, host_numa_top)
    cells = host_numa_top['cells']
    sorted_cells = sorted(
        cells, key=lambda c: c['cpu_bind_num'].values().count(0),
        reverse=True)
    sorted_cells = sorted(
        sorted_cells, key=lambda c: sum(c['cpu_bind_num'].values()))
    sorted_cells = sorted(sorted_cells, key=lambda c: c['pci'])

    LOG.debug("sorted cells is %s and candidate numa is %s",
              sorted_cells, numa_ids)
    return [c for c in sorted_cells if c['id'] in numa_ids][0]


def _get_pci_numa(host_state, host_numa_top):
    compute_physical_network = host_state.stats.get("network", {})
    # maybe the compute physical network is in json format
    if not isinstance(compute_physical_network, dict):
        compute_physical_network = jsonutils.loads(
            compute_physical_network)

    # get host pci device numa info
    pci_numas = []
    for physical_network, info in compute_physical_network.iteritems():
        numa_id = info.get("numa_id")
        if numa_id != "None" and numa_id:
            pci_numas.append(int(numa_id))

    # set pci device info in cell
    cells = host_numa_top['cells']
    for cell in cells:
        if cell['id'] in pci_numas:
            cell['pci'] = 1
        else:
            cell['pci'] = 0


def _get_the_suitable_numa(host_state, host_numa_top, candidate_numa_ids):
    _get_pci_numa(host_state, host_numa_top)

    cells = host_numa_top['cells']
    # get the cells sorted by pci device
    sorted_cells = sorted(cells, key=lambda c: c['pci'])
    candidate_numa = [c for c in sorted_cells if c['id']
                      in candidate_numa_ids][0]
    LOG.debug("sorted cells is %s", sorted_cells)
    LOG.debug("candidate numa is %s", candidate_numa)
    return candidate_numa['id'], candidate_numa_ids[candidate_numa['id']]


def pin_vcpu(enable_bind, enable_ht, any_mode, vcpus, mem, host_numa_top,
             numa_opts=0, **kwargs):
    """The structure of host_numa_top is:
    {
        u'cells': [{
            u'mem': {
                u'total': 12008,
                u'used': 1024
            },
            u'siblings': [[3,11],[0,8],[1,9],[2,10]],
            u'unbound_cpu_siblings':[[3,11],[0],[1,9],[2]],
            u'cpu_bind_num':{0:0, 1:0, 2:0}
            u'cpu_usage': 2,
            u'cpus': u'0,1,2,3,8,9,10,11',
            u'id': 0
        },}
        The format of return:
        ret_vcpu_pin: {0:[3], 1:[4],2:[8],3:[9]} or{0:[0,1,2,3],2:[0,1,2,3]}
        ret_inst_numa: {"cells": [{"mem": {"total": 256}, "cpuset": [0],
        "id": 0, 'is_huawei': True}]} or {}
        The 'is_huawei' field is to differentiate with openstack numa
        there are 10 cases:
         3(any_mode, enable_ht, others)* 2(numa or not)* 2(bind or not)
         two cases is not supported:
        1). not numa_opts and enable_ht and not enable_bind
        2).numa_opts and enable_ht and not enable_bind
    """

    ret_vcpu_pin = {}
    selected_numa_id = None
    if any_mode and enable_ht:
        raise exception.NovaException('Parameters conflict of any_mode and '
                                      'enable_ht')
    if not numa_opts and enable_ht and not enable_bind:
        raise exception.NovaException('Not support this cases: not numa_opts'
                                      ' and enable_ht and not enable_bind')
    if numa_opts and enable_ht and not enable_bind:
        raise exception.NovaException('Not support this cases: numa_opts and'
                                      ' enable_ht and not enable_bind')
    if enable_ht and vcpus % 2:
        msg = ('In sync mode, the cpuset  %s should be even number.'
               % vcpus)
        raise exception.NovaException(msg)

    if not is_host_enable_hyperthread(host_numa_top) and enable_ht:
        LOG.warning("Host don't support ht, but specified sync mode, ignore.")
        enable_ht = False

    if any_mode and numa_opts and not enable_bind:
        numa_cell_ids = get_res_enough_numa(host_numa_top, vcpus, mem,
                                            kwargs['numa_id'],
                                            kwargs['pagesize'])
        selected_numa = _get_bound_least_numa(
            kwargs['host_state'], host_numa_top, numa_cell_ids)
        selected_numa_id = selected_numa['id']
        for i in range(vcpus):
            ret_vcpu_pin.update({i: selected_numa['cpu_bind_num'].keys()})

    if any_mode and numa_opts and enable_bind:
        numa_cell_ids = get_res_enough_numa(host_numa_top, vcpus, mem,
                                            kwargs['numa_id'],
                                            kwargs['pagesize'])
        selected_numa = _get_bound_least_numa(
            kwargs['host_state'], host_numa_top, numa_cell_ids)
        selected_numa_id = selected_numa['id']
        sorted_cpus = [k for k, v in sorted(
            selected_numa['cpu_bind_num'].items(), key=lambda i: i[1])]
        for i in range(vcpus):
            ret_vcpu_pin.update({i: [sorted_cpus[i]]})

    if any_mode and not numa_opts and enable_bind:
        #all_cpu_bind_count.keys() means all cpus of this host
        all_cpu_bind_count = {}
        cells = host_numa_top['cells']
        for cell in cells:
            all_cpu_bind_count.update(cell['cpu_bind_num'])
        sorted_cpus = [k for k, v in sorted(
            all_cpu_bind_count.items(), key=lambda i: i[1])]
        cpu_len = len(sorted_cpus)
        for i in range(vcpus):
            # NOTE: the i maybe larger than cpu_len
            ret_vcpu_pin.update({i: [sorted_cpus[i % cpu_len]]})
    if any_mode and not numa_opts and not enable_bind:
        all_cpu_bind_count = {}
        cells = host_numa_top['cells']
        for cell in cells:
            all_cpu_bind_count.update(cell['cpu_bind_num'])
        for i in range(vcpus):
            ret_vcpu_pin.update({i: all_cpu_bind_count.keys()})

    # NOTE: the following cases is not any_mode
    if enable_ht and numa_opts and enable_bind:
        #usually the thread_per_core is 2
        numa_cell_ids = get_res_enough_numa(host_numa_top, vcpus, mem,
                                            kwargs['numa_id'],
                                            kwargs['pagesize'])
        quotient, remainder = vcpus / 2, vcpus % 2
        candidate_numa_ids = {}
        for cell in host_numa_top['cells']:
            siblings = ([s for s in cell['unbound_cpu_siblings']
                         if len(s) >= 2])
            singles = ([s[0] for s in cell['unbound_cpu_siblings']
                        if len(s) == 1])
            if (len(siblings) >= quotient and 2 * (
                    len(siblings) - quotient) + len(singles) >= remainder
                and cell['id'] in numa_cell_ids):
                selected = []
                for s in siblings[:quotient]:
                    selected += s
                if remainder and singles:
                    selected += singles[:remainder]
                if remainder and not singles:
                    selected += [siblings[quotient][0]]
                candidate_numa_ids[cell['id']] = selected

        if len(candidate_numa_ids) > 0:
            (selected_numa_id, selected) = _get_the_suitable_numa(
                kwargs['host_state'], host_numa_top, candidate_numa_ids)

            for i in range(vcpus):
                ret_vcpu_pin.update({i: [selected[i]]})

    if enable_ht and not numa_opts and enable_bind:
        quotient, remainder = vcpus / 2, vcpus % 2
        # the remainder can be 0 or 1
        siblings = []
        singles = []
        for cell in host_numa_top['cells']:
            siblings += ([s for s in cell['unbound_cpu_siblings']
                          if len(s) >= 2])
            singles += ([s[0] for s in cell['unbound_cpu_siblings']
                         if len(s) == 1])
        if (len(siblings) >= quotient and 2 * (
                len(siblings) - quotient) + len(singles) >= remainder):
            selected = []
            for s in siblings[:quotient]:
                selected += s
            if remainder and singles:
                selected += singles[:remainder]
            if remainder and not singles:
                selected += [siblings[quotient][0]]
            for i in range(vcpus):
                ret_vcpu_pin.update({i: [selected[i]]})

    if (not enable_ht and not any_mode) and numa_opts and enable_bind:
        numa_cell_ids = get_res_enough_numa(host_numa_top, vcpus, mem,
                                            kwargs['numa_id'],
                                            kwargs['pagesize'])
        candidate_numa_ids = {}
        for cell in host_numa_top['cells']:
            sorted_siblings = sorted(cell['unbound_cpu_siblings'],
                                     key=lambda s: len(s))
            selected_cpus = [c for s in sorted_siblings for c in s]
            if len(selected_cpus) >= vcpus and cell['id'] in numa_cell_ids:
                candidate_numa_ids[cell['id']] = selected_cpus

        if len(candidate_numa_ids) > 0:
            (selected_numa_id, selected_cpus) = _get_the_suitable_numa(
                kwargs['host_state'], host_numa_top, candidate_numa_ids)
            for i in range(vcpus):
                ret_vcpu_pin.update({i: [selected_cpus[i]]})

    if (not enable_ht and not any_mode) and numa_opts and not enable_bind:
        numa_cell_ids = get_res_enough_numa(host_numa_top, vcpus, mem,
                                            kwargs['numa_id'],
                                            kwargs['pagesize'])
        candidate_numa_ids = {}
        for cell in host_numa_top['cells']:
            sorted_siblings = sorted(cell['unbound_cpu_siblings'],
                                     key=lambda s: len(s))
            selected_cpus = [c for s in sorted_siblings for c in s]
            if len(selected_cpus) >= vcpus and cell['id'] in numa_cell_ids:
                candidate_numa_ids[cell['id']] = selected_cpus

        if len(candidate_numa_ids) > 0:
            (selected_numa_id, selected_cpus) = _get_the_suitable_numa(
                kwargs['host_state'], host_numa_top, candidate_numa_ids)
            for i in range(vcpus):
                ret_vcpu_pin.update({i: selected_cpus[:vcpus]})

    if (not enable_ht and not any_mode) and not numa_opts and enable_bind:
        all_unbound_siblings = []
        for cell in host_numa_top['cells']:
            all_unbound_siblings += cell['unbound_cpu_siblings']
        all_unbound_siblings = sorted(
            all_unbound_siblings, key=lambda s: len(s))
        all_unbound_cpus = [c for s in all_unbound_siblings for c in s]
        if len(all_unbound_cpus) >= vcpus:
            for i in range(vcpus):
                ret_vcpu_pin.update({i: [all_unbound_cpus[i]]})

    if (not enable_ht and not any_mode) and not numa_opts and not enable_bind:
        all_unbound_siblings = []
        for cell in host_numa_top['cells']:
            all_unbound_siblings += cell['unbound_cpu_siblings']
        all_unbound_siblings = sorted(
            all_unbound_siblings, key=lambda s: len(s))
        all_unbound_cpus = [c for s in all_unbound_siblings for c in s]
        if len(all_unbound_cpus) >= vcpus:
            for i in range(vcpus):
                ret_vcpu_pin.update({i: all_unbound_cpus[:vcpus]})

    if not ret_vcpu_pin or len(ret_vcpu_pin.keys()) != vcpus:
        msg = ('Cpu bind failed, the host numa topology is %s ,'
               'parameters is :enable_bind(%s), enable_ht(%s), any_mode(%s),'
               ' vcpus(%s),mem(%s), numa_opts(%s)' %
               (host_numa_top, enable_bind, enable_ht, any_mode, vcpus, mem,
                numa_opts))
        raise exception.NovaException(msg)
    if selected_numa_id is not None:
        ret_inst_numa = {"cells": [{"mem": {"total": mem}, "cpuset":
            [c for c in range(vcpus)], "id": selected_numa_id, 'is_huawei':
                                        True}]}
    else:
        ret_inst_numa = {}

    # add pagesize in instance cell
    if kwargs['pagesize']:
        pagesize = int(kwargs['pagesize'])
        inst_topology = ret_inst_numa.get('cells', [])
        for inst_cell in inst_topology:
            inst_cell['pagesize'] = pagesize

    return ret_vcpu_pin, ret_inst_numa


def get_inst_affinity_mask(filter_properties):
    """Get the affinity mask from scheduler_hints

    ::return (enable_bind, enable_ht, any_mode, numa_opts)
    """
    scheduler_hints = filter_properties.get("scheduler_hints", {})
    numa_opts = int(scheduler_hints.get('numaOpts', 0))
    if not scheduler_hints:
        return False, False, True, 0
    vcpu_aff = scheduler_hints.get('vcpuAffinity', 0)
    vcpu_aff = jsonutils.loads(vcpu_aff) if isinstance(
        vcpu_aff, six.text_type) else vcpu_aff
    vcpu_aff = vcpu_aff[0] if isinstance(vcpu_aff, list) else vcpu_aff
    enable_bind = vcpu_aff in (1, '1')
    ht = scheduler_hints.get('hyperThreadAffinity', 'any')
    any_mode = (ht == 'any')
    enable_ht = (ht == 'sync' or ht == "lock")
    return enable_bind, enable_ht, any_mode, numa_opts


def get_evs_affinity(filter_properties, instance_uuid=None):
    """
    :param filter_properties:
    :return: enable_evs
    """
    admin_context = context.get_admin_context()
    scheduler_hints = {}
    if filter_properties:
        scheduler_hints = filter_properties.get("scheduler_hints", {})
    elif instance_uuid:
        instance_extra = objects.HuaweiInstanceExtra.get_by_instance_uuid(
            admin_context, instance_uuid=instance_uuid)

        scheduler_hints = jsonutils.loads(
            instance_extra.scheduler_hints or '{}')

    return bool(int(scheduler_hints.get("evsOpts", 0)))

def get_fitted_inst_numas(instance, host):
    requested_topology = hardware.instance_topology_from_instance(instance)
    host_topology, _fmt = hardware.host_topology_and_format_from_host(
        host)
    if requested_topology and host_topology:
        limit_cells = []
        for cell in host_topology.cells:
            limit_cells.append(hardware.VirtNUMATopologyCellLimit(
                cell.id, cell.cpuset, cell.memory,
                len(cell.cpuset), int(cell.memory)))
        limits = hardware.VirtNUMALimitTopology(cells=limit_cells)
        instance_topologys = (numas_fit_instance_to_host(
            host_topology, requested_topology,
            limits_topology=limits))
        return instance_topologys


def numas_fit_instance_to_host(host_topology, instance_topology,
                               limits_topology=None):
    can_fitteds = []
    if (not (host_topology and instance_topology) or
                len(host_topology) < len(instance_topology)):
        return
    else:
        if limits_topology is None:
            limits_topology_cells = itertools.repeat(
                None, len(host_topology))
        else:
            limits_topology_cells = limits_topology.cells
            # TODO(): We may want to sort permutations differently
        # depending on whether we want packing/spreading over NUMA nodes
        for host_cell_perm in itertools.permutations(
                zip(host_topology.cells, limits_topology_cells),
                len(instance_topology)
        ):
            cells = []
            for (host_cell, limit_cell), instance_cell in zip(
                    host_cell_perm, instance_topology.cells):
                got_cell = hardware._numa_fit_instance_cell(
                    host_cell, instance_cell, limit_cell)
                if got_cell is None:
                    break
                cells.append(got_cell)
            if len(cells) == len(host_cell_perm):
                can_fitteds.append(objects.InstanceNUMATopology(cells=cells))
    return can_fitteds


def pin_vcpu_with_inst_numa(enable_bind, enable_ht, any_mode,
                            fitted_numa_topologys, host_numa_top):
    for topo in fitted_numa_topologys:
        if not isinstance(topo, dict):
            topo = topo._to_json()
            topo = jsonutils.loads(topo)
            topo = convert_inst_numa_topology(topo)
        try:
            return  pin_vcpu_with_fitted_numa(enable_bind, enable_ht,
                                              any_mode, topo, host_numa_top)
        except exception.NovaException:
            continue
    msg = ('Pin vcpu withi instance numa failed, the host_numa_top is: %s, '
           'the fitted_numa_topologys is %s.' %
           (host_numa_top, fitted_numa_topologys))
    raise exception.NovaException(message=msg)


def pin_vcpu_with_fitted_numa(enable_bind, enable_ht, any_mode, inst_numa_top,
                              host_numa_top):
    """
    This method will be called for the native numa feature of openstack with
    huawei cpu bind feature.
    The instance numa topology is like this:
    {"cells": [{"mem": {"total": 256}, "cpuset": [0}, "cpus": "0", "id": 0},
    {"mem":{"total": 768}, "cpuset": [1,2,3], "cpus": "1,2,3" "id": 1}]}
    The cases should be considered:
    3(any_mode, enable_ht, not enable_ht and any_mode)*2(enable_bind or not)
    """
    if any_mode and enable_ht:
        raise exception.NovaException('Parameters conflict of any_mode and '
                                      'enable_ht')

    ret_vcpu_pin = {}
    vcpus = sum([len(cell['cpuset']) for cell in inst_numa_top['cells']])

    def _host_cell_top_get_by_id(host_numa_top, cell_id):
        for cell in host_numa_top['cells']:
            if cell['id'] == cell_id:
                return cell
        return {}

    #NOTE: any_mode and enable_ht is mutex
    if any_mode and not enable_bind: #ignore enable_ht and not enable_ht
        for inst_cell in inst_numa_top['cells']:
            host_cell = _host_cell_top_get_by_id(host_numa_top,
                                                 inst_cell['id'])
            for vcpu in inst_cell['cpuset']:
                ret_vcpu_pin.update(
                    {vcpu: [int(c) for c in host_cell['cpus'].split(',')]})
    if any_mode and enable_bind:  #not enable_ht
        for inst_cell in inst_numa_top['cells']:
            host_cell = _host_cell_top_get_by_id(host_numa_top,
                                                 inst_cell['id'])
            sorted_binds = sorted(host_cell['cpu_bind_num'].items(),
                                  key=lambda c: c[1])
            inst_cpus_len = len(inst_cell['cpuset'])
            selected_cpus = [k for k, v in sorted_binds]
            if len(selected_cpus) >= inst_cpus_len:
                for i in range(inst_cpus_len):
                    ret_vcpu_pin.update(
                        {inst_cell['cpuset'][i]: [selected_cpus[i]]})
    # NOTE: the following cases is not any_mode
    if (not any_mode) and enable_bind and enable_ht:
        for inst_cell in inst_numa_top['cells']:
            host_cell = _host_cell_top_get_by_id(host_numa_top,
                                                 inst_cell['id'])
            inst_cpus_len = len(inst_cell['cpuset'])
            if inst_cpus_len % 2:
                msg = ('In sync mode, the cpuset  %s should be even number.'
                       % inst_cpus_len)
                raise exception.NovaException(msg)
            sorted_siblings = sorted(host_cell['unbound_cpu_siblings'],
                                     key=lambda s: len(s), reverse=True)
            unbound_siblings = [s for s in sorted_siblings if len(s) >= 2]
            if len(unbound_siblings) < inst_cpus_len / 2:
                msg = ('In sync mode, the numa %s haven\'t enough free '
                       'Hyper-Threading core' % inst_cell['id'])
                raise exception.NovaException(msg)
            selected_cpus = [c for s in unbound_siblings for c in s]
            for i in range(inst_cpus_len):
                ret_vcpu_pin.update(
                    {inst_cell['cpuset'][i]: [selected_cpus[i]]})

    if (not any_mode) and not enable_bind and enable_ht:
        for inst_cell in inst_numa_top['cells']:
            host_cell = _host_cell_top_get_by_id(host_numa_top,
                                                 inst_cell['id'])
            inst_cpus_len = len(inst_cell['cpuset'])
            if inst_cpus_len % 2:
                msg = ('In sync mode, the cpuset %s should be even number.'
                       % inst_cpus_len)
                raise exception.NovaException(msg)
            sorted_siblings = sorted(host_cell['unbound_cpu_siblings'],
                                     key=lambda s: len(s), reverse=True)
            unbound_siblings = [s for s in sorted_siblings if len(s) >= 2]
            if len(unbound_siblings) < inst_cpus_len / 2:
                msg = ('In sync mode, the numa %s haven\'t enough free '
                       'Hyper-Threading core' % inst_cell['id'])
                raise exception.NovaException(msg)
            selected_cpus = [c for s in unbound_siblings for c in s]
            for i in range(inst_cpus_len):
                ret_vcpu_pin.update(
                    {inst_cell['cpuset'][i]: selected_cpus[:inst_cpus_len]})

    if (not any_mode and not enable_ht) and enable_bind:
        for inst_cell in inst_numa_top['cells']:
            host_cell = _host_cell_top_get_by_id(host_numa_top,
                                                 inst_cell['id'])
            sorted_siblings = sorted(host_cell['unbound_cpu_siblings'],
                                     key=lambda s: len(s))
            inst_cpus_len = len(inst_cell['cpuset'])
            sorted_cpus = [c for s in sorted_siblings for c in s]
            if len(sorted_cpus) >= inst_cpus_len:
                for i in range(inst_cpus_len):
                    ret_vcpu_pin.update(
                        {inst_cell['cpuset'][i]: [sorted_cpus[i]]})

    if (not any_mode and not enable_ht) and not enable_bind:
        for inst_cell in inst_numa_top['cells']:
            host_cell = _host_cell_top_get_by_id(host_numa_top,
                                                 inst_cell['id'])
            sorted_siblings = sorted(host_cell['unbound_cpu_siblings'],
                                     key=lambda s: len(s))
            inst_cpus_len = len(inst_cell['cpuset'])
            sorted_cpus = [c for s in sorted_siblings for c in s]
            if len(sorted_cpus) >= inst_cpus_len:
                for i in range(inst_cpus_len):
                    ret_vcpu_pin.update(
                        {inst_cell['cpuset'][i]: sorted_cpus[:inst_cpus_len]})

    if not ret_vcpu_pin or len(ret_vcpu_pin.keys()) != vcpus:
        raise exception.NovaException('Cpu bind failed, the instance numa'
                                      ' topology is %s, the host numa topology'
                                      ' is %s' % (inst_numa_top, host_numa_top))

    return ret_vcpu_pin, inst_numa_top


def _convert_bind_info2core_bind(bind_info):
    if type(bind_info) in (str, unicode):
        bind_info = jsonutils.loads(bind_info)
    if type(bind_info) != dict:
        return {}
    core_bind = []
    for k, v in bind_info.items():
        core_bind.append({'vcpu': k, 'pcpus': v})
    return core_bind


def _convert_core_bind2bind_info(core_bind):
    if type(core_bind) in (str, unicode):
        core_bind = jsonutils.loads(core_bind)
    if type(core_bind) != list:
        return []
    vcpus = [cell['vcpu'] for cell in core_bind]
    pcpus = [cell['pcpus'] for cell in core_bind]
    return dict(zip(vcpus, pcpus))


def _extend_hw_instance_extra(context, hostname):
    hw_instance_extras = []
    migs = objects.HuaweiLiveMigrationList.get_by_host(context.elevated(), hostname)
    # get all migs
    for mig in migs:
        if mig.dest_host != hostname:
            continue
        try:
            instance = objects.Instance.get_by_uuid(
                context, mig.instance_uuid, expected_attrs=['system_metadata'])
        except exception.InstanceNotFound as e:
            LOG.warning("Instance %s is deleted but left a live-migration"
                        % mig.instance_uuid)
            continue
        hw_extra = objects.HuaweiInstanceExtra.get_by_instance_uuid(
            context.elevated(), mig.instance_uuid)
        bind_info = instance.system_metadata.get("new_bind_info", [])
        # for numa/core_bind only, mem check is availabel in
        # update availabel resource
        if bind_info:
            tmp_extra = copy.deepcopy(hw_extra)
            tmp_extra.core_bind = jsonutils.dumps(
                _convert_bind_info2core_bind(bind_info))
            hw_instance_extras.append(tmp_extra)

    instance_extras = objects.HuaweiInstanceExtra.get_by_host(
        context.elevated(), hostname)
    for ins_ext in instance_extras:
        hw_instance_extras.append(ins_ext)
    migrations = objects.MigrationList.\
        get_in_progress_by_host_and_node(context, hostname, hostname)
    tracked_uuid = [extra.instance_uuid for extra in hw_instance_extras]
    for migration in migrations:
        if migration.status == 'error':
            continue
        try:
            instance = objects.Instance.get_by_uuid(
                context, migration.instance_uuid,
                expected_attrs=['system_metadata'])
        except exception.InstanceNotFound as e:
            LOG.warning("Instance %s is deleted with a migration record left"
                        % migration.instance_uuid)
            continue
        if migration.source_node == migration.dest_node:
            sys_meta = instance.system_metadata
            hw_extra = objects.HuaweiInstanceExtra.get_by_instance_uuid(
                context, migration.instance_uuid)
            tmp_extra = copy.deepcopy(hw_extra)
            bind_info = sys_meta.get("old_bind_info") or \
                sys_meta.get("new_bind_info") or {}
            tmp_extra.core_bind = jsonutils.dumps(
                _convert_bind_info2core_bind(bind_info))
            hw_instance_extras.append(tmp_extra)
        elif migration.instance_uuid not in tracked_uuid:
            sys_meta = instance.system_metadata
            hw_extra = objects.HuaweiInstanceExtra.get_by_instance_uuid(
                context, migration.instance_uuid)
            tmp_extra = copy.deepcopy(hw_extra)
            if migration.source_node == hostname:
                bind_info = sys_meta.get("old_bind_info")
            elif migration.dest_node == hostname:
                bind_info = sys_meta.get("new_bind_info")
            else:
                bind_info = []
            tmp_extra.core_bind = jsonutils.dumps(
                _convert_bind_info2core_bind(bind_info))
            hw_instance_extras.append(tmp_extra)

    return hw_instance_extras


def get_inst_cpu_bind_info(instance, host,
                           filter_properties=None, **kwargs):
    """
    The format of returns:
    {0:[3], 1:[4],2:[8],3:[9]} or{0:[0,1,2,3],2:[0,1,2,3]}
    """

    admin_context = context.get_admin_context()

    if isinstance(instance, dict):
        instance_uuid = instance['uuid']
        vcpus = instance['vcpus']
        mem = instance['memory_mb']
        inst_numa_top = instance.get('numa_topology', {})
    else:
        instance_uuid = instance.uuid
        vcpus = instance.vcpus
        mem = instance.memory_mb
        inst_numa_top = instance.numa_topology
    if not inst_numa_top and kwargs.get('action', '') != "resize":
        inst_numa_top = objects.InstanceNUMATopology.get_by_instance_uuid(
            admin_context, instance_uuid)
    if isinstance(inst_numa_top, six.string_types):
        inst_numa_top = jsonutils.loads(inst_numa_top)
    # 'host' can be host's name or compute_node obj
    host_name = getattr(host, 'host', None)
    if isinstance(host, six.string_types):
        host_name = host
        service = objects.Service.get_by_compute_host(admin_context, host,
                                                      use_slave=False)
        host = hw_cn_obj_cls.ComputeNode.get_by_service_id(
            admin_context, service.id)

    host_numa_top = host.numa_topology
    host_numa_top = jsonutils.loads(host_numa_top) if isinstance(
        host_numa_top, six.string_types) else copy.deepcopy(host_numa_top)

    if host_numa_top and host_numa_top.get('nova_object.data'):
        host_numa_top = convert_host_numa_topology(
            host_numa_top)
    else:
        host_numa_top = {}
    if not filter_properties:
        inst_extra = objects.HuaweiInstanceExtra.get_by_instance_uuid(
            admin_context, instance_uuid)
        scheduler_hints = jsonutils.loads(inst_extra.scheduler_hints or '{}')
        stats = jsonutils.loads(inst_extra.stats or '{}')
        sched_properties = dict(scheduler_hints=scheduler_hints, stats=stats)
    else:
        sched_properties = filter_properties
    pagesize = None
    if inst_numa_top:
        if not isinstance(inst_numa_top, dict):
            inst_numa_top = inst_numa_top._to_json()
            inst_numa_top = jsonutils.loads(inst_numa_top)
            inst_numa_top = convert_inst_numa_topology(inst_numa_top)
        for cell in inst_numa_top['cells']:
            if cell.get('cpus'):
                cell['cpuset'] = [int(c) for c in cell['cpus'].split(',')]
        pagesize = inst_numa_top.get('cells')[0].get('pagesize')
    enable_bind, enable_ht, any_mode, numa_opts = \
        get_inst_affinity_mask(sched_properties)
    if not inst_numa_top and not numa_opts and not enable_bind and any_mode:
        return {}, {}, False
    elif not host_numa_top:
        raise Exception('Cannot boot instance %s with because the host don\'t'
                        ' support numa' % instance_uuid)

    hw_instance_extras = \
        _extend_hw_instance_extra(admin_context, host_name)
    update_numa_topo_bind_info(host_numa_top, hw_instance_extras, any_mode,
                               instance_uuid)
    LOG.debug(_("host_numa_top is %s"), host_numa_top)
    enable_evs = get_evs_affinity(sched_properties)
    LOG.debug(_("enable_evs is %s"), enable_evs)

    sriov_numa_id = None
    evs_numa_id = None
    if numa_opts == 2:
        sriov_numa_id = get_numa_id_with_vf_request(
            host, sched_properties, network_info=kwargs.get('network_info'))
    if enable_evs:
        evs_numa_id = get_specific_numa(host, sched_properties,
                                        network_info=kwargs.get('network_info'))
    if sriov_numa_id and enable_evs and sriov_numa_id != evs_numa_id:
        msg = ("Both EVS Numa and IO Numa are specified, But SRIOV"
               "(node:%s) and EVS(node:%s) devices are not in one "
               "numa cell." % (sriov_numa_id, evs_numa_id))
        raise exception.NovaException(msg)
    specific_numa_id = sriov_numa_id or evs_numa_id
    LOG.debug(_("specific_numa_id is %s"), specific_numa_id)

    try:
        if inst_numa_top and not numa_opts:
            if not filter_properties:
                host_topo = copy.deepcopy(host)
                host_topo = modify_host_numa_topology(host_topo, host_numa_top)
            else:
                host_topo = host
            LOG.debug(_("host_topo : %s"), host_topo)
            fitted_inst_numas = get_fitted_inst_numas(instance, host_topo)
            vcpu_pin, inst_numa = pin_vcpu_with_inst_numa(
                enable_bind, enable_ht, any_mode, fitted_inst_numas,
                host_numa_top)
        else:
            vcpu_pin, inst_numa = pin_vcpu(enable_bind, enable_ht, any_mode,
                                           vcpus, mem, host_numa_top,
                                           numa_opts,
                                           numa_id=specific_numa_id,
                                           pagesize=pagesize,
                                           host_state=host)
    except exception.NovaException as ex:
        raise ex

    return vcpu_pin, inst_numa, enable_ht


def update_cpu_bind_info_to_db(bind_info, instance_uuid, instance_numa=None,
                               scheduler_hints=None, vcpu_topo=None):
    """
    Update cpu bind info and scheduler_hints to huawei_instance_extra,
    and update instance numa topology to instance_extra table for resource
    updating

    """
    if not bind_info:
        return

    admin_context = context.get_admin_context()
    bind_info_to_db = []
    for k, v in bind_info.items():
        bind_info_to_db.append({'vcpu': k, 'pcpus': v})
    bind_info_to_db = jsonutils.dumps(bind_info_to_db)
    kwargs = {}
    kwargs.update(dict(instance_uuid=instance_uuid))
    kwargs.update(dict(core_bind=bind_info_to_db))
    if vcpu_topo:
        vcpu_topo = jsonutils.dumps(vcpu_topo)
        kwargs.update(dict(vcpu_topology=vcpu_topo))
    if scheduler_hints:
        scheduler_hints = jsonutils.dumps(scheduler_hints)
        kwargs.update(dict(scheduler_hints=scheduler_hints))
    obj = objects.HuaweiInstanceExtra(**kwargs)

    obj.create(admin_context)
    if instance_numa and instance_numa['cells'][0].get('is_huawei'):
        cell = instance_numa['cells'][0]
        cells = [objects.InstanceNUMACell(id=cell['id'],
                                          cpuset=set(cell['cpuset']),
                                          memory=cell['mem']['total'],
                                          pagesize=cell.get('pagesize'))]
        instance_numa_topology = (
            objects.InstanceNUMATopology(
                cells=cells, instance_uuid=instance_uuid))
        instance_numa_topology.create(admin_context)


def get_pci_numa_mapping(context, filter_properties, host_state,
                         network_info=None):
    # get the pci numa node info according physical network
    physical_planes = []
    phy_net_numa_mapping = {}

    if network_info:
        LOG.debug("get physical plane from vif")
        for vif in network_info:
            physical_plane = vif.get("details",{}).get(
                pci_request.PCI_NET_TAG)
            if physical_plane:
                physical_planes.append(physical_plane)

    elif filter_properties:
        request_info = filter_properties.get("stats").get("network", {})
        for phy_req in request_info:
            physical_planes.append(phy_req)

    if not physical_planes:
        raise exception.NovaException(_("evsOpts is enabled, but no "
                                      "vhostuser physical network found"))

    if host_state:
        compute_physical_network = host_state.stats.get("network", {})
        # maybe the compute physical network is in json fa
        if not isinstance(compute_physical_network, dict):
            compute_physical_network = jsonutils.loads(
                compute_physical_network)

        LOG.debug(_("compute_physical_network is %s"),
                  compute_physical_network)
    else:
        LOG.debug(_("no host info specified."))

    for physical_plane in physical_planes:
        if physical_plane in compute_physical_network.keys():
            numa_id = compute_physical_network[physical_plane].get(
                "numa_id")
            if numa_id != "None" and numa_id:
                phy_net_numa_mapping[physical_plane] = str(numa_id)

    # log here for debug
    if len(phy_net_numa_mapping.keys()) != len(set(physical_planes)):
        raise exception.NovaException(_("The host is lack of some "
                                      "physical network"))

    LOG.debug(_("phy_net_numa_mapping is %s"), phy_net_numa_mapping)
    return phy_net_numa_mapping


def get_numa_id_with_vf_request(host_state, filter_properties=None,
                                network_info=None):
    specific_numa_id = None
    req_phy_nets = []
    if filter_properties and not network_info:
        inst_prop = filter_properties.get('request_spec', {}).get(
            'instance_properties', {})
        network_info = inst_prop.get('info_cache',{}).get('network_info')
    if network_info:
        LOG.debug("get physical plane from vif")
        for vif in network_info:
            pci_net = vif.get("profile", {}).get(pci_request.PCI_NET_TAG)
            if pci_net:
                req_phy_nets.append(pci_net)
    elif filter_properties and filter_properties.get("pci_requests"):
        pci_requests = filter_properties.get("pci_requests")
        req_phy_nets = [spec['physical_network'] for req in
                        pci_requests.requests for spec in req.spec
                        if 'physical_network' in spec]
    else:
        msg = 'IO numa specified, but pci_requests not found'
        raise exception.NovaException(msg)
    host_pci_stats = host_state.pci_stats
    host_pci_stats = pci_stats.PciDeviceStats(host_pci_stats) if isinstance(
        host_pci_stats, six.string_types) else host_pci_stats
    numa_ids = set()
    for stat, req_phy_net in itertools.product(host_pci_stats, req_phy_nets):
        if stat.get(pci_request.PCI_NET_TAG) == req_phy_net:
            if stat.get('numa_id'):
                numa_ids.add(stat.get('numa_id'))

    if len(numa_ids) > 1:
        msg = ('The specified numa should be unique, numa ids: %s have found'
               % list(numa_ids))
        raise exception.NovaException(msg)

    specific_numa_id = numa_ids.pop() if numa_ids else None
    LOG.debug('IO numa specified, the request physical networks is %s,'
              'the selected nuam is %s' % (req_phy_nets, specific_numa_id))
    if specific_numa_id is None or specific_numa_id == "None":
        raise exception.NovaException("Get Numa with VF failed, the "
                                      "host.pci_stats is %s" %
                                      host_pci_stats.pools)
    return str(specific_numa_id)


def convert_host_numa_topology(host_numa_topology):
    converted_numa = {'cells':[]}
    cells = host_numa_topology.get('nova_object.data',{}).get('cells',[])
    for cell in cells:
        cell_data = cell.get('nova_object.data')
        if not cell_data:
            continue

        converted_cell = {'mem': {}, 'mempages': []}
        converted_cell['cpus'] = ','.join([str(c) for c in
                                           cell_data['cpuset']])
        if cell_data.get('siblings'):
            converted_cell['siblings'] = [list(c) for c in
                                          cell_data['siblings']]
        else:
            converted_cell['siblings'] = [[c] for c in cell_data['cpuset']]
        converted_cell['id'] = cell_data['id']
        converted_cell['cpu_usage'] = cell_data['cpu_usage']
        converted_cell['mem']['total'] = cell_data['memory']
        converted_cell['mem']['used'] = cell_data['memory_usage']

        mempages = cell_data.get('mempages', [])
        for mempage in mempages:
            pagedata = mempage.get('nova_object.data')
            mempage_data = {}
            mempage_data['total'] = pagedata.get('total')
            mempage_data['size_kb'] = pagedata.get('size_kb')
            mempage_data['used'] = pagedata.get('used')
            converted_cell['mempages'].append(mempage_data)

        converted_numa['cells'].append(converted_cell)

    return converted_numa


def convert_inst_numa_topology(inst_numa_topology):
    if not isinstance(inst_numa_topology, dict):
        inst_numa_topology = inst_numa_topology._to_json()
        inst_numa_topology = jsonutils.loads(inst_numa_topology)
    converted_numa = {'cells': []}
    cells = inst_numa_topology.get('nova_object.data', {}).get('cells', [])
    for cell in cells:
        cell_data = cell.get('nova_object.data')
        if not cell_data:
            continue
        converted_cell = {'mem': {}}
        converted_cell['id'] = cell_data['id']
        converted_cell['mem']['total'] = cell_data['memory']
        converted_cell['cpuset'] = cell_data['cpuset']
        converted_cell['cups'] = ",".join(
            str(cpu) for cpu in cell_data['cpuset'])
        converted_cell['pagesize'] = cell_data.get('pagesize')
        converted_numa['cells'].append(converted_cell)

    return converted_numa


def get_instance_emulatorpin(instance, instance_numa):
    admin_context = context.get_admin_context()
    inst_extra = objects.HuaweiInstanceExtra.get_by_instance_uuid(
        admin_context, instance.uuid)
    scheduler_hints = jsonutils.loads(inst_extra.scheduler_hints or '{}')
    ht = scheduler_hints.get('hyperThreadAffinity', 'any')

    def _get_emulatorpin_by_cell_id(cell_id):
        # example CONF.qemu_pin_set =2,3:8,9::12
        #emulatorpin of numa0 is 2,3
        #emulatorpin of numa1 is 8,9
        #emulatorpin of numa2 is null
        #emulatorpin of numa3 is 12
        qemu_pin_set = eval(CONF.qemu_pin_set.strip())
        if qemu_pin_set.get(cell_id, []):
            qemu_pin_set = [str(cpu) for cpu in qemu_pin_set.get(cell_id, [])]
            return ','.join(qemu_pin_set)
        else:
            return None

    if ht == 'lock' and CONF.qemu_pin_set:
        if instance_numa and instance_numa['cells'][0].get('is_huawei'):
            cell_id = instance_numa['cells'][0]['id']
            cell_emulatorpin = _get_emulatorpin_by_cell_id(cell_id)
            LOG.debug("instance cell_emulatorpin is %s", cell_emulatorpin)
            return cell_emulatorpin
        return None
    else:
        return None

def modify_host_numa_topology(host_topo, host_numa_top):
    if not host_topo or not host_numa_top:
        return None
    host_topo_topology = host_topo.get('numa_topology', '{}')
    host_topo_topology = jsonutils.loads(host_topo_topology)
    host_topo_topology_data = host_topo_topology.get('nova_object.data')
    host_numa_top_cells = host_numa_top.get('cells')
    if host_topo_topology_data and host_numa_top_cells:
        host_topo_topology_cells = host_topo_topology_data.get('cells', [])
        for cell in host_topo_topology_cells:
            cell = cell.get('nova_object.data')
            for host_numa_top_cell in host_numa_top_cells:
                if cell['id'] == host_numa_top_cell['id']:
                    cell['cpu_usage'] = host_numa_top_cell['cpu_usage']
                    cell['memory_usage'] = host_numa_top_cell.get('mem',
                        {}).get('used')
                    mempages = host_numa_top_cell.get('mempages')
                    host_mempages = cell.get('mempages')
                    for host_mempage in host_mempages:
                        host_mempage = host_mempage.get('nova_object.data')
                        for mempage in mempages:
                            if mempage.get('size_kb') == host_mempage.get(
                                    'size_kb'):
                                host_mempage['used'] = mempage.get('used')

    host_topo_topology = jsonutils.dumps(host_topo_topology)
    if host_topo_topology == '{}':
        host_topo_topology = None
    host_topo.numa_topology = host_topo_topology
    return host_topo


def get_host_cpu_reserve(host_state):
    """
    :param host_state:
    :return:
    """
    if host_state is None or not host_state.cpu_info:
        return None

    if isinstance(host_state.cpu_info, unicode):
        try:
            cpu_info_list = ast.literal_eval(host_state.cpu_info).items()
        except Exception:
            return None

        extra_cpu_info = None
        for (key, values) in cpu_info_list:
            if key == 'extra_info':
                extra_cpu_info = values
                break

        if isinstance(extra_cpu_info, dict):
            totalSizeMHz = extra_cpu_info.get('totalSizeMHz')
            allocatedSizeMHz = extra_cpu_info.get('allocatedSizeMHz')

            try:
                host_cpu_reserve = int(totalSizeMHz)\
                                   - int(allocatedSizeMHz)
                return host_cpu_reserve
            except Exception:
                pass
    return None

def get_host_cpu_usage(host_state):
    """
    :param host_state:
    :return:
    """
    if host_state is None or not host_state.cpu_info:
        return None

    if isinstance(host_state.cpu_info, unicode):
        try:
            cpu_info_list = ast.literal_eval(host_state.cpu_info).items()
        except Exception:
            return None

        extra_cpu_info = None
        for (key, values) in cpu_info_list:
            if key=="extra_info":
                extra_cpu_info = values
                break

        if isinstance(extra_cpu_info, dict):
            usage = extra_cpu_info.get('usage')
            try:
                return float(usage)
            except Exception:
                pass
    return None

def get_instance_cpu_reserve(instance_type):
    """
    :param instance_type:
    :return:
    """
    if not instance_type:
        return None

    extra_specs = instance_type.get('extra_specs', None)

    if extra_specs is not None:
        cpu_reserve = extra_specs.get('quota:cpu_reserve', None)
        try:
            return int(cpu_reserve)
        except Exception:
            pass
    return None



