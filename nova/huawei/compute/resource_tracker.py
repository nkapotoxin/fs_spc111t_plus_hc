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

"""
Track resources like memory and disk for a compute host.  Provides the
scheduler with useful information about availability through the ComputeNode
model.
"""

from oslo.config import cfg
import re
from nova import exception
from nova.i18n import _
from nova import utils
from nova import objects
from nova.huawei.pci import pci_manager
from nova.compute import resource_tracker
from nova.compute import task_states
from nova.compute import vm_states
from nova.openstack.common import log as logging
from nova.openstack.common import jsonutils
from nova.compute import claims
from nova.objects import base as obj_base
from nova.huawei.compute import claims as h_claims
from nova.huawei import utils as h_utils
from nova.virt import hardware
from nova.huawei.scheduler import utils as sched_utils

LOG = logging.getLogger(__name__)
CONF = cfg.CONF

CONF.import_opt('reserved_host_disk_mb', 'nova.huawei.compute.resource_tracker')
CONF.import_opt('reserved_host_memory_mb', 'nova.huawei.compute.resource_tracker')

class HuaweiResourceTracker(resource_tracker.ResourceTracker):
    """
    HUAWEI resource tracker
    """
    def __init__(self, host, driver, nodename):
        super(HuaweiResourceTracker, self).__init__(host, driver, nodename)

    @utils.synchronized(resource_tracker.COMPUTE_RESOURCE_SEMAPHORE)
    def instance_claim(self, context, instance_ref, limits=None):
        """Indicate that some resources are needed for an upcoming compute
        instance build operation.

        This should be called before the compute node is about to perform
        an instance build operation that will consume additional resources.

        :param context: security context
        :param instance_ref: instance to reserve resources for
        :param limits: Dict of oversubscription limits for memory, disk,
                       and CPUs.
        :returns: A Claim ticket representing the reserved resources.  It can
                  be used to revert the resource usage if an error occurs
                  during the instance build.
        """
        if self.disabled:
            # compute_driver doesn't support resource tracking, just
            # set the 'host' and node fields and continue the build:
            self._set_instance_host_and_node(context, instance_ref)
            return claims.NopClaim()

        # sanity checks:
        if instance_ref['host']:
            LOG.warning(_("Host field should not be set on the instance until "
                          "resources have been claimed."),
                          instance=instance_ref)

        if instance_ref['node']:
            LOG.warning(_("Node field should not be set on the instance "
                          "until resources have been claimed."),
                          instance=instance_ref)

        # get memory overhead required to build this instance:
        overhead = self.driver.estimate_instance_overhead(instance_ref)
        LOG.debug("Memory overhead for %(flavor)d MB instance; %(overhead)d "
                  "MB", {'flavor': instance_ref['memory_mb'],
                          'overhead': overhead['memory_mb']})

        try:
            claim = h_claims.HuaweiClaim(context, instance_ref, self,
                                         self.compute_node,
                                         overhead=overhead, limits=limits)
        except Exception as e:
            # Update partial stats locally and populate them to Scheduler
            self._update(context.elevated(), self.compute_node, force=True)
            raise exception.InstanceFaultRollback(inner_exception=e)

        self._set_instance_host_and_node(context, instance_ref)
        instance_ref['numa_topology'] = claim.claimed_numa_topology

        # Mark resources in-use and update stats
        self._update_usage_from_instance(context, self.compute_node,
                                         instance_ref)

        elevated = context.elevated()
        # persist changes to the compute node:
        self._update(elevated, self.compute_node)

        return claim

    @utils.synchronized(resource_tracker.COMPUTE_RESOURCE_SEMAPHORE)
    def resize_claim(self, context, instance, instance_type,
                     image_meta=None, limits=None):
        """Indicate that resources are needed for a resize operation to this
        compute host.
        :param context: security context
        :param instance: instance object to reserve resources for
        :param instance_type: new instance_type being resized to
        :param limits: Dict of oversubscription limits for memory, disk,
        and CPUs
        :returns: A Claim ticket representing the reserved resources.  This
        should be turned into finalize  a resource claim or free
        resources after the compute operation is finished.
        """
        image_meta = image_meta or {}

        if self.disabled:
            # compute_driver doesn't support resource tracking, just
            # generate the migration record and continue the resize:
            migration = self._create_migration(context, instance,
                                               instance_type)
            return claims.NopClaim(migration=migration)

        # get memory overhead required to build this instance:
        overhead = self.driver.estimate_instance_overhead(instance_type)
        LOG.debug("Memory overhead for %(flavor)d MB instance; %(overhead)d "
                  "MB", {'flavor': instance_type['memory_mb'],
                          'overhead': overhead['memory_mb']})

        instance_ref = obj_base.obj_to_primitive(instance)
        try:
            claim = h_claims.HuaweiResizeClaim(context, instance_ref,
                                               instance_type, image_meta,
                                               self, self.compute_node,
                                               overhead=overhead,
                                               limits=limits)
        except Exception as e:
            # Update partial stats locally and populate them to Scheduler
            self._update(context.elevated(), self.compute_node, force=True)
            LOG.exception("Failed to claim when resize %s." % instance['uuid'])
            raise exception.InstanceFaultRollback(inner_exception=e)
        migration = self._create_migration(context, instance_ref,
                                           instance_type)
        # save pci_requests
        if claim.pci_requests:
            claim.pci_requests.save(context)
        claim.migration = migration
        system_metadata = instance.system_metadata
        if claim.claimed_numa_topology:
            system_metadata['new_numa_topo'] = jsonutils.dumps(
                claim.claimed_numa_topology)
        if claim.bind_info:
            system_metadata['new_bind_info'] = jsonutils.dumps(claim.bind_info)
        instance.system_metadata = system_metadata
        instance.save()
        # Mark the resources in-use for the resize landing on this
        # compute host:
        self._update_usage_from_migration(context, instance_ref, image_meta,
                                          self.compute_node, migration)
        elevated = context.elevated()
        self._update(elevated, self.compute_node)

        return claim

    @utils.synchronized(resource_tracker.COMPUTE_RESOURCE_SEMAPHORE)
    def rebuild_claim(self, context, instance_ref, limits=None):
        """Indicate that some resources are needed for an upcoming compute
        instance build operation.

        This should be called before the compute node is about to perform
        an instance build operation that will consume additional resources.

        :param context: security context
        :param instance_ref: instance to reserve resources for
        :param limits: Dict of oversubscription limits for memory, disk,
                       and CPUs.
        :returns: A Claim ticket representing the reserved resources.  It can
                  be used to revert the resource usage if an error occurs
                  during the instance build.
        """
        if self.disabled:
            # compute_driver doesn't support resource tracking, just
            # set the 'host' and node fields and continue the build:
            self._set_instance_host_and_node(context, instance_ref)
            return claims.NopClaim()

        # sanity checks:
        if instance_ref['host']:
            LOG.warning(_("Host field should not be set on the instance until "
                          "resources have been claimed."),
                          instance=instance_ref)

        if instance_ref['node']:
            LOG.warning(_("Node field should not be set on the instance "
                          "until resources have been claimed."),
                          instance=instance_ref)

        # get memory overhead required to build this instance:
        overhead = self.driver.estimate_instance_overhead(instance_ref)
        LOG.debug("Memory overhead for %(flavor)d MB instance; %(overhead)d "
                  "MB", {'flavor': instance_ref['memory_mb'],
                         'overhead': overhead['memory_mb']})
        try:
            claim = h_claims.HuaweiRebuildClaim(context, instance_ref, self,
                                                self.compute_node,
                                                overhead=overhead,
                                                limits=limits)
        except Exception as e:
            # Update partial stats locally and populate them to Scheduler
            self._update(context.elevated(), self.compute_node, force=True)
            LOG.exception("Failed to claim when ha.", instance=instance_ref)
            raise exception.InstanceFaultRollback(inner_exception=e)
        # save pci_requests
        if claim.pci_requests:
            claim.pci_requests.save(context)

        self._set_instance_host_and_node(context, instance_ref)
        instance_ref['numa_topology'] = claim.claimed_numa_topology

        # Mark resources in-use and update stats
        self._update_usage_from_instance(context, self.compute_node,
                                         instance_ref)

        elevated = context.elevated()
        # persist changes to the compute node:
        self._update(elevated, self.compute_node)

        return claim

    def _update_usage(self, context, resources, usage, sign=1):
        """override the parent method for vm boot from volume case

        """
        mem_usage = usage['memory_mb']

        overhead = self.driver.estimate_instance_overhead(usage)
        mem_usage += overhead['memory_mb']

        resources['memory_mb_used'] += sign * mem_usage

        #if the vm is boot form volume, we shouldn't calculate the disk usage
        if not h_utils.is_boot_from_volume(context, usage):
            resources['local_gb_used'] += sign * usage.get('root_gb', 0)

        resources['local_gb_used'] += sign * usage.get('ephemeral_gb', 0)

        # free ram and disk may be negative, depending on policy:
        resources['free_ram_mb'] = (resources['memory_mb'] -
                                    resources['memory_mb_used'])
        resources['free_disk_gb'] = (resources['local_gb'] -
                                     resources['local_gb_used'])

        resources['running_vms'] = self.stats.num_instances
        self.ext_resources_handler.update_from_instance(usage, sign)

        # Calculate the numa usage
        free = sign == -1
        updated_numa_topology = hardware.get_host_numa_usage_from_instance(
            resources, usage, free)
        if updated_numa_topology:
            updated_numa_topology = jsonutils.loads(updated_numa_topology)
            # The following statements is to keep numa siblings in resources
            resource_numa_topology= jsonutils.loads(resources['numa_topology'])
            updated_cells = updated_numa_topology.get(
                'nova_object.data', {}).get('cells', [])
            res_cells = resource_numa_topology.get(
                'nova_object.data', {}).get('cells', [])
            # NOTE, we assume the order is constant
            for res_cell, updated_cell in zip(res_cells, updated_cells):
                res_cell_date = res_cell.get('nova_object.data')
                updated_cell_date = updated_cell.get('nova_object.data')
                if res_cell_date['id'] == updated_cell_date['id']:
                    updated_cell_date['siblings'] = res_cell_date['siblings']
            updated_numa_topology = jsonutils.dumps(updated_numa_topology)
        resources['numa_topology'] = updated_numa_topology

    def _find_instances_to_host_in_livemig(self, context):
        LOG.info(_("enter into _find_instances_to_host_in_livemig"))
        local_uuids = self.driver.list_instance_uuids()
        instances = None
        # get all instances including inactive
        for uuid in local_uuids:
            filters = {'uuid': uuid, 'deleted': False}
            instances = objects.InstanceList.get_by_filters(
                context, filters=filters)

        if instances:                            
            for inst in instances.objects:
                if (inst['task_state'] == task_states.MIGRATING and
                      inst['host'] != self.host):
                    LOG.info(_("instance %s is live-migrating to this host."
                               % inst['uuid']))
                    yield inst

    def _find_isntances_to_host_in_livemig_by_db(self, context):
        migs = objects.HuaweiLiveMigrationList.get_all(context)
        for mig in migs:
            if mig["dest_host"] == self.host:
                inst = None
                try:
                    inst = objects.Instance.get_by_uuid(context,
                                             mig['instance_uuid'])
                except Exception as e:
                    continue
                
                if not inst:
                    continue
                                
                yield mig.instance


    def _get_compute_node_ref(self, context):
        service = self._get_service(context)
        if not service:
            # no service record, disable resource
            return

        compute_node_refs = service['compute_node']
        if compute_node_refs:
            for cn in compute_node_refs:
                if cn.get('hypervisor_hostname') == self.nodename:
                    return cn

    @utils.synchronized(resource_tracker.COMPUTE_RESOURCE_SEMAPHORE)
    def _update_available_resource(self, context, resources):
        if 'pci_passthrough_devices' in resources:
            if not self.pci_tracker:
                self.compute_node = self._get_compute_node_ref(context)
                node_id = (self.compute_node['id'] if self.compute_node else
                           None)
                self.pci_tracker = pci_manager.HuaweiPciDevTracker(
                    ctxt=context, node_id=node_id)
            self.pci_tracker.set_hvdevs(jsonutils.loads(resources.pop(
                'pci_passthrough_devices')))

        # In wmware clusters, the node name includes reserved char such
        # as ( or ), we should escape it.
        node_name = h_utils.regex_escape(self.nodename)

        # Grab all instances assigned to this node:
        instances = objects.InstanceList.get_by_host_and_node(
            context, self.host, node_name,
            expected_attrs=['system_metadata',
                            'numa_topology'])

        # find instance that in live-migrating
        func = self._find_isntances_to_host_in_livemig_by_db
        for inst in func(context):
            instances.objects.append(inst)
        
        # Now calculate usage based on instance utilization:
        self._update_usage_from_instances(context, resources, instances)

        # Grab all in-progress migrations:
        capi = self.conductor_api
        migrations = capi.migration_get_in_progress_by_host_and_node(context,
                self.host, self.nodename)

        self._update_usage_from_migrations(context, resources, migrations)

        # Detect and account for orphaned instances that may exist on the
        # hypervisor, but are not in the DB:
        orphans = self._find_orphaned_instances()
        self._update_usage_from_orphans(context, resources, orphans)

        # NOTE(): Because pci device tracker status is not cleared in
        # this periodic task, and also because the resource tracker is not
        # notified when instances are deleted, we need remove all usages
        # from deleted instances.
        if self.pci_tracker:
            self.pci_tracker.clean_usage(instances, migrations, orphans)
            resources['pci_stats'] = jsonutils.dumps(self.pci_tracker.stats)
        else:
            resources['pci_stats'] = jsonutils.dumps([])

        self._report_final_resource_view(resources)

        metrics = self._get_host_metrics(context, self.nodename)
        resources['metrics'] = jsonutils.dumps(metrics)
        self._sync_compute_node(context, resources)

    def _get_instance_type(self, context, instance, prefix,
            instance_type_id=None):
        """Get the instance type from sys metadata if it's stashed.  If not,
        fall back to fetching it via the object API.

        See bug 1164110
        """
        usage = {}
        instance_type = super(HuaweiResourceTracker, self)._get_instance_type(
            context, instance, prefix, instance_type_id)

        if isinstance(instance_type, (objects.Flavor, objects.Instance)):
            usage = obj_base.obj_to_primitive(instance_type)
        else:
            usage.update(instance_type)

        usage.update({"instance_uuid": instance['uuid']})

        return usage

    def _update_usage_from_migration(self, context, instance, image_meta,
                                     resources, migration):
        """Update usage for a single migration.  The record may
        represent an incoming or outbound migration.
        """
        uuid = migration['instance_uuid']
        LOG.audit(_("Updating from migration %s") % uuid)

        incoming = (migration['dest_compute'] == self.host and
                    migration['dest_node'] == self.nodename)
        outbound = (migration['source_compute'] == self.host and
                    migration['source_node'] == self.nodename)
        same_node = (incoming and outbound)
        instance = objects.Instance.get_by_uuid(
            context, uuid, expected_attrs=['system_metadata'])
        record = self.tracked_instances.get(uuid, None)
        itype = None
        numa_topology = None
        core_bind = None

        if same_node:
            # same node resize. record usage for whichever instance type the
            # instance is *not* in:
            if (instance['instance_type_id'] ==
                    migration['old_instance_type_id']):
                itype = self._get_instance_type(context, instance, 'new_',
                        migration['new_instance_type_id'])
                numa_topology = instance['system_metadata'].get('new_numa_topo')
            else:
                # instance record already has new flavor, hold space for a
                # possible revert to the old instance type:
                itype = self._get_instance_type(context, instance, 'old_',
                        migration['old_instance_type_id'])
                numa_topology = instance['system_metadata'].get('old_numa_topo')

        elif incoming and not record:
            # instance has not yet migrated here:
            itype = self._get_instance_type(context, instance, 'new_',
                    migration['new_instance_type_id'])
            numa_topology = instance['system_metadata'].get('new_numa_topo')

        elif outbound and not record:
            # instance migrated, but record usage for a possible revert:
            itype = self._get_instance_type(context, instance, 'old_',
                    migration['old_instance_type_id'])
            numa_topology = instance['system_metadata'].get('old_numa_topo')

        if image_meta is None:
            image_meta = utils.get_image_from_system_metadata(
                    instance['system_metadata'])

        if itype:
            host_topology = resources.get('numa_topology')
            if host_topology:
                host_topology = objects.NUMATopology.obj_from_db_obj(
                        host_topology)
            if numa_topology:
                numa_topology = jsonutils.loads(numa_topology)
            usage = self._get_usage_dict(itype, numa_topology=numa_topology)

            if self.pci_tracker:
                if same_node or not outbound:
                    self.pci_tracker.update_pci_for_migration(
                        context, instance)

            self._update_usage(context, resources, usage)
            if self.pci_tracker:
                resources['pci_stats'] = jsonutils.dumps(
                        self.pci_tracker.stats)
            else:
                resources['pci_stats'] = jsonutils.dumps([])
            self.tracked_migrations[uuid] = (migration, itype)

    @utils.synchronized(resource_tracker.COMPUTE_RESOURCE_SEMAPHORE)
    def _revert_pci(self, context, instance):
        if self.pci_tracker:
            self.pci_tracker.update_pci_for_migration(context,
                                                      instance,
                                                      sign=-1)

    @utils.synchronized(resource_tracker.COMPUTE_RESOURCE_SEMAPHORE)
    def _finish_resize_pci(self, context, instance):
        if self.pci_tracker:
            self.pci_tracker.update_pci_for_instance(context, instance)

    @utils.synchronized(resource_tracker.COMPUTE_RESOURCE_SEMAPHORE)
    def free_pci_dev(self, context, instance, is_new=False):
        if self.pci_tracker:
            self.pci_tracker.free_pci_dev(context, instance, is_new)

    def free_pci_request(self, context, instance, is_new=False):
        source_pci_requests = objects.InstancePCIRequests.\
            get_by_instance_uuid(context, instance['uuid'])
        requests = []
        for request in source_pci_requests.requests:
            if request.is_new == is_new:
                continue
            request.is_new = False
            requests.append(request)
        source_pci_requests.requests = requests
        source_pci_requests.save(context)

    @utils.synchronized(resource_tracker.COMPUTE_RESOURCE_SEMAPHORE)
    def get_nw_pci_slot_info(self, context, instance, is_new=False):
        requests = objects.InstancePCIRequests.\
            get_by_instance_uuid_and_newness(context, instance['uuid'], is_new)
        if self.pci_tracker:
            pci_devices = self.pci_tracker.pci_devs
        else:
            pci_devices = []
        nw_pci_info = {}
        # might not have network
        for request in requests.requests:
            if request.spec[0]['physical_network']:
                nw_pci_info[request.request_id] =\
                    request.spec[0]['physical_network']
        nw_pci_slot_info = {}
        for device in pci_devices:
            # when host ha happend, delete might later than rebuild
            # filter pci_device in rebuild host
            if device.instance_uuid != instance['uuid']:
                continue
            if device.request_id in nw_pci_info:
                network = nw_pci_info[device.request_id]
                if network in nw_pci_slot_info:
                    nw_pci_slot_info[network].append(device)
                else:
                    nw_pci_slot_info[network] = [device]
                nw_pci_info.pop(device.request_id, None)

        if nw_pci_info:
            added_requests = []
            for request in requests.requests:
                if request.request_id in nw_pci_info:
                    added_requests.append(request)
            requests.requests = added_requests
            LOG.info("Get Request %s without PCI device" % added_requests)
            new_devices = []
            if self.pci_tracker:
                try:
                    new_devices = self.pci_tracker._allocate_from_request(
                        context, instance, requests)
                    LOG.info("Allocate PCI devices %s " % new_devices)
                except Exception as e:
                    LOG.exception("Failed to allocate pci devices")
                    new_devices = []
            for device in new_devices:
                if device.request_id in nw_pci_info:
                    network = nw_pci_info[device.request_id]
                    if network in nw_pci_slot_info:
                        nw_pci_slot_info[network].append(device)
                    else:
                        nw_pci_slot_info[network] = [device]
        return nw_pci_slot_info

    @utils.synchronized(resource_tracker.COMPUTE_RESOURCE_SEMAPHORE)
    def drop_resize_from_instance(self, context, instance, migration):
        if migration.dest_compute != migration.source_compute:
            if migration.instance_uuid in self.tracked_instances:
                self.tracked_instances.pop(migration.instance_uuid)
        new_pci_requests = objects.InstancePCIRequests.\
            get_by_instance_uuid_and_newness(context,
                                             instance['uuid'],
                                             True)
        if self.pci_tracker and new_pci_requests.requests:
            self.pci_tracker.update_pci_for_migration(context,
                                                      instance,
                                                      sign=-1)

    def test_mem_in_resource_tracker(self, context, instance):
        avail = self.compute_node['free_ram_mb']
        mem_inst = instance.memory_mb
        free_huge = 0
        if not instance.system_metadata.get(
                'instance_type_extra_hw:mem_page_size'):
            host_topology, _fmt = hardware.host_topology_and_format_from_host(
                self.compute_node)
            cells = host_topology.cells or []
            for cell in cells:
                for page in cell.mempages or []:
                    if page.size_kb != 4:
                        free_huge += (page.total - page.used) * \
                            page.size_kb / 1024
            avail = avail - free_huge
        if not mem_inst or avail <= mem_inst:
            raise exception.NovaException("Lack of memory(host:%(avail)s <= "
                                          "instance:%(mem_inst)s)" %
                                          dict(avail=avail, mem_inst=mem_inst))

    def _create_live_migration_record(self, context, instance, block_migration,
                                      migrate_data):
        live_migration = objects.HuaweiLiveMigration()
        live_migration.instance_uuid = instance['uuid']
        live_migration.source_host = instance['host']
        live_migration.dest_host = self.host
        live_migration.dest_addr = CONF.my_ip
        live_migration.block_migration = block_migration
        live_migration.migrate_data = jsonutils.dumps(migrate_data)
        live_migration.create(context.elevated())
        return live_migration

    @utils.synchronized(resource_tracker.COMPUTE_RESOURCE_SEMAPHORE)
    def get_cpu_at_live_migration(self, context, instance, network_info,
                                  block_migration, migrate_data):
        # should check mem is ok
        self.test_mem_in_resource_tracker(context, instance)
        bind_info, instance_numa, _ = sched_utils.get_inst_cpu_bind_info(
            instance, self.host, network_info=network_info)
        if instance_numa and instance_numa['cells'][0].get('mem'):
            numa_id = instance_numa['cells'][0]['id']
        else:
            numa_id = None
        # check live migration record has already created
        migrate_data['cpu'] = bind_info
        migrate_data['numa'] = numa_id
        self._create_live_migration_record(
            context, instance, block_migration, migrate_data)
        if instance_numa and instance_numa['cells'][0].get('mem'):
            cells = []
            for cell in instance_numa['cells']:
                cells.append(objects.InstanceNUMACell(
                    id=cell['id'], cpuset=set(cell['cpuset']),
                    memory=cell['mem']['total'],
                    pagesize=cell.get('pagesize')))

            format_inst_numa = objects.InstanceNUMATopology(
                cells=cells, instance_uuid=instance['uuid'])

            sys_meta = instance.system_metadata
            sys_meta['new_numa_topo'] = jsonutils.dumps(format_inst_numa)
            sys_meta['new_bind_info'] = jsonutils.dumps(bind_info)
            instance.system_metadata = sys_meta
            instance.save()

            instance.numa_topology = format_inst_numa
        # trigger update_resource
        self._update_usage_from_instance(context, self.compute_node, instance)
        # if necessary
        elevated = context.elevated()
        # persist changes to the compute node:
        self._update(elevated, self.compute_node)

        return migrate_data

    def _update(self, context, values, force=False):
        if not force:
            super(HuaweiResourceTracker, self)._update(context, values)
        else:
            LOG.info("Instance Claim failed and revert resource to scheduler")
            """Update partial stats locally and populate them to Scheduler."""
            self._write_ext_resources(values)
            # NOTE(): the stats field is stored as a json string. The
            # json conversion will be done automatically by the ComputeNode object
            # so this can be removed when using ComputeNode.
            values['stats'] = jsonutils.dumps(values['stats'])

            if "service" in self.compute_node:
                del self.compute_node['service']
            # NOTE(): Now the DB update is asynchronous, we need to locally
            #               update the values
            self.compute_node.update(values)
            # Persist the stats to the Scheduler
            self._update_resource_stats(context, values)
            if self.pci_tracker:
                self.pci_tracker.save(context)

    @utils.synchronized(resource_tracker.COMPUTE_RESOURCE_SEMAPHORE)
    def drop_resize_claim(self, context, instance, instance_type=None,
                          image_meta=None, prefix='new_'):
        """Remove usage for an incoming/outgoing migration."""
        if instance['uuid'] in self.tracked_migrations:
            migration, itype = self.tracked_migrations.pop(instance['uuid'])

            if not instance_type:
                ctxt = context.elevated()
                instance_type = self._get_instance_type(ctxt, instance, prefix)

            if image_meta is None:
                image_meta = utils.get_image_from_system_metadata(
                        instance['system_metadata'])

            if instance_type['id'] == itype['id']:
                sys_metadata = instance['system_metadata']
                if instance['task_state'] == task_states.RESIZE_REVERTING:
                    numa_topology = sys_metadata.get('new_numa_topo')
                else:
                    numa_topology = sys_metadata.get('old_numa_topo')
                if numa_topology:
                    numa_topology = jsonutils.loads(numa_topology)
                usage = self._get_usage_dict(
                        itype, numa_topology=numa_topology)
                if self.pci_tracker:
                    self.pci_tracker.update_pci_for_migration(context,
                                                              instance,
                                                              sign=-1)
                self._update_usage(context, self.compute_node, usage, sign=-1)

                ctxt = context.elevated()
                self._update(ctxt, self.compute_node)

    def _update_usage_from_instances(self, context, resources, instances):
        """Calculate resource usage based on instance utilization.  This is
        different than the hypervisor's view as it will account for all
        instances assigned to the local compute host, even if they are not
        currently powered on.
        """
        self.tracked_instances.clear()

        # purge old stats and init with anything passed in by the driver
        self.stats.clear()
        self.stats.digest_stats(resources.get('stats'))

        # set some initial values, reserve room for host/hypervisor:
        resources['local_gb_used'] = CONF.reserved_host_disk_mb / 1024
        resources['memory_mb_used'] = CONF.reserved_host_memory_mb
        resources['free_ram_mb'] = (resources['memory_mb'] -
                                    resources['memory_mb_used'])
        resources['free_disk_gb'] = (resources['local_gb'] -
                                     resources['local_gb_used'])
        resources['current_workload'] = 0
        resources['running_vms'] = 0

        # Reset values for extended resources
        self.ext_resources_handler.reset_resources(resources, self.driver)

        for instance in instances:
            if instance['vm_state'] != vm_states.DELETED:
                try:
                    self._update_usage_from_instance(context, resources,
                                                     instance)
                except:
                    LOG.exception("Failed update resource", instance=instance)