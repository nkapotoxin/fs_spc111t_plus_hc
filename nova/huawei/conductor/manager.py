from oslo.config import cfg

from nova.compute import flavors
from nova.compute import task_states
from nova.compute import utils as compute_utils
from nova.conductor.manager import *
from nova.huawei.conductor.tasks import live_migrate
from nova import exception
from nova.i18n import _
from nova import objects
from nova.openstack.common import excutils
from nova.openstack.common import jsonutils
from nova.openstack.common import log as logging
from nova.scheduler import utils as scheduler_utils
from nova import hooks

LOG = logging.getLogger(__name__)

compute_opts = [
    cfg.BoolOpt('resize_prefer_to_same_host',
                default=False,
                help='Destination machine prefer to match source for resize.'),
]

CONF = cfg.CONF
CONF.register_opts(compute_opts)


class HuaweiComputeTaskManager(ComputeTaskManager):
    def __init__(self):
        super(HuaweiComputeTaskManager, self).__init__()

    @hooks.add_hook("cold_migrate_hook")
    def _cold_migrate(self, context, instance, flavor, filter_properties,
                      reservations):
        """Overwrite parent method for:
           1. get scheduler_hints from db
           2. resize prefer to same host
        """
        # get scheduler_hints for cpu_filter
        info = objects.HuaweiInstanceExtra.get_by_instance_uuid(
            context, instance['uuid'])
        if not info.scheduler_hints:
            sch_hints = {}
        else:
            sch_hints = jsonutils.loads(info.scheduler_hints)
        filter_properties['scheduler_hints'] = sch_hints
        # resize prefer to same host
        current_instance_type = flavors.extract_flavor(instance)
        new_instance_type = flavor
        same_instance_type = (current_instance_type['id'] ==
                              new_instance_type['id'])
        if not same_instance_type and CONF.resize_prefer_to_same_host:
            filter_properties['resize_prefer_to_same_host'] = instance.get(
                'host', '')

        """SRIOV resize
           1. Load pci_requests
           2. Put pci into filter_properties
        """
        pci_requests = objects.InstancePCIRequests.\
            get_by_instance_uuid_and_newness(
                context, instance['uuid'], False)
        if pci_requests:
            filter_properties['pci_requests'] = pci_requests
        super(HuaweiComputeTaskManager, self)._cold_migrate(context, instance,
                                                            flavor,
                                                            filter_properties,
                                                            reservations)

    @hooks.add_hook("live_migrate_hook")
    def _live_migrate(self, context, instance, scheduler_hint,
                      block_migration, disk_over_commit):
        destination = scheduler_hint.get("host")
        try:
            live_migrate.execute(context, instance, destination,
                             block_migration, disk_over_commit)
        except (exception.NoValidHost,
                exception.ComputeServiceUnavailable,
                exception.InvalidHypervisorType,
                exception.InvalidCPUInfo,
                exception.UnableToMigrateToSelf,
                exception.DestinationHypervisorTooOld,
                exception.InvalidLocalStorage,
                exception.InvalidSharedStorage,
                exception.HypervisorUnavailable,
                exception.InstanceNotRunning,
                exception.ComputeHostNotFound,
                exception.MigrationPreCheckError) as ex:
            with excutils.save_and_reraise_exception():
                # TODO() - eventually need instance actions here
                request_spec = {'instance_properties': {
                    'uuid': instance['uuid'], },
                }
                scheduler_utils.set_vm_state_and_notify(context,
                        'compute_task', 'migrate_server',
                        dict(vm_state=instance['vm_state'],
                             task_state=None,
                             expected_task_state=task_states.MIGRATING,),
                        ex, request_spec, self.db)
        except Exception as ex:
            LOG.error(_('Migration of instance %(instance_id)s to host'
                       ' %(dest)s unexpectedly failed.'),
                       {'instance_id': instance['uuid'], 'dest': destination},
                       exc_info=True)
            raise exception.MigrationError(reason=ex)

    def rebuild_instance(self, context, instance, orig_image_ref, image_ref,
                         injected_files, new_pass, orig_sys_metadata,
                         bdms, recreate, on_shared_storage,
                         preserve_ephemeral=False, host=None):

        with compute_utils.EventReporter(context, 'rebuild_server',
                                         instance.uuid):
            if not host:
                # NOTE(): Retrieve scheduler filters for the
                # instance when the feature is available
                filter_properties = {'ignore_hosts': [instance.host]}
                extra = objects.HuaweiInstanceExtra.get_by_instance_uuid(
                    context, instance['uuid'])
                if not extra.scheduler_hints:
                    sch_hints = {}
                else:
                    sch_hints = jsonutils.loads(extra.scheduler_hints)
                filter_properties['scheduler_hints'] = sch_hints

                request_spec = scheduler_utils.build_request_spec(context,
                                                                  image_ref,
                                                                  [instance])
                
                scheduler_utils.setup_instance_group(context, request_spec,
                                                     filter_properties)
                try:
                    hosts = self.scheduler_client.select_destinations(context,
                                                                      request_spec,
                                                                      filter_properties)
                    host = hosts.pop(0)['host']
                except exception.NoValidHost as ex:
                    with excutils.save_and_reraise_exception():
                        self._set_vm_state_and_notify(context,
                                                      'rebuild_server',
                                                      {'vm_state': instance.vm_state,
                                                       'task_state': None}, ex, request_spec)
                        LOG.warning(_("No valid host found for rebuild"),
                                    instance=instance)

            self.compute_rpcapi.rebuild_instance(context,
                                                 instance=instance,
                                                 new_pass=new_pass,
                                                 injected_files=injected_files,
                                                 image_ref=image_ref,
                                                 orig_image_ref=orig_image_ref,
                                                 orig_sys_metadata=orig_sys_metadata,
                                                 bdms=bdms,
                                                 recreate=recreate,
                                                 on_shared_storage=on_shared_storage,
                                                 preserve_ephemeral=preserve_ephemeral,
                                                 host=host)


class HuaweiConductorManager(ConductorManager):
    def __init__(self, *args, **kwargs):
        super(HuaweiConductorManager, self).__init__(*args, **kwargs)
        self.compute_task_mgr = HuaweiComputeTaskManager()
        self.additional_endpoints = [self.compute_task_mgr]   