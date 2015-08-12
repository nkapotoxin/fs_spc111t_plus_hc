
import threading
import os
from oslo import messaging

from nova.compute.manager import *
from nova.compute import task_states
from nova.compute import utils as compute_utils
from nova.compute import vm_states
from nova.huawei.objects import affinity_group as affinitygroup_obj
from nova.fusioncompute.compute import resource_tracker as hwrt
from nova.huawei import exception as huawei_exception
from nova.i18n import _LE
from nova.i18n import _LW
from nova.i18n import _LI
from nova.openstack.common import importutils
from nova.openstack.common.gettextutils import _
from nova import utils
from nova import objects
from nova.virt import driver
from nova.objects.huawei_instance_extra import HuaweiInstanceExtra
from nova.openstack.common import periodic_task
from nova.huawei.scheduler import utils as hw_shed_utils
from nova.virt import hardware
from nova import hooks
from keystoneclient.v2_0 import client as key_client

LOG = logging.getLogger(__name__)
REBOOT_DELETE_PLOCK = threading.Lock()

CONF = cfg.CONF
running_deleted_notify_opts = [
    cfg.IntOpt("running_deleted_instance_notify_interval",
               default=0,
               help="Number of seconds to notify the runing_deleted_instances."),
    cfg.IntOpt("task_monitor_interval",
               default=60,
               help="The interval to write the monitor time, seconds."),
    cfg.StrOpt('libvirt_snapshots_directory',
               default="/opt/HUAWEI/image",
               help=''),
]
CONF.register_opts(running_deleted_notify_opts)

extend_opts = [
    cfg.StrOpt('task_monitor_file',
               default=os.path.join(CONF.libvirt_snapshots_directory, "nova-compute_heart.ini"),
               help='The path of file to write the monitor time.'),
]
reschedule_opts = [
    cfg.IntOpt("reschedule_delay_rebuild_time",
               default=60,
               help="Number of seconds to wait before rebuilding"
                    "instance after rescheduling instance"),
    cfg.IntOpt("irqbalance_update_interval",
           default=60,
           help="Interval in seconds for update irqbalance"),
]

fusion_compute_opts = [
    cfg.IntOpt("fc_port_group_clean_time",
               default=3600,
               help="clean fusion compute port group periodic time"),
]
CONF.register_opts(fusion_compute_opts)

CONF.register_opts(extend_opts)
CONF.register_opts(reschedule_opts)
COMPUTE_INSTANCES_INFO_SEMAPHORE = "instances_info"

def load_compute_driver(virtapi, compute_driver):
    if not compute_driver:
        compute_driver = CONF.compute_driver
    LOG.info(_("Loading huawei compute driver %s ."), compute_driver)
    try:
        drv = importutils.import_object_ns('nova.fusioncompute.virt',
            compute_driver, virtapi)
        return utils.check_isinstance(drv, driver.ComputeDriver)
    except ImportError:
        LOG.exception(_("Unable to load the huawei virtualization driver"))
        LOG.info(_("Try to import original virtualzation driver."))
        try:
            driver.load_compute_driver(virtapi, compute_driver)
        except ImportError:
            LOG.exception(_("Unable to load the virtualization driver"))
            sys.exit(1)

class HuaweiComputeManager(ComputeManager):
    def __init__(self, compute_driver=None, *args, **kwargs):
        super(HuaweiComputeManager, self).__init__('libvirt.LibvirtDriver',
            *args, **kwargs)
        self.virtapi = HuaweiComputeVirtAPI(self)
        self.driver = load_compute_driver(self.virtapi, compute_driver)
        self._instances_state = None
        self._instances_name = None
        self.roles = []
        self.user_name = None
        self.tenant_id = None

    def get_admin_roles(self):
        if not self.roles or not self.user_name or not self.tenant_id:
            try:
                _ksclient = key_client.Client(
                    tenant_name=CONF.neutron.admin_tenant_name,
                    username=CONF.neutron.admin_username,
                    password=CONF.neutron.admin_password,
                    auth_url=CONF.neutron.admin_auth_url,
                    insecure=CONF.neutron.api_insecure)

                for role in _ksclient.roles.list():
                    self.roles.append(role.name)
                self.user_name = CONF.neutron.admin_username
                self.tenant_id = _ksclient.tenant_id
                LOG.info("The tenants is %s" % self.tenant_id)
                LOG.info("The roles is %s" % self.roles)
            except Exception as e:
                LOG.error("Get the token failed, msg: %s" % e)

        return self.roles

    def get_admin_token(self):
        try:
            _ksclient = key_client.Client(
                tenant_name=CONF.neutron.admin_tenant_name,
                username=CONF.neutron.admin_username,
                password=CONF.neutron.admin_password,
                auth_url=CONF.neutron.admin_auth_url,
                insecure=CONF.neutron.api_insecure)

            return _ksclient.auth_token
        except Exception as e:
            LOG.error("Get the token failed, msg: %s" % e)

        return None

    def get_admin_context(self):
        """
        Init_instance has same problem, might change when it's solved
        """
        context = nova.context.get_admin_context()
        # Get the roles and token to call the cinder and nova api.
        context.roles = self.get_admin_roles()
        context.auth_token = self.get_admin_token()
        context.user_name = self.user_name
        context.project_id = self.tenant_id
        return context

    def _get_power_state_from_cache(self, instance):
        """
        When driver is FusionComputeDriver, get all vms state from driver
        on the first call and cached them. Otherwise, use default function
        :param instance:
        :return:
        """
        @utils.synchronized(COMPUTE_INSTANCES_INFO_SEMAPHORE)
        def _refresh_cache():
            if self._instances_state is None:
                LOG.info("instances info cache is empty, need refresh ...")
                self._instances_state, self._instances_name \
                    = self.driver.get_instances_info()

        if self._instances_state is None:
            _refresh_cache()

        return self._instances_state.get(instance.uuid, power_state.NOSTATE)

    def _get_vm_info_from_cache(self, instance):
        """
        When driver is FusionComputeDriver, get all vms info from driver
        on the first call and cached them.
        :param instance:
        :return:
        """

        state = power_state.NOSTATE
        name = None

        if self._instances_state:
            state = self._instances_state.get(instance.uuid,
                power_state.NOSTATE)
        if self._instances_name:
            name = self._instances_name.get(instance.uuid)

        return state,name

    def _retry_reboot(self, context, instance):
        """Overwrite parent method for:
           1. get instance power state from cache
        """
        current_power_state = self._get_power_state_from_cache(instance)
        current_task_state = instance.task_state
        retry_reboot = False
        reboot_type = compute_utils.get_reboot_type(current_task_state,
            current_power_state)

        pending_soft = (current_task_state == task_states.REBOOT_PENDING and
                        instance.vm_state in vm_states.ALLOW_SOFT_REBOOT)
        pending_hard = (current_task_state == task_states.REBOOT_PENDING_HARD
                        and instance.vm_state in vm_states.ALLOW_HARD_REBOOT)
        started_not_running = (current_task_state in
                               [task_states.REBOOT_STARTED,
                                task_states.REBOOT_STARTED_HARD] and
                               current_power_state != power_state.RUNNING)

        if pending_soft or pending_hard or started_not_running:
            retry_reboot = True

        return retry_reboot, reboot_type

    def _init_instance(self, context, instance):
        """Overwrite parent method for:
           1. live-migration --- modify if instance in task_state migrating
        """
        if (instance.vm_state == vm_states.SOFT_DELETED or
            (instance.vm_state == vm_states.ERROR and
             instance.task_state not in
             (task_states.RESIZE_MIGRATING, task_states.DELETING))):
            LOG.debug("Instance is in %s state.",
                      instance.vm_state, instance=instance)
            return

        if instance.vm_state == vm_states.DELETED:
            try:
                self._complete_partial_deletion(context, instance)
            except Exception:
                # we don't want that an exception blocks the init_host
                msg = _LE('Failed to complete a deletion')
                LOG.exception(msg, instance=instance)
            return

        if (instance.vm_state == vm_states.BUILDING or
            instance.task_state in [task_states.SCHEDULING,
                                    task_states.BLOCK_DEVICE_MAPPING,
                                    task_states.NETWORKING,
                                    task_states.SPAWNING]):
            # NOTE(dave-mcnally) compute stopped before instance was fully
            # spawned so set to ERROR state. This is safe to do as the state
            # may be set by the api but the host is not so if we get here the
            # instance has already been scheduled to this particular host.
            LOG.debug("Instance failed to spawn correctly, "
                      "setting to ERROR state", instance=instance)
            instance.task_state = None
            instance.vm_state = vm_states.ERROR
            instance.save()
            return

        if (instance.vm_state in [vm_states.ACTIVE, vm_states.STOPPED] and
            instance.task_state in [task_states.REBUILDING,
                                    task_states.REBUILD_BLOCK_DEVICE_MAPPING,
                                    task_states.REBUILD_SPAWNING]):
            # NOTE(jichenjc) compute stopped before instance was fully
            # spawned so set to ERROR state. This is consistent to BUILD
            LOG.debug("Instance failed to rebuild correctly, "
                      "setting to ERROR state", instance=instance)
            instance.task_state = None
            instance.vm_state = vm_states.ERROR
            instance.save()
            return

        if (instance.vm_state != vm_states.ERROR and
            instance.task_state in [task_states.IMAGE_SNAPSHOT_PENDING,
                                    task_states.IMAGE_PENDING_UPLOAD,
                                    task_states.IMAGE_UPLOADING,
                                    task_states.IMAGE_SNAPSHOT]):
            LOG.debug("Instance in transitional state %s at start-up "
                      "clearing task state",
                      instance['task_state'], instance=instance)
            try:
                self._post_interrupted_snapshot_cleanup(context, instance)
            except Exception:
                # we don't want that an exception blocks the init_host
                msg = _LE('Failed to cleanup snapshot.')
                LOG.exception(msg, instance=instance)
            instance.task_state = None
            instance.save()

        if instance.task_state == task_states.DELETING:
            try:
                LOG.info(_('Service started deleting the instance during '
                           'the previous run, but did not finish. Restarting '
                           'the deletion now.'), instance=instance)
                instance.obj_load_attr('metadata')
                instance.obj_load_attr('system_metadata')
                bdms = objects.BlockDeviceMappingList.get_by_instance_uuid(
                    context, instance.uuid)
                # FIXME(comstud): This needs fixed. We should be creating
                # reservations and updating quotas, because quotas
                # wouldn't have been updated for this instance since it is
                # still in DELETING.  See bug 1296414.
                #
                # Create a dummy quota object for now.
                quotas = objects.Quotas.from_reservations(
                    context, None, instance=instance)
                self._delete_instance(self.get_admin_context(), instance, bdms,
                                      quotas)
            except Exception:
                # we don't want that an exception blocks the init_host
                msg = _LE('Failed to complete a deletion')
                LOG.exception(msg, instance=instance)
                self._set_instance_error_state(context, instance)
            return

        try_reboot, reboot_type = self._retry_reboot(context, instance)
        current_power_state = self._get_power_state_from_cache(instance)

        if try_reboot:
            LOG.debug("Instance in transitional state (%(task_state)s) at "
                      "start-up and power state is (%(power_state)s), "
                      "triggering reboot",
                      {'task_state': instance['task_state'],
                       'power_state': current_power_state},
                      instance=instance)
            self.compute_rpcapi.reboot_instance(context, instance,
                                                block_device_info=None,
                                                reboot_type=reboot_type)
            return
        elif (current_power_state == power_state.RUNNING and
              instance.task_state in [task_states.REBOOT_STARTED,
                                      task_states.REBOOT_STARTED_HARD]):
            LOG.warning(_("Instance in transitional state "
                          "(%(task_state)s) at start-up and power state "
                          "is (%(power_state)s), clearing task state"),
                        {'task_state': instance['task_state'],
                         'power_state': current_power_state},
                        instance=instance)
            instance.task_state = None
            instance.vm_state = vm_states.ACTIVE
            instance.save()

        if instance.task_state == task_states.POWERING_OFF:
            try:
                LOG.debug("Instance in transitional state %s at start-up "
                          "retrying stop request",
                          instance['task_state'], instance=instance)
                self.stop_instance(context, instance)
            except Exception:
                # we don't want that an exception blocks the init_host
                msg = _LE('Failed to stop instance')
                LOG.exception(msg, instance=instance)
            return

        if instance.task_state == task_states.POWERING_ON:
            try:
                LOG.debug("Instance in transitional state %s at start-up "
                          "retrying start request",
                          instance['task_state'], instance=instance)
                self.start_instance(context, instance)
            except Exception:
                # we don't want that an exception blocks the init_host
                msg = _LE('Failed to start instance')
                LOG.exception(msg, instance=instance)
            return

        net_info = compute_utils.get_nw_info_for_instance(instance)
        try:
            self.driver.plug_vifs(instance, net_info)
        except NotImplementedError as e:
            LOG.debug(e, instance=instance)
        if instance.task_state == task_states.RESIZE_MIGRATING:
            # We crashed during resize/migration, so roll back for safety
            try:
                # NOTE(mriedem): check old_vm_state for STOPPED here, if it's
                # not in system_metadata we default to True for backwards
                # compatibility
                power_on = (instance.system_metadata.get('old_vm_state') !=
                            vm_states.STOPPED)

                block_dev_info = self._get_instance_block_device_info(context,
                                                                      instance)

                self.driver.finish_revert_migration(context, instance,
                                                    net_info, block_dev_info,
                                                    power_on)

            except Exception as e:
                LOG.exception(_LE('Failed to revert crashed migration'),
                              instance=instance)
            finally:
                LOG.info(_('Instance found in migrating state during '
                           'startup. Resetting task_state'),
                         instance=instance)
                instance.task_state = None
                instance.save()
        if instance.task_state == task_states.MIGRATING:
            # Live migration did not complete, but instance is on this
            # host, so reset the state.
            # instance.task_state = None
            # instance.save(expected_task_state=[task_states.MIGRATING])
            mig = objects.HuaweiLiveMigration.get_by_instance_uuid(context,
                                                                instance.uuid)
            if not mig:
                LOG.info(_("Instance found in live-migrating but no record in db."))
                instance.task_state = None
                instance.save(expected_task_state=[task_states.MIGRATING])
            else:
                mig_data = jsonutils.loads(mig['migrate_data'])
                block_mig = mig['block_migration']
                if self.host == mig['source_host']:
                    # call rollback
                    LOG.info(_("source host restart when migrating."))
                try:
                    self._rollback_live_migration(context,
                                                  instance,
                                                  mig["dest_host"],
                                                  block_migration=block_mig,
                                                  migrate_data=mig_data)
                except Exception as e:
                    msg = "_rollback_live_migration exception in init_instance."
                    LOG.error(_LE(msg + "detail:%s"%e))
                instance.task_state = None
                instance.save()
                mig.destroy(context)

        db_state = instance.power_state
        drv_state = self._get_power_state_from_cache(instance)
        expect_running = (db_state == power_state.RUNNING and
                          drv_state != db_state)

        LOG.debug('Current state is %(drv_state)s, state in DB is '
                  '%(db_state)s.',
                  {'drv_state': drv_state, 'db_state': db_state},
                  instance=instance)

        if expect_running and CONF.resume_guests_state_on_host_boot:
            LOG.debug(_('No deed do resume on host boot in FC mode'))

        elif drv_state == power_state.RUNNING:
            # VMwareAPI drivers will raise an exception
            try:
                self.driver.ensure_filtering_rules_for_instance(
                    instance, net_info)
            except NotImplementedError:
                LOG.warning(_('Hypervisor driver does not support '
                              'firewall rules'), instance=instance)

    def _destroy_evacuated_instances(self, context):
        """Destroys evacuated instances.

        While nova-compute was down, the instances running on it could be
        evacuated to another host. Check that the instances reported
        by the driver are still associated with this host.  If they are
        not, destroy them, with the exception of instances which are in
        the MIGRATING, RESIZE_MIGRATING, RESIZE_MIGRATED, RESIZE_FINISH
        task state or RESIZED vm state.
        """
        our_host = self.host
        filters = {'deleted': False}
        local_instances = self._get_instances_on_driver(context, filters)
        for instance in local_instances:
            if instance.host != our_host:
                LOG.warn(_('Instance %(uuid)s host ('
                           '%(instance_host)s) is not equal to our '
                           'host (%(our_host)s).'),
                    {'uuid': instance.uuid,
                     'instance_host': instance.host,
                     'our_host': our_host}, instance=instance)

    @wrap_exception()
    @wrap_instance_fault
    def _rollback_live_migration(self, context, instance,
                                 dest, block_migration, migrate_data=None):
        """Rewrite rollback function.
           1 add None to expected_task_state.
        """
        if migrate_data != None and migrate_data.get('rollback_port', None):
            # call by rollback_instance_position in driver
            migration = {'dest_compute': self.host}
            self.network_api.migrate_instance_finish(context, 
                                                     instance,
                                                     migration)
            return 
        
        instance.vm_state = vm_states.ACTIVE
        instance.task_state = None
        instance.save(expected_task_state=[task_states.MIGRATING, None])

        # NOTE(tr3buchet): setup networks on source host (really it's re-setup)
        self.network_api.setup_networks_on_host(context, instance, self.host)

        bdms = objects.BlockDeviceMappingList.get_by_instance_uuid(
            context, instance['uuid'])
        for bdm in bdms:
            if bdm.is_volume:
                self.compute_rpcapi.remove_volume_connection(
                    context, instance, bdm.volume_id, dest)
        self._get_instance_block_device_info(
            context, instance, refresh_conn_info=True)
        self._notify_about_instance_usage(context, instance,
                                          "live_migration._rollback.start")

        do_cleanup, destroy_disks = \
            self._live_migration_cleanup_flags(
                block_migration, migrate_data)

        if do_cleanup:
            self.compute_rpcapi.rollback_live_migration_at_destination(
                context, instance, dest, destroy_disks=destroy_disks,
                migrate_data=migrate_data)

        self._notify_about_instance_usage(context, instance,
                                          "live_migration._rollback.end")

    def _get_resource_tracker(self, nodename):
        rt = self._resource_tracker_dict.get(nodename)
        if not rt:
            if not self.driver.node_is_available(nodename):
                raise exception.NovaException(
                        _("%s is not a valid node managed by this "
                          "compute host.") % nodename)

            rt = hwrt.HuaweiResourceTracker(self.host,
                                            self.driver,
                                            nodename)
            self._resource_tracker_dict[nodename] = rt
        return rt

    @compute_utils.periodic_task_spacing_warn("sync_power_state_interval")
    @periodic_task.periodic_task(spacing=CONF.sync_power_state_interval,
        run_immediately=True)
    def _clear_instances_info_cache(self, context):
        @utils.synchronized(COMPUTE_INSTANCES_INFO_SEMAPHORE)
        def _clear_cache():
            self._instances_state = None
            self._instances_name = None
            LOG.info("clear instances info cache.")

        _clear_cache()

    @periodic_task.periodic_task(spacing=CONF.fc_port_group_clean_time,
        run_immediately=True)
    def _clear_fc_network_pg(self, context):
        """

        :param context:
        :return:
        """
        self.driver.clean_fc_network_pg()


    def _query_driver_power_state_and_sync(self, context, db_instance):
        if db_instance.task_state is not None:
            LOG.info(_LI("During sync_power_state the instance has a "
                         "pending task (%(task)s). Skip."),
                {'task': db_instance.task_state}, instance=db_instance)
            return

        try:
            self._get_power_state_from_cache(db_instance)
            vm_power_state, vm_name = self._get_vm_info_from_cache(db_instance)
        except exception.InstanceNotFound:
            vm_power_state = power_state.NOSTATE
            vm_name = None

        try:
            self._sync_instance_power_state(context,
                                            db_instance,
                                            vm_power_state,
                                            use_slave=True)
        except exception.InstanceNotFound:
            pass

        if vm_name is not None and vm_name != db_instance['display_name']:
            try:
                self._sync_instance_info(context, db_instance)
            except exception.InstanceNotFound:
                pass

    def _sync_instance_info(self,context,db_instance):
        self.driver.change_instance_info(context,db_instance)

    def _sync_instance_power_state(self, context, db_instance, vm_power_state,
                                   event=None, use_slave=False):
        """ Overwrite the original _sync_instance_power_state. """
        """ See SR-RSP-001-031-ECS-009 for detail """
        if not CONF.local_resume_instance:
            return super(HuaweiComputeManager, self)._sync_instance_power_state(context,
                                                        db_instance, vm_power_state, use_slave)
        # We re-query the DB to get the latest instance info to minimize
        # (not eliminate) race condition.
        db_instance.refresh(use_slave=use_slave)
        db_power_state = db_instance.power_state
        vm_state = db_instance.vm_state

        if self.host != db_instance.host:
            # on the sending end of nova-compute _sync_power_state
            # may have yielded to the greenthread performing a live
            # migration; this in turn has changed the resident-host
            # for the VM; However, the instance is still active, it
            # is just in the process of migrating to another host.
            # This implies that the compute source must relinquish
            # control to the compute destination.
            LOG.info(_("During the sync_power process the "
                       "instance has moved from "
                       "host %(src)s to host %(dst)s")%
                       {'src': self.host,
                        'dst': db_instance.host},
                        instance=db_instance)
            return
        elif db_instance.task_state is not None:
            # on the receiving end of nova-compute, it could happen
            # that the DB instance already report the new resident
            # but the actual VM has not showed up on the hypervisor
            # yet. In this case, let's allow the loop to continue
            # and run the state sync in a later round
            LOG.info(_("During sync_power_state the instance has a "
                       "pending task. Skip."), instance=db_instance)
            return

        try:
            vm_power_state = self._get_power_state_from_cache(db_instance)
            LOG.info("Get the vm power stat.id: %s, state: %s" % (db_instance['uuid'], vm_power_state))
        except Exception as e:
            LOG.info("Get the vm stat failed. id: %s, error: %s" % (db_instance['uuid'], e))

        if vm_power_state != db_power_state:
            # power_state is always updated from hypervisor to db
            db_instance.power_state = vm_power_state
            db_instance.save()
            db_power_state = vm_power_state

        # Note: Now resolve the discrepancy between vm_state and
        # vm_power_state. We go through all possible vm_states.
        if vm_state in (vm_states.BUILDING,
                        vm_states.RESCUED,
                        vm_states.RESIZED,
                        vm_states.SUSPENDED,
                        vm_states.PAUSED,
                        vm_states.ERROR):
            # TODO: we ignore these vm_state for now.
            pass
        elif vm_state == vm_states.ACTIVE:
            if vm_power_state == power_state.SHUTDOWN:
                LOG.warn(_("Instance shutdown by itself or by user manually."), instance=db_instance)
                try:
                    self.compute_api.stop(context, db_instance)
                except Exception:
                    LOG.exception(_("error during power_off() in "
                                    "sync_power_state."),
                                  instance=db_instance)

            elif vm_power_state in (power_state.SUSPENDED,
                                    power_state.CRASHED,
                                    power_state.NOSTATE):
                if vm_power_state == power_state.SUSPENDED:
                    LOG.warn(_("Instance is suspended unexpectedly. Trying to "
                               "hard_reoot."), instance=db_instance)
                elif vm_power_state == power_state.NOSTATE:
                    LOG.warn(_("Instance is unexpectedly not found. Trying to."
                               "hard_reboot"), instance=db_instance)
                else:
                    LOG.warn(_("Instance is unexpectedly crashed. Trying to."
                               "hard_reboot"), instance=db_instance)

                LOG.debug(_('No deed do resume on host boot in FC mode'))

            elif vm_power_state == power_state.PAUSED:
                # Note: a VM may get into the paused state not only
                # because the user request via API calls, but also
                # due to (temporary) external instrumentations.
                # Before the virt layer can reliably report the reason,
                # we simply ignore the state discrepancy. In many cases,
                # the VM state will go back to running after the external
                # instrumentation is done. See bug 1097806 for details.
                LOG.warn(_("Instance is paused unexpectedly. Ignoring it."),
                         instance=db_instance)

        elif vm_state == vm_states.STOPPED:
            if vm_power_state not in (power_state.NOSTATE,
                                      power_state.SHUTDOWN,
                                      power_state.CRASHED):
                LOG.warn(_LW("Instance is not stopped. Calling "
                             "the stop API. Current vm_state: %(vm_state)s, "
                             "current task_state: %(task_state)s, "
                             "current DB power_state: %(db_power_state)s, "
                             "current VM power_state: %(vm_power_state)s"),
                         {'vm_state': vm_state,
                          'task_state': db_instance.task_state,
                          'db_power_state': db_power_state,
                          'vm_power_state': vm_power_state},
                          instance=db_instance)
                try:
                    # NOTE Force the stop, because normally the
                    # compute API would not allow an attempt to stop a stopped
                    # instance.
                    self.compute_api.force_stop(context, db_instance)
                except Exception:
                    LOG.exception(_LE("error during stop() in "
                                      "sync_power_state."),
                                  instance=db_instance)

            elif vm_power_state in (power_state.NOSTATE,
                                    power_state.CRASHED):
                LOG.debug(_('No deed do resume on host boot in FC mode'))

        elif vm_state in (vm_states.SOFT_DELETED,
                          vm_states.DELETED):
            if vm_power_state not in (power_state.NOSTATE,
                                      power_state.SHUTDOWN):
                # Note: this should be taken care of periodically in
                # _cleanup_running_deleted_instances().
                LOG.warn(_("Instance is not (soft-)deleted."),
                         instance=db_instance)

    @wrap_exception()
    @wrap_instance_event
    @wrap_instance_fault
    def delete_localinstance(self, context, instance, bdms=None):
        LOG.info(_LI("Enter clean rescheduler instance"),
                      instance=instance)
        if (bdms and
            any(not isinstance(bdm, obj_base.NovaObject)
                for bdm in bdms)):
            bdms = objects.BlockDeviceMappingList.get_by_instance_uuid(
                context, instance.uuid)

        context = context.elevated()
        try:
            network_info = self._get_instance_nw_info(context, instance)
        except (exception.NetworkNotFound, exception.NoMoreFixedIps):
            network_info = network_model.NetworkInfo()

        # NOTE(vish) get bdms before destroying the instance
        vol_bdms = [bdm for bdm in bdms if bdm.is_volume]
        bdi = self._get_instance_block_device_info(
            context, instance, bdms=bdms)

        try:
            self.driver.destroy(context, instance, network_info,
                                block_device_info=bdi)
        except Exception:
            with excutils.save_and_reraise_exception():
                pass

        for bdm in vol_bdms:
            try:
                # NOTE(vish): actual driver detach done in driver.destroy, so
                #             just tell cinder that we are done with it.
                connector = self.driver.get_volume_connector(instance)
                self.volume_api.terminate_connection(context,
                                                     bdm.volume_id,
                                                     connector,
                                                     instance['uuid'],
                                                     self.host)
            except exception.DiskNotFound as exc:
                LOG.debug('Ignoring DiskNotFound: %s', exc,
                          instance=instance)
            except exception.VolumeNotFound as exc:
                LOG.debug('Ignoring VolumeNotFound: %s', exc,
                          instance=instance)
            except cinder_exception.EndpointNotFound as exc:
                LOG.warn(_LW('Ignoring EndpointNotFound: %s'), exc,
                             instance=instance)

    @wrap_exception()
    @reverts_task_state
    @wrap_instance_event
    @wrap_instance_fault
    def reschedule_instance(self, context, instance, 
                            orig_image_ref, image_ref,
                            injected_files, new_pass, 
                            host, orig_sys_metadata=None,
                            bdms=None, recreate=False, 
                            on_shared_storage=False, 
                            filter_properties={}):
        """Rescheule instance for HA

        If we use HA, heat will use this fuction to 
        rescheule instance to another host
        """

        context = context.elevated()
        try:
            limits = filter_properties.get('limits', {})
            # Note(huawei) update node info for HA 
            node_name = None
            try:
                compute_node = self._get_compute_info(context, host)
                node_name = compute_node.hypervisor_hostname
                instance.host = host
                instance.node = node_name
                instance.save()
            except exception.NotFound:
                LOG.exception(_LE('Failed to get compute_info for %s'),
                              host)
                raise
             
            rt = self._get_resource_tracker(host)
            with rt.instance_claim(context, instance, limits):
                LOG.audit(_('rebuilding'), context=context, instance=instance)
                LOG.info(_("reschedule instance  %s will begin after %d seconds" % 
                                (instance['uuid'], CONF.reschedule_delay_rebuild_time)))
                greenthread.sleep(CONF.reschedule_delay_rebuild_time)
                self.rebuild_instance(context, instance, orig_image_ref, image_ref,
                             injected_files, new_pass, orig_sys_metadata,
                             bdms, recreate, on_shared_storage)
        except Exception as e:
            with excutils.save_and_reraise_exception():
                self._set_instance_error_state(context, instance)
                
    @hooks.add_hook("live_migrate_manager_hook")            
    @wrap_exception()
    @wrap_instance_fault
    def live_migration(self, context, dest, instance, block_migration,
                       migrate_data):
        """rewrite for add delete huawei_live_migration record.
        """
        if not isinstance(instance, obj_base.NovaObject):
            expected = ['metadata', 'system_metadata',
                        'security_groups', 'info_cache']
            instance = objects.Instance._from_db_object(
                context, objects.Instance(), instance,
                expected_attrs=expected)

        # Create a local copy since we'll be modifying the dictionary
        migrate_data = dict(migrate_data or {})
        try:
            if block_migration:
                disk = self.driver.get_instance_disk_info(instance.name)
            else:
                disk = None

            pre_migration_data = self.compute_rpcapi.pre_live_migration(
                context, instance,
                block_migration, disk, dest, migrate_data)
            migrate_data['pre_live_migration_result'] = pre_migration_data

        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE('Pre live migration failed at %s'),
                              dest, instance=instance)
                try:
                    self._rollback_live_migration(context, instance, dest,
                                            block_migration, migrate_data)
                except Exception as e:
                    msg = '_Rollback_live_migration error. %s' % e
                    LOG.exception(_LE(msg))
                getfun = objects.HuaweiLiveMigration.get_by_instance_uuid
                obj = getfun(context, instance.uuid)
                if obj:
                    obj.destroy(context)
                

        # Executing live migration
        # live_migration might raises exceptions, but
        # nothing must be recovered in this version.
        self.driver.live_migration(context, instance, dest,
                                   self._post_live_migration,
                                   self._rollback_live_migration,
                                   block_migration, migrate_data)

    def _complete_deletion(self, context, instance, bdms,
                           quotas, system_meta):
        super(HuaweiComputeManager, self)._complete_deletion(context, 
                            instance, bdms, quotas, system_meta)
        # add for deletion of relative-live-migrations record.
        getfun = objects.HuaweiLiveMigration.get_by_instance_uuid
        obj = getfun(context, instance['uuid'])
        if obj:
            LOG.info(_("Find instance in live-migrating, delete record."))
            obj.destroy(context)


    def get_pci_slots(self, instance):
        return self.driver.get_pci_slots_from_xml(instance)

    @object_compat
    @wrap_exception()
    @reverts_task_state
    @wrap_instance_fault
    def attach_interface(self, context, instance, network_id, port_id,
                         requested_ip):
        """Use hotplug to add an network adapter to an instance."""
        pci_list = self.get_pci_slots(instance)
        LOG.debug(_("PCI list:%s" % pci_list))
        network_info = self.network_api.allocate_port_for_instance(
            context, instance, port_id, network_id, requested_ip, pci_list)
        if len(network_info) != 1:
            LOG.error(_('allocate_port_for_instance returned %(ports)s ports')
                      % dict(ports=len(network_info)))
            raise exception.InterfaceAttachFailed(
                instance_uuid=instance.uuid)
        image_ref = instance.get('image_ref')
        image_meta = compute_utils.get_image_metadata(
            context, self.image_api, image_ref, instance)

        try:
            self.driver.attach_interface(instance, image_meta, network_info[0])
        except Exception:
            if not port_id:
                port_id = dict(network_info[0]).get('id')
                LOG.error(_('begin delete allocated port: %s'), port_id)
                self.network_api.deallocate_port_for_instance(context,
                    instance, port_id)
            raise exception.InterfaceAttachFailed(instance_uuid=instance.uuid)

        if utils.is_neutron():
            db_req_networks = []
            db_obj = HuaweiInstanceExtra(instance_uuid=instance.uuid)
            db_instance = db_obj.get_by_instance_uuid(context, instance_uuid=instance.uuid)
            if db_instance.request_network:
                db_req_networks = jsonutils.loads(db_instance.request_network)
                LOG.debug(_("attach db_req_networks before: %s"), db_req_networks)

            vif_info = dict(network_info[0])
            # Update port and network ids
            if not port_id:
                port_id = vif_info.get('id')
                if port_id:
                    LOG.debug(_("Allocated port id: %s"), port_id)
                else:
                    LOG.error(_("No port 'id' in allocated VIF info!"))
            if not network_id:
                alloc_network_info = vif_info.get('network')
                if alloc_network_info:
                    network_id = alloc_network_info.get('id')
                    if not network_id:
                        LOG.error(_("No network 'id' in allocated VIF info!"))

            db_req_networks.append([network_id, None, port_id])
            LOG.debug(_("attach db_req_networks after: %s"), db_req_networks)
            HuaweiInstanceExtra(instance_uuid=instance.uuid,
                request_network = jsonutils.dumps(db_req_networks)).create(context)
        return network_info[0]

    @object_compat
    @wrap_exception()
    @reverts_task_state
    @wrap_instance_fault
    def detach_interface(self, context, instance, port_id):
        """Detach an network adapter from an instance."""
        network_info = instance.info_cache.network_info
        condemned = None
        network_id = None
        for vif in network_info:
            if vif['id'] == port_id:
                condemned = vif
                network_id = vif['network']['id']
                break
        if condemned is None:
            raise exception.PortNotFound(_("Port %s is not "
                                           "attached") % port_id)

        #first driver detach
        self.driver.detach_interface(instance, condemned)
        self.network_api.deallocate_port_for_instance(context, instance,
            port_id)
        networks_info = []
        if utils.is_neutron():
            db_obj = HuaweiInstanceExtra(instance_uuid=instance.uuid)
            db_instance = db_obj.get_by_instance_uuid(context,instance_uuid=instance.uuid)
            if db_instance.request_network:
                networks_info = jsonutils.loads(db_instance.request_network)
                LOG.debug(_("detach db_req_networks before: %s"), networks_info)
            port_removed = False
            if port_id:
                for network_info in networks_info:
                    [net_id, _i, port] = network_info[:3]
                    if port == port_id:
                        networks_info.remove(network_info)
                        port_removed = True
                        LOG.info(_("Removed request_network port: %s"), port)
                        break
            if not port_removed:
                for network_info in networks_info:
                    [net_id, _i, port] = network_info[:3]
                    if net_id == network_id:
                        networks_info.remove(network_info)
                        LOG.info(_("Removed request_network net_id: %s"), net_id)
                        break
            LOG.debug(_("detach db_req_networks after: %s"), networks_info)
            HuaweiInstanceExtra(instance_uuid=instance.uuid,
                request_network = jsonutils.dumps(networks_info)).create(context)

    @wrap_exception()
    def add_vms_to_affinity_group(self, context, affinity_group_id, instances):
        LOG.debug(_('add vms to affinity group %s'), affinity_group_id)
        affinity_group = None
        if affinity_group_id:
            instance_ids = []
            try:
                affinity_group = affinitygroup_obj.AffinityGroup.get_by_id(
                    context, affinity_group_id)
                type = "add"
                affinityVMS =  affinity_group.get_all_vms(context)
                if affinityVMS != None and affinityVMS != []:
                    type = "edit"
                for instance in instances:
                    if str(instance.get('id')) in affinity_group.get_all_vms(context):
                        LOG.debug(_('instance contain in vms'))
                        continue
                    affinity_group.add_vm(context, str(instance.get('id')))
                    instance_ids.append(instance.get('id'))
                if instance_ids == []:
                    return
                self._reconfigure_affinity_group(context, affinity_group, type)
            except Exception:
                with excutils.save_and_reraise_exception():
                    for id in instance_ids:
                        affinity_group.delete_vm(context, str(id))

    @wrap_exception()
    def remove_vms_from_affinity_group(self, context, affinity_group_id,
                                       instances):
        LOG.debug(_('delete vms from affinity group %s'), affinity_group_id)
        affinity_group = None
        if affinity_group_id:
            instance_ids = []
            try:
                affinity_group = affinitygroup_obj.AffinityGroup.get_by_id(
                    context, affinity_group_id)
                type = "edit"
                node =None
                for instance in instances:
                    if str(instance.get('id')) in affinity_group.get_all_vms(context):
                        LOG.debug(_('instance contain in vms'))
                        node = instance.get('node')
                        affinity_group.delete_vm(context, str(instance.get('id')))
                        instance_ids.append(str(instance.get('id')))
                if affinity_group.get_all_vms(context) == [] or \
                                affinity_group.get_all_vms(context) == None:
                    type = "remove"
                self._reconfigure_affinity_group(context, affinity_group, type,
                                                 node=node, instances=instance_ids)
            except Exception:
                with excutils.save_and_reraise_exception():
                    for id in instance_ids:
                        affinity_group.add_vm(context, str(id))

    def _reconfigure_affinity_group(self, context, affinity_group, type,
                                    node=None, instances=None):
        ins_ref_list = []
        all_vms = affinity_group.get_all_vms(context)
        if type == "remove":
            all_vms = instances
        if len(all_vms) == 1:
            raise huawei_exception.AffinityGroupOneVMExists()
        for instance_id in all_vms:
            vm = self.compute_api.get(context, instance_id, want_objects=True)
            ins_ref = {'id': vm.get('id'),
                       'node': vm.get('node'),
                       'name': vm.get('uuid')}
            ins_ref_list.append(ins_ref)
        self.driver.reconfigure_affinity_group(ins_ref_list, affinity_group, type,
                                               node=node)

    @wrap_instance_fault
    def update_vif_pg_info(self, context, instance):
        LOG.debug(_('update vif network info'), context=context,
                  instance=instance)

        network_info = self._get_instance_nw_info(context, instance)
        LOG.debug(_('network_info to update: |%s|'), network_info,
                  instance=instance)

        self.driver.update_vif_pg_info(instance, network_info)
        return network_info

    @wrap_exception()
    @reverts_task_state
    @wrap_instance_fault
    def build_and_run_instance(self, context, instance, image, request_spec,
                     filter_properties, admin_password=None,
                     injected_files=None, requested_networks=None,
                     security_groups=None, block_device_mapping=None,
                     node=None, limits=None):

        # NOTE(danms): Remove this in v4.0 of the RPC API
        if (requested_networks and
                not isinstance(requested_networks,
                               objects.NetworkRequestList)):
            requested_networks = objects.NetworkRequestList(
                objects=[objects.NetworkRequest.from_tuple(t)
                         for t in requested_networks])

        @utils.synchronized(instance.uuid)
        def _locked_do_build_and_run_instance(*args, **kwargs):
            self._do_build_and_run_instance(*args, **kwargs)

        # NOTE(danms): We spawn here to return the RPC worker thread back to
        # the pool. Since what follows could take a really long time, we don't
        # want to tie up RPC workers.
        utils.spawn_n(_locked_do_build_and_run_instance,
                      context, instance, image, request_spec,
                      filter_properties, admin_password, injected_files,
                      requested_networks, security_groups,
                      block_device_mapping, node, limits)

    def _cleanup_inner_created_volumes(self, context, instance_uuid, bdms,
                                       raise_exc=True):
        exc_info = None

        for bdm in bdms:
            if bdm.volume_id and bdm.delete_on_termination:
                if bdm.get('source_type') \
                and (bdm.source_type == 'image'
                     or bdm.source_type == 'snapshot'):
                    LOG.debug("terminating inner created bdm %s", bdm,
                        instance_uuid=instance_uuid)
                    try:
                        self.volume_api.delete(context, bdm.volume_id)
                    except Exception as exc:
                        exc_info = sys.exc_info()
                        LOG.warn(_LW('Failed to delete volume: %(volume_id)s '
                                     'due to %(exc)s'),
                                     {'volume_id': bdm.volume_id,
                                      'exc': unicode(exc)})

        if exc_info is not None and raise_exc:
            six.reraise(exc_info[0], exc_info[1], exc_info[2])

    @wrap_exception()
    @reverts_task_state
    @wrap_instance_event
    @wrap_instance_fault
    def _do_build_and_run_instance(self, context, instance, image,
            request_spec, filter_properties, admin_password, injected_files,
            requested_networks, security_groups, block_device_mapping,
            node=None, limits=None):

        try:
            LOG.audit(_('Starting instance...'), context=context,
                  instance=instance)
            instance.vm_state = vm_states.BUILDING
            instance.task_state = None
            instance.save(expected_task_state=
                    (task_states.SCHEDULING, None))
        except exception.InstanceNotFound:
            msg = 'Instance disappeared before build.'
            LOG.debug(msg, instance=instance)
            return
        except exception.UnexpectedTaskStateError as e:
            LOG.debug(e.format_message(), instance=instance)
            return

        # b64 decode the files to inject:
        decoded_files = self._decode_files(injected_files)

        if limits is None:
            limits = {}

        if node is None:
            node = self.driver.get_available_nodes(refresh=True)[0]
            LOG.debug('No node specified, defaulting to %s', node,
                      instance=instance)

        try:
            self._build_and_run_instance(context, instance, image,
                    decoded_files, admin_password, requested_networks,
                    security_groups, block_device_mapping, node, limits,
                    filter_properties)
        except exception.RescheduledException as e:
            LOG.debug(e.format_message(), instance=instance)
            retry = filter_properties.get('retry', None)
            if not retry:
                # no retry information, do not reschedule.
                LOG.debug("Retry info not present, will not reschedule",
                    instance=instance)
                self._cleanup_allocated_networks(context, instance,
                    requested_networks)
                self._cleanup_inner_created_volumes(context, instance.uuid,
                    block_device_mapping, raise_exc=False)
                compute_utils.add_instance_fault_from_exc(context,
                        instance, e, sys.exc_info())
                self._set_instance_error_state(context, instance)
                return
            retry['exc'] = traceback.format_exception(*sys.exc_info())
            # NOTE(comstud): Deallocate networks if the driver wants
            # us to do so.
            if self.driver.deallocate_networks_on_reschedule(instance):
                self._cleanup_allocated_networks(context, instance,
                        requested_networks)

            instance.task_state = task_states.SCHEDULING
            instance.save()

            self.compute_task_api.build_instances(context, [instance],
                    image, filter_properties, admin_password,
                    injected_files, requested_networks, security_groups,
                    block_device_mapping)
        except (exception.InstanceNotFound,
                exception.UnexpectedDeletingTaskStateError):
            msg = 'Instance disappeared during build.'
            LOG.debug(msg, instance=instance)
            self._cleanup_allocated_networks(context, instance,
                    requested_networks)
            self._cleanup_inner_created_volumes(context, instance.uuid,
                    block_device_mapping, raise_exc=False)
        except exception.BuildAbortException as e:
            LOG.exception(e.format_message(), instance=instance)
            self._cleanup_allocated_networks(context, instance,
                    requested_networks)
            self._cleanup_inner_created_volumes(context, instance.uuid,
                    block_device_mapping, raise_exc=False)
            compute_utils.add_instance_fault_from_exc(context, instance,
                    e, sys.exc_info())
            self._set_instance_error_state(context, instance)
        except Exception as e:
            # Should not reach here.
            msg = _LE('Unexpected build failure, not rescheduling build.')
            LOG.exception(msg, instance=instance)
            self._cleanup_allocated_networks(context, instance,
                    requested_networks)
            self._cleanup_inner_created_volumes(context, instance.uuid,
                    block_device_mapping, raise_exc=False)
            compute_utils.add_instance_fault_from_exc(context, instance,
                    e, sys.exc_info())
            self._set_instance_error_state(context, instance)

    def _finish_resize(self, context, instance, migration, disk_info,
                       image):
        resize_instance = False
        old_instance_type_id = migration['old_instance_type_id']
        new_instance_type_id = migration['new_instance_type_id']
        old_instance_type = flavors.extract_flavor(instance)
        sys_meta = instance.system_metadata
        # NOTE(mriedem): Get the old_vm_state so we know if we should
        # power on the instance. If old_vm_state is not set we need to default
        # to ACTIVE for backwards compatibility
        old_vm_state = sys_meta.get('old_vm_state', vm_states.ACTIVE)
        flavors.save_flavor_info(sys_meta,
                                 old_instance_type,
                                 prefix='old_')

        if old_instance_type_id != new_instance_type_id:
            instance_type = flavors.extract_flavor(instance, prefix='new_')
            self._save_instance_info(instance, instance_type, sys_meta)
            resize_instance = True

        # NOTE(tr3buchet): setup networks on destination host
        self.network_api.setup_networks_on_host(context, instance,
                                                migration['dest_compute'])

        instance_p = obj_base.obj_to_primitive(instance)
        migration_p = obj_base.obj_to_primitive(migration)
        self.network_api.migrate_instance_finish(context,
                                                 instance_p,
                                                 migration_p)

        network_info = self._get_instance_nw_info(context, instance)

        instance.task_state = task_states.RESIZE_FINISH
        instance.system_metadata = sys_meta

        if old_instance_type_id != new_instance_type_id:
            old_instance_numa = instance.numa_topology
            instance.system_metadata['old_instance_numa'] = jsonutils.dumps(
                old_instance_numa)
            instance_type = objects.Flavor.get_by_id(context,
                                                     new_instance_type_id)
            numa_topology = hardware.numa_get_constraints(
                instance_type, {})
            instance.numa_topology = numa_topology
            if numa_topology:
                bind_info, new_instance_numa, enable_ht = \
                hw_shed_utils.get_inst_cpu_bind_info(instance, self.driver.host,
                network_info=network_info)
                if new_instance_numa and new_instance_numa['cells'][0].get('is_huawei'):
                    cells = []
                    for cell in new_instance_numa['cells']:
                        cells.append(objects.InstanceNUMACell(
                            id=cell['id'], cpuset=set(cell['cpuset']),
                            memory=cell['mem']['total'],
                            pagesize=cell.get('pagesize')))
                    format_inst_numa = objects.InstanceNUMATopology(cells=cells)
                    instance.numa_topology = format_inst_numa

        instance.save(expected_task_state=task_states.RESIZE_MIGRATED)

        self._notify_about_instance_usage(
            context, instance, "finish_resize.start",
            network_info=network_info)

        block_device_info = self._get_instance_block_device_info(
                            context, instance, refresh_conn_info=True)

        # NOTE(mriedem): If the original vm_state was STOPPED, we don't
        # automatically power on the instance after it's migrated
        power_on = old_vm_state != vm_states.STOPPED

        try:
            self.driver.finish_migration(context, migration, instance,
                                         disk_info,
                                         network_info,
                                         image, resize_instance,
                                         block_device_info, power_on)
        except Exception:
            with excutils.save_and_reraise_exception():
                if resize_instance:
                    instance.numa_topology = old_instance_numa
                    instance.system_metadata.pop('old_instance_numa', None)
                    self._save_instance_info(instance,
                                             old_instance_type, sys_meta)

        migration.status = 'finished'
        migration.save(context.elevated())

        instance.vm_state = vm_states.RESIZED
        instance.task_state = None
        instance.launched_at = timeutils.utcnow()
        instance.save(expected_task_state=task_states.RESIZE_FINISH)

        self._notify_about_instance_usage(
            context, instance, "finish_resize.end",
            network_info=network_info)

    def _confirm_resize(self, context, instance, quotas,
                        migration=None):
        """Destroys the source instance."""
        self._notify_about_instance_usage(context, instance,
                                          "resize.confirm.start")

        with self._error_out_instance_on_exception(context, instance,
                                                   quotas=quotas):
            # NOTE(danms): delete stashed migration information
            sys_meta, instance_type, old_instance_type = (
                self._cleanup_stored_instance_types(migration, instance))
            sys_meta.pop('old_vm_state', None)
            sys_meta.pop('old_instance_numa', None)

            instance.system_metadata = sys_meta
            instance.save()

            # NOTE(tr3buchet): tear down networks on source host
            self.network_api.setup_networks_on_host(context, instance,
                               migration.source_compute, teardown=True)

            network_info = self._get_instance_nw_info(context, instance)
            self.driver.confirm_migration(migration, instance,
                                          network_info)

            migration.status = 'confirmed'
            migration.save(context.elevated())

            rt = self._get_resource_tracker(migration.source_node)
            rt.drop_resize_claim(context, instance, old_instance_type)

            # NOTE(mriedem): The old_vm_state could be STOPPED but the user
            # might have manually powered up the instance to confirm the
            # resize/migrate, so we need to check the current power state
            # on the instance and set the vm_state appropriately. We default
            # to ACTIVE because if the power state is not SHUTDOWN, we
            # assume _sync_instance_power_state will clean it up.
            p_state = instance.power_state
            vm_state = None
            if p_state == power_state.SHUTDOWN:
                vm_state = vm_states.STOPPED
                LOG.debug("Resized/migrated instance is powered off. "
                          "Setting vm_state to '%s'.", vm_state,
                          instance=instance)
            else:
                vm_state = vm_states.ACTIVE

            instance.vm_state = vm_state
            instance.task_state = None
            instance.save(expected_task_state=[None, task_states.DELETING])

            self._notify_about_instance_usage(
                context, instance, "resize.confirm.end",
                network_info=network_info)

            quotas.commit()

    @wrap_exception()
    @reverts_task_state
    @wrap_instance_event
    @wrap_instance_fault
    def finish_revert_resize(self, context, instance, reservations, migration):
        """Finishes the second half of reverting a resize.

        Bring the original source instance state back (active/shutoff) and
        revert the resized attributes in the database.

        """

        quotas = quotas_obj.Quotas.from_reservations(context,
                                                     reservations,
                                                     instance=instance)

        with self._error_out_instance_on_exception(context, instance,
                                                   quotas=quotas):
            network_info = self._get_instance_nw_info(context, instance)

            self._notify_about_instance_usage(
                    context, instance, "resize.revert.start")

            sys_meta, instance_type, drop_instance_type = (
                self._cleanup_stored_instance_types(migration, instance, True))

            # NOTE(mriedem): delete stashed old_vm_state information; we
            # default to ACTIVE for backwards compatibility if old_vm_state
            # is not set
            old_vm_state = sys_meta.pop('old_vm_state', vm_states.ACTIVE)

            old_instance_numa = sys_meta.pop('old_instance_numa', None)
            # convert dict to object
            if old_instance_numa:
                old_instance_numa = jsonutils.loads(old_instance_numa)
            if old_instance_numa and old_instance_numa.get('cells'):
                cells = []
                for cell in old_instance_numa['cells']:
                    cells.append(objects.InstanceNUMACell(
                        id=cell['id'], cpuset=set(cell['cpuset']),
                        memory=cell['memory'],
                        pagesize=cell.get('pagesize')))
                instance.numa_topology = objects.InstanceNUMATopology(
                    cells=cells)
            else:
                 instance.numa_topology = None

            instance.system_metadata = sys_meta
            instance.memory_mb = instance_type['memory_mb']
            instance.vcpus = instance_type['vcpus']
            instance.root_gb = instance_type['root_gb']
            instance.ephemeral_gb = instance_type['ephemeral_gb']
            instance.instance_type_id = instance_type['id']
            instance.host = migration['source_compute']
            instance.node = migration['source_node']
            instance.save()

            self.network_api.setup_networks_on_host(context, instance,
                                            migration['source_compute'])

            block_device_info = self._get_instance_block_device_info(
                    context, instance, refresh_conn_info=True)

            power_on = old_vm_state != vm_states.STOPPED
            self.driver.finish_revert_migration(context, instance,
                                       network_info,
                                       block_device_info, power_on)

            instance.launched_at = timeutils.utcnow()
            instance.save(expected_task_state=task_states.RESIZE_REVERTING)

            instance_p = obj_base.obj_to_primitive(instance)
            migration_p = obj_base.obj_to_primitive(migration)
            self.network_api.migrate_instance_finish(context,
                                                     instance_p,
                                                     migration_p)

            # if the original vm state was STOPPED, set it back to STOPPED
            LOG.info(_("Updating instance to original state: '%s'") %
                     old_vm_state)
            if power_on:
                instance.vm_state = vm_states.ACTIVE
                instance.task_state = None
                instance.save()
            else:
                instance.task_state = task_states.POWERING_OFF
                instance.save()
                self.stop_instance(context, instance=instance)

            self._notify_about_instance_usage(
                    context, instance, "resize.revert.end")
            quotas.commit()

    @wrap_exception()
    @reverts_task_state
    @wrap_instance_event
    @wrap_instance_fault
    def suspend_instance(self, context, instance):
        """Suspend the given instance."""
        context = context.elevated()

        # Store the old state
        instance.system_metadata['old_vm_state'] = instance.vm_state

        with self._error_out_instance_on_exception(context, instance,
            instance_state=instance['vm_state']):
            self.driver.suspend(context, instance)
        current_power_state = self._get_power_state(context, instance)
        instance.power_state = current_power_state
        instance.vm_state = vm_states.SUSPENDED
        instance.task_state = None
        instance.save(expected_task_state=task_states.SUSPENDING)
        self._notify_about_instance_usage(context, instance, 'suspend')

    def _check_vm_boot_from(self, bdms):
        is_boot_from_volume = False
        for bdm in bdms:
            destination_type = bdm.get('destination_type')
            boot_index = bdm.get('boot_index')
            if boot_index==0 and destination_type=='volume':
                is_boot_from_volume = True
                break
        return is_boot_from_volume

    @object_compat
    @messaging.expected_exceptions(exception.PreserveEphemeralNotSupported)
    @wrap_exception()
    @reverts_task_state
    @wrap_instance_event
    @wrap_instance_fault
    def rebuild_instance(self, context, instance, orig_image_ref, image_ref,
                         injected_files, new_pass, orig_sys_metadata,
                         bdms, recreate, on_shared_storage,
                         preserve_ephemeral=False):
        is_boot_from_volume = self._check_vm_boot_from(bdms)
        bdm_num = len(bdms)
        max_volume_num = self.driver.fc_max_volumes()
        if is_boot_from_volume is True and bdm_num>=max_volume_num:
            LOG.info(_("vm bdm count %d is more than fc volume count limit %d, will not rebuild"),
                     bdm_num, max_volume_num)

            instance.power_state = self._get_power_state(context, instance)
            instance.vm_state = vm_states.ACTIVE
            instance.task_state = None
            instance.launched_at = timeutils.utcnow()
            instance.save()

            orig_vm_state = instance.vm_state
            if orig_vm_state == vm_states.STOPPED:
                LOG.info(_LI("bringing vm to original state: '%s'"),
                         orig_vm_state, instance=instance)
                instance.vm_state = vm_states.ACTIVE
                instance.task_state = task_states.POWERING_OFF
                instance.progress = 0
                instance.save()
                self.stop_instance(context, instance)
            return

        super(HuaweiComputeManager, self).rebuild_instance(context,
                                          instance, orig_image_ref, image_ref,
                                          injected_files, new_pass, orig_sys_metadata,
                                          bdms, recreate, on_shared_storage,
                                          preserve_ephemeral)

    def _rebuild_default_impl(self, context, instance, image_meta,
                              injected_files, admin_password, bdms,
                              detach_block_devices, attach_block_devices,
                              network_info=None,
                              recreate=False, block_device_info=None,
                              preserve_ephemeral=False):
        if preserve_ephemeral:
            # The default code path does not support preserving ephemeral
            # partitions.
            raise exception.PreserveEphemeralNotSupported()

        detach_block_devices(context, bdms, instance['uuid'])

        if not recreate:
            try:
                self.driver.destroy(context, instance, network_info,
                                    block_device_info=block_device_info)
            except Exception as e:
                attach_block_devices(context, instance, bdms)
                raise exception.InstanceFaultRollback(inner_exception=e)

        instance.task_state = task_states.REBUILD_BLOCK_DEVICE_MAPPING
        instance.save(expected_task_state=[task_states.REBUILDING])

        #only for volume boot vm, disk name need change
        is_boot_from_volume = self._check_vm_boot_from(bdms)

        for bdm in bdms:
            destination_type = bdm.get('destination_type')
            device_name_old = bdm.get('device_name')
            device_name_new = self.driver.get_next_disk_name(device_name_old)
            boot_index = bdm.get('boot_index')

            if destination_type == 'volume' \
                    and device_name_new is not None \
                    and is_boot_from_volume is True:
                LOG.info(_("change device name from %s to %s"),
                         device_name_old, device_name_new)
                bdm['device_name'] = device_name_new
                if boot_index is not None:
                    bdm['boot_index'] = None

        new_block_device_info = attach_block_devices(context, instance, bdms)

        instance.task_state = task_states.REBUILD_SPAWNING
        instance.save(
            expected_task_state=[task_states.REBUILD_BLOCK_DEVICE_MAPPING])

        self.driver.spawn(context, instance, image_meta, injected_files,
                          admin_password, network_info=network_info,
                          block_device_info=new_block_device_info)

    @contextlib.contextmanager
    def _error_out_instance_on_exception(self, context, instance,
                                         quotas=None,
                                         instance_state=vm_states.ACTIVE):
        instance_uuid = instance['uuid']
        try:
            yield
        except NotImplementedError as error:
            with excutils.save_and_reraise_exception():
                if quotas:
                    quotas.rollback()
                LOG.info(_("Setting instance back to %(state)s after: "
                           "%(error)s") %
                         {'state': instance_state, 'error': error},
                    instance_uuid=instance_uuid)
                self._instance_update(context, instance_uuid,
                    vm_state=instance_state,
                    task_state=None)
        except exception.InstanceFaultRollback as error:
            if quotas:
                quotas.rollback()
            if instance.task_state == task_states.RESIZE_REVERTING:
                LOG.info(_("Revert resize failed for: %s"),
                    error, instance_uuid=instance_uuid)
                elevated = context.elevated()
                migration = objects.Migration.get_by_instance_and_status(
                    elevated, instance.uuid, 'reverting')
                migration.status = 'finished'
                migration.save()
                self._instance_update(context, instance_uuid,
                    vm_state=vm_states.RESIZED,
                    task_state=None)
            else:
                LOG.info(_("Setting instance back to ACTIVE after: %s"),
                    error, instance_uuid=instance_uuid)
                self._instance_update(context, instance_uuid,
                    vm_state=vm_states.ACTIVE,
                    task_state=None)
            raise error.inner_exception
        except Exception:
            LOG.exception(_LE('Setting instance vm_state to ERROR'),
                instance_uuid=instance_uuid)
            with excutils.save_and_reraise_exception():
                if quotas:
                    quotas.rollback()
                self._set_instance_error_state(context, instance)

class HuaweiComputeVirtAPI(ComputeVirtAPI):
    def __init__(self, compute):
        super(HuaweiComputeVirtAPI, self).__init__(compute)

    def instance_get_all_by_host(self, context, host):
        return objects.InstanceList.get_by_host(context, host)

    def instance_get_by_uuid(self, context, instance_uuid):
        return objects.Instance.get_by_uuid(context, instance_uuid)

    def instance_update(self, context, instance_uuid, **kwargs):
        self._compute._instance_update(context, instance_uuid, **kwargs)

    def get_instance_nw_info(self, context, instance):
        return self._compute._get_instance_nw_info(context, instance)

    def get_instance_block_device_info(self, context, instance):
        return self._compute._get_instance_block_device_info(context, instance)

