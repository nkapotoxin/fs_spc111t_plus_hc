
import copy
import itertools
import threading
import os

from cinderclient import exceptions as cinder_exception
from keystoneclient.v2_0 import client as key_client
from nova.compute.manager import *
from nova.compute import task_states
from nova.compute import utils as compute_utils
from nova.compute import vm_states
from nova.huawei.objects import affinity_group as affinitygroup_obj
from nova.huawei.virt.libvirt import event as extend_virtevent
from nova.huawei.compute import resource_tracker as hwrt
from nova.huawei import exception as huawei_exception
from nova.i18n import _LE
from nova.i18n import _LW
from nova.i18n import _LI
from nova.openstack.common import importutils
from nova.openstack.common.gettextutils import _
from nova.pci import pci_device
from nova.pci import pci_manager
from nova import utils
from nova import objects
from nova.virt import driver
from nova.objects.huawei_instance_extra import HuaweiInstanceExtra
from nova.openstack.common import periodic_task
import libuvp_compute
from nova.huawei.scheduler import utils as hw_shed_utils
from nova.virt import hardware
from nova import hooks
from nova.network import model as network_model

from nova.huawei.compute import rpcapi as hw_rpcapi
from nova.huawei import utils as h_utils

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
    cfg.IntOpt('sync_state_count',
               default=3,
               help=''),
    cfg.IntOpt('heartbeat_interval',
               default=30,
               help=''),
]
CONF.register_opts(running_deleted_notify_opts)

extend_opts = [
    cfg.StrOpt('monitor_file',
               default=os.path.join(CONF.libvirt_snapshots_directory, "nova-compute_heart.ini"),
               help='The path of file to write the monitor time.'),
]
reschedule_opts = [
    cfg.IntOpt("reschedule_delay_rebuild_time",
               default=60,
               help="Number of seconds to wait before rebuilding"
                    "instance after rescheduling instance"),
]

interval_opts = [
    cfg.IntOpt("emulatorpin_update_interval",
           default=60,
           help="Interval in seconds for update emulatorpin"),
]

CONF.register_opts(extend_opts)
CONF.register_opts(reschedule_opts)
CONF.register_opts(interval_opts)

# param& value of upgCtrlAutoUpgrade
UVP_VMTOOLS_FLAGTYPE = {"DEFAULT": 1, "1": 2, "0": 3}

UVP_VMTOOLS_STATECODE = {
    "0": {"MSG": "SUCCESS"},
    "1": {"MSG": "FAILED"},
    "2": {"DB": "1", "MSG": "UPGRADE ON"},
    "3": {"DB": "0", "MSG": "UPGRADE OFF"},
    "5": {"MSG": "UPGRADING"}
}
UVP_VMTOOLS_PROGRAMID = 1
UVP_VMTOOLS_SUCCESS = "0"


def load_compute_driver(virtapi, compute_driver):
    if not compute_driver:
        compute_driver = CONF.compute_driver
    LOG.info(_("Loading huawei compute driver %s ."), compute_driver)
    try:
        drv = importutils.import_object_ns('nova.huawei.virt',
                                           compute_driver,
                                           virtapi)
        return utils.check_isinstance(drv, driver.ComputeDriver)
    except ImportError:
        LOG.exception(_("Unable to load the huawei virtualization driver"))
        LOG.info(_("Try to import original virtualzation driver."))
        try:
            driver.load_compute_driver(virtapi, compute_driver)
        except ImportError:
            LOG.exception(_("Unable to load the virtualization driver"))
            sys.exit(1)


def wrap_instance_error(function):
    """Wraps a method to catch exceptions related to instances.

    This decorator wraps a method to catch any exceptions having to do with
    an instance that may get thrown. It then logs an instance fault in the db.
    """

    @functools.wraps(function)
    def _wrap_instance_error(self, context, instance, *args, **kwargs):
        try:
            return function(self, context, instance, *args, **kwargs)
        except exception.InstanceNotFound:
            raise
        except Exception as e:
            instance.task_state = None
            instance.vm_state = vm_states.ERROR
            instance.save()
            LOG.exception("instance %s ERROR" % instance['uuid'])
    return _wrap_instance_error


def roll_back_migration(function):
    @functools.wraps(function)
    def _roll_back_migration(self, context, *args, **kwargs):
        try:
            return function(self, context, *args, **kwargs)
        except exception.InstanceNotFound:
            raise
        except Exception:
            with excutils.save_and_reraise_exception():
                kwargs.update(dict(zip(function.func_code.co_varnames[2:],
                                       args)))
                instance = objects.Instance.get_by_uuid(
                    context, kwargs['instance']['uuid'])
                migration = kwargs['migration']
                incoming = (migration['dest_compute'] == instance.host and
                            migration['dest_node'] == instance.node)
                outbound = (migration['source_compute'] == instance.host and
                            migration['source_node'] == instance.node)
                same_node = (incoming and outbound)
                this_node = (instance.host == self.host)
                if same_node:
                    # if same node, just remove pci of new allocated
                    pci_flag = False
                    update_nwinfo = True
                elif incoming:
                    # at dest node
                    pci_flag = True
                    if migration.status == "post-migrating":
                        # resize_migrated & resize_finished
                        update_nwinfo = True
                    else:
                        update_nwinfo = False
                elif outbound:
                    # at source node
                    pci_flag = False
                    if migration.status == "reverted":
                        # resize revert at source node, after host changed
                        update_nwinfo = True
                    else:
                        update_nwinfo = False
                else:
                    pci_flag = False
                    update_nwinfo = False
                if migration and migration.status != "error":
                    # change migration status to error before free_pci_dev
                    # so will not allocate PCI again at resource update
                    migration.status = "error"
                    migration.save(context.elevated())
                if update_nwinfo:
                    rt = self._get_resource_tracker(instance.node)
                    if same_node and this_node:
                        # only free PCI device when same node
                        # value in db & mem are consistent with this
                        rt.free_pci_dev(context, instance, is_new=not pci_flag)

                    network_info = self._get_instance_nw_info(context,
                                                              instance)
                    nw_pci_info = rt.get_nw_pci_slot_info(context, instance,
                                                          is_new=pci_flag)
                    network_info = self._update_pci_slot2nw_info(context,
                                                                 nw_pci_info,
                                                                 network_info)
                    self.network_api.update_port_profile(context, instance,
                                                         network_info)
                    instance_info_cache = instance.info_cache
                    instance_info_cache.network_info = network_info
                    instance.info_cache = instance_info_cache

                # save pci_request with pci_flag
                # if flag is different with pci_flag, will be deleted
                pci_requests = objects.InstancePCIRequests.\
                    get_by_instance_uuid_and_newness(
                        context, instance['uuid'], is_new=pci_flag)
                if pci_requests:
                    for req in pci_requests.requests:
                        req.is_new = False
                    pci_requests.save()
                sys_meta = instance.system_metadata
                sys_meta.pop('old_vm_state', None)
                sys_meta.pop('old_numa_topo', None)
                sys_meta.pop('old_core_bind', None)
                sys_meta.pop('new_numa_topo', None)
                sys_meta.pop('new_core_bind', None)
                instance.system_metadata = sys_meta
                instance.save()
                LOG.exception("Clean up migration info of %s" %
                              instance['uuid'])
    return _roll_back_migration


def wrap_live_migration_rollback(function):
    @functools.wraps(function)
    def _wrap_live_migration_rollback(self, context, instance,
                                      block_migration, *args, **kwargs):
        try:
            return function(self, context, instance, block_migration,
                            *args, **kwargs)
        except:
            if instance['task_state'] == task_states.MIGRATING:
                try:
                    bdms = objects.BlockDeviceMappingList.get_by_instance_uuid(
                        context, instance['uuid'])
                    for bdm in bdms:
                        if bdm.is_volume:
                            self.remove_volume_connection(
                                context, bdm.volume_id, instance)
                finally:
                    migrate_data = {}
                    # cann't get migrate_data here
                    # when is_shared_instance_path is true, this might be wrong
                    do_cleanup, destroy_disks = self.\
                        _live_migration_cleanup_flags(
                            block_migration, migrate_data)
                    self.rollback_live_migration_at_destination(
                        context, instance, destroy_disks=destroy_disks,
                        migrate_data=None)
                    instance.task_state = None
                    instance.save(expected_task_state=task_states.MIGRATING)

                    get_migrate_obj = objects.HuaweiLiveMigration.\
                        get_by_instance_uuid
                    obj_migrate = get_migrate_obj(context, instance['uuid'])
                    if obj_migrate:
                        obj_migrate.destroy()
    return _wrap_live_migration_rollback


class HuaweiComputeManager(ComputeManager):
    # because shutdown in fsp will use agent mode,
    # shutdown will added a timeout feature,
    # use less retry times to forbidden too long waiting
    SHUTDOWN_RETRY_INTERVAL = 40

    def __init__(self, compute_driver=None, *args, **kwargs):
        # in order to avoiding wasting too much times to init hosts
        h_utils.heartbeat_period_task(CONF.heartbeat_interval,
                                      CONF.monitor_file)
        super(HuaweiComputeManager, self).__init__(
            'libvirt.LibvirtDriver', *args, **kwargs)
        self.virtapi = HuaweiComputeVirtAPI(self)
        self.driver = load_compute_driver(self.virtapi, compute_driver)
        self.compute_rpcapi = hw_rpcapi.HuaweiComputeAPI()
        self.roles = []
        self.user_name = None
        self.tenant_id = None
        self._sync_state_counts = {}
        self._pulls_min_times = 10
        self._pulls_max_times = 30
        self._pulls_current_times = 0
        self._pulls_in_progress = {}
        self._pulls_pool = eventlet.GreenPool()

    def check_alive(self, context, from_host=None):
        """sync check alive"""
        LOG.debug('check alive from %s', from_host)

    @wrap_exception()
    @reverts_task_state
    @wrap_instance_fault
    def _reboot_instance(self, context, instance):
        """Reboot an instance on this host."""
        instance.task_state = task_states.REBOOT_PENDING_HARD
        expected_states = (task_states.REBOOTING_HARD,
                           task_states.REBOOT_PENDING_HARD,
                           task_states.REBOOT_STARTED_HARD)

        context = context.elevated()
        LOG.audit(_("Rebooting instance"), context=context, instance=instance)

        block_device_info = self._get_instance_block_device_info(context,
                                                                 instance)

        network_info = self._get_instance_nw_info(context, instance)

        current_power_state = self._get_power_state(context, instance)
        instance.power_state = current_power_state
        instance.save(expected_task_state=expected_states)

        def bad_volumes_callback(bad_devices):
            self._handle_bad_volumes_detached(
                    context, instance, bad_devices, block_device_info)

        try:
            new_vm_state = vm_states.ACTIVE
            new_power_state = None
            instance.task_state = task_states.REBOOT_STARTED_HARD
            expected_state = task_states.REBOOT_PENDING_HARD
            instance.save(expected_task_state=expected_state)
            self.driver.reboot(context, instance,
                               network_info,
                               "HARD",
                               block_device_info=block_device_info,
                               bad_volumes_callback=bad_volumes_callback)

        except Exception as error:
            with excutils.save_and_reraise_exception() as ctxt:
                exc_info = sys.exc_info()
                # if the reboot failed but the VM is running don't
                # put it into an error state
                new_power_state = self._get_power_state(context, instance)
                if new_power_state == power_state.RUNNING:
                    LOG.warning(_('Reboot failed but instance is running'),
                                context=context, instance=instance)
                    compute_utils.add_instance_fault_from_exc(context,
                            instance, error, exc_info)
                    ctxt.reraise = False
                else:
                    LOG.error(_('Cannot reboot instance: %s'), error,
                              context=context, instance=instance)
                    self._set_instance_obj_error_state(context, instance)

        if not new_power_state:
            new_power_state = self._get_power_state(context, instance)
        try:
            instance.power_state = new_power_state
            instance.vm_state = new_vm_state
            instance.task_state = None
            instance.save()
        except exception.InstanceNotFound:
            LOG.warn(_("Instance disappeared during reboot"),
                     context=context, instance=instance)

    def get_ha_info_from_metadata(self, instance):
        sign = 1
        metadata = utils.instance_meta(instance)
        if metadata is not None:
            if isinstance(metadata, dict):
                for key, value in metadata.iteritems():
                    if '_ha_policy_type' == key:
                        if 'remote_rebuild' == value:
                            sign = 1
                        elif 'close' == value:
                            sign = -1
                        else:
                            sign = 0
            elif isinstance(metadata, list):
                for element in metadata:
                    if '_ha_policy_type' == element.get("key", None):
                        if 'remote_rebuild' == element.get("value", None):
                            sign = 1
                        elif 'close' == element.get("value", None):
                            sign = -1
                        else:
                            sign = 0
            else:
                sign = 0
        return sign

    @compute_utils.periodic_task_spacing_warn("pull_instances_with_exceptional_state")
    @periodic_task.periodic_task(spacing=CONF.sync_power_state_interval,
                                 run_immediately=True)
    def pull_instances_with_exceptional_state(self, context):
        """
        Pull instances with power_state is shutdown and vm_state is error
        because storage node initialization delay.
        """
        out, err = utils.execute('cat', '/proc/uptime', run_as_root=False)
        uptime_list = out.split(" ")
        pull_timeout = self._pulls_max_times*CONF.sync_power_state_interval
        min_time = self._pulls_min_times*CONF.sync_power_state_interval
        try:
            if ( (uptime_list[0]) and
                        (round(float(uptime_list[0])) >= pull_timeout) ):
                LOG.debug("Pull instances timeout")
                return
            elif ( (uptime_list[0]) and
                       (round(float(uptime_list[0])) <= min_time) ):
                LOG.debug("Pull instances in reserve time")
                return
        except Exception:
            return

        if self._pulls_current_times == 0:
            LOG.debug("Start periodic task for pull instances.")
        if self._pulls_current_times >= self._pulls_max_times:
            return

        filters = {'vm_state': vm_states.ERROR,
                   'power_state': power_state.SHUTDOWN,
                   'task_state': None,
                   'host': self.host}
        target_insts = objects.InstanceList.get_by_filters(context,
                           filters, expected_attrs=[], use_slave=True)

        def _pull(instance):
            try:
                instance.task_state = task_states.REBOOTING_HARD
                instance.save(expected_task_state=[None, task_states.REBOOTING,
                                           task_states.REBOOT_PENDING,
                                           task_states.REBOOT_STARTED])
                self._reboot_instance(context, instance)
            except Exception:
                LOG.exception(_LE("Pull task had an error while hard-reboot."),
                                   instance=instance)
            finally:
                self._pulls_in_progress.pop(instance.uuid)

        for instance in target_insts:
            block_device_info = self._get_instance_block_device_info(context,
                                                                     instance,
                                                                     bdms=None)
            if not block_device_info['block_device_mapping']:
                LOG.debug('Instance has no volume',
                          instance=instance)
                continue

            sign = self.get_ha_info_from_metadata(instance)
            if (sign != -1):
                LOG.debug('Instance HA enable, Skip',
                          instance=instance)
                continue

            uuid = instance.uuid
            if uuid in self._pulls_in_progress:
                LOG.debug('Pull already in progress for %s' % uuid)
            else:
                LOG.debug('Triggering Pull for uuid %s' % uuid)
                self._pulls_in_progress[uuid] = True
                self._pulls_pool.spawn_n(_pull, instance)

        self._pulls_current_times = self._pulls_current_times + 1
        if self._pulls_current_times == self._pulls_max_times:
            LOG.debug("Periodic task for pull instances is finished.")

    @periodic_task.periodic_task
    def _cycle_change_vnc_passwd(self, context):
        """change the vnc password when it is expired"""
        if not self.driver.capabilities.get("supports_vnc_passwd", False):
            return
        self.driver.cycle_change_vnc_passwd()

    @hooks.add_hook("compute_manager_init_host_hook")
    def init_host(self):
        self.driver.init_host(host=self.host)
        context = nova.context.get_admin_context()
        instances = objects.InstanceList.get_by_host(
            context, self.host, expected_attrs=['info_cache'])

        if CONF.defer_iptables_apply:
            self.driver.filter_defer_apply_on()

        self.init_virt_events()

        self.init_virt_resource_tracker()
        try:
            # checking that instance was not already evacuated to other host
            self._destroy_evacuated_instances(context)
            for instance in instances:
                self._init_instance(context, instance)
        finally:
            if CONF.defer_iptables_apply:
                self.driver.filter_defer_apply_off()

    # wrap error decorator
    @wrap_instance_error
    @wrap_instance_fault
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
            # NOTE() compute stopped before instance was fully
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
            # NOTE() compute stopped before instance was fully
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
                # FIXME(): This needs fixed. We should be creating
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
        current_power_state = self._get_power_state(context, instance)

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
                # NOTE(): check old_vm_state for STOPPED here, if it's
                # not in system_metadata we default to True for backwards
                # compatibility
                power_on = (instance.system_metadata.get('old_vm_state') !=
                            vm_states.STOPPED)

                block_dev_info = self._get_instance_block_device_info(
                    self.get_admin_context(), instance, refresh_conn_info=True)

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
        drv_state = self._get_power_state(context, instance)
        expect_running = (db_state == power_state.RUNNING and
                          drv_state != db_state)

        LOG.debug('Current state is %(drv_state)s, state in DB is '
                  '%(db_state)s.',
                  {'drv_state': drv_state, 'db_state': db_state},
                  instance=instance)

        if expect_running and CONF.resume_guests_state_on_host_boot:
            LOG.info(_('Rebooting instance after nova-compute restart.'),
                     instance=instance)

            block_device_info = \
                self._get_instance_block_device_info(context, instance)

            try:
                self.driver.resume_state_on_host_boot(
                    context, instance, net_info, block_device_info)

                # VM may stuck in rebooting_hard state, should clean it in
                # product env, if there still has a hard reboot message in
                # message queue, it will fail, but acceptable.
                if instance.task_state == task_states.REBOOTING_HARD:
                    LOG.debug('resume ok, clean rebooting_hard task state, '
                              'instance: %s', instance.uuid)
                    instance.task_state = None
                    instance.save()

            except NotImplementedError:
                LOG.warning(_('Hypervisor driver does not support '
                              'resume guests'), instance=instance)
            except Exception as ex:
                # NOTE(): The instance failed to resume, so we set the
                #             instance to error and attempt to continue.
                LOG.exception(_('Failed to resume instance, the details is: '
                                '%s'), ex.message, instance=instance)
                self._set_instance_error_state(context, instance)

        elif drv_state == power_state.RUNNING:
            # VMwareAPI drivers will raise an exception
            try:
                self.driver.ensure_filtering_rules_for_instance(
                    instance, net_info)
            except NotImplementedError:
                LOG.warning(_('Hypervisor driver does not support '
                              'firewall rules'), instance=instance)

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

        instance.vm_state = vm_states.ACTIVE
        instance.task_state = None
        sys_meta = instance.system_metadata
        sys_meta.pop('new_numa_topo', None)
        sys_meta.pop('new_bind_info', None)
        instance.system_metadata = sys_meta
        instance.save(expected_task_state=[task_states.MIGRATING, None])
        try:
            # NOTE(): setup networks on source host (really it's re-setup)
            self.network_api.setup_networks_on_host(context, instance,
                                                    self.host)

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
        except:
            LOG.exception("Failed to roll back instance")
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
        '''
        Init_instance has same problem, might change when it's solved
        '''
        context = nova.context.get_admin_context()
        # Get the roles and token to call the cinder and nova api.
        context.roles = self.get_admin_roles()
        context.auth_token = self.get_admin_token()
        context.user_name = self.user_name
        context.project_id = self.tenant_id
        return context

    def handle_lifecycle_event(self, event):
        """
        Where the local_resume_instance is True, 
        call the _sync_instance_power_state with detail
        """
        if not CONF.local_resume_instance:
            return super(HuaweiComputeManager, self).handle_lifecycle_event(event)

        LOG.info(_("Lifecycle event %(state)d with detail %(detail)d on VM %(uuid)s") %
                  {'state': event.get_transition(),
                   'detail': event.get_detail(),
                   'uuid': event.get_instance_uuid()})
        context = nova.context.get_admin_context()
        # Get the roles and token to call the cinder and nova api.
        context.roles = self.get_admin_roles()
        context.auth_token = self.get_admin_token()
        context.user_name = self.user_name
        context.project_id = self.tenant_id
        instance = instance_obj.Instance.get_by_uuid(
            context, event.get_instance_uuid())
        vm_power_state = None
        if event.get_transition() == virtevent.EVENT_LIFECYCLE_STOPPED:
            vm_power_state = power_state.SHUTDOWN
        elif event.get_transition() == virtevent.EVENT_LIFECYCLE_STARTED:
            vm_power_state = power_state.RUNNING
        elif event.get_transition() == virtevent.EVENT_LIFECYCLE_PAUSED:
            vm_power_state = power_state.PAUSED
        elif event.get_transition() == virtevent.EVENT_LIFECYCLE_RESUMED:
            vm_power_state = power_state.RUNNING
        else:
            LOG.warning(_("Unexpected power state %d") %
                        event.get_transition())

        if vm_power_state is not None:
            self._sync_instance_power_state(context,
                                            instance,
                                            vm_power_state, 
                                            event)

    def handle_events(self, event):
        """
        Where the local_resume_instance is True,
        the event object file type is Extend_LifecycleEvent
        """
        if not CONF.local_resume_instance:
            return super(HuaweiComputeManager, self).handle_events(event)

        if isinstance(event, extend_virtevent.Extend_LifecycleEvent):
            try:
                self.handle_lifecycle_event(event)
            except exception.InstanceNotFound:
                LOG.debug("Event %s arrived for non-existent instance. The"
                          "instance was probably deleted.", event)
        else:
            LOG.debug("Ignoring event %s", event)

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
            vm_instance = self.driver.get_info(db_instance)
            vm_power_state = vm_instance['state']
            LOG.info("Get the vm power stat.id: %s, state: %s" % (db_instance['uuid'], vm_power_state))
        except Exception as e:
            LOG.info("Get the vm stat failed. id: %s, error: %s" % (db_instance['uuid'], e))

        if vm_power_state != db_power_state:
            # power_state is always updated from hypervisor to db
            db_instance.power_state = vm_power_state
            db_instance.save()
            db_power_state = vm_power_state
        # Use count, sync process will wait till event's progress is finished
        state_info = self._sync_state_counts.get(db_instance['uuid'], {})
        if event is None:
            if state_info and state_info['vm_state'] == vm_power_state \
                    and state_info['db_state'] == vm_state:
                state_info['count'] = state_info.get('count', 0) + 1
            else:
                state_info = {"vm_state": vm_power_state,
                              "db_state": vm_state,
                              "count": 1}
            self._sync_state_counts[db_instance['uuid']] = state_info
            # only when state is diff for a long time, 3min for example
            if state_info['count'] < CONF.sync_state_count:
                LOG.info("instance %s with power state %s and state %s"
                         " will not process in %ind count"
                         % (db_instance['uuid'], vm_power_state,
                            vm_state, state_info['count']))
                return
            else:
                state_info = {"db_state": vm_power_state,
                              "vm_state": vm_state,
                              "count": 0}
                self._sync_state_counts[db_instance['uuid']] = state_info

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
            if event and str(event.get_detail()) == "0" and \
                    event.get_transition() == virtevent.EVENT_LIFECYCLE_STOPPED and \
                    vm_power_state == power_state.SHUTDOWN:
                LOG.info("vm %s have been stopped"
                         " by user manually." % (db_instance['uuid']))
                self.compute_api.stop(context, db_instance)
            # The only rational power state should be RUNNING
            elif vm_power_state == power_state.SHUTDOWN:
                LOG.warn(_("Instance shutdown by itself. Trying to  "
                           "power_on it"), instance=db_instance)
                try:
                    self._power_on(context, db_instance)
                except Exception:
                    # Note: there is no need to propagate the error
                    # because the same power_state will be retrieved next
                    # time and retried.
                    # For example, there might be another task scheduled.
                    LOG.exception(_("error during power_on() in "
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

                try:
                    # get network info
                    net_info = compute_utils.get_nw_info_for_instance(db_instance)
                    try:
                        self.driver.plug_vifs(db_instance, net_info)
                    except NotImplementedError as e:
                        LOG.debug(e, instance=db_instance)

                    if vm_power_state == power_state.NOSTATE:
                        # connection_info might terminate already
                        block_device_info = \
                            self._get_instance_block_device_info(
                                self.get_admin_context(), db_instance,
                                refresh_conn_info=True)
                    else:
                        # get block_device_info
                        block_device_info = \
                            self._get_instance_block_device_info(
                                context, db_instance)

                    self.driver.resume_state_on_host_boot(context, 
                                                          db_instance,
                                                          net_info, 
                                                          block_device_info)
                except Exception:
                    LOG.exception(_("error during resume_state_on_host_boot() in "
                                    "sync_power_state. Expected to active."),
                                  instance=db_instance)

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
                try:
                    # get network info
                    net_info = compute_utils.get_nw_info_for_instance(db_instance)
                    try:
                        self.driver.plug_vifs(db_instance, net_info)
                    except NotImplementedError as e:
                        LOG.debug(e, instance=db_instance)

                    if vm_power_state == power_state.NOSTATE:
                        # connection_info might terminate already
                        block_device_info = \
                            self._get_instance_block_device_info(
                                self.get_admin_context(), db_instance,
                                refresh_conn_info=True)
                    else:
                        # get block_device_info
                        block_device_info = \
                            self._get_instance_block_device_info(
                                context, db_instance)

                    self.driver.resume_state_on_host_boot(context, 
                                                          db_instance,
                                                          net_info, 
                                                          block_device_info)
                except Exception:
                    LOG.exception(_("error during resume_state_on_host_boot() in "
                                    "sync_power_state. Expected to shutoff."),
                                  instance=db_instance)

        elif vm_state in (vm_states.SOFT_DELETED,
                          vm_states.DELETED):
            if vm_power_state not in (power_state.NOSTATE,
                                      power_state.SHUTDOWN):
                # Note: this should be taken care of periodically in
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
        # not sure delete later or earlier than rebuild
        # get PCI devices from memory
        # write to nw_info
        try:
            network_info = self._get_instance_nw_info(context, instance)
            # old pci requests migth not exists
            rt = self._get_resource_tracker(self.host)
            nw_pci_info = rt.get_nw_pci_slot_info(context, instance,
                                                  is_new=False)
            # if devices has already been freed, set a default value to vif
            # then will do nothing in unplug
            network_info = self._update_pci_slot2nw_info(context, nw_pci_info,
                                                         network_info)
        except (exception.NetworkNotFound, exception.NoMoreFixedIps):
            network_info = network_model.NetworkInfo()

        # NOTE() get bdms before destroying the instance
        vol_bdms = [bdm for bdm in bdms if bdm.is_volume]
        bdi = self._get_instance_block_device_info(
            context, instance, bdms=bdms)

        try:
            self.driver.destroy(context, instance, network_info,
                                block_device_info=bdi)
            self.driver.delete_instance_files(instance, force_delete=True)
        except Exception:
            with excutils.save_and_reraise_exception():
                pass

        for bdm in vol_bdms:
            try:
                # NOTE(): actual driver detach done in driver.destroy, so
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
        # TODO
        rt = self._get_resource_tracker(self.host)
        rt.free_pci_dev(context, instance, is_new=False)

    @wrap_exception()
    @reverts_task_state
    @wrap_instance_fault
    def reschedule_instance(self, context, instance,
                            orig_image_ref, image_ref,
                            injected_files, new_pass,
                            host, orig_sys_metadata=None,
                            bdms=None, recreate=False,
                            on_shared_storage=False,
                            filter_properties={}):
        # NOTE: reschedule is a long process, like build_and_run_instance, so
        # we use spawn_n too
        utils.spawn_n(self._reschedule_instance, context, instance,
                      orig_image_ref, image_ref,
                      injected_files, new_pass,
                      host, orig_sys_metadata=orig_sys_metadata,
                      bdms=bdms, recreate=recreate,
                      on_shared_storage=on_shared_storage,
                      filter_properties=filter_properties)

    @wrap_exception()
    @reverts_task_state
    @wrap_instance_event
    @wrap_instance_fault
    def _reschedule_instance(self, context, instance,
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

        # use for delete local instance on original host
        copyed_instance = copy.deepcopy(instance)

        try:
            limits = filter_properties.get('limits', {})
            rt = self._get_resource_tracker(host)
            # rewrite claim
            with rt.rebuild_claim(context, instance, limits):
                # when instance's host changed success, delete instance on
                # original host
                self.compute_rpcapi.delete_localinstance(
                    context, instance=copyed_instance,
                    bdms=bdms, host=copyed_instance['host'])

                self._validate_instance_group_policy(context, instance,
                                                     filter_properties)
                LOG.audit(_('rebuilding'), context=context, instance=instance)
                LOG.info(_("reschedule instance  %s will begin after %d"
                           "seconds" % (instance['uuid'],
                                        CONF.reschedule_delay_rebuild_time)))
                greenthread.sleep(CONF.reschedule_delay_rebuild_time)
                # TODO
                rt.free_pci_request(context, instance, is_new=False)

                network_info = compute_utils.get_nw_info_for_instance(instance)
                nw_pci_info = rt.get_nw_pci_slot_info(context, instance,
                                                      is_new=False)
                network_info = self._update_pci_slot2nw_info(context,
                                                             nw_pci_info,
                                                             network_info)

                self.network_api.update_port_profile(context, instance,
                                                     network_info)
                info_cache = instance.info_cache
                info_cache.network_info = network_info
                instance.info_cache = info_cache
                instance.save()
                self.rebuild_instance(context, instance, orig_image_ref,
                                      image_ref, injected_files, new_pass,
                                      orig_sys_metadata, bdms, recreate,
                                      on_shared_storage)
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
            instance.refresh(context)
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
        elevated = context.elevated()
        obj = getfun(elevated, instance['uuid'])
        if obj:
            LOG.info(_("Find instance in live-migrating, delete record."))
            obj.destroy(elevated)

    def get_pci_slots(self, instance):
        return self.driver.get_pci_slots_from_xml(instance)

    @object_compat
    @wrap_exception()
    @reverts_task_state
    @wrap_instance_fault
    def attach_interface(self, context, instance, network_id, port_id,
                         requested_ip):
        """Use hotplug to add an network adapter to an instance."""

        @utils.synchronized(instance.uuid)
        def do_attach_interface(context, instance, network_id, port_id,
                         requested_ip):

            if port_id:
                self.network_api.check_port_usable(context, instance, port_id)

            pci_list = self.get_pci_slots(instance)
            LOG.debug(_("PCI list:%s" % pci_list))

            if not network_id and not port_id:
                nets = self.network_api._get_available_networks(context,
                                                            context.project_id)
                if len(nets) > 1:
                    msg = _("Multiple possible networks found, use a Network "
                            "ID to be more specific.")
                    raise exception.NetworkAmbiguous(msg)


            requested_networks = objects.NetworkRequestList(
                objects=[objects.NetworkRequest(network_id=network_id,
                                                address=requested_ip,
                                                port_id=port_id,
                                                pci_request_id=None)])

            pci_requests = objects.InstancePCIRequests.get_by_instance_uuid(
                context, instance.uuid)
            pre_pcis = len(pci_requests.requests)
            self.network_api.create_pci_requests_for_sriov_ports(
                context, pci_requests, requested_networks)
            post_pcis = len(pci_requests.requests)
            if pre_pcis < post_pcis:
                self._update_pci_usage_for_attach(context, pci_requests,
                                                  instance,
                                                  post_pcis - pre_pcis)
            network_info = None
            try:
                network_info = self.network_api.allocate_for_instance(
                    context, instance, requested_networks=requested_networks,
                    pci_list=pci_list)

                if len(network_info) != 1:
                    LOG.error(_('allocate_port_for_instance returned %(ports)s ports')
                              % dict(ports=len(network_info)))
                    raise exception.InterfaceAttachFailed(
                        instance_uuid=instance.uuid)
                image_ref = instance.get('image_ref')
                image_meta = compute_utils.get_image_metadata(
                    context, self.image_api, image_ref, instance)

                self.driver.attach_interface(instance, image_meta, network_info[0])

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
            except Exception:
                LOG.error("except: %s" % str(traceback.format_exc()))
                self.network_api.deallocate_ports_for_instance(context, instance, network_info, requested_networks)
                raise exception.InterfaceAttachFailed(instance_uuid=instance.uuid)

        return do_attach_interface(context, instance, network_id,
                                   port_id,requested_ip)

    @utils.synchronized(resource_tracker.COMPUTE_RESOURCE_SEMAPHORE)
    def _update_pci_usage_for_attach(self, context, pci_requests,
                                     instance, pcis):
        rt = self._get_resource_tracker(instance.get('node'))
        new_pci_request = pci_requests.requests[-pcis:]
        if rt.pci_tracker:
            devs = rt.pci_tracker.stats.consume_requests(new_pci_request)
            if not devs:
                raise exception.PciDeviceRequestFailed(pci_requests)
            for dev in devs:
                pci_device.claim(dev, instance)
            rt.pci_tracker._allocate_instance(instance, devs)
            if instance.uuid not in rt.pci_tracker.allocations:
                rt.pci_tracker.allocations[instance.uuid] = []
            rt.pci_tracker.allocations[instance.uuid].extend(devs)
            rt.pci_tracker.save(context)
        else:
            raise exception.PciDeviceRequestFailed(pci_requests)
        pci_requests.save(context)

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

        self.network_api.deallocate_port_for_instance(context, instance,
            port_id)
        self.driver.detach_interface(instance, condemned)
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
                    if network_info[2] == port_id:
                        networks_info.remove(network_info)
                        port_removed = True
                        LOG.info(_("Removed request_network port: %s"),
                                 network_info[2])
                        break
            if not port_removed:
                for network_info in networks_info:
                    if network_info[0] == network_id:
                        networks_info.remove(network_info)
                        LOG.info(_("Removed request_network net_id: %s"),
                                 network_info[0])
                        break
            LOG.debug(_("detach db_req_networks after: %s"), networks_info)
            HuaweiInstanceExtra(instance_uuid=instance.uuid,
                request_network = jsonutils.dumps(networks_info)).create(context)
        self._update_pci_usage_for_detach(context, instance, port_id)

    @utils.synchronized(resource_tracker.COMPUTE_RESOURCE_SEMAPHORE)
    def _update_pci_usage_for_detach(self, context, instance, port_id):
        network_info = instance.info_cache.network_info
        vif_to_detach = None
        for vif in network_info:
            if port_id == vif['id']:
                vif_to_detach = vif
                break
        if not vif_to_detach:
            LOG.error(_LE('Cannot found port with id:%s to detach'), port_id)
        if vif_to_detach['vnic_type'] in ( 'vhostuser', 'normal'):
            LOG.debug('Detaching %s type vif, don\'t need to update pci'
                      ' usage.' % vif_to_detach['vnic_type'])
            return
        pci_slot = vif_to_detach['profile'].get('pci_slot')
        rt = self._get_resource_tracker(instance.get('node'))
        inst_pci_devs = rt.pci_tracker.allocations[instance.uuid]
        dev_to_free = None
        for dev in inst_pci_devs:
            if pci_slot == dev.address:
                dev_to_free=dev
                break
        if dev_to_free:
            rt.pci_tracker.free_detached_device(dev_to_free,instance)
        rt.pci_tracker.save(context)

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

    @periodic_task.periodic_task
    def _auto_update_vm_tools_of_instances(self, context):
        exec_file = '/var/run/upgraded_manage'

        if os.path.exists(exec_file):
            utils.execute('chmod', '766', exec_file, run_as_root=True)

        try:
            self._auto_update_vm_tools_of_instances_task(context)
        finally:
            if os.path.exists(exec_file):
                utils.execute('chmod', '750', exec_file, run_as_root=True)

    def _auto_update_vm_tools_of_instances_task(self, context):
        # request uvp and return, also print logs
        def wrap_uvp_request(instance=None):
            def _wrap_uvp_request(func):
                def __wrap_uvp_request(*args, **kvargs):
                    conn = None
                    try:
                        conn = libuvp_compute.openV2(UVP_VMTOOLS_PROGRAMID)
                    except libuvp_compute.libuvpintfError:
                        LOG.warning("uvpConnectOpen() failed."
                                    "Please check "
                                    "/etc/init.d/vmtools-upgd status")
                        return None
                    try:
                        return func(conn, *args, **kvargs)
                    except libuvp_compute.libuvpintfError:
                        if instance:
                            vm_state = instance.get("vm_state", None)
                            if vm_state == "active":
                                LOG.warning("Instance (%(uuid)s) didnot "
                                            "accept message of vmtools.",
                                            {"uuid": instance['uuid']},
                                            instance=instance)
                            else:
                                LOG.info("Instance (%(uuid)s) with stat"
                                         " (%(vm_state)s) didnot accept "
                                         "message from vmtools .",
                                         {"uuid": instance['uuid'],
                                          "vm_state": vm_state},
                                         instance=instance)
                        else:
                            LOG.warning("Host (%(host)s) didnot "
                                        "accept message of vmtools.",
                                        {"host": self.host})
                        return None
                    finally:
                        if conn:
                            conn.close()
                return __wrap_uvp_request
            return _wrap_uvp_request

        def _parse_uvp_result(uvp_result, expect_size=None, msg_type="Normal"):
            if uvp_result is None:
                return None
            if msg_type == "Normal":
                try:
                    result = uvp_result.split("}")[0].split("{")[1].split(",")
                except:
                    LOG.error(uvp_result)
                    result = []
                if expect_size is not None and len(result) != expect_size:
                    LOG.warning("Message: \"(%(result)s) \""
                                "format wrong.",
                                {"result": uvp_result})
                    return None
                return result
            return uvp_result
        # These 3 API are in class uvpConnectV2
        _upgGetUpgradeResult = getattr(libuvp_compute.uvpConnectV2,
                                       "upgGetUpgradeResult")
        _upgCtrlAutoUpgrade = getattr(libuvp_compute.uvpConnectV2,
                                      "upgCtrlAutoUpgrade")
        _upgChannelControl = getattr(libuvp_compute.uvpConnectV2,
                                     "upgChannelControl")

        def _check_vmtools_installed(instance, instance_name):
            conn = None
            try:
                conn = libuvp_compute.open()
                conn.getInBandInfo(instance_name, None)
                return True
            except:
                errNo = libuvp_compute.uvpGetLastError()
                LOG.info("Instance failted to getinfo with err %s", errNo,
                         instance=instance)
                if errNo == 21:
                    return False
            finally:
                if conn is not None:
                    conn.close()

        LOG.info("Upgrade vmtools on host (%(host)s)", {'host': self.host})
        filters = {'host': self.host, 'deleted': False}
        instances = instance_obj.InstanceList.get_by_filters(
            context, filters, expected_attrs=["metadata"])
        LOG.debug("GET (%(num)s) instances in host (%(host_name)s).",
                  {"num": len(instances),
                   "host_name": self.host})
        for instance in instances:
            instance_name = instance['name']
            metadata = instance['metadata']
            if instance['task_state'] is not None:
                LOG.info("Instance with task_state %s will skip.",
                         instance['task_state'], instance=instance)
                continue
            if not _check_vmtools_installed(instance, instance_name):
                continue
            _func_get_upgrade_pro = wrap_uvp_request(instance)(
                _upgGetUpgradeResult)

            # uvp_result:instance-00000008:{vmtools,1.3.1.13,2,1.3.1.14}
            uvp_result = _func_get_upgrade_pro(instance_name, "vmtools")
            vm_info_list = _parse_uvp_result(uvp_result, expect_size=4)
            if vm_info_list is None:
                continue
            vm_info = {
                "vt_current_version": vm_info_list[1],
                "vt_upgrade_stat": vm_info_list[2],
                "vt_target_version": vm_info_list[3]
            }
            # When updating version is meaningless
            if vm_info_list[2] == "15":
                vm_info.pop("vt_current_version", None)
                vm_info.pop("vt_target_version", None)

            metachange = {}
            for key, value in vm_info.iteritems():
                if key not in metadata or metadata[key] != value:
                    metachange[key] = [metadata.get(key, "None"), value]
                    metadata[key] = value

            # init upgrade tag, only 2 or 3 is acceptable
            if "vt_upgrade_tag" not in metadata:
                # get update tag from uvp
                _func_set_upgrade_tag = wrap_uvp_request(instance)(
                    _upgCtrlAutoUpgrade)
                # uvp_result:instance-00000008:{2}
                uvp_result = _func_set_upgrade_tag(
                    instance_name, UVP_VMTOOLS_FLAGTYPE["DEFAULT"])
                vt_upgrade_result = _parse_uvp_result(uvp_result,
                                                      expect_size=1)
                if vt_upgrade_result is None:
                    continue
                vt_upgrade_tag = UVP_VMTOOLS_STATECODE.get(
                    vt_upgrade_result[0], {"MSG": "Unknown message."})

                if "DB" in vt_upgrade_tag:
                    metadata["vt_upgrade_tag"] = vt_upgrade_tag["DB"]
                    metachange["vt_upgrade_tag"] = [
                        "None", vt_upgrade_tag["DB"]]
                    LOG.info(
                        "Init vmtools upgrade tag (%(message)s).",
                        instance=instance)
                else:
                    LOG.info(
                        "Get vmtools upgrade stats error: (%(error)s)",
                        {"error": vt_upgrade_tag["MSG"]},
                        instance=instance)
            # only save when metadata changed
            if metachange:
                instance.save(context)
                LOG.info("Instance metadata has changed: "
                         "(%(changed_info)s)",
                         {"changed_info": ', '.join("%s from %r to %r" % (
                             key, val[0], val[1])for (
                                 key, val) in metachange.iteritems())},
                         instance=instance)
            greenthread.sleep(0)

        # set upgrade stat to vm
        for instance in instances:
            instance_name = instance['name']
            metadata = instance['metadata']
            if "vt_upgrade_tag" not in metadata:
                continue
            _func_set_upgrade_tag = wrap_uvp_request(instance)(
                _upgCtrlAutoUpgrade)
            flagType = UVP_VMTOOLS_FLAGTYPE[metadata['vt_upgrade_tag']]
            # uvp_result:instance-00000008:{0}
            uvp_result = _func_set_upgrade_tag(instance_name, flagType)
            vt_upgrade_result = _parse_uvp_result(uvp_result,
                                                  expect_size=1)
            if vt_upgrade_result is None:
                continue
            if vt_upgrade_result[0] == UVP_VMTOOLS_SUCCESS:
                LOG.info("Successfuly set vmtools autoupgrade flag.",
                         instance=instance)
            else:
                LOG.warning("Failed to set vmtools autoupgrade flag.",
                            instance=instance)
            greenthread.sleep(0)
        if filter(lambda i:
                  i.get("metadata", {}).get("vt_upgrade_tag", "0") == "1" and
                  i.get("metadata", {}).get("vt_upgrade_stat", "0") != "1",
                  instances):
            func_trigger_upgrade = wrap_uvp_request()(_upgChannelControl)
            func_trigger_upgrade(1, 0, "no")

    @wrap_exception()
    @reverts_task_state
    @wrap_instance_fault
    def build_and_run_instance(self, context, instance, image, request_spec,
                     filter_properties, admin_password=None,
                     injected_files=None, requested_networks=None,
                     security_groups=None, block_device_mapping=None,
                     node=None, limits=None):

        # NOTE(): Remove this in v4.0 of the RPC API
        if (requested_networks and
                not isinstance(requested_networks,
                               objects.NetworkRequestList)):
            requested_networks = objects.NetworkRequestList(
                objects=[objects.NetworkRequest.from_tuple(t)
                         for t in requested_networks])

        @utils.synchronized(instance.uuid)
        def _locked_do_build_and_run_instance(*args, **kwargs):
            self._do_build_and_run_instance(*args, **kwargs)

        # NOTE(): We spawn here to return the RPC worker thread back to
        # the pool. Since what follows could take a really long time, we don't
        # want to tie up RPC workers.
        utils.spawn_n(_locked_do_build_and_run_instance,
                      context, instance, image, request_spec,
                      filter_properties, admin_password, injected_files,
                      requested_networks, security_groups,
                      block_device_mapping, node, limits)

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
                compute_utils.add_instance_fault_from_exc(context,
                        instance, e, sys.exc_info())
                self._set_instance_error_state(context, instance)
                return
            retry['exc'] = traceback.format_exception(*sys.exc_info())
            # NOTE(): Deallocate networks if the driver wants
            # us to do so.
            if self.driver.deallocate_networks_on_reschedule(instance):
                self._cleanup_allocated_networks(context, instance,
                        requested_networks)
            else:
                # NOTE(): Network already allocated and we don't
                # want to deallocate them before rescheduling. But we need
                # cleanup those network resource setup on this host before
                # rescheduling.
                self.network_api.cleanup_instance_network_on_host(
                    context, instance, self.host)

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
        except exception.BuildAbortException as e:
            LOG.exception(e.format_message(), instance=instance)
            self._cleanup_allocated_networks(context, instance,
                    requested_networks)
            compute_utils.add_instance_fault_from_exc(context, instance,
                    e, sys.exc_info())
            self._set_instance_error_state(context, instance)
        except Exception as e:
            # Should not reach here.
            msg = _LE('Unexpected build failure, not rescheduling build.')
            LOG.exception(msg, instance=instance)
            self._cleanup_allocated_networks(context, instance,
                    requested_networks)
            compute_utils.add_instance_fault_from_exc(context, instance,
                    e, sys.exc_info())
            self._set_instance_error_state(context, instance)

    @periodic_task.periodic_task(spacing=CONF.emulatorpin_update_interval)
    def _run_emulatorpin_update(self, context):
        if not self.driver.capabilities.get("supports_emulatorpin_update", False):
            return
        if CONF.emulatorpin_update_interval < 1:
            return
        instance_extra_db_obj = HuaweiInstanceExtra()
        instance_extras = instance_extra_db_obj.get_by_host(context,
                                                                self.host)
        if instance_extras:
            for extra in instance_extras:
                scheduler_hints = jsonutils.loads(
                    extra.scheduler_hints or '{}')

                if scheduler_hints.get('hyperThreadAffinity',
                                       'any') == 'lock':
                    request_network = jsonutils.loads(
                        extra.request_network or '[]')
                    # str to list
                    if request_network:
                        is_sriov = False
                        for net in request_network:
                            port_id = net[2]
                            if port_id:
                                port_type = self.network_api.get_port_type(context,
                                    port_id)
                                if network_model.VNIC_TYPE_DIRECT == port_type:
                                    is_sriov = True
                                    break

                        if not is_sriov:
                            break

                        inst_core_binds = jsonutils.loads(
                            extra.core_bind or '[]')
                        # example : [{"vcpu": 0, "pcpus": [15]}, {"vcpu": 1, "pcpus": [7]}]
                        pcpus = [core_bind['pcpus'] for core_bind in
                                 inst_core_binds]
                        pcpus = sum(pcpus, [])
                        instance = objects.Instance.get_by_uuid(context,
                                               extra['instance_uuid'])
                        self.driver.update_emulatorpin(instance, pcpus)

    @roll_back_migration
    def _finish_resize(self, context, instance, migration, disk_info,
                       image):
        self._instance_update(context, instance['uuid'])
        resize_instance = False
        old_instance_type_id = migration['old_instance_type_id']
        new_instance_type_id = migration['new_instance_type_id']
        old_instance_type = flavors.extract_flavor(instance)
        instance.refresh(context)
        sys_meta = instance.system_metadata
        # NOTE(): Get the old_vm_state so we know if we should
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

        # NOTE(): setup networks on destination host
        self.network_api.setup_networks_on_host(context, instance,
                                                migration['dest_compute'])

        instance_p = obj_base.obj_to_primitive(instance)
        migration_p = obj_base.obj_to_primitive(migration)
        rt = self._get_resource_tracker(migration['dest_node'])
        nw_pci_info = rt.get_nw_pci_slot_info(context, instance,
                                              is_new=True)
        network_info = self._get_instance_nw_info(context, instance)
        network_info = self._update_pci_slot2nw_info(context, nw_pci_info,
                                                     network_info)
        # update nw_info info
        self.network_api.update_port_profile(context, instance, network_info)
        instance_info_cache = instance.info_cache
        instance_info_cache.network_info = network_info
        instance.info_cache = instance_info_cache

        self.network_api.migrate_instance_finish(context,
                                                 instance_p,
                                                 migration_p)
        instance.task_state = task_states.RESIZE_FINISH

        instance.save(expected_task_state=task_states.RESIZE_MIGRATED)

        self._notify_about_instance_usage(
            context, instance, "finish_resize.start",
            network_info=network_info)

        block_device_info = self._get_instance_block_device_info(
                            context, instance, refresh_conn_info=True)

        # NOTE(): If the original vm_state was STOPPED, we don't
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
                    self._save_instance_info(instance,
                                             old_instance_type, sys_meta)

        # allocate pci devices
        rt._finish_resize_pci(context, instance)

        migration.status = 'finished'
        migration.save(context.elevated())

        instance.vm_state = vm_states.RESIZED
        instance.task_state = None
        instance.launched_at = timeutils.utcnow()
        instance.save(expected_task_state=task_states.RESIZE_FINISH)

        self._notify_about_instance_usage(
            context, instance, "finish_resize.end",
            network_info=network_info)

    @roll_back_migration
    def _confirm_resize(self, context, instance, quotas,
                        migration=None):
        """Destroys the source instance."""
        self._notify_about_instance_usage(context, instance,
                                          "resize.confirm.start")

        with self._error_out_instance_on_exception(context, instance,
                                                   quotas=quotas):
            # NOTE(): delete stashed migration information
            instance.refresh(context)
            sys_meta, instance_type, old_instance_type = (
                self._cleanup_stored_instance_types(migration, instance))


            # NOTE(): tear down networks on source host
            self.network_api.setup_networks_on_host(context, instance,
                               migration.source_compute, teardown=True)

            network_info = self._get_instance_nw_info(context, instance)
            old_network_info = copy.deepcopy(network_info)

            rt = self._get_resource_tracker(migration.source_node)
            nw_pci_info = rt.get_nw_pci_slot_info(context, instance,
                                                  is_new=False)
            old_network_info = self._update_pci_slot2nw_info(
                context, nw_pci_info, old_network_info)
            self.driver.confirm_migration(migration, instance,
                                          old_network_info)

            migration.status = 'confirmed'
            migration.save(context.elevated())

            # TODO remove or clear code
            rt.drop_resize_claim(context, instance, old_instance_type)
            # after _update_available_resource, instance uuid puts into
            # tracked_instances but not into tracked_migrations
            # so need to free here
            rt.drop_resize_from_instance(context, instance, migration)

            # NOTE(): The old_vm_state could be STOPPED but the user
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
            # delete template data only
            sys_meta.pop('old_vm_state', None)
            sys_meta.pop('old_numa_topo', None)
            sys_meta.pop('old_bind_info', None)
            sys_meta.pop('new_numa_topo', None)
            sys_meta.pop('new_bind_info', None)
            instance.system_metadata = sys_meta

            instance.vm_state = vm_state
            instance.task_state = None
            instance.save(expected_task_state=[None, task_states.DELETING])
            self._notify_about_instance_usage(
                context, instance, "resize.confirm.end",
                network_info=network_info)

            quotas.commit()

    def _update_nw_for_confirm_resize(self, instance, network_info):
        rt = self._get_resource_tracker(self.host)
        allocations = rt.pci_tracker.allocations[instance.uuid]

        old_pci_devs = [dev for dev in allocations if filter(
            lambda vif: vif['profile'].get('pci_slot') !=
                        dev.address, network_info)]
        old_network_info = copy.deepcopy(network_info)
        for dev, vif in itertools.product(old_pci_devs, old_network_info):
            pool = rt.pci_tracker.pci_stats._create_pool_keys_from_dev(
                dev)
            if not pool or 'physical_network' not in pool:
                LOG.warning(_("Cannot get pool for dev: %s or device "
                              "haven't physical_network"), dev)
                continue
            if (pool['physical_network'] == vif['profile'].get(
                    'physical_network')):
                vif['profile']['pci_slot'] = dev.address
                vif['meta']['pci_slotnum'] = int(dev.address[5:7])
        return old_network_info

    @wrap_exception()
    @reverts_task_state
    @wrap_instance_event
    @wrap_instance_fault
    @roll_back_migration
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
            instance.refresh(context)
            self.network_api.setup_instance_network_on_host(context,
                                                            instance,
                                                            self.host)
            network_info = self._get_instance_nw_info(context, instance)

            self._notify_about_instance_usage(
                    context, instance, "resize.revert.start")

            sys_meta, instance_type, drop_instance_type = (
                self._cleanup_stored_instance_types(migration, instance, True))

            # NOTE(): delete stashed old_vm_state information; we
            # default to ACTIVE for backwards compatibility if old_vm_state
            # is not set
            old_vm_state = sys_meta.pop('old_vm_state', vm_states.ACTIVE)
            # load old numa info, set to extra table
            old_numa_topo = jsonutils.loads(sys_meta.pop('old_numa_topo',
                                                         '{}'))
            old_bind_info = jsonutils.loads(sys_meta.pop('old_bind_info',
                                                         '{}'))
            # delete temp data
            sys_meta.pop('new_numa_topo', None)
            sys_meta.pop('new_bind_info', None)
            hw_shed_utils.update_cpu_bind_info_to_db(
                old_bind_info, instance['uuid'], old_numa_topo)

            if old_numa_topo and old_numa_topo.get('cells'):
                cells = []
                for cell in old_numa_topo['cells']:
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
            migration.status = 'reverted'
            migration.save(context.elevated())
            self.network_api.setup_networks_on_host(context, instance,
                                            migration['source_compute'])

            block_device_info = self._get_instance_block_device_info(
                    context, instance, refresh_conn_info=True)

            power_on = old_vm_state != vm_states.STOPPED
            rt = self._get_resource_tracker(migration['source_node'])
            nw_pci_info = rt.get_nw_pci_slot_info(context, instance,
                                                  is_new=False)
            network_info = self._update_pci_slot2nw_info(context, nw_pci_info,
                                                         network_info)
            # need neutron API
            # TODO
            self.network_api.update_port_profile(context, instance,
                                                 network_info)
            instance_info_cache = instance.info_cache
            instance_info_cache.network_info = network_info
            instance.info_cache = instance_info_cache

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

    @wrap_exception()
    @reverts_task_state
    @wrap_instance_event
    @errors_out_migration
    @wrap_instance_fault
    @roll_back_migration
    def resize_instance(self, context, instance, image,
                        reservations, migration, instance_type,
                        clean_shutdown=True):
        """Starts the migration of a running instance to another host with
        cinder exception process."""

        quotas = quotas_obj.Quotas.from_reservations(context,
                                                     reservations,
                                                     instance=instance)

        with self._error_out_instance_on_exception(context, instance,
                                                   quotas=quotas):
            if not instance_type:
                instance_type = objects.Flavor.get_by_id(
                    context, migration['new_instance_type_id'])

            network_info = self._get_instance_nw_info(context, instance)

            migration.status = 'migrating'
            migration.save(context.elevated())

            instance.task_state = task_states.RESIZE_MIGRATING
            instance.save(expected_task_state=task_states.RESIZE_PREP)

            self._notify_about_instance_usage(
                context, instance, "resize.start", network_info=network_info)

            bdms = objects.BlockDeviceMappingList.get_by_instance_uuid(
                    context, instance.uuid)
            block_device_info = self._get_instance_block_device_info(
                                context, instance, bdms=bdms)

            timeout, retry_interval = self._get_power_off_values(context,
                                            instance, clean_shutdown)
            disk_info = self.driver.migrate_disk_and_power_off(
                    context, instance, migration.dest_host,
                    instance_type, network_info,
                    block_device_info,
                    timeout, retry_interval)

            try:
                self._terminate_volume_connections(context, instance, bdms)
            except  Exception as e:
                LOG.warn(_LW('Cinder Exception, Start Reverting'))
                self.driver.cold_migrate_revert_for_blockstorage_except(
                    context, instance, migration.dest_host)
                raise e

            migration_p = obj_base.obj_to_primitive(migration)
            instance_p = obj_base.obj_to_primitive(instance)
            self.network_api.migrate_instance_start(context,
                                                    instance_p,
                                                    migration_p)

            migration.status = 'post-migrating'
            migration.save(context.elevated())

            sys_meta = instance.system_metadata
            # save old_numa_topo & old_bind_info to system metadata
            # then can load to extra table when revert
            if instance.numa_topology:
                # object -> dict
                sys_meta['old_numa_topo'] = jsonutils.dumps(instance.numa_topology)
            # core_bind to bind_info
            # core_bind:[{"vcpu": 0, "pcpus": [8]}, {"vcpu": 1, "pcpus": [10]}]
            # bind_info:{0:[3], 1:[4],2:[8],3:[9]} or{0:[0,1,2,3],2:[0,1,2,3]}
            inst_extra = objects.HuaweiInstanceExtra.get_by_instance_uuid(
                context, instance.uuid)
            # not set yet
            old_bind_info = hw_shed_utils._convert_core_bind2bind_info(
                inst_extra.core_bind)
            if old_bind_info:
                sys_meta['old_bind_info'] = jsonutils.dumps(old_bind_info)
            # save new_numa_topo& new_bind_info to instance_extra table..
            numa_topology = jsonutils.loads(sys_meta.get('new_numa_topo', '{}'))
            bind_info = jsonutils.loads(sys_meta.get('new_bind_info', '{}'))
            instance.system_metadata = sys_meta
            hw_shed_utils.update_cpu_bind_info_to_db(bind_info, instance['uuid'])
            if numa_topology and numa_topology.get('cells'):
                cells = []
                for cell in numa_topology['cells']:
                    cells.append(objects.InstanceNUMACell(
                        id=cell['id'], cpuset=set(cell['cpuset']),
                        memory=cell['memory'],
                        pagesize=cell.get('pagesize')))

                format_inst_numa = objects.InstanceNUMATopology(
                    cells=cells, instance_uuid=instance.uuid)
                instance.numa_topology = format_inst_numa

            instance.host = migration.dest_compute
            instance.node = migration.dest_node
            instance.task_state = task_states.RESIZE_MIGRATED
            instance.save(expected_task_state=task_states.RESIZE_MIGRATING)

            self.compute_rpcapi.finish_resize(context, instance,
                    migration, image, disk_info,
                    migration.dest_compute, reservations=quotas.reservations)

            self._notify_about_instance_usage(context, instance, "resize.end",
                                              network_info=network_info)
            self.instance_events.clear_events_for_instance(instance)

    @wrap_exception()
    @reverts_task_state
    @wrap_instance_event
    @wrap_instance_fault
    @roll_back_migration
    def revert_resize(self, context, instance, migration, reservations):
        """Destroys the new instance on the destination machine.

        Reverts the model changes, and powers on the old instance on the
        source machine.

        """

        quotas = quotas_obj.Quotas.from_reservations(context,
                                                     reservations,
                                                     instance=instance)

        # NOTE(): A revert_resize is essentially a resize back to
        # the old size, so we need to send a usage event here.
        self.conductor_api.notify_usage_exists(
                context, instance, current_period=True)

        with self._error_out_instance_on_exception(context, instance,
                                                   quotas=quotas):
            # NOTE(): tear down networks on destination host
            self.network_api.setup_networks_on_host(context, instance,
                                                    teardown=True)

            instance_p = obj_base.obj_to_primitive(instance)
            migration_p = obj_base.obj_to_primitive(migration)
            self.network_api.migrate_instance_start(context,
                                                    instance_p,
                                                    migration_p)

            network_info = self._get_instance_nw_info(context, instance)
            bdms = objects.BlockDeviceMappingList.get_by_instance_uuid(
                    context, instance.uuid)
            block_device_info = self._get_instance_block_device_info(
                                context, instance, bdms=bdms)

            self.driver.destroy(context, instance, network_info,
                                block_device_info)

            self._terminate_volume_connections(context, instance, bdms)

            # TODO clear code
            rt = self._get_resource_tracker(migration['dest_node'])
            rt.drop_resize_claim(context, instance)
            # after _update_available_resource, instance uuid puts into
            # tracked_instances but not into tracked_migrations
            # so need to free here
            rt.drop_resize_from_instance(context, instance, migration)
            rt._revert_pci(context, instance)
            self.compute_rpcapi.finish_revert_resize(context, instance,
                    migration, migration.source_compute,
                    quotas.reservations)

    def _cleanup_allocated_networks(self, context, instance,
            requested_networks):

        super(HuaweiComputeManager, self)._cleanup_allocated_networks(
            context, instance,requested_networks)

        # assign system metadata for bug
        system_meta = instance.system_metadata
        system_meta['network_allocated'] = 'False'
        instance.system_metadata = system_meta

        try:
            instance.save()
        except exception.InstanceNotFound:
            pass

    def _update_pci_slot2nw_info(self, context, nw_pci_info, network_info):
        for port in network_info:
            physical_network = port['network']['meta'].get('physical_network',
                                                           None)
            if not physical_network:
                continue
            if nw_pci_info.get(physical_network, []):
                device = nw_pci_info.get(physical_network).pop()
                port['profile']['pci_slot'] = device['address']
                port['profile']['pci_vendor_info'] = \
                    device['vendor_id'] + ":" + device['product_id']
            else:
                port['profile']['pci_slot'] = None
        return network_info

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
                if (instance.task_state in [task_states.MIGRATING,
                                            task_states.RESIZE_MIGRATING,
                                            task_states.RESIZE_MIGRATED,
                                            task_states.RESIZE_FINISH]
                    or instance.vm_state in [vm_states.RESIZED]):
                    LOG.debug('Will not delete instance as its host ('
                              '%(instance_host)s) is not equal to our '
                              'host (%(our_host)s) but its task state is '
                              '(%(task_state)s) and vm state is '
                              '(%(vm_state)s)',
                              {'instance_host': instance.host,
                               'our_host': our_host,
                               'task_state': instance.task_state,
                               'vm_state': instance.vm_state},
                              instance=instance)
                    continue
                LOG.info(_('Deleting instance as its host ('
                           '%(instance_host)s) is not equal to our '
                           'host (%(our_host)s).'),
                         {'instance_host': instance.host,
                          'our_host': our_host}, instance=instance)
                try:
                    network_info = self._get_instance_nw_info(context,
                                                              instance)
                    # old pci requests migth not exists
                    rt = self._get_resource_tracker(self.host)
                    nw_pci_info = rt.get_nw_pci_slot_info(context, instance,
                                                          is_new=False)
                    # if devices has already been freed, set a default value
                    # to vif then will do nothing in unplug
                    network_info = self._update_pci_slot2nw_info(context,
                                                                 nw_pci_info,
                                                                 network_info)
                    bdi = self._get_instance_block_device_info(context,
                                                               instance)
                    destroy_disks = not (self._is_instance_storage_shared(
                                                            context, instance))
                except exception.InstanceNotFound:
                    network_info = network_model.NetworkInfo()
                    bdi = {}
                    LOG.info(_('Instance has been marked deleted already, '
                               'removing it from the hypervisor.'),
                             instance=instance)
                    # always destroy disks if the instance was deleted
                    destroy_disks = True
                self.driver.destroy(context, instance,
                                    network_info,
                                    bdi, destroy_disks)

    def init_virt_resource_tracker(self):
        if hasattr(self.driver, "register_resource_tracker"):
            rt = self._get_resource_tracker(self.host)
            self.driver.register_resource_tracker(rt)

    def _build_networks_for_instance(self, context, instance,
            requested_networks, security_groups):
        # this is just a temp, when community modify this question
        # will remove this method.
        # If we're here from a reschedule the network may already be allocated.
        if strutils.bool_from_string(
                instance.system_metadata.get('network_allocated', 'False')):
            # NOTE(): The network_allocated is True means the network
            # resource already allocated at previous scheduling, and the
            # network setup is cleanup at previous. After rescheduling, the
            # network resource need setup on the new host.
            self.network_api.setup_instance_network_on_host(
                context, instance, instance.host)

            # update pci_slot in sriov port info
            self.network_api.update_port_info(
                context, instance, requested_networks)

            return self._get_instance_nw_info(context, instance)

        return super(HuaweiComputeManager, self)._build_networks_for_instance(
            context, instance, requested_networks, security_groups)

    @object_compat
    @wrap_exception()
    @wrap_instance_fault
    @wrap_live_migration_rollback
    def post_live_migration_at_destination(self, context, instance,
                                           block_migration):
        """Post operations for live migration .

        :param context: security context
        :param instance: Instance dict
        :param block_migration: if true, prepare for block migration

        """
        LOG.info(_('Post operation of migration started'),
                 instance=instance)

        # NOTE(): setup networks on destination host
        #                  this is called a second time because
        #                  multi_host does not create the bridge in
        #                  plug_vifs
        self.network_api.setup_networks_on_host(context, instance,
                                                         self.host)
        migration = {'source_compute': instance['host'],
                     'dest_compute': self.host, }
        self.network_api.migrate_instance_finish(context,
                                                 instance,
                                                 migration)

        network_info = self._get_instance_nw_info(context, instance)
        self._notify_about_instance_usage(
                     context, instance, "live_migration.post.dest.start",
                     network_info=network_info)
        block_device_info = self._get_instance_block_device_info(context,
                                                                 instance)

        self.driver.post_live_migration_at_destination(context, instance,
                                            network_info,
                                            block_migration, block_device_info)
        # Restore instance state
        current_power_state = self._get_power_state(context, instance)
        node_name = None
        try:
            compute_node = self._get_compute_info(context, self.host)
            node_name = compute_node.hypervisor_hostname
        except exception.NotFound:
            LOG.exception(_LE('Failed to get compute_info for %s'), self.host)
        finally:
            instance.refresh(context)
            instance.host = self.host
            instance.power_state = current_power_state
            instance.vm_state = vm_states.ACTIVE
            instance.task_state = None
            instance.node = node_name
            # load numatopy to new data
            sys_meta = instance.system_metadata
            numa_topology = jsonutils.loads(sys_meta.pop('new_numa_topo',
                                                         '{}'))
            bind_info = jsonutils.loads(sys_meta.pop('new_bind_info', '{}'))
            instance.system_metadata = sys_meta
            hw_shed_utils.update_cpu_bind_info_to_db(bind_info,
                                                     instance['uuid'])
            if numa_topology and numa_topology.get('cells'):
                cells = []
                for cell in numa_topology['cells']:
                    cells.append(objects.InstanceNUMACell(
                        id=cell['id'], cpuset=set(cell['cpuset']),
                        memory=cell['memory'],
                        pagesize=cell.get('pagesize')))

                format_inst_numa = objects.InstanceNUMATopology(
                    cells=cells, instance_uuid=instance.uuid)
                instance.numa_topology = format_inst_numa
            instance.system_metadata = sys_meta

            instance.save(expected_task_state=task_states.MIGRATING)
            get_migrate_obj = objects.HuaweiLiveMigration.get_by_instance_uuid
            obj_migrate = get_migrate_obj(context, instance['uuid'])
            if obj_migrate:
                obj_migrate.destroy()
        # NOTE(): this is necessary to update dhcp
        self.network_api.setup_networks_on_host(context, instance, self.host)
        self._notify_about_instance_usage(
                     context, instance, "live_migration.post.dest.end",
                     network_info=network_info)

    @wrap_exception()
    @reverts_task_state
    @wrap_instance_event
    @wrap_instance_fault
    def reboot_instance(self, context, instance, block_device_info,
                        reboot_type):
        LOG.info(_('Reboot instance started'), instance=instance)

        @utils.synchronized(instance['uuid'])
        def do_reboot_instance(context, instance, block_device_info,
                               reboot_type):
            super(HuaweiComputeManager, self).reboot_instance(
                context,
                instance,
                block_device_info,
                reboot_type)

        do_reboot_instance(context, instance, block_device_info, reboot_type)

    @wrap_exception()
    @reverts_task_state
    @wrap_instance_event
    @wrap_instance_fault
    def start_instance(self, context, instance):

        @utils.synchronized(instance.uuid)
        def do_start_instance():
            super(HuaweiComputeManager, self).start_instance(context, instance)

        do_start_instance()

    @object_compat
    @wrap_exception()
    @reverts_task_state
    @wrap_instance_fault
    def detach_volume(self, context, volume_id, instance):
        """Detach a volume from an instance."""
        try:
            super(HuaweiComputeManager, self).detach_volume(context, volume_id,
                                                            instance)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception("Error when detaching volume")
                self.volume_api.roll_detaching(context, volume_id)

    @wrap_exception()
    @wrap_instance_fault
    def check_can_live_migrate_destination(self, ctxt, instance,
                                           block_migration, disk_over_commit):
        migrate_data = super(HuaweiComputeManager, self).\
            check_can_live_migrate_destination(
                ctxt, instance, block_migration, disk_over_commit)
        rt = self._get_resource_tracker(self.host)
        try:
            network_info = self._get_instance_nw_info(ctxt, instance)
            migrate_data = rt.get_cpu_at_live_migration(
                ctxt, instance, network_info, block_migration, migrate_data)
        except exception.NovaException as ex:
            raise exception.MigrationPreCheckError(reason=ex.message)
        except Exception as ex:
            raise exception.MigrationPreCheckError(reason="Unknown Error")

        return migrate_data


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

