"""
    Huawei FusionCompute (FC) Driver
"""
import inspect

from nova import exception as nova_exc
from nova.openstack.common import jsonutils
from nova.openstack.common.gettextutils import _
from nova import context as nova_context

from nova import objects
from nova.virt import driver as compute_driver
from nova.fusioncompute.virt.huaweiapi.fcclient import FCBaseClient
from nova.fusioncompute.virt.huaweiapi import computeops
from nova.fusioncompute.virt.huaweiapi import cluster as fc_cluster
from nova.fusioncompute.virt.huaweiapi import networkops
from nova.fusioncompute.virt.huaweiapi import taskops
from nova.fusioncompute.virt.huaweiapi import volumeops
from nova.fusioncompute.virt.huaweiapi import utils
from nova.fusioncompute.virt.huaweiapi import constant
from nova.fusioncompute.virt.huaweiapi.fcinstance import FC_INSTANCE_MANAGER as FC_MGR
from nova.fusioncompute.virt.huaweiapi.utils import LOG
from FSComponentUtil import crypt

class FusionComputeDriver(compute_driver.ComputeDriver):
    """FusionComputeDriver: for Openstack Manager"""

    def __init__(self, virtapi):
        LOG.info(_('begin to init FusionComputeDriver ...'))
        super(FusionComputeDriver, self).__init__(virtapi)

        self._client = FCBaseClient(constant.CONF.fusioncompute.fc_ip,
                                    constant.CONF.fusioncompute.fc_user,
                                    crypt.decrypt(constant.CONF.fusioncompute.fc_pwd),
                                    constant.FC_DRIVER_JOINT_CFG['user_type'],
                                    ssl=True,
                                    port=constant.FC_DRIVER_JOINT_CFG['fc_port'],
                                    api_version=constant.FC_DRIVER_JOINT_CFG['api_version'],
                                    request_time_out=
                                    constant.FC_DRIVER_JOINT_CFG['request_time_out'])
        self._client.set_default_site()

        # task ops is need by other ops, init it first
        self.task_ops = taskops.TaskOperation(self._client)
        FC_MGR.set_client(self._client)

        self.network_ops = networkops.NetworkOps(self._client, self.task_ops)
        self.volume_ops = volumeops.VolumeOps(self._client, self.task_ops)
        self.cluster_ops = fc_cluster.ClusterOps(self._client, self.task_ops)
        self.compute_ops = computeops.ComputeOps(self._client, self.task_ops,
                                                 self.network_ops,
                                                 self.volume_ops,
                                                 self.cluster_ops)

    def init_host(self, host):
        """FC driver init goes here"""
        pass

    def get_info(self, instance):
        """
        Get the current status of an instance by uuid
        :param instance:
        :return:
        """
        return self.compute_ops.get_info(instance)

    def get_instance_extra_specs(self, instance):
        """
        get instance extra info
        :param instance:
        :return:
        """
        #ignore pylint:disable=E1101
        inst_type = objects.Flavor.get_by_id(
            nova_context.get_admin_context(read_deleted='yes'),
            instance['instance_type_id'])
        return inst_type.get('extra_specs', {})

    @utils.timelimited(constant.CONF.fusioncompute.fc_request_timeout_max)
    def get_instances_info(self):
        """
        Get all instances info from FusionCompute
        :return:
        """
        return self.compute_ops.get_instances_info()


    def spawn(self, context, instance, image_meta, injected_files,
              admin_password, network_info=None, block_device_info=None):
        """ Create vm.

        :param context:
        :param instance:
        :param image_meta:
        :param injected_files:
        :param admin_password:
        :param network_info:
        :param block_device_info:
        :return:
        """
        @utils.func_log_circle(instance)
        def _create_vm():
            """
            inner create vm
            :return:
            """
            LOG.debug(_('spawning instance: %s'), jsonutils.dumps(instance))
            LOG.debug(_("block_device_info is %s."),
                      jsonutils.dumps(block_device_info))
            LOG.debug(_("network_info is %s."),
                      jsonutils.dumps(network_info))
            extra_specs = self.get_instance_extra_specs(instance)
            LOG.debug(_("extra_specs is %s."), jsonutils.dumps(extra_specs))

            vm_password = admin_password if constant.CONF.fusioncompute.use_admin_pass\
            else None

            # create vm on FC
            self.compute_ops.create_vm(context, instance, network_info,
                                       block_device_info,
                                       image_meta, injected_files,
                                       vm_password, extra_specs)
        _create_vm()

    def power_off(self, instance, timeout=0, retry_interval=0):
        """Power off the specified instance.

        :param instance: nova.objects.instance.Instance
        """
        @utils.func_log_circle(instance)
        def _stop_vm():
            """
            inner stop vm
            :return:
            """
            self.compute_ops.stop_vm(instance)
        _stop_vm()

    def power_on(self, context, instance, network_info,
                 block_device_info=None):
        """Power on the specified instance.

        :param instance: nova.objects.instance.Instance
        """
        @utils.func_log_circle(instance)
        def _start_vm():
            """
            inner start vm
            :return:
            """
            self.compute_ops.start_vm(instance)
        _start_vm()

    def reboot(self, context, instance, network_info, reboot_type,
               block_device_info=None, bad_volumes_callback=None):
        @utils.func_log_circle(instance)
        def _reboot_vm_fc():
            """
            inner reboot vm
            :return:
            """
            self.compute_ops.reboot_vm(instance, reboot_type)
        _reboot_vm_fc()

    def cleanup(self, context, instance, network_info, block_device_info=None,
                destroy_disks=True, migrate_data=None, destroy_vifs=True):
        """Cleanup the instance resources ."""
        pass

    def destroy(self, context, instance, network_info, block_device_info=None,
                destroy_disks=True, migrate_data=None):
        """FC itself will clean up network and disks"""
        @utils.func_log_circle(instance)
        def _delete_vm():
            """
            inner delete vm
            :return:
            """
            self.compute_ops.delete_vm(context, instance,
                                       block_device_info=block_device_info,
                                       destroy_disks=destroy_disks)
        _delete_vm()

    def pause(self, instance):
        """Pause the specified instance.

        :param instance: nova.objects.instance.Instance
        """
        @utils.func_log_circle(instance)
        def _pause_vm():
            """
            inner pause vm
            :return:
            """
            self.compute_ops.pause_vm(instance)
        _pause_vm()

    def unpause(self, instance):
        """Unpause paused instance.

        :param instance: nova.objects.instance.Instance
        """
        @utils.func_log_circle(instance)
        def _unpause_vm():
            """
            inner unpause vm
            :return:
            """
            self.compute_ops.unpause_vm(instance)
        _unpause_vm()

    def suspend(self, context, instance):
        """Suspend instance.

        :param instance: nova.objects.instance.Instance
        """
        @utils.func_log_circle(instance, nova_exc.InstanceFaultRollback)
        def _suspend_vm():
            """
            inner unpause vm
            :return:
            """
            self.compute_ops.suspend_vm(instance)
        _suspend_vm()

    def resume(self, context, instance, network_info, block_device_info=None):
        """resume the specified instance.

        :param context: the context for the resume
        :param instance: nova.objects.instance.Instance being resumed
        :param network_info:
           :py:meth:`~nova.network.manager.NetworkManager.get_instance_nw_info`
        :param block_device_info: instance volume block device info
        """
        @utils.func_log_circle(instance)
        def _resume_vm():
            """
            inner resume vm, same action as start_vm in FC
            :return:
            """
            self.compute_ops.start_vm(instance)
        _resume_vm()

    def change_instance_metadata(self, context, instance, diff):
        """

        :param context:
        :param instance:
        :param diff:
        :return:
        """
        @utils.func_log_circle(instance)
        def _change_instance_metadata():
            """

            :return:
            """
            self.compute_ops.change_instance_metadata(instance)
        _change_instance_metadata()

    def change_instance_info(self, context, instance):
        """

        :param context:
        :param instance:
        :return:
        """
        @utils.func_log_circle(instance)
        def _change_instance_info():
            """

            :return:
            """
            self.compute_ops.change_instance_info(instance)
        _change_instance_info()

    def resume_state_on_host_boot(self, context, instance, network_info,
                                  block_device_info=None):
        """resume guest state when a host is booted.
        FC can do HA automatically, so here we only rewrite this interface
        to avoid NotImplementedError() in nova-compute.log

        :param instance: nova.objects.instance.Instance
        """
        pass

    def confirm_migration(self, migration, instance, network_info):
        """Confirms a resize, destroying the source VM.

        :param instance: nova.objects.instance.Instance
        """
        @utils.func_log_circle(instance, nova_exc.InstanceFaultRollback)
        def _confirm_migration():
            """
            inner confirm migration
            :return:
            """
            self.compute_ops.confirm_migration(instance)
        _confirm_migration()

    def pre_live_migration(self, ctxt, instance, block_device_info,
                           network_info, disk_info, migrate_data=None):
        """Prepare an instance for live migration"""

        # do nothing on FC
        pass

    #ignore pylint:disable=W0613
    def live_migration(self, context, instance_ref, dest,
                       post_method, recover_method, block_migration=False,
                       migrate_data=None):
        """Live migration of an instance to another host."""
        @utils.func_log_circle(instance_ref)
        def _live_migration():
            """
            inner live migrate vm
            :return:
            """
            self.compute_ops.live_migration(instance_ref, dest)
        _live_migration()

    def post_live_migration(self, ctxt, instance_ref, block_device_info,
                            migrate_data=None):
        """Post operation of live migration at source host."""

        # do nothing on FC
        pass

    def post_live_migration_at_destination(self, ctxt, instance_ref,
                                           network_info,
                                           block_migration=False,
                                           block_device_info=None):
        """Post operation of live migration at destination host."""

        # do nothing on FC
        pass

    def rollback_live_migration_at_destination(self, ctxt, instance_ref,
                                               network_info,
                                               block_device_info,
                                               destroy_disks=True,
                                               migrate_data=None):
        """Clean up destination node after a failed live migration."""

        # do nothing on FC
        pass

    def get_volume_connector(self, instance):
        return {'ip': constant.CONF.my_ip,
                'host': constant.CONF.host}

    def instance_exists(self, instance):
        try:
            FC_MGR.get_vm_by_uuid(instance)
            return True
        except nova_exc.InstanceNotFound:
            return False

    def get_available_resource(self, nodename):
        """Retrieve resource info.

        This method is called when nova-compute launches, and
        as part of a periodic task.

        :returns: dictionary describing resources
        """
        return self.cluster_ops.get_available_resource(nodename)

    def get_host_stats(self, refresh=False):
        """Return currently known host stats."""

        stats_list = []
        nodes = self.get_available_nodes(refresh=refresh)
        for node in nodes:
            stats_list.append(self.get_available_resource(node))
        return stats_list

    def get_host_ip_addr(self):
        """Retrieves the IP address of the dom0
        """
        # Avoid NotImplementedError
        pass

    @utils.timelimited(constant.CONF.fusioncompute.fc_request_timeout_min)
    def get_available_nodes(self, refresh=True):
        """Returns nodenames of all nodes managed by the compute service."""

        # default is refresh to ensure it is latest
        if refresh:
            self.cluster_ops.update_resources()

        node_list = self.cluster_ops.resources
        LOG.debug(_("The available nodes are: %s") % node_list)
        return node_list

    def get_hypervisor_version(self):
        """Get hypervisor version."""
        return self.cluster_ops.get_hypervisor_version()

    def get_hypervisor_type(self):
        """Returns the type of the hypervisor."""
        return self.cluster_ops.get_hypervisor_type()

    def get_instance_capabilities(self):
        """get_instance_capabilities"""
        return self.cluster_ops.get_instance_capabilities()

    @utils.timelimited(constant.CONF.fusioncompute.fc_request_timeout_min)
    def list_instances(self):
        instances = self.compute_ops.list_all_fc_instance()
        return [vm['name'] for vm in instances]

    @utils.timelimited(constant.CONF.fusioncompute.fc_request_timeout_min)
    def list_instance_uuids(self):
        """list_instance_uuids"""
        fc_instances = self.compute_ops.list_all_fc_instance()
        return [vm['uuid'] for vm in fc_instances]

    def get_vnc_console(self, context, instance):
        """Get connection info for a vnc console.

        :param instance: nova.objects.instance.Instance
        """
        # return password only in called by manager.get_vnc_console
        # if called by manager.validate_console_port, return without password
        get_opt = True
        stack_list = inspect.stack()
        if str(stack_list[1][3]) != "get_vnc_console":
            get_opt = False

        return self.compute_ops.get_vnc_console(instance, get_opt)

    def cycle_change_vnc_passwd(self):
        """change to a random password cycle
           use fc cycle change vnc pwd function instead
        """
        pass

    def attach_interface(self, instance, image_meta, vif):
        """
        attach interface into fusion compute virtual machine, now
        do not consider inic network interface

        :param instance:
        :param image_meta:
        :param vif:
        :return:
        """

        @utils.func_log_circle(instance)
        def attach_intf_inner():
            """
            inner attach interface
            """
            return self.compute_ops.attach_interface(instance, vif)
        return attach_intf_inner()

    def detach_interface(self, instance, vif):
        """
        detach interface from fusion compute virtual machine, if the nic has
        not exited, don't raise exception

        :param instance:
        :param vif:
        :return:
        """

        @utils.func_log_circle(instance)
        def detach_intf_inner():
            """
            inner detach interface
            :return:
            """
            return self.compute_ops.detach_interface(instance, vif)
        return detach_intf_inner()

    def migrate_disk_and_power_off(self, context, instance, dest, flavor,
                                   network_info, block_device_info=None,
                                   timeout=0, retry_interval=0):
        """Transfers the disk of a running instance in multiple phases, turning
        off the instance before the end.

        :param instance: nova.objects.instance.Instance
        """
        @utils.func_log_circle(instance, nova_exc.InstanceFaultRollback)
        def _migrate_disk_and_power_off():
            """
            inner modify vm
            :return:
            """
            self.compute_ops.migrate_disk_and_power_off(instance, flavor)
        _migrate_disk_and_power_off()

    def finish_migration(self, context, migration, instance, disk_info,
                         network_info, image_meta, resize_instance,
                         block_device_info=None, power_on=True):
        """Completes a resize.

        :param context: the context for the migration/resize
        :param migration: the migrate/resize information
        :param instance: nova.objects.instance.Instance being migrated/resized
        :param disk_info: the newly transferred disk information
        :param network_info:
           :py:meth:`~nova.network.manager.NetworkManager.get_instance_nw_info`
        :param image_meta: image object returned by nova.image.glance that
                           defines the image from which this instance
                           was created
        :param resize_instance: True if the instance is being resized,
                                False otherwise
        :param block_device_info: instance volume block device info
        :param power_on: True if the instance should be powered on, False
                         otherwise
        """
        @utils.func_log_circle(instance)
        def _finish_migration():
            """
            inner finish migrate vm
            :return:
            """
            self.compute_ops.finish_migration(instance, power_on)
        _finish_migration()

    def finish_revert_migration(self, context, instance, network_info,
                                block_device_info=None, power_on=True):
        """Finish reverting a resize.

        :param context: the context for the finish_revert_migration
        :param instance: nova.objects.instance.Instance being migrated/resized
        :param network_info:
           :py:meth:`~nova.network.manager.NetworkManager.get_instance_nw_info`
        :param block_device_info: instance volume block device info
        :param power_on: True if the instance should be powered on, False
                         otherwise
        """

        @utils.func_log_circle(instance)
        def _finish_revert_migration():
            """
            inner finish revert migration
            :return:
            """
            self.compute_ops.finish_revert_migration(instance, power_on)
        _finish_revert_migration()

    def attach_volume(self, context, connection_info, instance, mountpoint,
                      disk_bus=None, device_type=None, encryption=None):
        """Attach the disk to the instance at mountpoint using info."""
        @utils.func_log_circle(instance)
        def _attach_volume():
            """
            inner attach volume
            :return:
            """
            self.compute_ops.attach_volume(connection_info,
                                           instance,
                                           mountpoint)

        _attach_volume()

    def detach_volume(self, connection_info, instance, mountpoint,
                      encryption=None):
        """Detach the disk attached to the instance."""
        @utils.func_log_circle(instance)
        def _detach_volume():
            """
            inner detach volume
            :return:
            """
            self.compute_ops.detach_volume(connection_info, instance)

        _detach_volume()

    def snapshot(self, context, instance, image_id, update_task_state):
        """
        Snapshots the specified instance.

        :param context: security context
        :param instance: Instance object as returned by DB layer.
        :param image_id: Reference to a pre-created image that will
                         hold the snapshot.
        """
        @utils.func_log_circle(instance)
        def _snapshot():
            """
            create vm snapshot
            :return:
            """
            self.compute_ops.snapshot(context, instance, image_id,
                                      update_task_state)

        _snapshot()

    def report_instances_state(self, host):
        """
        Report instances state on compute starting.
        """
        pass

    def report_host_state(self, host):
        """
        Report host state on compute starting.
        """
        pass

    def get_pci_slots_from_xml(self, instance):
        """

        :param instance:
        :return:
        """
        return []

    def reconfigure_affinity_group(self, instances, affinity_group, action,
                                   node=None):
        """
        Add or Remove vms from affinity group
        :param instances:
        :param affinity_group:
        :param action:
        :param node:
        :return:
        """

        @utils.func_log_circle()
        def _reconfigure_affinity_group():
            """

            :return:
            """
            self.compute_ops.reconfigure_affinity_group(instances,
                                                        affinity_group,
                                                        action,
                                                        node)

        _reconfigure_affinity_group()

    def clean_fc_network_pg(self):
        """

        :return:
        """
        @utils.func_log_circle()
        def _clean_fc_network_pg():
            self.network_ops.audit_pg()

        _clean_fc_network_pg()

    def get_next_disk_name(self, disk_name=None):
        """
        :param disk_name:
        :return:
        """
        if disk_name is None:
            return None

        next_disk_name = None
        disk_id = constant.MOUNT_DEVICE_SEQNUM_MAP.get(disk_name)
        if disk_id is None:
            return None
        next_disk_id = disk_id + 1
        for key, value in constant.MOUNT_DEVICE_SEQNUM_MAP.items():
            if value == next_disk_id:
                str_a = disk_name[:7]
                str_b = key[:7]
                if str_a == str_b:
                    next_disk_name = key
                    break
        return next_disk_name

    def fc_max_volumes(self):
        return constant.FUSIONCOMPUTE_MAX_VOLUME_NUM