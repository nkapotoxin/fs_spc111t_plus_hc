"""
    API of Compute Resource on FusionCompute
"""

import ast

from nova import exception
from nova.openstack.common.gettextutils import _
from nova.compute import power_state
from nova.compute import task_states
from nova.image import glance
from nova.openstack.common import jsonutils

from nova.fusioncompute.virt.huaweiapi import ops_task_base
from nova.fusioncompute.virt.huaweiapi import utils
from nova.fusioncompute.virt.huaweiapi import exception as fc_exc
from nova.openstack.common import loopingcall
from nova.fusioncompute.virt.huaweiapi import constant
from nova.fusioncompute.virt.huaweiapi import vmcreation
from nova.fusioncompute.virt.huaweiapi.fcinstance import FC_INSTANCE_MANAGER as FC_MGR
from nova.huawei.objects import affinity_group as affinitygroup_obj

from nova.fusioncompute.virt.huaweiapi.utils import LOG

from nova.huawei.console import type as hwtype
from nova.console import type as ctype

class ComputeOps(ops_task_base.OpsTaskBase):
    """computer option"""
    def __init__(self, fc_client, task_ops, network_ops, volume_ops,
                 cluster_ops):
        super(ComputeOps, self).__init__(fc_client, task_ops)

        self._network_ops = network_ops
        self._volume_ops = volume_ops
        self._cluster_ops = cluster_ops

        self._init_os_config()

    def _init_os_config(self):
        """

        :return:
        """
        constant.HUAWEI_OS_VERSION_INT(config_file=constant.OS_CONFIG_FILE)
        constant.HUAWEI_OS_VERSION_STR(config_file=constant.OS_CONFIG_FILE)

        os_type = constant.DEFAULT_HUAWEI_OS_TYPE
        os_version = constant.DEFAULT_HUAWEI_OS_VERSION.lower()
        constant.DEFAULT_HUAWEI_OS_CONFIG = [
            os_type,
            int(constant.HUAWEI_OS_VERSION_INT[os_type][os_version])
        ]

    def _split_injected_files(self, injected_files):
        """
        FC plug in use injected_files impress custom info, split this
        :return:
        """
        customization = {}
        filtered_injected_files = []
        try:
            for (path, contents) in injected_files:
                if path == 'fc_customization':
                    for (key, values) in \
                            ast.literal_eval(contents).items():
                        customization[key] = values
                else:
                    filtered_injected_files.append([path, contents])
        except Exception as exc:
            utils.log_exception(exc)
            msg = _("Error dict object !")
            raise fc_exc.InvalidCustomizationInfo(reason=msg)
        return customization, filtered_injected_files

    def create_vm(self, context, instance, network_info, block_device_info,
                  image_meta, injected_files, admin_password, extra_specs):
        """
        Create VM on FC

        :param instance:
        :param network_info:
        :param image_meta:
        :param injected_files:
        :param admin_password:
        :param block_device_info:
        :return:
        """
        customization, filtered_injected_files = \
            self._split_injected_files(injected_files)

        # set qos io
        self._volume_ops.set_qos_specs_to_volume(block_device_info)

        # prepare network on FC
        LOG.debug(_('prepare network'))
        vifs = []
        for idx, network_item in enumerate(network_info):
            pg_urn = self._network_ops.ensure_network(network_item['network'])
            enable_dhcp = self._network_ops.\
                              is_enable_dhcp(context, network_item['id'])
            vifs.append({
                'sequence_num': idx,
                'pg_urn': pg_urn,
                'enable_dhcp': enable_dhcp,
                'network_info': network_item
            })
        location = self._cluster_ops.\
            get_cluster_urn_by_nodename(instance['node'])

        # initial obj and create vm
        try:
            LOG.debug(_('begin create vm in fc.'))
            vm_create = vmcreation.get_vm_create(self.fc_client, self.task_ops,
                instance, image_meta)
            vm_create(context, self._volume_ops, location, vifs,
                block_device_info, image_meta, filtered_injected_files,
                admin_password, extra_specs, customization)
            vm_create.create_and_boot_vm()
        except Exception as exc:
            utils.log_exception(exc)
            msg = _("create and boot vm %s failed.") % instance['name']
            self.delete_vm(context, instance, block_device_info)
            raise exception.InstancePowerOnFailure(msg)

        boot_result = {'result': False}
        def _wait_for_boot():
            """Called at an interval until the VM is running."""

            statue = FC_MGR.get_vm_by_uuid(instance).status
            if statue == constant.VM_STATUS.RUNNING:
                LOG.debug(_("vm %s create success."), instance['name'])
                boot_result['result'] = True
                raise loopingcall.LoopingCallDone()
            elif statue == constant.VM_STATUS.STOPPED:
                LOG.debug(_("create vm %s success, but start failed."),
                          instance['name'])
                raise loopingcall.LoopingCallDone()
            else:
                LOG.debug(_("vm %s is still in creating state."),
                          instance['name'])

        timer = loopingcall.FixedIntervalLoopingCall(_wait_for_boot)
        timer.start(interval=1).wait()

        if not boot_result['result']:
            self.delete_vm(context, instance, block_device_info)
            msg = _("create vm %s success, but start failed.") % \
                  instance['name']
            raise exception.InstancePowerOnFailure(msg)

        try:
            urn = FC_MGR.get_vm_by_uuid(instance).urn
            instance.system_metadata.update({'fc_vm_id': urn.split(':')[-1]})
            instance.save()
        except Exception as exc:
            utils.log_exception(exc)
            LOG.warn(_("update sys metadata for %s failed."), instance['name'])

    def stop_vm(self, instance):
        """Stop vm on FC

        :param instance:nova.objects.instance.Instance
        :return:
        """
        LOG.info(_("trying to stop vm: %s."), instance['name'])
        fc_vm = FC_MGR.get_vm_by_uuid(instance)
        if fc_vm.status == constant.VM_STATUS.STOPPED:
            LOG.info(_("vm has already stopped."))
            return
        elif fc_vm.status == constant.VM_STATUS.RUNNING \
        and fc_vm['pvDriverStatus'] == 'running':
            body = {'mode': 'safe'}
        else:
            body = {'mode': 'force'}

        self.post(fc_vm.get_vm_action_uri('stop'), data=body,
                  excp=exception.InstancePowerOffFailure)
        LOG.info(_("stop vm %s success"), fc_vm.name)

    def _modify_boot_option_if_needed(self, instance, fc_vm):
        """

        :param instance: OpenStack instance object
        :param fc_vm: FusionCompute vm object
        :return:
        """

        new_boot_option = utils.get_boot_option_from_metadata(
            instance.get('metadata'))

        old_boot_option = None
        if 'vmConfig' in fc_vm:
            vm_property = fc_vm['vmConfig'].get('properties')
            old_boot_option = vm_property.get('bootOption') if vm_property \
                              else None

        if new_boot_option and old_boot_option and \
           new_boot_option != old_boot_option:
            LOG.info(_("trying to modify boot option from %s to %s") %
                     (old_boot_option, new_boot_option))
            body = {
                'properties':{
                    'bootOption': new_boot_option
                }
            }
            try:
                self.modify_vm(instance, vm_config=body)
            except Exception as msg:
                LOG.error(_("modify boot option has exception: %s") % msg)

    def change_instance_metadata(self, instance):
        """

        :param instance:
        :return:
        """
        LOG.info(_("trying to change metadata for vm: %s.") % instance['name'])

        try:
            fc_vm = FC_MGR.get_vm_by_uuid(instance)
            self._modify_boot_option_if_needed(instance, fc_vm)
        #ignore pylint:disable=W0703
        except Exception as msg:
            LOG.error(_("change_instance_metadata has exception, msg = %s")
                      % msg)

    def change_instance_info(self, instance):

        LOG.info(_("trying to change instance display_name = %s"),
                 instance['display_name'])

        body = {'name':instance['display_name']}
        try:
            self.modify_vm(instance,vm_config=body)
        except Exception as msg:
            LOG.error(_("change_instance_info has exception, msg = %s")
                  % msg)


    def start_vm(self, instance):
        """Start vm on FC

        :param instance:nova.objects.instance.Instance
        :return:
        """
        LOG.info(_("trying to start vm: %s.") % instance['name'])

        fc_vm = FC_MGR.get_vm_by_uuid(instance)
        if fc_vm.status in [constant.VM_STATUS.STOPPED,
                            constant.VM_STATUS.SUSPENDED]:
            self._modify_boot_option_if_needed(instance, fc_vm)
            self.post(fc_vm.get_vm_action_uri('start'),
                      excp=exception.InstancePowerOnFailure)
            LOG.info(_("start vm %s success"), fc_vm.name)
        elif fc_vm.status == constant.VM_STATUS.RUNNING:
            LOG.info(_("vm has already running."))
        else:
            reason = _("vm status is %s and cannot be powered on.") % \
                     fc_vm.status
            raise exception.InstancePowerOnFailure(reason=reason)

    def _reboot_vm(self, fc_vm, reboot_type):
        """reboot vm inner func"""
        body = {'mode': constant.FC_REBOOT_TYPE[reboot_type]}
        self.post(fc_vm.get_vm_action_uri('reboot'), data=body,
                  excp=exception.InstanceRebootFailure)
        LOG.debug(_("_reboot_vm %s success"), fc_vm.uri)

    def reboot_vm(self, instance, reboot_type):
        """reboot vm"""
        fc_vm = FC_MGR.get_vm_by_uuid(instance)
        LOG.debug(_("reboot_vm %s, reboot_type %s, fc_vm.status %s."),
                  instance['name'], reboot_type, fc_vm.status)

        # if it is fault-resuming or unknown, do nothing
        if fc_vm.status == constant.VM_STATUS.UNKNOWN \
        or fc_vm.status == constant.VM_STATUS.FAULTRESUMING \
        or fc_vm.status == constant.VM_STATUS.MIGRATING:
            LOG.debug(_("vm %s status is fault-resuming or unknown "
                        "or migrating, just ignore this reboot action."),
                        fc_vm.uri)
            return

        # if it is stopped or suspended, just start it
        if fc_vm.status == constant.VM_STATUS.STOPPED \
        or fc_vm.status == constant.VM_STATUS.SUSPENDED:
            LOG.debug(_("vm %s is stopped, will start vm."), fc_vm.uri)
            self.start_vm(instance)
            return

        # if it is paused, first unpause it
        if fc_vm.status == constant.VM_STATUS.PAUSED:
            self.unpause_vm(instance)

        # modify vm boot type if needed
        self._modify_boot_option_if_needed(instance, fc_vm)

        if reboot_type == constant.REBOOT_TYPE.SOFT:
            try:
                self._reboot_vm(fc_vm, reboot_type)
                return
            except exception.InstanceRebootFailure:
                LOG.debug(_("soft reboot vm %s failed, will hard reboot."),
                          instance['name'])

        # if soft reboot failed, hard reboot
        self._reboot_vm(fc_vm, constant.REBOOT_TYPE.HARD)

    def pause_vm(self, instance):
        """Pause vm on FC

        :param instance:nova.objects.instance.Instance
        :return:
        """
        LOG.info(_("trying to pause vm: %s.") % instance['name'])

        fc_vm = FC_MGR.get_vm_by_uuid(instance)
        if fc_vm.status == constant.VM_STATUS.RUNNING:
            self.post(fc_vm.get_vm_action_uri('pause'),
                      excp=fc_exc.InstancePauseFailure)
            LOG.info(_("pause vm %s success" % fc_vm['name']))
        elif fc_vm.status == constant.VM_STATUS.PAUSED:
            LOG.info(_("vm status is paused, consider it success."))
        else:
            reason = _("vm status is %s and cannot be paused.") % fc_vm.status
            raise fc_exc.InstancePauseFailure(reason=reason)

    def unpause_vm(self, instance):
        """Unpause vm on FC

        :param instance:nova.objects.instance.Instance
        :return:
        """
        LOG.info(_("trying to unpause vm: %s."), instance['name'])
        fc_vm = FC_MGR.get_vm_by_uuid(instance)
        if fc_vm.status == constant.VM_STATUS.PAUSED:
            self.post(fc_vm.get_vm_action_uri('unpause'),
                      excp=fc_exc.InstanceUnpauseFailure)
            LOG.info(_("unpause vm %s success"), fc_vm.name)
        elif fc_vm.status == constant.VM_STATUS.RUNNING:
            LOG.info(_("vm status is running, consider it success"))
        else:
            reason = _("vm status is %s and cannot be unpaused.") % \
                     fc_vm.status
            raise fc_exc.InstanceUnpauseFailure(reason=reason)

    def suspend_vm(self, instance):
        """suspend vm on FC

        :param instance:nova.objects.instance.Instance
        :return:
        """

        LOG.info(_("trying to suspend vm: %s."), instance['name'])
        fc_vm = FC_MGR.get_vm_by_uuid(instance)
        if fc_vm.status == constant.VM_STATUS.RUNNING:
            self.post(fc_vm.get_vm_action_uri('suspend'),
                      excp=exception.InstanceFaultRollback)
            LOG.info(_("suspend vm %s success"), fc_vm.name)
        else:
            LOG.error(_("error vm status: %s.") % fc_vm.status)
            raise exception.InstanceFaultRollback

    def _delete_vm_with_fc_vm(self, fc_vm, destroy_disks=True):
        """
        delete vm with fc instance, inner function
        :param fc_vm:
        :param destroy_disks:
        :return:
        """
        reserve_disks = {'isReserveDisks': 0 if destroy_disks else 1}
        LOG.info(_('Deleting VM on FC, instance: %s reserve_disks %s'),
                 fc_vm.name, jsonutils.dumps(reserve_disks))

        self.delete(utils.build_uri_with_params(fc_vm.uri, reserve_disks))

    def _update_affinity_groups(self, context, instance):
        """

        :param context:
        :param instance:
        :return:
        """

        groups = affinitygroup_obj.AffinityGroupList().get_all(context)
        for group in groups:
            vm_id = str(instance.get('id'))
            all_vms = group.get_all_vms(context)
            if vm_id in all_vms:
                vms_to_del = [vm_id] if len(all_vms) > 2 else all_vms
                for vm_to_del in vms_to_del:
                    LOG.info(_('delete vm %s from affinity group %s'),
                             vm_to_del, group.id)
                    group.delete_vm(context, vm_to_del)

    def _update_drs_rules(self, instance):
        """

        :param instance:
        :return:
        """

        node = instance.get('node')
        if node is None:
            LOG.error(_('failed to get node info from instance'))
            return

        cluster = self._cluster_ops.get_cluster_detail_by_nodename(node)
        if cluster is None:
            LOG.error(_('failed to get cluster info by node: %s'), node)
            return

        drs_rules = cluster['drsSetting']['drsRules']
        for drs_rule in drs_rules:
            if len(drs_rule['vms']) < 2:
                rule_name = str(drs_rule['ruleName'])
                rule_type = drs_rule['ruleType']
                self._cluster_ops.\
                    delete_drs_rules(cluster, rule_name, rule_type)

    def delete_vm(self, context, instance, block_device_info=None,
                  destroy_disks=True):
        """Delete VM on FC

        :param context:
        :param instance:
        :param block_device_info:
        :param destroy_disks:
        :return:
        """

        # if revert resize, only stop vm. when resize operation
        # task state will be resize_reverting or resize_confirming
        if instance and (instance.get('task_state') == 'resize_reverting'
                         or instance.get('task_state') == 'resize_confirming'):
            LOG.info(_('revert resize now, here only stop vm.'))
            try:
                self.stop_vm(instance)
            except Exception as e:
                LOG.warn(_('stop vm failed, trigger rollback'))
                raise exception.InstanceFaultRollback(inner_exception=e)
            return

        try:
            fc_vm = FC_MGR.get_vm_by_uuid(instance)
        except exception.InstanceNotFound:
            LOG.warn(_('instance exist no more. ignore this deleting.'))
            return

        # detach volume created by cinder
        if block_device_info:
            LOG.info(_('now will stop vm before detach cinder volumes.'))
            self.stop_vm(instance)
            for vol in block_device_info['block_device_mapping']:
                self.detach_volume(vol['connection_info'], instance)

        # if vm is in fault-resuming or unknown status, stop it before delete
        if fc_vm.status == constant.VM_STATUS.UNKNOWN \
        or fc_vm.status == constant.VM_STATUS.FAULTRESUMING:
            LOG.debug(_("vm %s status is fault-resuming or unknown, "
                        "stop it before delete."), fc_vm.uri)
            self.stop_vm(instance)

        self._delete_vm_with_fc_vm(fc_vm, destroy_disks)

        # update affinity group info if needed
        try:
            self._update_drs_rules(instance)
            self._update_affinity_groups(context, instance)
        #ignore pylint:disable=W0703
        except Exception as excp:
            utils.log_exception(excp)
            LOG.error(_('update affinity group info failed !'))

    def clone_vm(self, instance, vm_config=None):
        """
        Clone vn in FC
        :param instance:
        :param vm_config:
        :return:
        """
        fc_vm = FC_MGR.get_vm_by_uuid(instance)
        return self.post(fc_vm.get_vm_action_uri('clone'), data=vm_config,
                         excp=fc_exc.InstanceCloneFailure)

    def modify_vm(self, instance, vm_config=None):
        """
        Modify vm config in FC
        :param instance:
        :param vm_config:
        :return:
        """
        fc_vm = FC_MGR.get_vm_by_uuid(instance)
        self.put(fc_vm.uri, data=vm_config, excp=fc_exc.InstanceModifyFailure)

    def live_migration(self, instance_ref, nodename):
        """Live migration of an instance to another host.

        :param instance_ref:
            nova.db.sqlalchemy.models.Instance object
            instance object that is migrated.
        :param nodename: destination node name

        """
        LOG.info(_("trying to migrate vm: %s.") % instance_ref['name'])

        # get destination cluster urn
        cluster_urn = self._cluster_ops.get_cluster_urn_by_nodename(nodename)
        if not cluster_urn:
            raise fc_exc.ClusterNotFound(cluster_name=nodename)
        LOG.debug(_("get cluster urn: %s."), cluster_urn)

        # generate migrate url and post msg to FC
        body = {
            'location': cluster_urn
        }
        fc_vm = FC_MGR.get_vm_by_uuid(instance_ref)
        self.post(fc_vm.get_vm_action_uri('migrate'), data=body,
                  excp=exception.MigrationError)
        LOG.info(_("migrate vm %s success" % fc_vm.name))

    def migrate_disk_and_power_off(self, instance, flavor):
        """
        modify the vm spec info
        :param instance:
            nova.db.sqlalchemy.models.Instance object
            instance object that is migrated.
        :param flavor:
        :return:
        """

        fc_vm = FC_MGR.get_vm_by_uuid(instance)
        if fc_vm.status == constant.VM_STATUS.UNKNOWN \
        or fc_vm.status == constant.VM_STATUS.FAULTRESUMING:
            LOG.debug(_("vm %s status is fault-resuming or unknown, "
                "can not do migrate or resize."), fc_vm.uri)
            raise exception.InstanceFaultRollback

        LOG.info(_("begin power off vm ..."))

        # 1.stop vm
        self.stop_vm(instance)

        # 2.save flavor and vol info in vm
        fc_vm = FC_MGR.get_vm_by_uuid(instance)
        old_flavor = self._gen_old_flavor_for_fc(fc_vm)
        new_flavor = self._gen_new_flavor_for_fc(flavor)
        flavor = {
            'old_flavor': old_flavor,
            'new_flavor': new_flavor
        }
        data = {
            'group': '%s:%s' % (constant.VM_GROUP_FLAG,
                                jsonutils.dumps(flavor))
        }
        self.modify_vm(fc_vm, vm_config=data)
        LOG.info(_("save flavor info success."))

        # 3. check cpu mem changes
        flavor = None
        if self._check_if_need_modify_vm_spec(old_flavor, new_flavor):
            flavor = new_flavor

        data = self._generate_vm_spec_info(flavor=flavor)
        self.modify_vm(fc_vm, vm_config=data)
        LOG.info(_("modify cpu and mem success."))

    def _get_flavor_from_group(self, group):
        """

        :param group:
        :return:
        """

        if not isinstance(group, str):
            group = str(group)

        flavor = ast.literal_eval(group[group.find(':')+1:])
        return flavor['old_flavor'], flavor['new_flavor']

    def finish_migration(self, instance, power_on=True):
        """

        :param instance:
        :param power_on:
        :return:
        """
        LOG.info(_("begin finish_migration ..."))

        fc_vm = FC_MGR.get_vm_by_uuid(instance)
        # update location
        location = self._cluster_ops.\
            get_cluster_urn_by_nodename(instance['node'])
        data = self._generate_vm_spec_info(location=location)
        self.modify_vm(fc_vm, vm_config=data)

        # power on vm if needed
        if power_on:
            self.start_vm(instance)

        LOG.info(_("modify location success, new location %s."), location)

    def _reset_vm_group(self, fc_vm):
        """

        :param fc_vm:
        :return:
        """

        data = {
            'group': constant.VM_GROUP_FLAG
        }
        self.modify_vm(fc_vm, vm_config=data)

    def finish_revert_migration(self, instance, power_on=True):
        """

        :param instance:
        :param power_on:
        :return:
        """

        LOG.info(_("begin finish_revert_migration ..."))

        # 1. get flavor info from fc
        fc_vm = FC_MGR.get_vm_by_uuid(instance)
        #ignore pylint:disable=W0612
        old_flavor, new_flavor = self._get_flavor_from_group(fc_vm.group)

        # 2. check cpu mem changes
        location = self._cluster_ops.\
            get_cluster_urn_by_nodename(instance['node'])
        data = self._generate_vm_spec_info(location=location,
                                           flavor=old_flavor)
        self.modify_vm(fc_vm, vm_config=data)
        LOG.info(_("modify cpu and mem success."))

        # 5. clear vm group info
        self._reset_vm_group(fc_vm)

        # 6. power on vm if needed
        if power_on:
            self.start_vm(instance)

    def confirm_migration(self, instance):
        """

        :param instance:
        :return:
        """

        LOG.info(_("begin confirm_migration ..."))

        # clear vm group info
        fc_vm = FC_MGR.get_vm_by_uuid(instance)
        self._reset_vm_group(fc_vm)

    def _check_if_need_modify_vm_spec(self, old_flavor, new_flavor):
        """
        Check if it is need to modify vm spec
        :param old_flavor:
        :param new_flavor:
        :return:
        """

        if not old_flavor or not new_flavor:
            return False

        old_quantity = old_flavor.get('vcpus', None)
        old_mem = old_flavor.get('memory_mb', None)
        old_reservation = old_flavor.get('reservation', None)
        old_weight = old_flavor.get('weight', None)
        old_limit = old_flavor.get('limit', None)

        new_quantity = new_flavor.get('vcpus', None)
        new_mem = new_flavor.get('memory_mb', None)
        new_reservation = new_flavor.get('reservation', None)
        new_weight = new_flavor.get('weight', None)
        new_limit = new_flavor.get('limit', None)

        if (old_quantity != new_quantity) \
           or (old_mem != new_mem) \
           or (old_reservation != new_reservation) \
           or (old_weight != new_weight) \
           or (old_limit != new_limit):
            return True

        return False

    def _get_sys_vol_from_vm_info(self, instance):
        """
        Get sys volume info from instance info
        :param instance:
        :return:
        """

        if not instance:
            return None

        for disk in instance['vmConfig']['disks']:
            if 1 == disk['sequenceNum']:
                return disk
        return None

    def _generate_vm_spec_info(self, location=None, flavor=None):
        """
        Generate the vm spec info for cole migration
        :param location:
        :param flavor:
        :return:
        """

        data = {}
        if location:
            data['location'] = location
        if flavor:
            if flavor.get('vcpus'):
                data['cpu'] = {
                    'quantity':flavor.get('vcpus')
                }

            if flavor.get('memory_mb'):
                data['memory'] = {
                    'quantityMB':flavor.get('memory_mb')
                }

            cpu_qos = utils.dict_filter_and_convert(flavor,
                                                    constant.CPU_QOS_FC_KEY,
                                                    constant.CPU_QOS_FC_KEY)
            if data.get('cpu', None):
                data['cpu'] = utils.dict_add(data['cpu'], cpu_qos)
            else:
                data['cpu'] = cpu_qos

        LOG.debug(_("vm spec data: %s.") % jsonutils.dumps(data))
        return data

    def _get_sys_vol_info(self, sys_vol):
        """

        :param sys_vol:
        :return:
        """
        return {
            'volUrn':sys_vol['volumeUrn'],
            'pciType':sys_vol['pciType'],
            'sequenceNum':1
        }

    def _gen_old_flavor_for_fc(self, instance):
        """

        :param instance:
        :return:
        """
        flavor_dict = {
            'vcpus':instance['vmConfig']['cpu']['quantity'],
            'memory_mb':instance['vmConfig']['memory']['quantityMB']
        }

        cpu_qos = utils.dict_filter_and_convert(instance['vmConfig']['cpu'],
                                                constant.CPU_QOS_FC_KEY,
                                                constant.CPU_QOS_FC_KEY)
        flavor_dict = utils.dict_add(flavor_dict, cpu_qos)
        return flavor_dict

    def _gen_new_flavor_for_fc(self, flavor):
        """

        :param flavor:
        :return:
        """
        flavor_dict = {
            'vcpus':flavor['vcpus'],
            'memory_mb':flavor['memory_mb']
        }
        extra_specs = flavor.get('extra_specs', None)
        if extra_specs:
            cpu_qos = utils.dict_filter_and_convert(extra_specs,
                                                    constant.CPU_QOS_NOVA_KEY,
                                                    constant.CPU_QOS_FC_KEY)
            flavor_dict = utils.dict_add(flavor_dict, cpu_qos)
        return flavor_dict

    def list_all_fc_instance(self):
        """
        List all vm info
        :return:
        """
        fc_all_vms = FC_MGR.get_all_vms(isTemplate='false',
            group=constant.VM_GROUP_FLAG)
        cluster_urn_list = self._cluster_ops.get_local_cluster_urn_list()
        result = []
        for fc_vm in fc_all_vms:
            if fc_vm['clusterUrn'] in cluster_urn_list:
                result.append(fc_vm)
        LOG.debug(_("after filtered by clusters, instance number is %d"),
            len(result))
        return result

    def get_vnc_console(self, instance, get_opt):
        """
        Get the vnc console information

        :param instance: the instance info
        :return: HuaweiConsoleVNC or ConsoleVNC
        """
        LOG.debug(_("start to get %s vnc console"), instance['name'])
        fc_vm = FC_MGR.get_vm_by_uuid(instance)
        host_ip = fc_vm.vncAcessInfo.get('hostIp', None)
        host_port = fc_vm.vncAcessInfo.get('vncPort', None)

        # raise exception if no information is provided
        if not host_port or not host_ip:
            raise exception.ConsoleNotFoundForInstance\
                (instance_uuid=instance['uuid'])

        if get_opt is False:
            LOG.debug(_("return vnc info is host: %s, port:%s,"
                        " internal_access_path: %s"),
                      host_ip, host_port, 'None')
            return ctype.ConsoleVNC(host=host_ip, port=host_port)

        password = fc_vm.vncAcessInfo.get('vncPassword', None)
        LOG.debug(_("return get vnc info is host: %s, port:%s,"
                    " internal_access_path: %s"),
                  host_ip, host_port, 'None')

        return hwtype.HuaweiConsoleVNC(host_ip, host_port, password, None)

    def attach_interface(self, instance, vif):
        """
        Send message to fusion compute virtual machine

        :param instance:
        :param vif:
        :return: response : {"taskUrn": string, "taskUri": string}
        """
        LOG.debug(_("trying to attach interface, vm name: %s,"
                    "vm uuid: %s, vif info: %s"), instance['name'],
                  instance['uuid'], vif)

        pg_urn = self._network_ops.ensure_network(vif['network'])
        vsp_body = {
            'name': vif['id'],
            'portId': vif['id'],
            'portGroupUrn': pg_urn,
            'mac': vif['address']
        }
        LOG.info("the vsp information is %s", vsp_body)

        fc_vm = FC_MGR.get_vm_by_uuid(instance)
        attach_interface_uri = fc_vm.get_vm_action_uri('nics')

        response = self.post(attach_interface_uri,
                             data=vsp_body,
                             excp=exception.InterfaceAttachFailed)
        LOG.info('send attach interface finished, return is: %s',
                 jsonutils.dumps(response))
        return response

    def detach_interface(self, instance, vif):
        """
        Send message to fusion compute virtual machine

        :param instance:
        :param vif:
        :return: response : {"taskUrn": string, "taskUri": string}
        if the nic does not exited, return {} else {"taskUrn": string,
        "taskUri": string}
        """
        LOG.debug(_("trying to detach interface for vm name: %s,"
                    "vm uuid: %s, vif information is %s"), instance['name'],
                  instance['uuid'], vif)

        response = {}
        fc_vm = FC_MGR.get_vm_by_uuid(instance)
        nics = fc_vm["vmConfig"]["nics"]
        LOG.info("nics in FusionCompute is %s", nics)
        nic_uri = None
        for nic in nics:
            if nic['name'] == vif['id']:
                nic_uri = nic['uri']
                break

        if nic_uri:
            detach_interface_uri = (nic_uri.replace("nics", "virtualNics"))
            LOG.info("detach_interface_uri is %s", detach_interface_uri)
            response = self.delete(detach_interface_uri,
                                   excp=exception.InstanceInvalidState)
        else:
            LOG.warn(_("detach interface for vm name: %s, not exist nic."),
                     instance['name'])
        LOG.info(_('send detach interface finished, return is: %s'),
                 jsonutils.dumps(response))
        return response

    def get_info(self, instance):
        """
        Get vm info from instance

        :param instance:
        :return:
        """
        fc_vm = FC_MGR.get_vm_state(instance)
        state = constant.VM_POWER_STATE_MAPPING.get(fc_vm.status,
            power_state.NOSTATE)
        return {'state': state}

    def get_instances_info(self):
        """
        Get all instances info from FusionCompute
        :return:
        """
        return FC_MGR.get_all_vms_info()

    def _check_if_vol_in_instance(self, instance, vol_urn):
        """

        :param instance: fc vm
        :param vol_urn:
        :return:
        """
        for vol in instance['vmConfig']['disks']:
            if vol_urn == vol['volumeUrn']:
                return True
        return False

    def _get_vol_urn_from_connection(self, connection_info):
        """

        :param connection_info:
        :return:
        """
        vol_urn = connection_info.get('vol_urn')
        if vol_urn is None:
            msg = (_("invalid connection_info: %s."), connection_info)
            raise exception.Invalid(msg)
        return vol_urn

    def _volume_action(self, action, vol_urn, fc_vm, mountpoint=None):
        """

        :param action: attach or detach
        :param vol_urn:
        :param fc_vm:
        :return:
        """

        if mountpoint is None:
            body = {
                'volUrn':vol_urn
            }
        else:
            body = {
                'volUrn':vol_urn,
                'sequenceNum':constant.MOUNT_DEVICE_SEQNUM_MAP[mountpoint]
            }

        action(fc_vm, vol_config=body)

    def attach_volume(self, connection_info, instance, mountpoint):
        """
        Attach volume for vm
        :param connection_info:
        :param instance:
        :return:
        """
        LOG.info(_("trying to attach vol for vm: %s.") % instance['name'])
        # 0. set qos io
        self._volume_ops.set_qos_specs_to_volume(connection_info)

        # 1. volume can only be attached when vm is running or stopped
        fc_vm = FC_MGR.get_vm_by_uuid(instance)
        if fc_vm.status not in [constant.VM_STATUS.RUNNING,
                                constant.VM_STATUS.STOPPED]:
            reason = _("vm status is not running or stopped !")
            raise fc_exc.InstanceAttachvolFailure(reason=reason)

        # 2. ignore this op when vm already has this volume
        vol_urn = self._get_vol_urn_from_connection(connection_info)
        if self._check_if_vol_in_instance(fc_vm, vol_urn) is True:
            LOG.info(_("vm %s already has vol %s, consider it success"),
                     fc_vm.name, vol_urn)
            return

        # 3. attach this volume
        self._volume_action(self._volume_ops.attach_volume,
                            vol_urn, fc_vm, mountpoint)

    def detach_volume(self, connection_info, instance):
        """
        Detach volume for vm
        :param connection_info:
        :param instance:
        :return:
        """
        LOG.info(_("trying to detach vol for vm: %s.") % instance['name'])

        # 1. volume can only be detached when vm is running or stopped
        fc_vm = FC_MGR.get_vm_by_uuid(instance)
        if fc_vm.status not in [constant.VM_STATUS.RUNNING,
                                constant.VM_STATUS.STOPPED]:
            reason = _("vm status is not running or stopped !")
            raise fc_exc.InstanceDetachvolFailure(reason=reason)

        # 2. ignore this op when vm do not have this volume
        vol_urn = self._get_vol_urn_from_connection(connection_info)
        if self._check_if_vol_in_instance(fc_vm, vol_urn) is False:
            LOG.info(_("vol %s is not in vm %s, consider it success"),
                     vol_urn, fc_vm.name)
            return

        # 3. detach this volume
        self._volume_action(self._volume_ops.detach_volume, vol_urn, fc_vm)

    def _generate_image_metadata(self, name, location, fc_vm, instance):
        """

        :param name: image name
        :param location: image location
        :param fc_vm: fc instance
        :param instance:
        :return:
        """

        os_type = fc_vm['osOptions']['osType']
        os_version = str(fc_vm['osOptions']['osVersion'])

        metadata = {
            'is_public': False,
            'status': 'active',
            'name': name or '',
            'size': constant.TEMPLATE_VHD_SIZE,
            'disk_format': 'vhd',
            'container_format': 'bare',
            'properties': {
                'image_state': 'available',
                'owner_id': instance['project_id'],
                constant.HUAWEI_OS_TYPE: os_type,
                constant.HUAWEI_OS_VERSION:
                    constant.HUAWEI_OS_VERSION_STR[os_type][os_version],
                constant.HUAWEI_IMAGE_LOCATION: location or '',
                constant.HUAWEI_IMAGE_TYPE: 'nfs'
                }
        }

        if instance['kernel_id']:
            metadata['properties']['kernel_id'] = instance['kernel_id']
        if instance['ramdisk_id']:
            metadata['properties']['ramdisk_id'] = instance['ramdisk_id']

        return metadata

    def _generate_image_location(self, image_id):
        """
        generate image location: '172.17.1.30:/image/base/uuid/uuid.ovf'
        :param image_id:
        :return:
        """
        if constant.CONF.fusioncompute.fc_image_path:
            return '%s/%s/%s.ovf' % (constant.CONF.fusioncompute.fc_image_path,
                                     image_id,
                                     image_id)
        else:
            return None

    def snapshot(self, context, instance, image_href, update_task_state):
        """
        Create sys vol image and upload to glance
        :param instance:
        :param image_href:
        :param update_task_state:
        :return:
        """

        if not constant.CONF.fusioncompute.fc_image_path:
            LOG.error(_("config option fc_image_path is None."))
            raise fc_exc.InvalidImageDir()

        # 0.get image service and image id
        _image_service = glance.get_remote_image_service(context, image_href)
        snapshot_image_service, image_id = _image_service

        # 1.import sys vol to nfs dir
        LOG.info(_("begin uploading sys vol to glance ..."))
        fc_vm = FC_MGR.get_vm_by_uuid(instance)
        sys_vol = self._get_sys_vol_from_vm_info(fc_vm)
        if not sys_vol:
            raise exception.DiskNotFound(_("can not find sys volume."))

        update_task_state(task_state=task_states.IMAGE_PENDING_UPLOAD)
        self._volume_ops.create_image_from_volume(self.site.volume_uri,
                                                  sys_vol,
                                                  image_id)

        # 2.update image metadata
        LOG.info(_("begin update image metadata ..."))
        update_task_state(task_state=task_states.IMAGE_UPLOADING,
                          expected_state=task_states.IMAGE_PENDING_UPLOAD)

        name = snapshot_image_service.show(context, image_id).get('name')
        location = self._generate_image_location(image_id)
        metadata = self._generate_image_metadata(name,
                                                 location,
                                                 fc_vm,
                                                 instance)
        snapshot_image_service.update(context, image_id, metadata)

    def reconfigure_affinity_group(self, instances, affinity_group, action,
                                   node=None):
        """

        :param instances:
        :param affinity_group:
        :param action:
        :param node:
        :return:
        """

        LOG.info(_("begin reconfigure affinity group ..."))

        # 1. all vms passed in should in the same cluster
        if node is None and len(instances) > 0:
            node = instances[0].get('node')

        if node is None:
            msg = _("Can not get any node info !")
            raise fc_exc.AffinityGroupException(reason=msg)

        for instance in instances:
            if node != instance.get('node'):
                msg = _("VMs cluster must be same !")
                raise fc_exc.AffinityGroupException(reason=msg)

        # 2. get fc cluster object
        cluster = self._cluster_ops.get_cluster_detail_by_nodename(node)
        if cluster is None:
            raise fc_exc.ClusterNotFound(cluster_name=node)

        # 3. do reconfigure
        rule_name = str(affinity_group.id)
        rule_type = constant.DRS_RULES_TYPE_MAP.get(affinity_group.type) or \
                    constant.DRS_RULES_TYPE_MAP['affinity']

        if action == 'remove':
            self._cluster_ops.delete_drs_rules(cluster, rule_name, rule_type)
            LOG.info(_("delete affinity group success and return"))
            return

        if action == 'add':
            self._cluster_ops.create_drs_rules(cluster, rule_name, rule_type)
            cluster = self._cluster_ops.get_cluster_detail_by_nodename(node)
            LOG.info(_("create affinity group success"))

        vms = []
        for instance in instances:
            instance['uuid'] = instance['name']
            fc_vm = FC_MGR.get_vm_by_uuid(instance)
            vm_info = {
                'urn': fc_vm['urn'],
                'name': fc_vm['name']
            }
            vms.append(vm_info)

        try:
            self._cluster_ops.\
                modify_drs_rules(cluster, rule_name, rule_type, vms)
        except Exception as exc:
            LOG.error(_("modify drs rules failed !"))
            if action == 'add':
                self._cluster_ops.\
                    delete_drs_rules(cluster, rule_name, rule_type)
            raise exc

        LOG.info(_("reconfigure affinity group success"))
