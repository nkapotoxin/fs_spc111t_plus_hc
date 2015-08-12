import copy

from oslo.config import cfg

from nova.compute.api import *
from nova.compute.manager import wrap_instance_event
from nova.compute.manager import wrap_instance_fault
from nova.openstack.common.gettextutils import _
from nova.openstack.common import jsonutils
from nova.openstack.common import loopingcall
from nova.huawei.compute import rpcapi as hw_rpcapi
from nova.huawei.compute import instance_actions as hw_actions
from nova.scheduler import utils as scheduler_utils
from nova.scheduler import rpcapi as scheduler_rpcapi
from nova import conductor
from nova import objects
from nova.huawei import exception as hw_exception

compute_opts = [
    cfg.BoolOpt('allow_reschedule_to_same_host',
                default=False,
                help='Allow destination machine to match source for reschedule.'),
]

CONF = cfg.CONF
CONF.register_opts(compute_opts)


class HuaweiAPI(API):
    def __init__(self, image_api=None, network_api=None, volume_api=None,
                 security_group_api=None, **kwargs):
        super(HuaweiAPI, self).__init__(
            image_api, network_api,
            volume_api, security_group_api, **kwargs)
        self.conductor_api = conductor.API()
        self.compute_rpcapi = hw_rpcapi.HuaweiComputeAPI()
        self.scheduler_rpcapi = scheduler_rpcapi.SchedulerAPI()

    def _check_port_in_metadata_requested_network(self, context, metadata,
                                                  requested_networks):
        port_set = set()
        requested_networks = requested_networks or []
        for requested_network in requested_networks:
            port_id = requested_network.port_id
            if port_id:
                port_set.add(port_id)

        for key, value in metadata.iteritems():
            key = key.strip()
            if key.startswith('vnic_info'):
                try:
                    ktitle, port_id = key.split(':')
                    if ktitle != 'vnic_info':
                        raise hw_exception.BandwidthInfoError(
                                        _("Bandwidth info format not correct"))
                    self.network_api.show_port(context, port_id)
                    if port_id not in port_set:
                        LOG.error(_('Port info in metadata and '
                                    'requested_network not match'))
                        raise hw_exception.BandwidthInfoError()
                    vtitle, bandwidth = value.strip().split(':')
                    if vtitle != 'bandwidth':
                        raise hw_exception.BandwidthInfoError(
                                        _("Bandwidth info format not correct"))
                    if int(bandwidth) < 0:
                        LOG.error(_('Bandwidth must be greater than 0'))
                        raise hw_exception.BandwidthInfoError(
                                        _("Bandwidth must be greater than 0"))
                except hw_exception.BandwidthInfoError, e:
                    raise e
                except:
                    raise hw_exception.BandwidthInfoError(
                                        _("Bandwidth info format not correct"))

    def _validate_and_build_base_options(self, context, instance_type,
                                         boot_meta, image_href, image_id,
                                         kernel_id, ramdisk_id, display_name,
                                         display_description, key_name,
                                         key_data, security_groups,
                                         availability_zone, forced_host,
                                         user_data, metadata, injected_files,
                                         access_ip_v4, access_ip_v6,
                                         requested_networks, config_drive,
                                         block_device_mapping,
                                         auto_disk_config, reservation_id,
                                         max_count):
        base_options, max_network_count = super(HuaweiAPI, self).\
                    _validate_and_build_base_options(
                        context, instance_type,
                        boot_meta, image_href, image_id,
                        kernel_id, ramdisk_id, display_name,
                        display_description, key_name,
                        key_data, security_groups,
                        availability_zone, forced_host,
                        user_data, metadata, injected_files,
                        access_ip_v4, access_ip_v6,
                        requested_networks, config_drive,
                        block_device_mapping,
                        auto_disk_config, reservation_id,
                        max_count)

        self._check_port_in_metadata_requested_network(context, metadata,
                                                       requested_networks)

        base_options.update({"forced_host" : forced_host})
        # get physical network information
        physical_networks = self.network_api.get_physical_network(
            context, requested_networks)

        if len(physical_networks.get("network")) > 0:
            # check the huge pages memory if the evs instance is created.
            extra_specs = instance_type['extra_specs']
            mem_page_size = extra_specs.get("hw:mem_page_size")
            if not mem_page_size:
                msg = ('huge pages memory size must be set in '
                       'flavor extra specs when evs instance is created')
                raise exception.Invalid(msg)

        base_options['physical_network'] = physical_networks['network']

        return base_options, max_network_count

    def _provision_instances(self, context, instance_type, min_count,
            max_count, base_options, boot_meta, security_groups,
            block_device_mapping, shutdown_terminate,
            instance_group, check_server_group_quota):
        """
        Set the force_host in instance metadata.
        """
        physical_network = {}
        physical_network['network'] = base_options.pop('physical_network')
        instances = super(HuaweiAPI, self).\
                        _provision_instances(context, instance_type,
                                             min_count, max_count,
                                             base_options, boot_meta,
                                             security_groups, block_device_mapping,
                                             shutdown_terminate, instance_group,
                                             check_server_group_quota)

        for instance in instances:
            force_host = base_options.get("forced_host", None)
            if force_host:
                _metadata = {"force_host" : force_host}
                self.db.instance_metadata_update(context, instance['uuid'],
                                             _metadata, False)

            # record physical network info to HuaweiInstanceExtra
            objects.HuaweiInstanceExtra(instance_uuid=instance.uuid,
                stats=jsonutils.dumps(physical_network)).create(context)

        return instances

    def get_network_info(self, context, instance):
        if (not hasattr(instance, 'system_metadata') or
                len(instance['system_metadata']) == 0):
            # NOTE: Several places in the code look up instances without
            # pulling system_metadata for performance, and call this function.
            # If we get an instance without it, re-fetch so that the call
            # to network_api (which requires it for instance_type) will
            # succeed.
            instance = self.conductor_api.instance_get_by_uuid(
                context, instance['uuid'])
        network_info = self.network_api.get_instance_nw_info(context,
                                                             instance)
        return network_info

    def judge_branch(self, context, instance, rq_network):
        """If the request_network is not null and the network_info is
            null,means creating a network failure,so recreate"""
        network_info = self.get_network_info(context, instance)

        if rq_network and not network_info:
            return False
        return True

    @wrap_instance_event
    @wrap_instance_fault
    def _select_destinations(self, context, instance, request_spec,
                             filter_properties):
        return self.scheduler_rpcapi.select_destinations(
            context, request_spec, filter_properties)

    @wrap_instance_event
    @wrap_instance_fault
    def _try_local_reboot(self, context, instance, reboot_type):
        service = objects.Service.get_by_args(context, instance['host'],
                                              'nova-compute')
        if not self.servicegroup_api.service_is_up(service):
            LOG.info('compute service seems down, give up local hard reboot',
                     instance=instance)
            return

        # generate a new request id
        copied_context = copy.deepcopy(context)
        copied_context.request_id = 'req-' + str(uuid.uuid4())
        super(HuaweiAPI, self).reboot(copied_context, instance, reboot_type)

    @wrap_check_policy
    @check_instance_lock
    @check_instance_cell
    @check_instance_state(task_state=None,
                          must_have_launched=False)
    def reschedule(self, context, instance):
        """Rescheduler the given instance."""

        # if reschedule process rebuild, instance is possibly in REBUILD- task
        # state for a long time, or just stuck in the task state, while a
        # second reschedule request triggered if vm status is ERROR or the host
        # is fault, we should ignore this kind of duplicated request
        if instance['task_state'] in (
                task_states.REBUILDING,
                task_states.REBUILD_BLOCK_DEVICE_MAPPING,
                task_states.REBUILD_SPAWNING,
                task_states.DELETING):
            LOG.warning(_('instance task_state is %s, ignore this request'),
                        instance['task_state'], instance=instance)
            return

        LOG.info('reschedule instance', instance=instance)

        orig_image_ref = instance['image_ref'] or ''

        current_instance_type = flavors.extract_flavor(instance)

        # Ignore current host
        filter_properties = {'ignore_hosts': []}
        if not CONF.allow_reschedule_to_same_host:
            filter_properties['ignore_hosts'].append(instance['host'])

        image_ref = instance.image_ref
        image = compute_utils.get_image_metadata(
            context, self.image_api, image_ref, instance)

        request_spec = scheduler_utils.build_request_spec(
            context, image, [instance], instance_type=current_instance_type)

        # Get scheduler_hint info
        inst_extra = objects.HuaweiInstanceExtra.get_by_instance_uuid(
            context, instance.uuid)
        injected_files = self.db.injected_files_get_by_instance_uuid(
            context, instance.uuid)
        request_networks = []
        if inst_extra:
            scheduler_hints = jsonutils.loads(inst_extra.scheduler_hints or '{}')
            request_networks = jsonutils.loads(inst_extra.request_network or '[]')
        else:
            scheduler_hints = {}
        pci_requests = objects.InstancePCIRequests.\
            get_by_instance_uuid_and_newness(
                context, instance['uuid'], False)
        if pci_requests:
            filter_properties['pci_requests'] = pci_requests
        filter_properties['scheduler_hints'] = scheduler_hints

        LOG.info("reschedule filter_properties %s",
                 filter_properties, instance=instance)

        self._record_action_start(context, instance,
                                  hw_actions.RESCHEDULE)
        try:
            hosts = self._select_destinations(context,
                                              instance,
                                              request_spec,
                                              filter_properties)
            host_state = hosts[0]['host']
            LOG.info("HA selected host %s", host_state, instance=instance)
        except exception.NoValidHost as ex:
            LOG.warning(_("No valid host found"), instance=instance)

            if instance['host']:
                self._try_local_reboot(context, instance, 'HARD')

            return

        bdms = objects.BlockDeviceMappingList.get_by_instance_uuid(
            context, instance.uuid)
        LOG.info("instance bdms %s", jsonutils.to_primitive(bdms),
                 instance=instance)

        scheduler_utils.populate_filter_properties(filter_properties,
                                                   hosts[0])

        def _get_network_info(nw_info):
            pci_req_id = None
            if len(nw_info) > 3:
                pci_req_id = nw_info[3]
            return (nw_info[0], nw_info[1], nw_info[2], pci_req_id)

        request_networks = [_get_network_info(n) for n in request_networks]

        alive_dict = {'alive': False, 'fault': False, 'count': 0}

        def async_check_live():
            try:
                self.compute_rpcapi.check_alive(context, host_state,
                                            'nova-api')
                alive_dict['alive'] = True
            except Exception as e:
                LOG.error(_LE('check alive fault, host %s, %s'),
                          host_state, e)
                alive_dict['fault'] = True

        def _loop_check():
            if alive_dict['fault']:
                raise loopingcall.LoopingCallDone()

            if alive_dict['alive']:
                LOG.debug('compute service alive, host %s', host_state,
                          instance=instance)
                raise loopingcall.LoopingCallDone()

            if alive_dict['count'] == 120:
                LOG.debug('check alive timeout, host %s', host_state,
                          instance=instance)
                raise loopingcall.LoopingCallDone()

            alive_dict['count'] += 1
        
        # Clear the resource of instance on the source host
        if instance['host'] and self.judge_branch(context, instance, request_networks):
            instance.task_state = task_states.REBUILDING
            instance.save()

            # in some extreme case rpc message will stack on HA dest host, to
            # avoid that we change rpc api build_and_run_instance to sync
            # 'call' instead of async 'cast', but we can't block outside
            # request, so use async way to call rpc method
            def _async_reschedule():
                # check dest compute service is alive
                utils.spawn_n(async_check_live)
                timer = loopingcall.FixedIntervalLoopingCall(_loop_check)
                timer.start(interval=1).wait()

                if not alive_dict['alive']:
                    LOG.warn('%s compute service seems down, revert instance '
                             'task state', host_state, instance=instance)
                    instance.task_state = None
                    instance.save()
                    return

                LOG.info('reschedule instance to host %s', host_state,
                         instance=instance)
                try:
                    self.compute_rpcapi.sync_reschedule_instance(
                        context, instance=instance, new_pass=None,
                        injected_files=jsonutils.loads(injected_files),
                        image_ref=image_ref,
                        orig_image_ref=orig_image_ref, orig_sys_metadata=None,
                        bdms=bdms, host=host_state,
                        filter_properties=filter_properties)
                except Exception as e:
                    LOG.error(_LE('reschedule call failed: %s'), e)
                    self.db.instance_update(context, instance.uuid,
                                            task_state=None)

            utils.spawn_n(_async_reschedule)
        else:
            security_groups = self.db.security_group_get_by_instance(
                context, instance.uuid)
            block_device_mapping = \
                self.db.block_device_mapping_get_all_by_instance(
                    context, instance.uuid)
            request_spec.update({'block_device_mapping': block_device_mapping,
                                 'security_group': security_groups})

            # TODO(): Remove this in version 2.0 of the RPC API
            if (request_networks and
                not isinstance(request_networks,
                               objects.NetworkRequestList)):
                request_networks = objects.NetworkRequestList(
                objects=[objects.NetworkRequest.from_tuple(t)
                         for t in request_networks])

            # in some extreme case rpc message will stack on HA dest host, to
            # avoid that we change rpc api build_and_run_instance to sync
            # 'call' instead of async 'cast', but we can't block outside
            # request, so use async way to call rpc method
            def _async_build_and_run_instance():
                # check dest compute service is alive
                utils.spawn_n(async_check_live)
                timer = loopingcall.FixedIntervalLoopingCall(_loop_check)
                timer.start(interval=1).wait()

                if not alive_dict['alive']:
                    LOG.warn('%s compute service seems down, revert instance '
                             'task state', host_state, instance=instance)
                    instance.task_state = None
                    instance.save()
                    return

                LOG.info('build instance on host %s', host_state,
                         instance=instance)
                self.compute_rpcapi.sync_build_and_run_instance(
                    context, instance=instance, host=host_state, image=image,
                    request_spec=request_spec,
                    filter_properties=filter_properties,
                    admin_password=None,
                    injected_files=jsonutils.loads(injected_files),
                    requested_networks=request_networks,
                    security_groups=security_groups,
                    block_device_mapping=bdms, node=host_state,
                    limits=hosts[0]['limits'])

            utils.spawn_n(_async_build_and_run_instance)

    def resize(self, context, instance, flavor_id=None,
               **extra_instance_updates):
        # check evs instance's flavor enable huge memory pages
        if flavor_id:
            inst_extra = objects.HuaweiInstanceExtra.get_by_instance_uuid(
                context, instance.uuid)
            stats = jsonutils.loads(inst_extra.stats, '{}')
            physical_network_info = stats.get("network")
            if len(physical_network_info) > 0:
                instance_flavor = flavors.get_flavor_by_flavor_id(
                        flavor_id, read_deleted="no")
                # check the huge pages memory if the evs instance is created.
                extra_specs = instance_flavor.get("extra_specs")
                mem_page_size = extra_specs.get("hw:mem_page_size")
                if not mem_page_size:
                    msg = ('huge pages memory size must be set in '
                           'flavor extra specs when it is an evs instance')
                    raise exception.NoValidHost(msg)

        super(HuaweiAPI, self).resize(context, instance, flavor_id,
                                      **extra_instance_updates)