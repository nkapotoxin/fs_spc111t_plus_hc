
from oslo.config import cfg

from nova import exception
from nova.objects import base as objects_base
from nova.openstack.common.gettextutils import _
from nova.openstack.common import jsonutils
from nova.compute.rpcapi import *


def _compute_host(host, instance):
    '''Get the destination host for a message.

    :param host: explicit host to send the message to.
    :param instance: If an explicit host was not specified, use
                     instance['host']

    :returns: A host
    '''
    if host:
        return host
    if not instance:
        raise exception.NovaException(_('No compute host specified'))
    if not instance['host']:
        raise exception.NovaException(_('Unable to find host for '
                                        'Instance %s') % instance['uuid'])
    return instance['host']


class HuaweiComputeAPI(ComputeAPI):
    def __init__(self):
        super(HuaweiComputeAPI, self).__init__()

    def reschedule_instance(self, ctxt, instance, new_pass, injected_files,
                            image_ref, orig_image_ref, orig_sys_metadata, bdms,
                            recreate=False, on_shared_storage=False, host=None,
                            filter_properties={}):
        version = '3.35'
        cctxt = self.client.prepare(server=_compute_host(host, instance),
                                    version=version)
        cctxt.cast(ctxt, 'reschedule_instance',
                   instance=instance, new_pass=new_pass,
                   injected_files=injected_files, image_ref=image_ref,
                   orig_image_ref=orig_image_ref,
                   orig_sys_metadata=orig_sys_metadata, bdms=bdms,
                   recreate=recreate, on_shared_storage=on_shared_storage,
                   host=host, filter_properties=filter_properties)

    def check_alive(self, ctxt, host, from_host):
        version = '3.35'
        cctxt = self.client.prepare(server=host, version=version)

        cctxt.call(ctxt, 'check_alive', from_host=from_host)

    def sync_reschedule_instance(self, ctxt, instance, new_pass,
                                 injected_files,
                                 image_ref, orig_image_ref, orig_sys_metadata,
                                 bdms,
                                 recreate=False, on_shared_storage=False,
                                 host=None,
                                 filter_properties={}):
        version = '3.35'
        cctxt = self.client.prepare(server=_compute_host(host, instance),
                                    version=version)
        cctxt.call(ctxt, 'reschedule_instance',
                   instance=instance, new_pass=new_pass,
                   injected_files=injected_files, image_ref=image_ref,
                   orig_image_ref=orig_image_ref,
                   orig_sys_metadata=orig_sys_metadata, bdms=bdms,
                   recreate=recreate, on_shared_storage=on_shared_storage,
                   host=host, filter_properties=filter_properties)

    def sync_build_and_run_instance(self, ctxt, instance, host, image,
                                    request_spec,
                                    filter_properties, admin_password=None,
                                    injected_files=None,
                                    requested_networks=None,
                                    security_groups=None,
                                    block_device_mapping=None, node=None,
                                    limits=None):
        version = '3.33'
        if not self.client.can_send_version(version):
            version = '3.23'
            if requested_networks is not None:
                requested_networks = [(network_id, address, port_id)
                                      for (network_id, address, port_id, _) in
                                      requested_networks.as_tuples()]

        cctxt = self.client.prepare(server=host, version=version)
        cctxt.call(ctxt, 'build_and_run_instance', instance=instance,
                   image=image, request_spec=request_spec,
                   filter_properties=filter_properties,
                   admin_password=admin_password,
                   injected_files=injected_files,
                   requested_networks=requested_networks,
                   security_groups=security_groups,
                   block_device_mapping=block_device_mapping, node=node,
                   limits=limits)

    def delete_localinstance(self, ctxt, instance, bdms, host=None):
        version = '3.35'
        cctxt = self.client.prepare(server=_compute_host(host, instance),
                                    version=version)
        cctxt.cast(ctxt, 'delete_localinstance',
                   instance=instance, bdms=bdms)

    # added for vmware affinity_group
    def add_vms_to_affinity_group(self, ctxt, affinity_group_id, instances):
        instances_p = []
        for instance in instances:
            instance_p = jsonutils.to_primitive(instance)
            instances_p.append(instance_p)
        instance = instances_p[0]
        cctxt = self.client.prepare(server=_compute_host(None, instance),
                                    version='3.35')
        cctxt.cast(ctxt, 'add_vms_to_affinity_group',
                   affinity_group_id=affinity_group_id,
                   instances=instances_p)

    # added for vmware affinity_group
    def remove_vms_from_affinity_group(self, ctxt, affinity_group_id,
                                       instances):
        instances_p = []
        for instance in instances:
            instance_p = jsonutils.to_primitive(instance)
            instances_p.append(instance_p)
        instance = instances_p[0]
        cctxt = self.client.prepare(server=_compute_host(None, instance),
                                    version='3.35')
        cctxt.cast(ctxt, 'remove_vms_from_affinity_group',
                   affinity_group_id=affinity_group_id,
                   instances=instances_p)

    # added for vmware nic update ip
    def update_vif_pg_info(self, ctxt, instance):
        instance_p = jsonutils.to_primitive(instance)
        cctxt = self.client.prepare(server=_compute_host(None, instance),
                                    version='3.35')
        cctxt.cast(ctxt, 'update_vif_pg_info', instance=instance_p)
