# -*- encoding: utf-8 -*-

import traceback

from nova import exception
from nova.virt.ironic import driver as ironic_driver
from nova.huawei.virt.ironic import rpcapi
from nova.openstack.common import importutils
from nova.i18n import _
from nova.i18n import _LE
from nova.virt.ironic import client_wrapper
from nova.openstack.common import log as logging
from oslo.config import cfg
from nova.i18n import _LW
from nova.virt.ironic import ironic_states
from nova.openstack.common import uuidutils
from nova.openstack.common import jsonutils
from nova.openstack.common import loopingcall
from nova.huawei.objects import ironic_volume as ironicvolume_obj
from nova import context as nova_context

LOG=logging.getLogger(__name__)
ironic = None

cps_opts = [
    cfg.StrOpt('baremetal_network_type',
               default="virtual",
               help='the baremetal network type'),
    cfg.IntOpt('clean_local_disk_retry_times',
               default=6,
               help='clean_local_disk retry times during destroy')
]

CONF = cfg.CONF
CONF.register_opts(cps_opts)


def _validate_instance_and_node(icli, instance):
    """Get the node associated with the instance.

    Check with the Ironic service that this instance is associated with a
    node, and return the node.
    """
    try:
        return icli.call("node.get_by_instance_uuid", instance['uuid'])
    except ironic.exc.NotFound:
        raise exception.InstanceNotFound(instance_id=instance['uuid'])

class IronicDriver(ironic_driver.IronicDriver):

    def __init__(self, virtapi, read_only=False):
        super(IronicDriver, self).__init__(virtapi, read_only)
        self.ironicAgent = rpcapi.ironicAgentApi()

        global ironic
        if ironic is None:
            ironic = importutils.import_module('ironicclient')
            if not hasattr(ironic, 'exc'):
                ironic.exc = importutils.import_module('ironicclient.exc')
            if not hasattr(ironic, 'client'):
                ironic.client = importutils.import_module(
                    'ironicclient.client')

    def _transfer_instance_to_node(self, instance):
        node_uuid = instance.get('node')
        if not node_uuid:
            raise ironic.exc.BadRequest(
                _("Ironic node uuid not supplied to "
                  "driver for instance %s.") % instance['uuid'])

        iCli = client_wrapper.IronicClientWrapper()
        node = iCli.call("node.get", node_uuid)
        return node

    def detach_volume(self, connection_info, instance, mountpoint,
                      encryption=None):
        LOG.debug(_("detach_volume start, connection_info=%s, instance=%s, mp=%s")
                    %(connection_info, instance, mountpoint))
        node = self._transfer_instance_to_node(instance)
        hostId = node.extra.get('cps_id')
        LOG.debug(_("detach_volume host_id=%s" % hostId))
        kwargs = {"connection_info": connection_info,
                  "instance": instance,
                  "mountpoint": mountpoint,
                  "encryption": encryption
        }

        self.ironicAgent.detach_volume(hostId, kwargs)
        LOG.debug(_("detach_volume end"))

    def attach_volume(self, context, connection_info, instance, mountpoint,
                      disk_bus=None, device_type=None, encryption=None):
        try:
            LOG.debug(_("attach_volume start, connection_info=%s, instance=%s, mp=%s")
                        %(connection_info, instance, mountpoint))
            node = self._transfer_instance_to_node(instance)
            hostId = node.extra.get('cps_id')

            LOG.debug(_("attach_volume host_id=%s" % hostId))
            kwargs = {"connection_info": connection_info,
                      "instance": instance,
                      "mountpoint": mountpoint,
                      "disk_bus": disk_bus,
                      "device_type": device_type,
                      "encryption": encryption
            }

            conn_info = self.ironicAgent.attach_volume(hostId, kwargs)
            connection_info['data']['device_path'] = conn_info['data']['device_path']
            connection_info['data']['devices'] = conn_info['data']['devices']
            LOG.debug(_("attach_volume end"))
        except Exception as ex:
            LOG.exception(_LE("attach_volume ironic-proxy exception:%s" % ex))
            self.detach_volume(connection_info, instance, mountpoint, encryption)
            raise

    def create_ironic_volume(self,context, node_uuid, connector):
        volumeConnector = ironicvolume_obj.VolumeConnector()
        volumeConnector.node_uuid = node_uuid
        volumeConnector.connector = jsonutils.dumps(connector)

        volumeConnector.create(context)

    def get_volume_connector(self, instance):
        LOG.debug(_("get_volume_connector instance=%s" % instance))

        node = self._transfer_instance_to_node(instance)

        context = nova_context.get_admin_context()
        ironicVol = None
        try:
            ironicVol = ironicvolume_obj.VolumeConnector.get_by_id(context, node.uuid)
        except Exception as e:
            LOG.debug("get connector form db have no data: %s" % str(e))

        if ironicVol:
            connector_info = jsonutils.loads(ironicVol.connector)
        else:
            hostId = node.extra.get('cps_id')
            kwargs = {"instance": instance}
            connector_info = self.ironicAgent.get_volume_connector(hostId, kwargs)
            
            try:
                self.create_ironic_volume(context, node.uuid, connector_info)
            except Exception as e:
                LOG.exception(_LE("attach_volume ironic-proxy exception:%s" % str(e)))

        LOG.debug(_("get_volume_connector end connector_info=%s" % connector_info))

        return connector_info

    def _attach_interface_physical(self, instance, image_meta, vif):
        icli = client_wrapper.IronicClientWrapper()
        try:
            node = icli.call("node.get", instance['node'])
        except ironic.exc.NotFound:
            return None
        ports = icli.call("node.list_ports", node.uuid)

        try:
            for p in ports:
                port = icli.call("port.get", p.uuid)
                if port.extra.get('type', None) == 'pxe':
                    continue

                port_id = unicode(vif['id'])
                patch = [{'op': 'add',
                          'path': '/extra/vif_port_id',
                          'value': port_id}]
                icli.call("port.update", p.uuid, patch)
                break
        except Exception as e:
            LOG.error(_("Error plugging vif: %s, instance is %s, "
                        "Traceback is %s")
                      % (e, instance['uuid'], traceback.format_exc()))
            self._detach_interface_physical(instance, vif)
            raise exception.InterfaceAttachFailed(
                instance_uuid=instance['uuid'])

    def _detach_interface_physical(self, instance, vif):
        icli = client_wrapper.IronicClientWrapper()
        try:
            node = icli.call("node.get", instance['node'])
        except ironic.exc.NotFound:
            return None
        ports = icli.call("node.list_ports", node.uuid)

        try:
            for p in ports:
                port = icli.call("port.get", p.uuid)
                port_id = unicode(vif['id'])
                if port.extra.get('vif_port_id', None) == port_id:
                    patch = [{'op': 'remove',
                              'path': '/extra/vif_port_id',
                              'value': port_id}]
                    icli.call("port.update", p.uuid, patch)
                    break
        except Exception as e:
            LOG.error(_("Error unplugging vif: %s, instance is %s, "
                      "Traceback is %s")
                      % (e, instance['uuid'], traceback.format_exc()))
            raise exception.InterfaceDetachFailed(
                instance_uuid=instance['uuid'])

    def _attach_interface_virtual(self, instance, image_meta, vif):
        node = self._transfer_instance_to_node(instance)
        host_id = node.extra.get('cps_id')

        kwargs = {"instance": instance,
                  "image_meta": image_meta,
                  "vif": vif}
        try:
            self.ironicAgent.attach_interface(host_id, kwargs)
        except Exception as e:
            LOG.error(_("Error plugging vif: %s, instance is %s, "
                        "Traceback is %s")
                      % (e, instance['uuid'], traceback.format_exc()))
            self._detach_interface_virtual(instance, vif)
            raise exception.InterfaceAttachFailed(
                instance_uuid=instance['uuid'])

    def _detach_interface_virtual(self, instance, vif):
        node = self._transfer_instance_to_node(instance)
        host_id = node.extra.get('cps_id')

        kwargs = {"instance": instance,
                  "vif": vif}
        try:
            self.ironicAgent.detach_interface(host_id, kwargs)
        except Exception as e:
            LOG.error(_("Error unplugging vif: %s, instance is %s, "
                      "Traceback is %s")
                      % (e, instance['uuid'], traceback.format_exc()))
            raise exception.InterfaceDetachFailed(
                instance_uuid=instance['uuid'])

    def attach_interface(self, instance, image_meta, vif):
        if CONF.baremetal_network_type == "virtual":
            self._attach_interface_virtual(instance, image_meta, vif)
        elif CONF.baremetal_network_type == "physical":
            self._attach_interface_physical(instance, image_meta, vif)

    def detach_interface(self, instance, vif):
        if CONF.baremetal_network_type == "virtual":
            self._detach_interface_virtual(instance, vif)
        elif CONF.baremetal_network_type == "physical":
            self._detach_interface_physical(instance, vif)

    def _plug_vifs_physical(self, node, instance, network_info):
        # NOTE(): Accessing network_info will block if the thread
        # it wraps hasn't finished, so do this ahead of time so that we
        # don't block while holding the logging lock.
        network_info_str = str(network_info)
        LOG.debug("plug: instance_uuid=%(uuid)s vif=%(network_info)s",
                  {'uuid': instance['uuid'],
                   'network_info': network_info_str})
        # start by ensuring the ports are clear
        self._unplug_vifs(node, instance, network_info)

        icli = client_wrapper.IronicClientWrapper()
        ports = icli.call("node.list_ports", node.uuid)

        # filter no pxe port
        no_pxe_ports = []
        for p in ports:
            port = icli.call("port.get", p.uuid)
            if port.extra.get('type', None) == 'pxe':
                continue
            no_pxe_ports.append(p)

        if len(network_info) > len(no_pxe_ports):
            raise exception.NovaException(_(
                "Ironic node: %(id)s virtual to physical interface count"
                "  missmatch"
                " (Vif count: %(vif_count)d, Pif count: %(pif_count)d)")
                % {'id': node.uuid,
                   'vif_count': len(network_info),
                   'pif_count': len(no_pxe_ports)})

        if len(network_info) > 0:
            # not needed if no vif are defined
            for vif, pif in zip(network_info, no_pxe_ports):
                # attach what neutron needs directly to the port
                port_id = unicode(vif['id'])
                patch = [{'op': 'add',
                          'path': '/extra/vif_port_id',
                          'value': port_id}]
                icli.call("port.update", pif.uuid, patch)

    def _unplug_vifs_physical(self, node, instance, network_info):
        # NOTE(): Accessing network_info will block if the thread
        # it wraps hasn't finished, so do this ahead of time so that we
        # don't block while holding the logging lock.
        network_info_str = str(network_info)
        LOG.debug("unplug: instance_uuid=%(uuid)s vif=%(network_info)s",
                  {'uuid': instance['uuid'],
                   'network_info': network_info_str})
        if network_info and len(network_info) > 0:
            icli = client_wrapper.IronicClientWrapper()
            ports = icli.call("node.list_ports", node.uuid)

            # filter no pxe port
            no_pxe_ports = []
            for p in ports:
                port = icli.call("port.get", p.uuid)
                if port.extra.get('type', None) == 'pxe':
                    continue
                no_pxe_ports.append(p)

            # not needed if no vif are defined
            for vif, pif in zip(network_info, no_pxe_ports):
                # we can not attach a dict directly
                patch = [{'op': 'remove', 'path': '/extra/vif_port_id'}]
                try:
                    icli.call("port.update", pif.uuid, patch)
                except ironic.exc.BadRequest:
                    pass

    def _plug_vifs_virtual(self, node, instance, network_info):
        pass

    def _unplug_vifs_virtual(self, node, instance, network_info):
        pass

    def _plug_vifs(self, node, instance, network_info):
        if CONF.baremetal_network_type == "virtual":
            self._plug_vifs_virtual(node, instance, network_info)
        elif CONF.baremetal_network_type == "physical":
            self._plug_vifs_physical(node, instance, network_info)

    def _unplug_vifs(self, node, instance, network_info):
        if CONF.baremetal_network_type == "virtual":
            self._unplug_vifs_virtual(node, instance, network_info)
        elif CONF.baremetal_network_type == "physical":
            self._unplug_vifs_physical(node, instance, network_info)


    def macs_for_instance(self, instance):
        """List the MAC addresses of an instance.

        List of MAC addresses for the node which this instance is
        associated with.

        :param instance: the instance object.
        :return: None, or a set of MAC ids (e.g. set(['12:34:56:78:90:ab'])).
            None means 'no constraints', a set means 'these and only these
            MAC addresses'.
        """
        if CONF.baremetal_network_type == "virtual":
            return None

        icli = client_wrapper.IronicClientWrapper()
        try:
            node = icli.call("node.get", instance['node'])
        except ironic.exc.NotFound:
            return None
        ports = icli.call("node.list_ports", node.uuid, detail=True)

        # filter no pxe macs
        no_pxe_macs = []
        try:
            for p in ports:
                if p.extra.get('type', None) == 'pxe':
                    continue
                no_pxe_macs.append(p.address)
        except ironic.exc.NotFound:
            return None

        return set(no_pxe_macs)

    def _clean_local_disk(self, instance):
        node = self._transfer_instance_to_node(instance)
        host_id = node.extra.get('cps_id')
        if not host_id or not uuidutils.is_uuid_like(host_id.lower()):
            raise Exception("instance %s cannot get cps_id, will not clean disk"
                            % instance.get('uuid'))

        kwargs = {"instance": instance}
        try:
            self.ironicAgent.clean_local_disk(host_id, kwargs)
        except Exception as e:
            LOG.error(_("Error clean local disk: %s, instance is %s, "
                        "Traceback is %s")
                      % (e, instance['uuid'], traceback.format_exc()))
            raise

    def destroy(self, context, instance, network_info,
                block_device_info=None, destroy_disks=True, migrate_data=None):
        """Destroy the specified instance, if it can be found.

        :param context: The security context.
        :param instance: The instance object.
        :param network_info: Instance network information.
        :param block_device_info: Instance block device
            information. Ignored by this driver.
        :param destroy_disks: Indicates if disks should be
            destroyed. Ignored by this driver.
        :param migrate_data: implementation specific params.
            Ignored by this driver.
        """
        icli = client_wrapper.IronicClientWrapper()
        try:
            node = _validate_instance_and_node(icli, instance)
        except exception.InstanceNotFound:
            LOG.warning(_LW("Destroy called on non-existing instance %s."),
                        instance['uuid'])
            # NOTE(): if nova.compute.ComputeManager._delete_instance()
            #             is called on a non-existing instance, the only way
            #             to delete it is to return from this method
            #             without raising any exceptions.
            return

        # need to power on the node before clean local disk
        if node.power_state == ironic_states.POWER_OFF:
            try:
                LOG.info("powering on the node %s" % node.uuid)
                icli.call("node.set_power_state", node.uuid, "on")
                timer = loopingcall.FixedIntervalLoopingCall(
                    self._wait_for_power_state, icli, instance, "power on")
                timer.start(interval=CONF.ironic.api_retry_interval).wait()
            except Exception:
                LOG.ERROR("set the node : %s to power on failed." % node.uuid)
                raise exception.NovaException(_("set the node : %s to "
                                                "power on failed.") % node.uuid)
        LOG.debug(_("Enter clean node disk for baremetal-server: %s"), node)

        retry_times = CONF.clean_local_disk_retry_times
        while retry_times > 0:
            try:
                self._clean_local_disk(instance)
            except Exception as e:
                retry_times -= 1
                LOG.error(_("Error clean local disk: %s, instance is %s, "
                            "Traceback is %s, remaining retry times %s."
                            % (e, instance['uuid'], traceback.format_exc(), retry_times)))
            else:
                break

        if node.provision_state in (ironic_states.ACTIVE,
                                    ironic_states.DEPLOYFAIL,
                                    ironic_states.ERROR,
                                    ironic_states.DEPLOYWAIT):
            self._unprovision(icli, instance, node)

        self._cleanup_deploy(context, node, instance, network_info)