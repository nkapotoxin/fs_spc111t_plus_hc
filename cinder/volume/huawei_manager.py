# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
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
Volume manager manages creating, attaching, detaching, and persistent storage.

Persistent storage volumes keep their state independent of instances.  You can
attach to an instance, terminate the instance, spawn a new instance (even
one from a different image) and re-attach the volume with the same data
intact.

**Related Flags**

:volume_topic:  What :mod:`rpc` topic to listen to (default: `cinder-volume`).
:volume_manager:  The module name of a class derived from
                  :class:`manager.Manager` (default:
                  :class:`cinder.volume.manager.Manager`).
:volume_driver:  Used by :class:`Manager`.  Defaults to
                 :class:`cinder.volume.drivers.lvm.LVMISCSIDriver`.
:volume_group:  Name of the group that will contain exported volumes (default:
                `cinder-volumes`)
:num_shell_tries:  Number of times to attempt to run commands (default: 3)

"""

from cinder import exception
from cinder.image import glance
from cinder.openstack.common import excutils
from cinder.openstack.common.gettextutils import _
from cinder.openstack.common import log as logging
from cinder import quota
from cinder import utils
from cinder.volume import manager as core_manager
from cinder.volume import volume_types
from cinder.volume import utils as vol_utils

LOG = logging.getLogger(__name__)

QUOTAS = quota.QUOTAS


class HuaweiVolumeManager(core_manager.VolumeManager):
    """The volume manager of huawei."""

    RPC_API_VERSION = '1.11'

    def __init__(self, volume_driver=None, service_name=None, *args, **kwargs):
        """Load the driver from the one specified in args, or from flags."""
        # update_service_capabilities needs service_name to be volume
        super(HuaweiVolumeManager, self).__init__(volume_driver=volume_driver,
                                                  service_name=service_name,
                                                  *args, **kwargs)

    def _is_share_volume(self, volume_type_id):
        if volume_type_id:
            value = volume_types.get_volume_type_extra_specs(volume_type_id,
                                                             key='is_shared')
            if value and value.lower() == 'true':
                return True

        return False

    def _check_volume_dependence(self, context, volume_id, volume_type_id,
                                 project_id):
        if context.project_id != project_id:
            project_id = project_id
        else:
            project_id = context.project_id

        if self._is_share_volume(volume_type_id):
            all_vols = self.db.volume_get_all_by_project(context, project_id,
                                                         None, None,
                                                         'source_volid', None)
            for vol in all_vols:
                if vol.source_volid == volume_id:
                    self.db.volume_update(context, volume_id,
                                          {'status': 'available'})
                    msg = _("Volume still has dependent volume")
                    raise exception.InvalidVolume(reason=msg)

    def delete_volume(self, context, volume_id, unmanage_only=False):
        """Deletes and unexports volume."""
        context = context.elevated()
        volume_ref = self.db.volume_get(context, volume_id)

        if context.project_id != volume_ref['project_id']:
            project_id = volume_ref['project_id']
        else:
            project_id = context.project_id

        LOG.info(_("volume %s: deleting"), volume_ref['id'])
        if volume_ref['attach_status'] == "attached":
            # Volume is still attached, need to detach first
            raise exception.VolumeAttached(volume_id=volume_id)
        if (vol_utils.extract_host(volume_ref['host']) != self.host):
            raise exception.InvalidVolume(
                reason=_("volume is not local to this node"))

        volume_type_id = volume_ref.get('volume_type_id', None)

        self._check_volume_dependence(context, volume_id, volume_type_id,
                                      project_id)

        self._notify_about_volume_usage(context, volume_ref, "delete.start")
        try:
            # NOTE(flaper87): Verify the driver is enabled
            # before going forward. The exception will be caught
            # and the volume status updated.
            utils.require_driver_initialized(self.driver)

            LOG.debug(_("volume %s: removing export"), volume_ref['id'])
            self.driver.remove_export(context, volume_ref)
            LOG.debug(_("volume %s: deleting"), volume_ref['id'])
            self.driver.delete_volume(volume_ref)
        except exception.VolumeIsBusy:
            LOG.error(_("Cannot delete volume %s: volume is busy"),
                      volume_ref['id'])
            self.driver.ensure_export(context, volume_ref)
            self.db.volume_update(context, volume_ref['id'],
                                  {'status': 'available'})
            return True
        except Exception:
            with excutils.save_and_reraise_exception():
                self.db.volume_update(context,
                                      volume_ref['id'],
                                      {'status': 'error_deleting'})

        # If deleting the source volume in a migration, we want to skip quotas
        # and other database updates.
        if volume_ref['migration_status']:
            return True

        # Get reservations
        try:
            reserve_opts = {'volumes': -1, 'gigabytes': -volume_ref['size']}
            QUOTAS.add_volume_type_opts(context,
                                        reserve_opts,
                                        volume_ref.get('volume_type_id'))
            reservations = QUOTAS.reserve(context,
                                          project_id=project_id,
                                          **reserve_opts)
        except Exception:
            reservations = None
            LOG.exception(_("Failed to update usages deleting volume"))

        # Delete glance metadata if it exists
        try:
            self.db.volume_glance_metadata_delete_by_volume(context, volume_id)
            LOG.debug(_("volume %s: glance metadata deleted"),
                      volume_ref['id'])
        except exception.GlanceMetadataNotFound:
            LOG.debug(_("no glance metadata found for volume %s"),
                      volume_ref['id'])

        self.db.volume_destroy(context, volume_id)
        LOG.info(_("volume %s: deleted successfully"), volume_ref['id'])
        self._notify_about_volume_usage(context, volume_ref, "delete.end")

        # Commit the reservations
        if reservations:
            QUOTAS.commit(context, reservations, project_id=project_id)

        self.publish_service_capabilities(context)

        return True

    def create_snapshot(self, context, volume_id, snapshot_id):
        """Creates and exports the snapshot."""
        caller_context = context
        context = context.elevated()
        snapshot_ref = self.db.snapshot_get(context, snapshot_id)
        LOG.info(_("snapshot %s: creating"), snapshot_ref['id'])

        vol_ref = self.db.volume_get(context, volume_id)
        volume_type_id = vol_ref.get('volume_type_id', None)
        if self._is_share_volume(volume_type_id):
            msg = _("Volume is share volume")
            self.db.snapshot_update(context,
                                    snapshot_ref['id'],
                                    {'status': 'error'})
            raise exception.InvalidVolume(reason=msg)

        self._notify_about_snapshot_usage(
            context, snapshot_ref, "create.start")

        try:
            # NOTE(flaper87): Verify the driver is enabled
            # before going forward. The exception will be caught
            # and the snapshot status updated.
            utils.require_driver_initialized(self.driver)

            LOG.debug(_("snapshot %(snap_id)s: creating"),
                      {'snap_id': snapshot_ref['id']})

            # Pass context so that drivers that want to use it, can,
            # but it is not a requirement for all drivers.
            snapshot_ref['context'] = caller_context

            model_update = self.driver.create_snapshot(snapshot_ref)
            if model_update:
                self.db.snapshot_update(context, snapshot_ref['id'],
                                        model_update)

        except Exception:
            with excutils.save_and_reraise_exception():
                self.db.snapshot_update(context,
                                        snapshot_ref['id'],
                                        {'status': 'error'})

        self.db.snapshot_update(context,
                                snapshot_ref['id'], {'status': 'available',
                                                     'progress': '100%'})

        if vol_ref.bootable:
            try:
                self.db.volume_glance_metadata_copy_to_snapshot(
                    context, snapshot_ref['id'], volume_id)
            except exception.CinderException as ex:
                LOG.exception(_("Failed updating %(snapshot_id)s"
                                " metadata using the provided volumes"
                                " %(volume_id)s metadata") %
                              {'volume_id': volume_id,
                               'snapshot_id': snapshot_id})
                raise exception.MetadataCopyFailure(reason=ex)
        LOG.info(_("snapshot %s: created successfully"), snapshot_ref['id'])
        self._notify_about_snapshot_usage(context, snapshot_ref, "create.end")
        return snapshot_id

    def copy_volume_to_image(self, context, volume_id, image_meta):
        """Uploads the specified volume to Glance.

        image_meta is a dictionary containing the following keys:
        'id', 'container_format', 'disk_format'

        """
        payload = {'volume_id': volume_id, 'image_id': image_meta['id']}
        try:
            # NOTE(flaper87): Verify the driver is enabled
            # before going forward. The exception will be caught
            # and the volume status updated.
            utils.require_driver_initialized(self.driver)

            volume = self.db.volume_get(context, volume_id)

            volume_type_id = volume.get('volume_type_id', None)
            if self._is_share_volume(volume_type_id):
                self.db.volume_update(context,
                                      volume_id,
                                      {'status': 'error'})
                msg = _("Volume is share volume")
                raise exception.InvalidVolume(reason=msg)

            self.driver.ensure_export(context.elevated(), volume)
            image_service, image_id = \
                glance.get_remote_image_service(context, image_meta['id'])
            self.driver.copy_volume_to_image(context, volume, image_service,
                                             image_meta)
            LOG.debug(_("Uploaded volume %(volume_id)s to "
                        "image (%(image_id)s) successfully"),
                      {'volume_id': volume_id, 'image_id': image_id})
        except Exception as error:
            with excutils.save_and_reraise_exception():
                payload['message'] = unicode(error)
        finally:
            if not volume['volume_attachment']:
                self.db.volume_update(context, volume_id,
                                      {'status': 'available'})
            else:
                self.db.volume_update(context, volume_id,
                                      {'status': 'in-use'})

    def initialize_connection(self, context, volume_id, connector):
        """Prepare volume for connection from host represented by connector.

        This method calls the driver initialize_connection and returns
        it to the caller.  The connector parameter is a dictionary with
        information about the host that will connect to the volume in the
        following format::

            {
                'ip': ip,
                'initiator': initiator,
            }

        ip: the ip address of the connecting machine

        initiator: the iscsi initiator name of the connecting machine.
        This can be None if the connecting machine does not support iscsi
        connections.

        driver is responsible for doing any necessary security setup and
        returning a connection_info dictionary in the following format::

            {
                'driver_volume_type': driver_volume_type,
                'data': data,
            }

        driver_volume_type: a string to identify the type of volume.  This
                           can be used by the calling code to determine the
                           strategy for connecting to the volume. This could
                           be 'iscsi', 'rbd', 'sheepdog', etc.

        data: this is the data that the calling code will use to connect
              to the volume. Keep in mind that this will be serialized to
              json in various places, so it should not contain any non-json
              data types.
        """
        # NOTE(flaper87): Verify the driver is enabled
        # before going forward. The exception will be caught
        # and the volume status updated.
        utils.require_driver_initialized(self.driver)

        volume = self.db.volume_get(context, volume_id)
        self.driver.validate_connector(connector)
        instance_uuid = connector.get('instance_uuid', None)
        self._check_attach_same_instance(context, volume, instance_uuid)
        conn_info = self.driver.initialize_connection(volume, connector)

        # Add qos_specs to connection info
        typeid = volume['volume_type_id']
        specs = None
        if typeid:
            res = volume_types.get_volume_type_qos_specs(typeid)
            qos = res['qos_specs']
            # only pass qos_specs that is designated to be consumed by
            # front-end, or both front-end and back-end.
            if qos and qos.get('consumer') in ['front-end', 'both']:
                specs = qos.get('specs')

        qos_spec = dict(qos_specs=specs)
        conn_info['data'].update(qos_spec)

        # Add access_mode to connection info
        volume_metadata = self.db.volume_admin_metadata_get(context.elevated(),
                                                            volume_id)
        if conn_info['data'].get('access_mode') is None:
            access_mode = volume_metadata.get('attached_mode')
            if access_mode is None:
                # NOTE(zhiyan): client didn't call 'os-attach' before
                access_mode = ('ro'
                               if volume_metadata.get('readonly') == 'True'
                               else 'rw')
            conn_info['data']['access_mode'] = access_mode
        return conn_info

    def _check_attach_same_instance(self, context, volume, instance_uuid):
        volume_type_id = volume['volume_type_id']
        if not self._is_share_volume(volume_type_id):
            return
        vol_attachments = self.db.volume_get_all_by_instance_uuid(context,
                                                                  instance_uuid)
        base_src_vol_id = self._get_source_volume_id_by_volume(context, volume)
        for vol_attachment in vol_attachments:
            vol = vol_attachment.volume
            volume_type_id = vol['volume_type_id']
            if not self._is_share_volume(volume_type_id):
                continue
            src_vol_id = self._get_source_volume_id_by_volume(context, vol)
            if base_src_vol_id == src_vol_id:
                LOG.warn(_("attach same instance with volume %s"),
                         vol['id'])
                msg = _("share volumes has the same source volume "
                        "can not attach to the same instance.")
                raise exception.InvalidVolume(reason=msg)

    def _get_source_volume_id_by_volume(self, context, volume):
        source_volume_id = volume['source_volid']
        if source_volume_id:
            return self._get_source_volume_id_by_volume_id(context,
                                                           source_volume_id)
        return volume['id']

    def _get_source_volume_id_by_volume_id(self, context, volume_id):
        volume = self.db.volume_get(context, volume_id)
        return self._get_source_volume_id_by_volume(context, volume)
