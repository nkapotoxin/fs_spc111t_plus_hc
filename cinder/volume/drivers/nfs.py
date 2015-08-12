# Copyright (c) 2012 NetApp, Inc.
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

import errno
import os

from oslo.config import cfg

from cinder.brick.remotefs import remotefs as remotefs_brick
from cinder import exception
from cinder.i18n import _
from cinder.image import image_utils
from cinder.openstack.common import log as logging
from cinder.openstack.common import processutils as putils
from cinder.openstack.common import units
from cinder import utils
from cinder.volume.drivers import remotefs

VERSION = '1.1.0'

LOG = logging.getLogger(__name__)

volume_opts = [
    cfg.StrOpt('nfs_shares_config',
               default='/etc/cinder/nfs_shares',
               help='File with the list of available nfs shares'),
    cfg.BoolOpt('nfs_sparsed_volumes',
                default=True,
                help=('Create volumes as sparsed files which take no space.'
                      'If set to False volume is created as regular file.'
                      'In such case volume creation takes a lot of time.')),
    cfg.FloatOpt('nfs_used_ratio',
                 default=0.95,
                 help=('Percent of ACTUAL usage of the underlying volume '
                       'before no new volumes can be allocated to the volume '
                       'destination.')),
    cfg.FloatOpt('nfs_oversub_ratio',
                 default=1.0,
                 help=('This will compare the allocated to available space on '
                       'the volume destination.  If the ratio exceeds this '
                       'number, the destination will no longer be valid.')),
    cfg.StrOpt('nfs_mount_point_base',
               default='$state_path/mnt',
               help=('Base dir containing mount points for nfs shares.')),
    cfg.StrOpt('nfs_mount_options',
               default=None,
               help=('Mount options passed to the nfs client. See section '
                     'of the nfs man page for details.')),
]

CONF = cfg.CONF
CONF.register_opts(volume_opts)


class NfsDriver(remotefs.RemoteFSDriver):
    """NFS based cinder driver. Creates file on NFS share for using it
    as block device on hypervisor.
    """

    driver_volume_type = 'nfs'
    driver_prefix = 'nfs'
    volume_backend_name = 'Generic_NFS'
    VERSION = VERSION

    def __init__(self, execute=putils.execute, *args, **kwargs):
        self._remotefsclient = None
        super(NfsDriver, self).__init__(*args, **kwargs)
        self.configuration.append_config_values(volume_opts)
        root_helper = utils.get_root_helper()
        # base bound to instance is used in RemoteFsConnector.
        self.base = getattr(self.configuration,
                            'nfs_mount_point_base',
                            CONF.nfs_mount_point_base)
        opts = getattr(self.configuration,
                       'nfs_mount_options',
                       CONF.nfs_mount_options)
        self._remotefsclient = remotefs_brick.RemoteFsClient(
            'nfs', root_helper, execute=execute,
            nfs_mount_point_base=self.base,
            nfs_mount_options=opts)

    def set_execute(self, execute):
        super(NfsDriver, self).set_execute(execute)
        if self._remotefsclient:
            self._remotefsclient.set_execute(execute)

    def do_setup(self, context):
        """Any initialization the volume driver does while starting."""
        super(NfsDriver, self).do_setup(context)

        config = self.configuration.nfs_shares_config
        if not config:
            msg = (_("There's no NFS config file configured (%s)") %
                   'nfs_shares_config')
            LOG.warn(msg)
            raise exception.NfsException(msg)
        if not os.path.exists(config):
            msg = (_("NFS config file at %(config)s doesn't exist") %
                   {'config': config})
            LOG.warn(msg)
            raise exception.NfsException(msg)
        if not self.configuration.nfs_oversub_ratio > 0:
            msg = _("NFS config 'nfs_oversub_ratio' invalid.  Must be > 0: "
                    "%s") % self.configuration.nfs_oversub_ratio

            LOG.error(msg)
            raise exception.NfsException(msg)

        if ((not self.configuration.nfs_used_ratio > 0) and
                (self.configuration.nfs_used_ratio <= 1)):
            msg = _("NFS config 'nfs_used_ratio' invalid.  Must be > 0 "
                    "and <= 1.0: %s") % self.configuration.nfs_used_ratio
            LOG.error(msg)
            raise exception.NfsException(msg)

        self.shares = {}  # address : options

        # Check if mount.nfs is installed
        try:
            self._execute('mount.nfs', check_exit_code=False, run_as_root=True)
        except OSError as exc:
            if exc.errno == errno.ENOENT:
                raise exception.NfsException('mount.nfs is not installed')
            else:
                raise exc

    def _ensure_share_mounted(self, nfs_share):
        mnt_flags = []
        if self.shares.get(nfs_share) is not None:
            mnt_flags = self.shares[nfs_share].split()
        self._remotefsclient.mount(nfs_share, mnt_flags)

    def _find_share(self, volume_size_in_gib):
        """Choose NFS share among available ones for given volume size.

        For instances with more than one share that meets the criteria, the
        share with the least "allocated" space will be selected.

        :param volume_size_in_gib: int size in GB
        """

        if not self._mounted_shares:
            raise exception.NfsNoSharesMounted()

        target_share = None
        target_share_reserved = 0

        for nfs_share in self._mounted_shares:
            if not self._is_share_eligible(nfs_share, volume_size_in_gib):
                continue
            total_size, total_available, total_allocated = \
                self._get_capacity_info(nfs_share)
            if target_share is not None:
                if target_share_reserved > total_allocated:
                    target_share = nfs_share
                    target_share_reserved = total_allocated
            else:
                target_share = nfs_share
                target_share_reserved = total_allocated

        if target_share is None:
            raise exception.NfsNoSuitableShareFound(
                volume_size=volume_size_in_gib)

        LOG.debug('Selected %s as target nfs share.', target_share)

        return target_share

    def _is_share_eligible(self, nfs_share, volume_size_in_gib):
        """Verifies NFS share is eligible to host volume with given size.

        First validation step: ratio of actual space (used_space / total_space)
        is less than 'nfs_used_ratio'. Second validation step: apparent space
        allocated (differs from actual space used when using sparse files)
        and compares the apparent available
        space (total_available * nfs_oversub_ratio) to ensure enough space is
        available for the new volume.

        :param nfs_share: nfs share
        :param volume_size_in_gib: int size in GB
        """

        used_ratio = self.configuration.nfs_used_ratio
        oversub_ratio = self.configuration.nfs_oversub_ratio
        requested_volume_size = volume_size_in_gib * units.Gi

        total_size, total_available, total_allocated = \
            self._get_capacity_info(nfs_share)
        apparent_size = max(0, total_size * oversub_ratio)
        apparent_available = max(0, apparent_size - total_allocated)
        used = (total_size - total_available) / total_size
        if used > used_ratio:
            # NOTE(morganfainberg): We check the used_ratio first since
            # with oversubscription it is possible to not have the actual
            # available space but be within our oversubscription limit
            # therefore allowing this share to still be selected as a valid
            # target.
            LOG.debug('%s is above nfs_used_ratio', nfs_share)
            return False
        if apparent_available <= requested_volume_size:
            LOG.debug('%s is above nfs_oversub_ratio', nfs_share)
            return False
        if total_allocated / total_size >= oversub_ratio:
            LOG.debug('%s reserved space is above nfs_oversub_ratio',
                      nfs_share)
            return False
        return True

    def _get_mount_point_for_share(self, nfs_share):
        """Needed by parent class."""
        return self._remotefsclient.get_mount_point(nfs_share)

    def _get_capacity_info(self, nfs_share):
        """Calculate available space on the NFS share.

        :param nfs_share: example 172.18.194.100:/var/nfs
        """

        mount_point = self._get_mount_point_for_share(nfs_share)

        df, _ = self._execute('stat', '-f', '-c', '%S %b %a', mount_point,
                              run_as_root=True)
        block_size, blocks_total, blocks_avail = map(float, df.split())
        total_available = block_size * blocks_avail
        total_size = block_size * blocks_total

        du, _ = self._execute('du', '-sb', '--apparent-size', '--exclude',
                              '*snapshot*', mount_point, run_as_root=True)
        total_allocated = float(du.split()[0])
        return total_size, total_available, total_allocated

    def _get_mount_point_base(self):
        return self.base

    def extend_volume(self, volume, new_size):
        """Extend an existing volume to the new size."""
        LOG.info(_('Extending volume %s.'), volume['id'])
        extend_by = int(new_size) - volume['size']
        if not self._is_share_eligible(volume['provider_location'],
                                       extend_by):
            raise exception.ExtendVolumeError(reason='Insufficient space to'
                                              ' extend volume %s to %sG'
                                              % (volume['id'], new_size))
        path = self.local_path(volume)
        LOG.info(_('Resizing file to %sG...'), new_size)
        image_utils.resize_image(path, new_size)
        if not self._is_file_size_equal(path, new_size):
            raise exception.ExtendVolumeError(
                reason='Resizing image file failed.')

    def _is_file_size_equal(self, path, size):
        """Checks if file size at path is equal to size."""
        data = image_utils.qemu_img_info(path)
        virt_size = data.virtual_size / units.Gi
        return virt_size == size
