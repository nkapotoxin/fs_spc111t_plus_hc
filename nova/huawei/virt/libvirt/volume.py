# Copyright 2011 OpenStack Foundation
# (c) Copyright 2013 Hewlett-Packard Development Company, L.P.
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

"""Volume drivers for libvirt."""

import os
import time
import re

from oslo.config import cfg

from nova import exception
from nova.i18n import _
from nova.i18n import _LW
from nova.openstack.common import log as logging
from nova.openstack.common import processutils
from nova import paths
from nova import utils
from nova.virt.libvirt.volume import LibvirtBaseVolumeDriver
from nova.openstack.common import loopingcall
from nova.huawei.storage import linuxscsi
from nova.virt.libvirt import utils as virtutils

LOG = logging.getLogger(__name__)

volume_opts = [
    cfg.IntOpt('num_iscsi_scan_tries',
               default=5,
               help='Number of times to rescan iSCSI target to find volume'),
    cfg.IntOpt('num_iser_scan_tries',
               default=5,
               help='Number of times to rescan iSER target to find volume'),
    cfg.StrOpt('rbd_user',
               help='The RADOS client name for accessing rbd volumes'),
    cfg.StrOpt('rbd_secret_uuid',
               help='The libvirt UUID of the secret for the rbd_user'
                    'volumes'),
    cfg.StrOpt('nfs_mount_point_base',
               default=paths.state_path_def('mnt'),
               help='Directory where the NFS volume is mounted on the'
               ' compute node'),
    cfg.StrOpt('nfs_mount_options',
               help='Mount options passedf to the NFS client. See section '
                    'of the nfs man page for details'),
    cfg.IntOpt('num_aoe_discover_tries',
               default=3,
               help='Number of times to rediscover AoE target to find volume'),
    cfg.StrOpt('glusterfs_mount_point_base',
               default=paths.state_path_def('mnt'),
               help='Directory where the glusterfs volume is mounted on the '
                    'compute node'),
    cfg.BoolOpt('iscsi_use_multipath',
                default=False,
                help='Use multipath connection of the iSCSI volume'),
    cfg.BoolOpt('iser_use_multipath',
                default=False,
                help='Use multipath connection of the iSER volume'),
    cfg.StrOpt('scality_sofs_config',
               help='Path or URL to Scality SOFS configuration file'),
    cfg.StrOpt('scality_sofs_mount_point',
               default='$state_path/scality',
               help='Base dir where Scality SOFS shall be mounted'),
    cfg.ListOpt('qemu_allowed_storage_drivers',
                default=[],
                help='Protocols listed here will be accessed directly '
                     'from QEMU. Currently supported protocols: [gluster]'),
    cfg.BoolOpt('libvirt_iscsi_use_ultrapath',
                default=False,
                help='use ultrapath connection of the iSCSI volume')
    ]

CONF = cfg.CONF
CONF.register_opts(volume_opts, 'libvirt')


class LibvirtISCSIVolumeDriver(LibvirtBaseVolumeDriver):
    """Driver to attach Network volumes to libvirt."""
    def __init__(self, connection):
        super(LibvirtISCSIVolumeDriver, self).__init__(connection,
                                                       is_block_dev=True)
        self.num_scan_tries = CONF.libvirt.num_iscsi_scan_tries
        self.use_multipath = CONF.libvirt.iscsi_use_multipath

    def _run_iscsiadm(self, iscsi_properties, iscsi_command, **kwargs):
        check_exit_code = kwargs.pop('check_exit_code', 0)
        (out, err) = utils.execute('iscsiadm', '-m', 'node', '-T',
                                   iscsi_properties['target_iqn'],
                                   '-p', iscsi_properties['target_portal'],
                                   *iscsi_command, run_as_root=True,
                                   check_exit_code=check_exit_code)
        msg = ('iscsiadm %(command)s: stdout=%(out)s stderr=%(err)s' %
               {'command': iscsi_command, 'out': out, 'err': err})
        # NOTE(bpokorny): iscsi_command can contain passwords so we need to
        # sanitize the password in the message.
        LOG.debug(logging.mask_password(msg))
        return (out, err)

    def _iscsiadm_update(self, iscsi_properties, property_key, property_value,
                         **kwargs):
        iscsi_command = ('--op', 'update', '-n', property_key,
                         '-v', property_value)
        return self._run_iscsiadm(iscsi_properties, iscsi_command, **kwargs)

    def _get_target_portals_from_iscsiadm_output(self, output):
        # return both portals and iqns
        #
        # as we are parsing a command line utility, allow for the
        # possibility that additional debug data is spewed in the
        # stream, and only grab actual ip / iqn lines.
        targets = []
        for data in [line.split() for line in output.splitlines()]:
            if len(data) == 2 and data[1].startswith('iqn.'):
                targets.append(data)
        return targets

    def get_config(self, connection_info, disk_info):
        """Returns xml for libvirt."""
        conf = super(LibvirtISCSIVolumeDriver,
                     self).get_config(connection_info, disk_info)
        conf.source_type = "block"
        conf.source_path = connection_info['data']['host_device']
        return conf

    def _test_ipadrress(self, ip):
        try:
            utils.execute('ping',ip,'-i','0.2','-c','3','-w', '1',
                          run_as_root=True,
                          check_exit_code=0)
            return True
        except Exception as e:
            LOG.error("%s is unable to connect." % ip)
            return False

    def _get_name_from_path(self, path):
        name = os.path.realpath(path)
        if name.startswith("/dev/"):
            return name
        else:
            return None

    def _remove_scsi_device(self, dev_name, is_ultrapath=False):
        if not is_ultrapath:
            path = "/sys/block/%s/device/delete" % dev_name.replace("/dev/", "")
            if os.path.exists(path):
                LOG.debug("Remove SCSI device(%s) with %s" % (dev_name, path))
                (out, err) = utils.execute('tee', '-a', path,
                                           process_input='1',
                                           run_as_root=True,
                                           check_exit_code=0)
        else:
            device_name = dev_name.replace("/dev/", "")
            (out, err) = utils.execute('sh', '/etc/FSComponentUtil/commShell/smartdelete.sh',
                                       device_name,
                                       run_as_root=True,
                                       check_exit_code=0)

    def _smartdelete_ultrapath(self, iscsi_properties):

        iscsi_ip_list = map(lambda a: a.split(':')[0], iscsi_properties['target_portal'])

        (out, err) = utils.execute('sh', '/etc/FSComponentUtil/commShell/private_smartdelete.sh',
                                   str(iscsi_properties['target_lun']),
                                   ','.join(iscsi_ip_list),
                                   run_as_root=True,
                                   check_exit_code=0)

    def _smartscan_ultrapath(self,iscsi_properties, del_params=""):

        iscsi_ip_list = map(lambda a:a.split(':')[0],iscsi_properties['target_portal'])

        (out, err) = utils.execute('sh', '/etc/FSComponentUtil/commShell/smartscan.sh',
                                       str(iscsi_properties['target_lun']),
                                       ','.join(iscsi_ip_list),
                                       del_params,
                                       run_as_root=True,
                                       check_exit_code=0)

    def _ultrapath_connect_to_iscsi_portal(self, connection_properties,exception_list=[],login_info = []):

        #duplicate logins crash iscsiadm after load,
        #so we scan active sessions to see if the node is logged in.
        out = self._run_iscsiadm_bare(["-m", "session"],
                                      run_as_root=True,
                                      check_exit_code=[0, 1, 21])[0] or ""

        portals = [{'portal': p.split(" ")[2], 'iqn': p.split(" ")[3]}
                   for p in out.splitlines() if p.startswith("tcp:")]

        for index in range(int(connection_properties.get('target_num',1))):
            if isinstance(connection_properties['target_portal'],list) is False:
                target_portal = connection_properties['target_portal']
            else:
                target_portal = connection_properties['target_portal'][index]

            if isinstance(connection_properties['target_iqn'],list) is False:
                target_iqn = connection_properties['target_iqn']
            else:
                target_iqn = connection_properties['target_iqn'][index]
            props = {"target_portal":target_portal,
                     "target_iqn":target_iqn}
            stripped_portal = target_portal.split(",")[0]
            if len(portals) == 0 or len([s for s in portals
                                     if stripped_portal ==
                                     s['portal'].split(",")[0]
                                     and
                                     s['iqn'] == target_iqn]) == 0:
                login_info.append(True)
                if not self._test_ipadrress(target_portal.split(':')[0]):
                    exception_list.append(target_portal)
                    continue

                try:
                    self._run_iscsiadm(props, ())
                except processutils.ProcessExecutionError as exc:
                    # iscsiadm returns 21 for "No records found" after version 2.0-871
                    if exc.exit_code in [21, 255]:
                        try:
                            self._reconnect(props)
                        except Exception as e:
                            exception_list.append(target_portal)
                            continue
                    else:
                        exception_list.append(target_portal)
                        continue

                if connection_properties.get('auth_method'):
                    try:
                        self._iscsiadm_update(props,
                                            "node.session.auth.authmethod",
                                            connection_properties['auth_method'])
                        self._iscsiadm_update(props,
                                        "node.session.auth.username",
                                        connection_properties['auth_username'])
                        self._iscsiadm_update(props,
                                        "node.session.auth.password",
                                        connection_properties['auth_password'])
                    except Exception as e:
                        exception_list.append(target_portal)
                        continue
                try:
                    self._run_iscsiadm(props,
                                    ("--login",),
                                    check_exit_code=[0, 255])
                except processutils.ProcessExecutionError as err:
                    #as this might be one of many paths,
                    #only set successful logins to startup automatically
                    if err.exit_code in [15]:
                        try:
                            self._iscsiadm_update(props,
                                                "node.startup",
                                                "automatic")
                        except Exception as e:
                            exception_list.append(target_portal)
                            continue
                        continue
                try:
                    self._iscsiadm_update(props,
                                        "node.startup",
                                        "automatic")
                except Exception as e:
                    exception_list.append(target_portal)

    def connect_volume_ultrapath(self, connection_info, disk_info):
        # add for FSP5.0 to FSP5.1, support huawei multipath
        conf = super(LibvirtISCSIVolumeDriver,
                     self).get_config(connection_info,
                                          disk_info)

        iscsi_properties = connection_info['data']
        # clean fail device
        # self._clean_ultrapath()
        exception_list = []
        valid_list = []
        login_info = []

        def _check_valid_device(path):
            cmd = ('dd', 'if=%(path)s' % {"path": path},
                   'of=/dev/null', 'iflag=direct','count=1')
            out, info = None, None
            try:
                out, info = utils.execute(*cmd, run_as_root=True)
            except processutils.ProcessExecutionError as e:
                LOG.error(_("Failed to access the device on the path "
                            "%(path)s: %(error)s.") %
                          {"path": path, "error": e.stderr})
                return False
            # If the info is none, the path does not exist.
            if info is None:
                return False
            return True

        def clean_device(dev_path, properties):
            self._smartdelete_ultrapath(properties)
            del_tries = 0
            while os.path.exists(dev_path):
                dev_name = self._get_name_from_path(dev_path)
                self._remove_scsi_device(dev_name, True)
                del_tries += 1
                if del_tries > 10:
                    utils.execute('rm',
                                  '-f',
                                  dev_path,
                                  run_as_root=True,
                                  check_exit_code=0)
                if os.path.exists(dev_path):
                    time.sleep(1)

        self._ultrapath_connect_to_iscsi_portal(iscsi_properties, exception_list,login_info)

        if len(exception_list) == int(iscsi_properties.get('target_num',1)):
            LOG.error("All paths don't work normally.")
            raise

        #self._rescan_iscsi()
        host_device = "/dev/disk/by-id/wwn-0x%s" % iscsi_properties['lun_wwn']
        login_flag = True if len(login_info) == int(iscsi_properties.get('target_num',1)) else False
        tries = 0
        del_params = 'SCAN'
        disk_dev = disk_info['dev']
        first_clean = True
        while not os.path.exists(host_device) or not _check_valid_device(host_device):
            '''
            base_devices = self._get_ultrapath_bypath_devices(iscsi_properties['target_lun'])
            if len(base_devices) > 1:
                LOG.error("found mutilple device paths:%s" % base_devices)
            for bydev in base_devices:
                LOG.error("%s not exist, but %s exist." % (host_device, bydev))
                #TODO: not goot for multiple ip-san devices.
                dev_name = self._get_name_from_path(bydev)
                self._remove_scsi_device(dev_name, True)
            '''
            if first_clean and not login_flag:
                clean_device(host_device,iscsi_properties)
                first_clean = False


            if tries >= CONF.libvirt.num_iscsi_scan_tries:
                raise exception.NovaException(_("iSCSI device not found at %s")
                                              % (host_device))
            if tries > 0:
                LOG.warn(_("ISCSI ultrapath volume not yet found at: %(disk_dev)s. "
                        "Will rescan & retry.  Try number: %(tries)s"),
                        {'disk_dev': disk_dev,
                        'tries': tries})

            '''
            # The rescan isn't documented as being necessary(?), but it helps
            for index in range(int(iscsi_properties['target_num'])):
                if iscsi_properties['target_iqn'][index] in valid_list:
                    cp = {'target_iqn':iscsi_properties['target_iqn'][index],
                          'target_portal':iscsi_properties['target_portal'][index]}
                    self._run_iscsiadm(cp,  ("--rescan",))
                #self._resan_ultrapath()
            '''
            if tries > 2:
                del_params = 'ALL'
                first_clean = False
                login_flag = False

            if not login_flag:
                self._smartscan_ultrapath(iscsi_properties, del_params)
            tries = tries + 1
            if not os.path.exists(host_device):
                time.sleep(tries ** 2)

        if tries != 0:
            LOG.debug(_("Found iSCSI ultrapath node %(disk_dev)s "
                        "(after %(tries)s rescans)"),
                      {'disk_dev': disk_dev,
                       'tries': tries})

        conf.source_type = "block"
        conf.source_path = host_device
        return conf

    @utils.synchronized('connect_volume')
    def connect_volume(self, connection_info, disk_info):
        """Attach the volume to instance_name."""
        if CONF.libvirt.libvirt_iscsi_use_ultrapath and connection_info['data'].get('description','') == 'huawei':
            return self.connect_volume_ultrapath(connection_info, disk_info)

        iscsi_properties = connection_info['data']

        if self.use_multipath:
            # multipath installed, discovering other targets if available
            # multipath should be configured on the nova-compute node,
            # in order to fit storage vendor
            out = self._run_iscsiadm_bare(['-m',
                                          'discovery',
                                          '-t',
                                          'sendtargets',
                                          '-p',
                                          iscsi_properties['target_portal']],
                                          check_exit_code=[0, 255])[0] \
                or ""

            for ip, iqn in self._get_target_portals_from_iscsiadm_output(out):
                props = iscsi_properties.copy()
                props['target_portal'] = ip
                props['target_iqn'] = iqn
                self._connect_to_iscsi_portal(props)

            self._rescan_iscsi()
        else:
            self._connect_to_iscsi_portal(iscsi_properties)

            # Detect new/resized LUNs for existing sessions
            self._run_iscsiadm(iscsi_properties, ("--rescan",))

        host_device = self._get_host_device(iscsi_properties)

        # The /dev/disk/by-path/... node is not always present immediately
        # TODO(justinsb): This retry-with-delay is a pattern, move to utils?
        tries = 0
        disk_dev = disk_info['dev']
        while not os.path.exists(host_device):
            if tries >= self.num_scan_tries:
                raise exception.NovaException(_("iSCSI device not found at %s")
                                              % (host_device))

            LOG.warn(_LW("ISCSI volume not yet found at: %(disk_dev)s. "
                         "Will rescan & retry.  Try number: %(tries)s"),
                     {'disk_dev': disk_dev, 'tries': tries})

            # The rescan isn't documented as being necessary(?), but it helps
            self._run_iscsiadm(iscsi_properties, ("--rescan",))

            tries = tries + 1
            if not os.path.exists(host_device):
                time.sleep(tries ** 2)

        if tries != 0:
            LOG.debug("Found iSCSI node %(disk_dev)s "
                      "(after %(tries)s rescans)",
                      {'disk_dev': disk_dev,
                       'tries': tries})

        if self.use_multipath:
            # we use the multipath device instead of the single path device
            self._rescan_multipath()

            multipath_device = self._get_multipath_device_name(host_device)

            if multipath_device is not None:
                host_device = multipath_device

        if "huawei" == connection_info['data'].get('description', ''):
            volume_device = os.path.join('/dev/disk/by-path', 'volume-%s' % connection_info['data']['volume_id'])
            try:
                utils.execute('ln',
                              '-sf',
                              host_device, volume_device,
                              run_as_root=True,
                              check_exit_code=0)
            except Exception as e:
                LOG.error(_("create symbolic link %(host_device)s from %(volume_device)s fail, %(e)s"),
                          {'host_device': host_device, 'volume_device': volume_device,
                           'e': e})
            connection_info['data']['host_device'] = volume_device
        else:
            connection_info['data']['host_device'] = host_device
        return self.get_config(connection_info, disk_info)

    def disconnect_volume_ultrapath(self, connection_info, disk_dev):
        # add for FSP5.0 to FSP5.1, support huawei multipath
        iscsi_properties = connection_info['data']
        super(LibvirtISCSIVolumeDriver,
              self).disconnect_volume(connection_info, disk_dev)
        host_device = "/dev/disk/by-id/wwn-0x%s" % iscsi_properties['lun_wwn']
        dev_name = self._get_name_from_path(host_device)
        LOG.debug("dev_name = %s" % dev_name)
        devices = self.connection._get_all_block_devices()
        # ensure that this dev don't be used by other instances.
        if host_device not in devices:
            if dev_name:
                flag = 0
                self._remove_scsi_device(dev_name, True)
                while True:
                    if os.path.exists(host_device):
                        self._remove_scsi_device(dev_name, True)
                        flag = flag + 1
                    else:
                        break
                    if flag == 10:
                        LOG.error("ERROR!The path still exist. path=%s, realpath=%s"
                                  % (host_device, dev_name))
                        LOG.error("force to delete the path.")
                        cmd_unlink = ['rm', host_device]
                        utils.execute(*cmd_unlink, run_as_root=True)
                        break
                    time.sleep(1)
        # TODO:not very good,but only ultrapath vm with this prefix
        device_prefix = "/dev/disk/by-id"
        devices = [dev for dev in devices if dev.startswith(device_prefix)]
        if not devices:
            by_path_devices = self.connection.get_all_block_devices_ext(True)
            if not by_path_devices:
                for index in range(int(iscsi_properties.get('target_num',1))):
                    if isinstance(iscsi_properties['target_portal'],list) is False:
                        cp= {'target_iqn':iscsi_properties['target_iqn'],
                              'target_portal':iscsi_properties['target_portal']}
                    else:
                        cp = {'target_iqn':iscsi_properties['target_iqn'][index],
                              'target_portal':iscsi_properties['target_portal'][index]}
                    try:
                        self._disconnect_from_iscsi_portal(cp)
                    except Exception as e:
                        LOG.error("disconnect %s fail.portal=%s"
                                  % (cp['target_iqn'], cp['target_portal']))
                        LOG.error("Detail:%s" % e)

    @utils.synchronized('connect_volume')
    def disconnect_volume(self, connection_info, disk_dev):
        """Detach the volume from instance_name."""
        if CONF.libvirt.libvirt_iscsi_use_ultrapath and connection_info['data'].get('description','') == 'huawei':
            return self.disconnect_volume_ultrapath(connection_info, disk_dev)

        iscsi_properties = connection_info['data']
        can_delete = False
        all_devices = self.connection._get_all_block_devices()
        if "huawei" == connection_info['data'].get('description', ''):
            volume_device = os.path.join('/dev/disk/by-path',
                                         'volume-%s' % connection_info['data']['volume_id'])
            if volume_device not in all_devices:
                can_delete = True
                if os.path.exists(volume_device):
                    utils.execute('rm',
                                  '-f',
                                  volume_device,
                                  run_as_root=True,
                                  check_exit_code=0)
        else:
            volume_device = self._get_host_device(iscsi_properties)
            if volume_device not in all_devices:
                can_delete = True

        host_device = self._get_host_device(iscsi_properties)
        multipath_device = None
        if self.use_multipath:
            multipath_device = self._get_multipath_device_name(host_device)

        super(LibvirtISCSIVolumeDriver,
              self).disconnect_volume(connection_info, disk_dev)

        if self.use_multipath and multipath_device:
            return self._disconnect_volume_multipath_iscsi(iscsi_properties,
                                                           multipath_device)

        # NOTE(vish): Only disconnect from the target if no luns from the
        #             target are in use.
        device_prefix = ("/dev/disk/by-path/ip-%s-iscsi-%s-lun-" %
                         (iscsi_properties['target_portal'],
                          iscsi_properties['target_iqn']))
        devices = self.connection.get_all_block_devices_ext()
        devices = [dev for dev in devices if dev.startswith(device_prefix)]
        if not devices:
            self._disconnect_from_iscsi_portal(iscsi_properties)
        elif can_delete:
            # Delete device if LUN is not in use by another instance
            self._delete_device(host_device)

    def _delete_device(self, device_path):
        device_name = os.path.basename(os.path.realpath(device_path))
        delete_control = '/sys/block/' + device_name + '/device/delete'
        if os.path.exists(delete_control):
            # Copy '1' from stdin to the device delete control file
            utils.execute('cp', '/dev/stdin', delete_control,
                          process_input='1', run_as_root=True)
        else:
            LOG.warn(_LW("Unable to delete volume device %s"), device_name)

    def _remove_multipath_device_descriptor(self, disk_descriptor):
        disk_descriptor = disk_descriptor.replace('/dev/mapper/', '')
        try:
            self._run_multipath(['-f', disk_descriptor],
                                check_exit_code=[0, 1])
        except processutils.ProcessExecutionError as exc:
            # Because not all cinder drivers need to remove the dev mapper,
            # here just logs a warning to avoid affecting those drivers in
            # exceptional cases.
            LOG.warn(_LW('Failed to remove multipath device descriptor '
                         '%(dev_mapper)s. Exception message: %(msg)s')
                     % {'dev_mapper': disk_descriptor,
                        'msg': exc.message})

    def _disconnect_volume_multipath_iscsi(self, iscsi_properties,
                                           multipath_device):
        self._rescan_iscsi()
        self._rescan_multipath()
        block_devices = self.connection._get_all_block_devices()
        devices = []
        for dev in block_devices:
            if "/mapper/" in dev:
                devices.append(dev)
            else:
                mpdev = self._get_multipath_device_name(dev)
                if mpdev:
                    devices.append(mpdev)

        # Do a discovery to find all targets.
        # Targets for multiple paths for the same multipath device
        # may not be the same.
        out = self._run_iscsiadm_bare(['-m',
                                      'discovery',
                                      '-t',
                                      'sendtargets',
                                      '-p',
                                      iscsi_properties['target_portal']],
                                      check_exit_code=[0, 255])[0] \
            or ""

        ips_iqns = self._get_target_portals_from_iscsiadm_output(out)

        if not devices:
            # disconnect if no other multipath devices
            self._disconnect_mpath(iscsi_properties, ips_iqns)
            return

        # Get a target for all other multipath devices
        other_iqns = [self._get_multipath_iqn(device)
                      for device in devices]
        # Get all the targets for the current multipath device
        current_iqns = [iqn for ip, iqn in ips_iqns]

        in_use = False
        for current in current_iqns:
            if current in other_iqns:
                in_use = True
                break

        # If no other multipath device attached has the same iqn
        # as the current device
        if not in_use:
            # disconnect if no other multipath devices with same iqn
            self._disconnect_mpath(iscsi_properties, ips_iqns)
            return
        elif multipath_device not in devices:
            # delete the devices associated w/ the unused multipath
            self._delete_mpath(iscsi_properties, multipath_device, ips_iqns)

        # else do not disconnect iscsi portals,
        # as they are used for other luns,
        # just remove multipath mapping device descriptor
        self._remove_multipath_device_descriptor(multipath_device)
        return

    def _connect_to_iscsi_portal(self, iscsi_properties, login_info=[]):
        # NOTE(vish): If we are on the same host as nova volume, the
        #             discovery makes the target so we don't need to
        #             run --op new. Therefore, we check to see if the
        #             target exists, and if we get 255 (Not Found), then
        #             we run --op new. This will also happen if another
        #             volume is using the same target.
        try:
            self._run_iscsiadm(iscsi_properties, ())
        except processutils.ProcessExecutionError as exc:
            # iscsiadm returns 21 for "No records found" after version 2.0-871
            if exc.exit_code in [21, 255]:
                self._reconnect(iscsi_properties)
            else:
                raise

        if iscsi_properties.get('auth_method'):
            self._iscsiadm_update(iscsi_properties,
                                  "node.session.auth.authmethod",
                                  iscsi_properties['auth_method'])
            self._iscsiadm_update(iscsi_properties,
                                  "node.session.auth.username",
                                  iscsi_properties['auth_username'])
            self._iscsiadm_update(iscsi_properties,
                                  "node.session.auth.password",
                                  iscsi_properties['auth_password'])

        # duplicate logins crash iscsiadm after load,
        # so we scan active sessions to see if the node is logged in.
        out = self._run_iscsiadm_bare(["-m", "session"],
                                      run_as_root=True,
                                      check_exit_code=[0, 1, 21])[0] or ""

        portals = [{'portal': p.split(" ")[2], 'iqn': p.split(" ")[3]}
                   for p in out.splitlines() if p.startswith("tcp:")]

        stripped_portal = iscsi_properties['target_portal'].split(",")[0]
        if len(portals) == 0 or len([s for s in portals
                                     if stripped_portal ==
                                     s['portal'].split(",")[0]
                                     and
                                     s['iqn'] ==
                                     iscsi_properties['target_iqn']]
                                    ) == 0:
            try:
                login_info.append(True)
                self._run_iscsiadm(iscsi_properties,
                                   ("--login",),
                                   check_exit_code=[0, 255])
            except processutils.ProcessExecutionError as err:
                # as this might be one of many paths,
                # only set successful logins to startup automatically
                if err.exit_code in [15]:
                    self._iscsiadm_update(iscsi_properties,
                                          "node.startup",
                                          "automatic")
                    return

            self._iscsiadm_update(iscsi_properties,
                                  "node.startup",
                                  "automatic")

    def _disconnect_from_iscsi_portal(self, iscsi_properties):
        self._iscsiadm_update(iscsi_properties, "node.startup", "manual",
                              check_exit_code=[0, 21, 255])
        self._run_iscsiadm(iscsi_properties, ("--logout",),
                           check_exit_code=[0, 21, 255])
        self._run_iscsiadm(iscsi_properties, ('--op', 'delete'),
                           check_exit_code=[0, 21, 255])

    def _get_multipath_device_name(self, single_path_device):
        device = os.path.realpath(single_path_device)

        out = self._run_multipath(['-ll',
                                  device],
                                  check_exit_code=[0, 1])[0]
        mpath_line = [line for line in out.splitlines()
                      if "scsi_id" not in line]  # ignore udev errors
        if len(mpath_line) > 0 and len(mpath_line[0]) > 0:
            return "/dev/mapper/%s" % mpath_line[0].split(" ")[0]

        return None

    def _get_iscsi_devices(self):
        try:
            devices = list(os.walk('/dev/disk/by-path'))[0][-1]
        except IndexError:
            return []
        return [entry for entry in devices if entry.startswith("ip-")]

    def _get_ultrapath_bypath_devices(self, lunid):
        files = []
        dir = "/dev/disk/by-path/"
        if os.path.isdir(dir):
            files = os.listdir(dir)
        devices = []
        template = "scsi-\d:\d:\d:%s$" % lunid
        func = lambda x: re.match(template, x)
        return [dir + f for f in files if func(f)]

    def _delete_mpath(self, iscsi_properties, multipath_device, ips_iqns):
        entries = self._get_iscsi_devices()
        # Loop through ips_iqns to construct all paths
        iqn_luns = []
        for ip, iqn in ips_iqns:
            iqn_lun = '%s-lun-%s' % (iqn,
                                     iscsi_properties.get('target_lun', 0))
            iqn_luns.append(iqn_lun)
        for dev in ['/dev/disk/by-path/%s' % dev for dev in entries]:
            for iqn_lun in iqn_luns:
                if iqn_lun in dev:
                    self._delete_device(dev)

        self._rescan_multipath()

    def _disconnect_mpath(self, iscsi_properties, ips_iqns):
        for ip, iqn in ips_iqns:
            props = iscsi_properties.copy()
            props['target_portal'] = ip
            props['target_iqn'] = iqn
            self._disconnect_from_iscsi_portal(props)

        self._rescan_multipath()

    def _get_multipath_iqn(self, multipath_device):
        entries = self._get_iscsi_devices()
        for entry in entries:
            entry_real_path = os.path.realpath("/dev/disk/by-path/%s" % entry)
            entry_multipath = self._get_multipath_device_name(entry_real_path)
            if entry_multipath == multipath_device:
                return entry.split("iscsi-")[1].split("-lun")[0]
        return None

    def _run_iscsiadm_bare(self, iscsi_command, **kwargs):
        check_exit_code = kwargs.pop('check_exit_code', 0)
        (out, err) = utils.execute('iscsiadm',
                                   *iscsi_command,
                                   run_as_root=True,
                                   check_exit_code=check_exit_code)
        LOG.debug("iscsiadm %(command)s: stdout=%(out)s stderr=%(err)s",
                  {'command': iscsi_command, 'out': out, 'err': err})
        return (out, err)

    def _run_multipath(self, multipath_command, **kwargs):
        check_exit_code = kwargs.pop('check_exit_code', 0)
        (out, err) = utils.execute('multipath',
                                   *multipath_command,
                                   run_as_root=True,
                                   check_exit_code=check_exit_code)
        LOG.debug("multipath %(command)s: stdout=%(out)s stderr=%(err)s",
                  {'command': multipath_command, 'out': out, 'err': err})
        return (out, err)

    def _rescan_iscsi(self):
        self._run_iscsiadm_bare(('-m', 'node', '--rescan'),
                                check_exit_code=[0, 1, 21, 255])
        self._run_iscsiadm_bare(('-m', 'session', '--rescan'),
                                check_exit_code=[0, 1, 21, 255])

    def _rescan_multipath(self):
        self._run_multipath(['-r'], check_exit_code=[0, 1, 21])

    def _get_host_device(self, iscsi_properties):
        return ("/dev/disk/by-path/ip-%s-iscsi-%s-lun-%s" %
                (iscsi_properties['target_portal'],
                 iscsi_properties['target_iqn'],
                 iscsi_properties.get('target_lun', 0)))

    def _reconnect(self, iscsi_properties):
        self._run_iscsiadm(iscsi_properties, ('--op', 'new'))


class LibvirtFibreChannelVolumeDriver(LibvirtBaseVolumeDriver):
    """Driver to attach Fibre Channel Network volumes to libvirt."""

    def __init__(self, connection):
        super(LibvirtFibreChannelVolumeDriver,
              self).__init__(connection, is_block_dev=False)

    def _get_pci_num(self, hba):
        # NOTE(walter-boring)
        # device path is in format of
        # /sys/devices/pci0000:00/0000:00:03.0/0000:05:00.3/host2/fc_host/host2
        # sometimes an extra entry exists before the host2 value
        # we always want the value prior to the host2 value
        pci_num = None
        if hba is not None:
            if "device_path" in hba:
                index = 0
                device_path = hba['device_path'].split('/')
                for value in device_path:
                    if value.startswith('host'):
                        break
                    index = index + 1

                if index > 0:
                    pci_num = device_path[index - 1]

        return pci_num

    def _remove_scsi_device(self, dev_name):
        device_name = dev_name.replace("/dev/", "")
        (out, err) = utils.execute('sh', '/etc/FSComponentUtil/commShell/smartdelete.sh',
                                   device_name,
                                   run_as_root=True,
                                   check_exit_code=0)

    def _get_ultrapath_bypath_devices(self, detail):
        files = []
        dir = "/dev/disk/by-path/"
        if os.path.isdir(dir):
            files = os.listdir(dir)
        devices = []
        template = "scsi-\d:\d:\d:%s$" % detail['target_lun']
        func = lambda x: re.match(template, x)
        return [dir + f for f in files if func(f)]

    @utils.synchronized('connect_volume')
    def connect_volume(self, connection_info, disk_info):
        """Attach the volume to instance_name."""
        fc_properties = connection_info['data']
        mount_device = disk_info["dev"]

        ports = fc_properties['target_wwn']
        wwns = []
        # we support a list of wwns or a single wwn
        if isinstance(ports, list):
            for wwn in ports:
                wwns.append(str(wwn))
        elif isinstance(ports, basestring):
            wwns.append(str(ports))

        # We need to look for wwns on every hba
        # because we don't know ahead of time
        # where they will show up.
        hbas = virtutils.get_fc_hbas_info()
        host_devices = []
        for hba in hbas:
            pci_num = self._get_pci_num(hba)
            if pci_num is not None:
                for wwn in wwns:
                    target_wwn = "0x%s" % wwn.lower()
                    host_device = ("/dev/disk/by-path/pci-%s-fc-%s-lun-%s" %
                                  (pci_num,
                                   target_wwn,
                                   fc_properties.get('target_lun', 0)))
                    host_devices.append(host_device)

        if len(host_devices) == 0:
            # this is empty because we don't have any FC HBAs
            msg = _("We are unable to locate any Fibre Channel devices")
            raise exception.NovaException(msg)

        def _check_valid_device(path):
            cmd = ('dd', 'if=%(path)s' % {"path": path},
                   'of=/dev/null', 'iflag=direct', 'count=1')
            out, info = None, None
            try:
                out, info = utils.execute(*cmd, run_as_root=True)
            except processutils.ProcessExecutionError as e:
                LOG.error(_("Failed to access the device on the path "
                            "%(path)s: %(error)s.") %
                          {"path": path, "error": e.stderr})
                time.sleep(5)
                return False
            # If the info is none, the path does not exist.
            if info is None:
                return False
            return True

        # The /dev/disk/by-path/... node is not always present immediately
        # We only need to find the first device.  Once we see the first device
        # multipath will have any others.
        def _wait_for_device_discovery(host_devices, mount_device):
            tries = self.tries
            if CONF.libvirt.libvirt_iscsi_use_ultrapath:
                if self.tries > 0:
                    time.sleep(self.tries ** 2)
                ultra_dev_path = "/dev/disk/by-id/wwn-0x%s" % fc_properties['lun_wwn']
                if os.path.exists(ultra_dev_path):
                    self.host_device = ultra_dev_path
                    self.device_name = os.path.realpath(ultra_dev_path)
                    if _check_valid_device(self.host_device):
                        raise loopingcall.LoopingCallDone()
                else:
                    #check is it valid
                    by_path_devs = self._get_ultrapath_bypath_devices(fc_properties)
                    if len(by_path_devs) > 1:
                        LOG.error("found multiple by-path link."
                                  "Host may connect multiple array.")
                    for del_dev in by_path_devs:
                        if fc_properties['lun_wwn'] == linuxscsi.get_scsi_wwn(del_dev):
                            LOG.info("Try to delete invalid path.%s" % del_dev)
                            self._remove_scsi_device(os.path.realpath(del_dev))
            else:
                for device in host_devices:
                    LOG.debug(_("Looking for Fibre Channel dev %(device)s"),
                              {'device': device})
                    if os.path.exists(device):
                        self.host_device = device
                        # get the /dev/sdX device.  This is used
                        # to find the multipath device.
                        self.device_name = os.path.realpath(device)
                        raise loopingcall.LoopingCallDone()

            if self.tries >= CONF.libvirt.num_iscsi_scan_tries:
                msg = _("Fibre Channel device not found.")
                raise exception.NovaException(msg)

            LOG.warn(_("Fibre volume not yet found at: %(mount_device)s. "
                       "Will rescan & retry.  Try number: %(tries)s"),
                     {'mount_device': mount_device,
                      'tries': tries})

            linuxscsi.rescan_hosts(hbas,fc_properties.get('target_lun', None))
            self.tries = self.tries + 1

        self.host_device = None
        self.device_name = None
        self.tries = 0
        timer = loopingcall.FixedIntervalLoopingCall(
            _wait_for_device_discovery, host_devices, mount_device)
        timer.start(interval=2).wait()

        tries = self.tries
        if self.host_device is not None and self.device_name is not None:
            LOG.debug(_("Found Fibre Channel volume %(mount_device)s "
                        "(after %(tries)s rescans)"),
                      {'mount_device': mount_device,
                       'tries': tries})

        # see if the new drive is part of a multipath
        # device.  If so, we'll use the multipath device.
        if not CONF.libvirt.libvirt_iscsi_use_ultrapath:
            mdev_info = linuxscsi.find_multipath_device(self.device_name)
            if mdev_info is not None:
                LOG.debug(_("Multipath device discovered %(device)s")
                          % {'device': mdev_info['device']})
                device_path = mdev_info['device']
                connection_info['data']['devices'] = mdev_info['devices']
                connection_info['data']['multipath_id'] = mdev_info['id']
            else:
                # we didn't find a multipath device.
                # so we assume the kernel only sees 1 device
                device_path = self.host_device
                device_info = linuxscsi.get_device_info(self.device_name)
                connection_info['data']['devices'] = [device_info]
        else:
            # use ultrapath the kernel only sees 1 virtual device
            device_path = self.host_device
            device_info = linuxscsi.get_device_info(self.device_name)
            connection_info['data']['devices'] = [device_info]

        conf = super(LibvirtFibreChannelVolumeDriver,
                     self).connect_volume(connection_info, disk_info)

        conf.source_type = "block"
        conf.source_path = device_path
        return conf

    @utils.synchronized('connect_volume')
    def disconnect_volume(self, connection_info, mount_device):
        """Detach the volume from instance_name."""
        super(LibvirtFibreChannelVolumeDriver,
              self).disconnect_volume(connection_info, mount_device)
        #devices_db = connection_info['data']['devices']
        if CONF.libvirt.libvirt_iscsi_use_ultrapath:
            host_device = "/dev/disk/by-id/wwn-0x%s" % connection_info['data']['lun_wwn']
            devices = self.connection._get_all_block_devices()
            if host_device not in devices:
                self._remove_scsi_device(os.path.realpath(host_device))
            return

        # If this is a multipath device, we need to search again
        # and make sure we remove all the devices. Some of them
        # might not have shown up at attach time.
        if 'multipath_id' in connection_info['data']:
            multipath_id = connection_info['data']['multipath_id']
            mdev_info = linuxscsi.find_multipath_device(multipath_id)
            devices = mdev_info['devices']
            LOG.debug("devices to remove = %s" % devices)

        # There may have been more than 1 device mounted
        # by the kernel for this volume.  We have to remove
        # all of them
            for device in devices:
                linuxscsi.remove_device(device)

class LibvirtDswareVolumeDriver(LibvirtBaseVolumeDriver):
    """Libvirt Dsware Volume Driver, access huawei Dsware"""

    def __init__(self, connection):
        """Create back-end to dsware."""
        super(LibvirtDswareVolumeDriver, self).__init__(connection, is_block_dev=True)

    def _create_dev_path(self, source, volume_id):
        dev_path = "/dev/disk/by-id/dsware-%s" % volume_id
        if os.path.exists(dev_path):
            cmd_unlink = ['unlink', dev_path]
            utils.execute(*cmd_unlink, run_as_root=True)
        cmd_link = ['ln', '-s', source, dev_path]
        utils.execute(*cmd_link, run_as_root=True)
        return dev_path

    def _remove_dev_path(self, volume_id):
        dev_path = "/dev/disk/by-id/dsware-%s" % volume_id
        if os.path.exists(dev_path):
            cmd_unlink = ['unlink', dev_path]
            utils.execute(*cmd_unlink, run_as_root=True)

    def _attach_volume(self, volume_name, dsw_manager_ip):
        cmd = ['vbs_cli', '-c', 'attachwithip', '-v', volume_name, '-i', dsw_manager_ip.replace('\n','') , '-p', 0]
        (out, err) = utils.execute(*cmd, run_as_root=True)
        analyse_result = self._analyse_output(out)
        LOG.debug(_("_attach_volume out is %s") % analyse_result)
        return analyse_result

    def _detach_volume(self, volume_name, dsw_manager_ip):
        cmd = ['vbs_cli', '-c', 'detachwithip', '-v', volume_name, '-i', dsw_manager_ip.replace('\n','') , '-p', 0]
        (out, err) = utils.execute(*cmd, run_as_root=True)
        analyse_result = self._analyse_output(out)
        LOG.debug(_("_detach_volume out is %s") % analyse_result)
        return analyse_result

    def connect_volume(self, connection_info, disk_info):
        """Connect the volume. Returns xml for libvirt."""
        LOG.info('connect_volume %s' % connection_info)
        conf = super(LibvirtDswareVolumeDriver, self).connect_volume(connection_info, disk_info)

        # get volume name, 50151401 volume or snapshot has been attached
        out = self._attach_volume(connection_info['data']['volume_name'],connection_info['data']['dsw_manager_ip'])
        if (out is not None and int(out['ret_code']) not in (0, 50151401)) or out is None:
            msg = "initialize_connection failed."
            raise exception.NovaException(msg=msg)

        conf.source_type = 'block'
        conf.source_path = self._create_dev_path(out['dev_addr'], conf.serial)
        return conf

    def _analyse_output(self, out):
        if out is not None:
            analyse_result = {}
            out_temp = out.split('\n')
            for line in out_temp:
                if re.search('^ret_code=', line):
                    analyse_result['ret_code'] = line[9:]
                elif re.search('^ret_desc=', line):
                    analyse_result['ret_desc'] = line[9:]
                elif re.search('^dev_addr=', line):
                    analyse_result['dev_addr'] = line[9:]
            return analyse_result
        else:
            return None


    def disconnect_volume(self, connection_info, disk_dev):
        """Disconnect the volume."""
        LOG.info('disconnect_volume %s' % connection_info)
        super(LibvirtDswareVolumeDriver, self).disconnect_volume(connection_info, disk_dev)
        # delete the symlink
        self._remove_dev_path(connection_info['serial'])
        out = self._detach_volume(connection_info['data']['volume_name'],connection_info['data']['dsw_manager_ip'])
        if (out is not None and int(out['ret_code']) not in (0, 50151601)) or out is None:
            msg = "detach volume failed."
            raise exception.NovaException(msg=msg)


