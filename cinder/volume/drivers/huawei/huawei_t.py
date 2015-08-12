# Copyright (c) 2013 Huawei Technologies Co., Ltd.
# Copyright (c) 2012 OpenStack Foundation
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
Volume Drivers for Huawei OceanStor T series storage arrays.
"""

import re
import time

from cinder import exception
from cinder.i18n import _
from cinder.openstack.common import lockutils
from cinder.openstack.common import log as logging
from cinder.volume import driver
from cinder.volume.drivers.huawei import huawei_utils
from cinder.volume.drivers.huawei import ssh_common
from cinder.zonemanager import utils as fczm_utils
from cinder import utils
from cinder.image import image_utils
from cinder.openstack.common import fileutils

LOG = logging.getLogger(__name__)

HOST_PORT_PREFIX = 'HostPort_'
synchronized = lockutils.synchronized_with_prefix('brick-')

class HuaweiTISCSIDriver(driver.ISCSIDriver):
    """ISCSI driver for Huawei OceanStor T series storage arrays."""

    VERSION = '1.1.0'

    def __init__(self, *args, **kwargs):
        super(HuaweiTISCSIDriver, self).__init__(*args, **kwargs)

    def do_setup(self, context):
        """Instantiate common class."""
        self.common = ssh_common.TseriesCommon(configuration=
                                               self.configuration)
        self.common.do_setup(context)
        self._assert_cli_out = self.common._assert_cli_out
        self._assert_cli_operate_out = self.common._assert_cli_operate_out

    def check_for_setup_error(self):
        """Check something while starting."""
        self.common.check_for_setup_error()

    @synchronized("huawei-t")
    def create_volume(self, volume):
        """Create a new volume."""
        volume_id = self.common.create_volume(volume)
        return {'provider_location': volume_id}

    @synchronized("huawei-t")
    def create_volume_from_snapshot(self, volume, snapshot):
        """Create a volume from a snapshot."""
        volume_id = self.common.create_volume_from_snapshot(volume, snapshot)
        return {'provider_location': volume_id}

    @synchronized("huawei-t")
    def create_cloned_volume(self, volume, src_vref):
        """Create a clone of the specified volume."""
        volume_id = self.common.create_cloned_volume(volume, src_vref)
        return {'provider_location': volume_id}
    
    @synchronized("huawei-t")
    def extend_volume(self, volume, new_size):
        """Extend a volume."""
        self.common.extend_volume(volume, new_size)
    
    @synchronized("huawei-t")
    def delete_volume(self, volume):
        """Delete a volume."""
        try:
            self.common.force_remove_map(volume)
        except Exception as e:
            LOG.info("try to remove_map, but fail.")
        self.common.delete_volume(volume)

    def create_export(self, context, volume):
        """Export the volume."""
        pass

    def ensure_export(self, context, volume):
        """Synchronously recreate an export for a volume."""
        pass

    def remove_export(self, context, volume):
        """Remove an export for a volume."""
        pass

    @synchronized("huawei-t")
    def create_snapshot(self, snapshot):
        """Create a snapshot."""
        snapshot_id = self.common.create_snapshot(snapshot)
        return {'provider_location': snapshot_id}

    @synchronized("huawei-t")
    def delete_snapshot(self, snapshot):
        """Delete a snapshot."""
        self.common.delete_snapshot(snapshot)

    def initialize_ultrapath_connection(self, volume, connector):
        """Map a volume to a host and return target iSCSI information."""
        def get_targets_ips_info(initiator):
            conf_file = self.common.configuration.cinder_huawei_conf_file
            iscsi_conf = self._get_iscsi_conf(conf_file)
            target_ip = []
                                 
            
            if iscsi_conf['DefaultTargetIP']:
                for ip in iscsi_conf['DefaultTargetIP'].split(','):
                    target_ip.append(ip)
                    
            if not target_ip:
                msg = (_('_get_iscsi_params: Failed to get target IP '
                         'for initiator %(ini)s, please check config file.')
                       % {'ini': initiator})
                LOG.error(msg)
                raise exception.InvalidInput(reason=msg)
                    
            return self._get_tgt_iqn_ultrapath(map(lambda x:x.strip(),target_ip))
                  
        LOG.debug(_('initialize_multipath_connection: volume name: %(vol)s, '
                    'host: %(host)s, initiator: %(ini)s')
                  % {'vol': volume['name'],
                     'host': connector['host'],
                     'ini': connector['initiator']})        
   
        self.common._update_login_info()
        ips_info = get_targets_ips_info(connector['initiator'])


        # First, add a host if not added before.
        host_id = self.common.add_host(connector['host'],
                                       connector['initiator'])        
        
        # Then, add the iSCSI port to the host.
        self._add_iscsi_port_to_host(host_id, connector)
        
        # Finally, map the volume to the host.
        volume_id = volume['provider_location']
        hostlun_id = self.common.map_volume(host_id, volume_id)
        
        # Change LUN ctr for better performance, just for single path.
        lun_details = self.common.get_lun_details(volume_id)
        
        target_portal_list = []
        target_iqn_list = []
        for info in ips_info:
            target_portal_list.append('%s:%s' % (info[1], '3260'))
            target_iqn_list.append(info[0])
        properties = {}
        properties['target_discovered'] = False
        properties['target_portal'] = target_portal_list
        properties['target_iqn'] = target_iqn_list
        properties['target_lun'] = int(hostlun_id)
        properties['volume_id'] = volume['id']
        properties['lun_wwn'] = lun_details['LUNWWN']
        properties['target_num'] = len(ips_info)
        auth = volume['provider_auth']
        if auth:
            (auth_method, auth_username, auth_secret) = auth.split()

            properties['auth_method'] = auth_method
            properties['auth_username'] = auth_username
            properties['auth_password'] = auth_secret       
        properties['description'] = 'huawei'                 
        return {'driver_volume_type': 'iscsi', 'data': properties}
     
    def initialize_common_connection(self, volume, connector):
        LOG.debug(_('initialize_common_connection: volume name: %(vol)s, '
                    'host: %(host)s, initiator: %(ini)s')
                  % {'vol': volume['name'],
                     'host': connector['host'],
                     'ini': connector['initiator']})

        self.common._update_login_info()
        (iscsi_iqn, target_ip, port_ctr) =\
            self._get_iscsi_params(connector['initiator'])

        # First, add a host if not added before.
        host_id = self.common.add_host(connector['host'],
                                       connector['initiator'])

        # Then, add the iSCSI port to the host.
        self._add_iscsi_port_to_host(host_id, connector)

        # Finally, map the volume to the host.
        volume_id = volume['provider_location']
        hostlun_id = self.common.map_volume(host_id, volume_id)

        ## Change LUN ctr for better performance, just for single path.
        lun_details = self.common.get_lun_details(volume_id)

        properties = {}
        properties['target_discovered'] = False
        properties['target_portal'] = ('%s:%s' % (target_ip, '3260'))
        properties['target_iqn'] = iscsi_iqn
        properties['target_lun'] = int(hostlun_id)
        properties['volume_id'] = volume['id']
        properties['lun_wwn'] = lun_details['LUNWWN']
        auth = volume['provider_auth']
        if auth:
            (auth_method, auth_username, auth_secret) = auth.split()

            properties['auth_method'] = auth_method
            properties['auth_username'] = auth_username
            properties['auth_password'] = auth_secret
        properties['description'] = 'huawei'
        return {'driver_volume_type': 'iscsi', 'data': properties}
    
    @synchronized("huawei-t")               
    def initialize_connection(self, volume, connector):
        """Map a volume to a host and return target iSCSI information."""
        if connector.has_key('nova_use_ultrapath'):
            if connector.get('nova_use_ultrapath'):
                return self.initialize_ultrapath_connection(volume, connector)
            else:
                return self.initialize_common_connection(volume, connector)
               
        if self.configuration.safe_get("use_ultrapath_for_image_xfer"):
            return self.initialize_ultrapath_connection(volume, connector)
        return self.initialize_common_connection(volume, connector)

    def _get_iscsi_params(self, initiator):
        """Get target iSCSI params, including iqn and IP."""
        conf_file = self.common.configuration.cinder_huawei_conf_file
        iscsi_conf = self._get_iscsi_conf(conf_file)
        target_ip = None
        for ini in iscsi_conf['Initiator']:
            if ini['Name'] == initiator:
                target_ip = ini['TargetIP']
                break
        # If didn't specify target IP for some initiator, use default IP.
        if not target_ip:
            if iscsi_conf['DefaultTargetIP']:
                target_ip = iscsi_conf['DefaultTargetIP']
                target_ip = target_ip.split(',')[0]

            else:
                msg = (_('_get_iscsi_params: Failed to get target IP '
                         'for initiator %(ini)s, please check config file.')
                       % {'ini': initiator})
                LOG.error(msg)
                raise exception.InvalidInput(reason=msg)

        (target_iqn, port_ctr) = self._get_tgt_iqn(target_ip)
        return (target_iqn, target_ip, port_ctr)

    def _get_iscsi_conf(self, filename):
        """Get iSCSI info from config file.

        This function returns a dict:
        {'DefaultTargetIP': '11.11.11.11',
         'Initiator': [{'Name': 'iqn.xxxxxx.1', 'TargetIP': '11.11.11.12'},
                       {'Name': 'iqn.xxxxxx.2', 'TargetIP': '11.11.11.13'}
                      ]
        }

        """

        iscsiinfo = {}
        root = huawei_utils.parse_xml_file(filename)

        default_ip = root.findtext('iSCSI/DefaultTargetIP')
        if default_ip:
            iscsiinfo['DefaultTargetIP'] = default_ip.strip()
        else:
            iscsiinfo['DefaultTargetIP'] = None
        initiator_list = []
        tmp_dic = {}
        for dic in root.findall('iSCSI/Initiator'):
            # Strip the values of dict.
            for k, v in dic.items():
                tmp_dic[k] = v.strip()
            initiator_list.append(tmp_dic)
        iscsiinfo['Initiator'] = initiator_list
        return iscsiinfo

    def _get_iscsi_tgt_port_info_ultrapath(self, port_ip_list):
        """Get iSCSI Port information of storage device."""
        port_info_list = []
        cli_cmd = 'showiscsiip'
        out = self.common._execute_cli(cli_cmd)
        if re.search('iSCSI IP Information', out):
            for line in out.split('\r\n')[6:-2]:
                tmp_line = line.split()
                if tmp_line[3] in port_ip_list:
                    port_info_list.append(tmp_line)

        if port_info_list:
            return port_info_list

        err_msg = _('All target IPs are not available,'
                    'all target IPs  is not configured in array')
        LOG.error(err_msg)
        raise exception.VolumeBackendAPIException(data=err_msg)

    def _get_tgt_iqn_ultrapath(self, port_ip_list):

        LOG.debug('_get_tgt_iqn_ultrapath: iSCSI list is %s.' % port_ip_list)

        cli_cmd = 'showiscsitgtname'
        out = self.common._execute_cli(cli_cmd)

        self._assert_cli_out(re.search('ISCSI Name', out),
                             '_get_tgt_iqn',
                             'Failed to get iSCSI target iqn.',
                             cli_cmd, out)

        lines = out.split('\r\n')
        index = lines[4].index('iqn')
        iqn_prefix = lines[4][index:].strip()
        # Here we make sure port_info won't be None.
        ret_info = []
        port_info_list = self._get_iscsi_tgt_port_info_ultrapath(port_ip_list)
        for port_info in port_info_list:
            ctr = ('0' if port_info[0] == 'A' else '1')
            interface = '0' + port_info[1]
            port = '0' + port_info[2][1:]
            iqn_suffix = ctr + '02' + interface + port
            # iqn_suffix should not start with 0
            while(True):
                if iqn_suffix.startswith('0'):
                    iqn_suffix = iqn_suffix[1:]
                else:
                    break

            iqn = iqn_prefix + ':' + iqn_suffix + ':' + port_info[3]

            LOG.debug('_get_tgt_iqn: iSCSI target iqn is %s.' % iqn)
            ret_info.append((iqn,port_info[3],port_info[0]))

        return ret_info

    def _get_tgt_iqn(self, port_ip):
        """Run CLI command to get target iSCSI iqn.

        The iqn is formed with three parts:
        iSCSI target name + iSCSI port info + iSCSI IP

        """

        LOG.debug('_get_tgt_iqn: iSCSI IP is %s.' % port_ip)

        cli_cmd = 'showiscsitgtname'
        out = self.common._execute_cli(cli_cmd)

        self._assert_cli_out(re.search('ISCSI Name', out),
                             '_get_tgt_iqn',
                             'Failed to get iSCSI target %s iqn.' % port_ip,
                             cli_cmd, out)

        lines = out.split('\r\n')
        index = lines[4].index('iqn')
        iqn_prefix = lines[4][index:].strip()
        # Here we make sure port_info won't be None.
        port_info = self._get_iscsi_tgt_port_info(port_ip)
        ctr = ('0' if port_info[0] == 'A' else '1')
        interface = '0' + port_info[1]
        port = '0' + port_info[2][1:]
        iqn_suffix = ctr + '02' + interface + port
        # iqn_suffix should not start with 0
        while(True):
            if iqn_suffix.startswith('0'):
                iqn_suffix = iqn_suffix[1:]
            else:
                break

        iqn = iqn_prefix + ':' + iqn_suffix + ':' + port_info[3]

        LOG.debug('_get_tgt_iqn: iSCSI target iqn is %s.' % iqn)

        return (iqn, port_info[0])

    def _get_iscsi_tgt_port_info(self, port_ip):
        """Get iSCSI Port information of storage device."""
        cli_cmd = 'showiscsiip'
        out = self.common._execute_cli(cli_cmd)
        if re.search('iSCSI IP Information', out):
            for line in out.split('\r\n')[6:-2]:
                tmp_line = line.split()
                if tmp_line[3] == port_ip:
                    return tmp_line

        err_msg = _('_get_iscsi_tgt_port_info: Failed to get iSCSI port '
                    'info. Please make sure the iSCSI port IP %s is '
                    'configured in array.') % port_ip
        LOG.error(err_msg)
        raise exception.VolumeBackendAPIException(data=err_msg)

    @synchronized("add_iscsi_port_to_host")
    def _add_iscsi_port_to_host(self, hostid, connector, multipathtype=0):
        """Add an iSCSI port to the given host.

        First, add an initiator if needed, the initiator is equivalent to
        an iSCSI port. Then, add the initiator to host if not added before.

        """

        initiator = connector['initiator']
        # Add an iSCSI initiator.
        if not self._initiator_added(initiator):
            self._add_initiator(initiator)
        # Add the initiator to host if not added before.
        port_name = HOST_PORT_PREFIX + str(hash(initiator))
        portadded = False
        hostport_info = self.common._get_host_port_info(hostid)
        if hostport_info:
            for hostport in hostport_info:
                if hostport[2] == initiator:
                    portadded = True
                    break
        if not portadded:
            cli_cmd = ('addhostport -host %(id)s -type 5 '
                       '-info %(info)s -n %(name)s -mtype %(multype)s'
                       % {'id': hostid,
                          'info': initiator,
                          'name': port_name,
                          'multype': multipathtype})
            out = self.common._execute_cli(cli_cmd)

            msg = ('Failed to add iSCSI port %(port)s to host %(host)s'
                   % {'port': port_name,
                      'host': hostid})
            self._assert_cli_operate_out('_add_iscsi_port_to_host',
                                         msg, cli_cmd, out)

    def _initiator_added(self, ininame):
        """Check whether the initiator is already added."""
        cli_cmd = 'showiscsiini -ini %(name)s' % {'name': ininame}
        out = self.common._execute_cli(cli_cmd)
        return (True if re.search('Initiator Information', out) else False)

    def _add_initiator(self, ininame):
        """Add a new initiator to storage device."""
        cli_cmd = 'addiscsiini -n %(name)s' % {'name': ininame}
        out = self.common._execute_cli(cli_cmd)

        self._assert_cli_operate_out('_add_iscsi_host_port',
                                     'Failed to add initiator %s' % ininame,
                                     cli_cmd, out)

    def _delete_initiator(self, ininame, attempts=2):
        """Delete an initiator."""
        cli_cmd = 'deliscsiini -n %(name)s' % {'name': ininame}
        while(attempts > 0):
            out = self.common._execute_cli(cli_cmd)
            if re.search('the port is in use', out):
                attempts -= 1
                time.sleep(10)
            else:
                break

        self._assert_cli_operate_out('_delete_initiator',
                                     'Failed to delete initiator %s.'
                                     % ininame,
                                     cli_cmd, out)

    @synchronized("huawei-t")
    def terminate_connection(self, volume, connector, **kwargs):
        """Terminate the map."""
        # TODO.check the connector, as we can't get initiatorname during
        # local_delete and the whole info in force-delete
        if not connector.has_key('host') or not connector.has_key('initiator'):
            LOG.info("terminate_connection: local-delete or force delete.")
            return
        LOG.debug('terminate_connection: volume: %(vol)s, host: %(host)s, '
                  'connector: %(initiator)s'
                  % {'vol': volume['name'],
                     'host': connector['host'],
                     'initiator': connector['initiator']})

        self.common._update_login_info()
        host_id = self.common.remove_map(volume['provider_location'],
                                         connector['host'],
                                         connector['initiator'])

    def _remove_iscsi_port(self, hostid, connector):
        """Remove iSCSI ports and delete host."""
        initiator = connector['initiator']
        # Delete the host initiator if no LUN mapped to it.
        port_num = 0
        port_info = self.common._get_host_port_info(hostid)
        if port_info:
            port_num = len(port_info)
            for port in port_info:
                if port[2] == initiator:
                    self.common._delete_hostport(port[0])
                    self._delete_initiator(initiator,5)
                    port_num -= 1
                    break
        else:
            LOG.warn(_('_remove_iscsi_port: iSCSI port was not found '
                       'on host %(hostid)s.') % {'hostid': hostid})

        # Delete host if no initiator added to it.
        if port_num == 0:
            self.common._delete_host(hostid)

    def get_volume_stats(self, refresh=False):
        """Get volume stats."""
        self._stats = self.common.get_volume_stats(refresh)
        self._stats['storage_protocol'] = 'iSCSI'
        self._stats['driver_version'] = self.VERSION
        backend_name = self.configuration.safe_get('volume_backend_name')
        self._stats['volume_backend_name'] = (backend_name or
                                              self.__class__.__name__)
        return self._stats

    def _detach_and_terminate_syc(self,context,attach_info,volume,properties):
        self._detach_volume(context,attach_info,volume,properties)
        self.terminate_connection(volume, properties)

    def _attach_volume_syc(self,context, volume):
        properties = utils.brick_get_connector_properties()
        attach_info = self._attach_volume(context, volume, properties)
        return (properties,attach_info)

    def backup_volume(self, context, backup, backup_service):
        """Create a new backup from an existing volume."""
        volume = self.db.volume_get(context, backup['volume_id'])

        LOG.debug(_('Creating a new backup for volume %s.') %
                  volume['name'])

        (properties,attach_info) = self._attach_volume_syc(context, volume)

        try:
            volume_path = attach_info['device']['path']
            with utils.temporary_chown(volume_path):
                with fileutils.file_open(volume_path) as volume_file:
                    backup_service.backup(backup, volume_file)

        finally:
            self._detach_and_terminate_syc(context,attach_info,volume,properties)
    
    def restore_backup(self, context, backup, volume, backup_service):
        """Restore an existing backup to a new or existing volume."""
        LOG.debug(_('Restoring backup %(backup)s to '
                    'volume %(volume)s.') %
                  {'backup': backup['id'],
                   'volume': volume['name']})

        (properties,attach_info) = self._attach_volume_syc(context, volume)

        try:
            volume_path = attach_info['device']['path']
            with utils.temporary_chown(volume_path):
                with fileutils.file_open(volume_path, 'wb') as volume_file:
                    backup_service.restore(backup, volume['id'], volume_file)

        finally:
            self._detach_and_terminate_syc(context,attach_info,volume,properties)

    def copy_volume_to_image(self, context, volume, image_service, image_meta):
        """Copy the volume to the specified image."""
    
        LOG.debug(_('copy_volume_to_image %s.') % volume['name'])
        (properties,attach_info) = self._attach_volume_syc(context, volume)

        try:
            image_utils.upload_volume(context,
                                      image_service,
                                      image_meta,
                                      attach_info['device']['path'])
        finally:
            self._detach_and_terminate_syc(context,attach_info,volume,properties)
                  
    def copy_image_to_volume(self, context, volume, image_service, image_id):
        """Fetch the image from image_service and write it to the volume."""
                    
        LOG.debug(_('copy_image_to_volume %s.') % volume['name'])

        (properties,attach_info) = self._attach_volume_syc(context, volume)

        try:
            image_utils.fetch_to_raw(context,
                                     image_service,
                                     image_id,
                                     attach_info['device']['path'],
                                     self.configuration.volume_dd_blocksize,
                                     size=volume['size'])
        finally:
            self._detach_and_terminate_syc(context,attach_info,volume,properties)
            
class HuaweiTFCDriver(driver.FibreChannelDriver):
    """FC driver for Huawei OceanStor T series storage arrays."""

    VERSION = '1.0.0'

    def __init__(self, *args, **kwargs):
        super(HuaweiTFCDriver, self).__init__(*args, **kwargs)

    def do_setup(self, context):
        """Instantiate common class."""
        self.common = ssh_common.TseriesCommon(configuration=
                                               self.configuration)
        self.common.do_setup(context)
        self._assert_cli_out = self.common._assert_cli_out
        self._assert_cli_operate_out = self.common._assert_cli_operate_out

    def check_for_setup_error(self):
        """Check something while starting."""
        self.common.check_for_setup_error()

    @synchronized("huawei-t")
    def create_volume(self, volume):
        """Create a new volume."""
        volume_id = self.common.create_volume(volume)
        return {'provider_location': volume_id}
    @synchronized("huawei-t")
    def create_volume_from_snapshot(self, volume, snapshot):
        """Create a volume from a snapshot."""
        volume_id = self.common.create_volume_from_snapshot(volume, snapshot)
        return {'provider_location': volume_id}
    @synchronized("huawei-t")
    def create_cloned_volume(self, volume, src_vref):
        """Create a clone of the specified volume."""
        volume_id = self.common.create_cloned_volume(volume, src_vref)
        return {'provider_location': volume_id}
    
    @synchronized("huawei-t")
    def extend_volume(self, volume, new_size):
        """Extend a volume."""
        self.common.extend_volume(volume, new_size)

    @synchronized("huawei-t")
    def delete_volume(self, volume):
        """Delete a volume."""
        try:
            self.common.force_remove_map(volume)
        except Exception as e:
            LOG.info("try to remove_map, but fail.")
        self.common.delete_volume(volume)

    def create_export(self, context, volume):
        """Export the volume."""
        pass

    def ensure_export(self, context, volume):
        """Synchronously recreate an export for a volume."""
        pass

    def remove_export(self, context, volume):
        """Remove an export for a volume."""
        pass
    @synchronized("huawei-t")
    def create_snapshot(self, snapshot):
        """Create a snapshot."""
        snapshot_id = self.common.create_snapshot(snapshot)
        return {'provider_location': snapshot_id}
    @synchronized("huawei-t")
    def delete_snapshot(self, snapshot):
        """Delete a snapshot."""
        self.common.delete_snapshot(snapshot)

    def validate_connector(self, connector):
        """Check for wwpns in connector."""
        if 'wwpns' not in connector:
            err_msg = (_('validate_connector: The FC driver requires the'
                         ' wwpns in the connector.'))
            LOG.error(err_msg)
            raise exception.VolumeBackendAPIException(data=err_msg)

    @synchronized("huawei-t")
    @fczm_utils.AddFCZone
    def initialize_connection(self, volume, connector):
        """Create FC connection between a volume and a host."""
        LOG.debug('initialize_connection: volume name: %(vol)s, '
                  'host: %(host)s, initiator: %(wwn)s'
                  % {'vol': volume['name'],
                     'host': connector['host'],
                     'wwn': connector['wwpns']})

        self.common._update_login_info()
        # First, add a host if it is not added before.
        host_id = self.common.add_host(connector['host'], connector['ip'])
        # Then, add free FC ports to the host.
        ini_wwns = connector['wwpns']
        free_wwns = self._get_connected_free_wwns()
        for wwn in free_wwns:
            if wwn in ini_wwns:
                self._add_fc_port_to_host(host_id, wwn)
        fc_port_details = self._get_host_port_details(host_id)
        tgt_wwns = self._get_tgt_fc_port_wwns(fc_port_details)

        LOG.debug('initialize_connection: Target FC ports WWNS: %s'
                  % tgt_wwns)

        # Finally, map the volume to the host.
        volume_id = volume['provider_location']
        hostlun_id = self.common.map_volume(host_id, volume_id)

        lun_details = self.common.get_lun_details(volume_id)
        properties = {}
        properties['target_discovered'] = False
        properties['target_wwn'] = tgt_wwns
        properties['target_lun'] = int(hostlun_id)
        properties['volume_id'] = volume['id']
        properties['lun_wwn'] = lun_details['LUNWWN']
        
        return {'driver_volume_type': 'fibre_channel',
                'data': properties}

    def _get_connected_free_wwns(self):
        """Get free connected FC port WWNs.

        If no new ports connected, return an empty list.

        """

        cli_cmd = 'showfreeport'
        out = self.common._execute_cli(cli_cmd)
        wwns = []
        if re.search('Host Free Port Information', out):
            for line in out.split('\r\n')[6:-2]:
                tmp_line = line.split()
                if (tmp_line[1] == 'FC') and (tmp_line[4] == 'Connected'):
                    wwns.append(tmp_line[0])

        return list(set(wwns))

    def _add_fc_port_to_host(self, hostid, wwn, multipathtype=0):
        """Add a FC port to host."""
        portname = HOST_PORT_PREFIX + wwn
        cli_cmd = ('addhostport -host %(id)s -type 1 '
                   '-wwn %(wwn)s -n %(name)s -mtype %(multype)s'
                   % {'id': hostid,
                      'wwn': wwn,
                      'name': portname,
                      'multype': multipathtype})
        out = self.common._execute_cli(cli_cmd)

        msg = ('Failed to add FC port %(port)s to host %(host)s.'
               % {'port': portname, 'host': hostid})
        self._assert_cli_operate_out('_add_fc_port_to_host', msg, cli_cmd, out)

    def _get_host_port_details(self, host_id):
        cli_cmd = 'showhostpath -host %s' % host_id
        out = self.common._execute_cli(cli_cmd)

        self._assert_cli_out(re.search('Multi Path Information', out),
                             '_get_host_port_details',
                             'Failed to get host port details.',
                             cli_cmd, out)

        port_details = []
        tmp_details = {}
        for line in out.split('\r\n')[4:-2]:
            line = line.split('|')
            # Cut-point of multipal details, usually is "-------".
            if len(line) == 1:
                port_details.append(dict(tmp_details))
                continue
            key = ''.join(line[0].strip().split())
            val = line[1].strip()
            tmp_details[key] = val
        port_details.append(tmp_details)
        return port_details

    def _get_tgt_fc_port_wwns(self, port_details):
        wwns = []
        for port in port_details:
            wwns.append(port['TargetWWN'])
        return wwns

    def _get_fc_port_ctr(self, port_details):
        return port_details['ControllerID']

    @synchronized("huawei-t")
    @fczm_utils.RemoveFCZone
    def terminate_connection(self, volume, connector, **kwargs):
        """Terminate the map."""
        LOG.debug('terminate_connection: volume: %(vol)s, host: %(host)s, '
                  'connector: %(initiator)s'
                  % {'vol': volume['name'],
                     'host': connector['host'],
                     'initiator': connector['initiator']})

        self.common._update_login_info()
        host_id = self.common.remove_map(volume['provider_location'],
                                         connector['host'])
        # Remove all FC ports and delete the host if
        # no volume mapping to it.
        if host_id is not None and not self.common._get_host_map_info(host_id):
            self._remove_fc_ports(host_id, connector)

    def _remove_fc_ports(self, hostid, connector):
        """Remove FC ports and delete host."""
        wwns = connector['wwpns']
        port_num = 0
        port_info = self.common._get_host_port_info(hostid)
        if port_info:
            port_num = len(port_info)
            for port in port_info:
                if port[2] in wwns:
                    self.common._delete_hostport(port[0])
                    port_num -= 1
        else:
            LOG.warn(_('_remove_fc_ports: FC port was not found '
                       'on host %(hostid)s.') % {'hostid': hostid})

        if port_num == 0:
            self.common._delete_host(hostid)

    def get_volume_stats(self, refresh=False):
        """Get volume stats."""
        self._stats = self.common.get_volume_stats(refresh)
        self._stats['storage_protocol'] = 'FC'
        self._stats['driver_version'] = self.VERSION
        backend_name = self.configuration.safe_get('volume_backend_name')
        self._stats['volume_backend_name'] = (backend_name or
                                              self.__class__.__name__)
        return self._stats

    def _detach_and_terminate_syc(self,context,attach_info,volume,properties):
        self._detach_volume(context,attach_info,volume,properties)
        self.terminate_connection(volume, properties)
       
    def _attach_volume_syc(self,context, volume):
        properties = utils.brick_get_connector_properties()
        attach_info = self._attach_volume(context, volume, properties)
        return (properties,attach_info)

    def copy_volume_to_image(self, context, volume, image_service, image_meta):
        """Copy the volume to the specified image."""
       
        LOG.debug(_('copy_volume_to_image %s.') % volume['name'])
        (properties,attach_info) = self._attach_volume_syc(context, volume)

        try:
            image_utils.upload_volume(context,
                                      image_service,
                                      image_meta,
                                      attach_info['device']['path'])
        finally:
            self._detach_and_terminate_syc(context,attach_info,volume,properties)
            
                   
    def copy_image_to_volume(self, context, volume, image_service, image_id):
        """Fetch the image from image_service and write it to the volume."""
                    
        LOG.debug(_('copy_image_to_volume %s.') % volume['name'])

        (properties,attach_info) = self._attach_volume_syc(context, volume)

        try:
            image_utils.fetch_to_raw(context,
                                     image_service,
                                     image_id,
                                     attach_info['device']['path'],
                                     self.configuration.volume_dd_blocksize,
                                     size=volume['size'])
        finally:
            self._detach_and_terminate_syc(context,attach_info,volume,properties)          
