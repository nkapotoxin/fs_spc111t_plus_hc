"""
    API of Volume Resource on FC
"""

from nova import volume
from nova.openstack.common.gettextutils import _

from nova.fusioncompute.virt.huaweiapi import ops_task_base
from nova.fusioncompute.virt.huaweiapi import exception as fc_exc
from nova.fusioncompute.virt.huaweiapi import constant
from nova.fusioncompute.virt.huaweiapi.utils import LOG
from nova.fusioncompute.virt.huaweiapi import utils

class VolumeOps(ops_task_base.OpsTaskBase):
    """
    volume operation class
    """
    def __init__(self, fc_client, task_ops):
        super(VolumeOps, self).__init__(fc_client, task_ops)
        self._volume_api = volume.API()

    def get_block_device_meta_data(self, context, block_device_info):
        """
        get volume meta data info from input info
        :param context:
        :param block_device_info:
        :return:
        """
        LOG.debug('volume info is: %s', block_device_info)
        if len(block_device_info['block_device_mapping']) > 0:
            volume_info = block_device_info['block_device_mapping'][0]
            volume_id = volume_info['connection_info']['serial']
            return self._get_volume_meta_data(context, volume_id)
        return None

    def ensure_volume(self, volume_info):
        """
        Ensure volume resource on FC
        :param volume_info:
        :return:
        """
        LOG.debug('volume info is: %s', volume_info)

        return [
            {
                'pci': 'IDE',
                'urn': bdm['connection_info']['vol_urn'],
                'mount_device': bdm['mount_device']
            }
            for bdm in volume_info['block_device_mapping']
        ]

    def expand_volume(self, fc_vm, vol_config):
        """
        Expand sys volume
        :param fc_vm: FC instance
        :param vol_config:
        :return:
        """
        vm_expandvol_uri = fc_vm.get_vm_action_uri('expandvol')
        return self.post(vm_expandvol_uri, data=vol_config,
                         excp=fc_exc.InstanceExpandvolFailure)

    def attach_volume(self, fc_vm, vol_config):
        """
        Attach volume for vm
        :param fc_vm: FC instance
        :param vol_config:
        :return:
        """
        vm_attachvol_uri = fc_vm.get_vm_action_uri('attachvol')
        self.post(vm_attachvol_uri, data=vol_config,
                  excp=fc_exc.InstanceAttachvolFailure)

    def detach_volume(self, fc_vm, vol_config):
        """
        Detach volume for vm
        :param fc_vm: FC instance
        :param vol_config:
        :return:
        """
        vm_detachvol_uri = fc_vm.get_vm_action_uri('detachvol')
        self.post(vm_detachvol_uri, data=vol_config,
                  excp=fc_exc.InstanceDetachvolFailure)

    def delete_volume(self, vol_uri):
        """
        Delete volume
        :param vol_uri:
        :return:
        """
        self.delete(vol_uri, excp=fc_exc.VolumeDeleteFailure)

    def create_image_from_volume(self, vol_uri, vol, image_id):
        """

        :param vol_uri: volume action uri
        :param vol:
        :param image_id:
        :return:
        """
        body = {
            'volumePara':{
                'quantityGB': vol.get('quantityGB'),
                'urn': vol.get('volumeUrn')
            },
            'imagePara':{
                'id': image_id,
                'url': constant.CONF.fusioncompute.fc_image_path
            }
        }

        image_create_uri = vol_uri + '/volumetoimage'
        self.post(image_create_uri, data=body, excp=fc_exc.ImageCreateFailure)

    def _get_volume_meta_data(self, context, volume_id):
        """
        from cinder get volume metadata
        :param volume_id:
        :return:
        """
        LOG.debug(_('get_volume_meta_data enter, volume_id:%s.'), volume_id)
        return self._volume_api.get(context, volume_id)

    def set_qos_specs_to_volume(self, info):
        """

        :param info
        :return:
        """
        def _set_qos_specs_to_volume(self, connection_info):
            """

            :param connection_info
            :return:
            """
            qos_para = {'maxReadBytes': 0,
                        'maxWriteBytes': 0,
                        'maxReadRequest': 0,
                        'maxWriteRequest': 0}
            key_cvt_map = {'read_bytes_sec': 'maxReadBytes',
                           'write_bytes_sec': 'maxWriteBytes',
                           'read_iops_sec': 'maxReadRequest',
                           'write_iops_sec': 'maxWriteRequest'}
            tune_opts = ['read_bytes_sec', 'write_bytes_sec',
                         'read_iops_sec', 'write_iops_sec']
            tune_cvt_opts = ['read_bytes_sec', 'write_bytes_sec']
            # Extract rate_limit control parameters
            if connection_info is None or 'data' not in connection_info:
                return

            specs = connection_info['data']['qos_specs']
            vol_urn = connection_info.get('vol_urn')

            if vol_urn is None:
                return

            # because the volume can be detached and attach to another instance
            # qos maybe disassociated from volume type
            # between the up two operations
            # so if specs is none,set default value to FC.
            if specs is not None:
                if isinstance(specs, dict):
                    for key, value in specs.iteritems():
                        if key in tune_opts:
                            # convert byte to KB for FC,0 is no limited,
                            # the value is at least 1
                            output_value = value

                            if key in tune_cvt_opts:
                                addition = 0
                                if output_value.isdigit():
                                    if long(value) % 1024 != 0:
                                        addition = 1
                                    output_value = long(value) / 1024 \
                                                   + addition

                            qos_para[key_cvt_map[key]] = output_value
                else:
                    LOG.debug(_('Unknown content in connection_info '
                                'qos_specs: %s'), specs)
                    return

            qos_specs_uri = utils.generate_uri_from_urn(vol_urn) \
                            + constant.VOL_URI_MAP['modio']

            # Send Qos IO Specs to VRM with put method
            self.put(qos_specs_uri, data=qos_para,
                     excp=fc_exc.SetQosIoFailure)

        if isinstance(info, dict):
            # input para is block_device_info
            if 'block_device_mapping' in info:
                block_device_mapping = info.get('block_device_mapping', [])
                for vol in block_device_mapping:
                    connection_info = vol['connection_info']
                    _set_qos_specs_to_volume(self, connection_info)
            # input para is connection_info
            else:
                _set_qos_specs_to_volume(self, info)
