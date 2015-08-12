"""
    FusionCompute create vm
"""

import re

from nova import exception
from nova.openstack.common import jsonutils
from nova.openstack.common.gettextutils import _

from nova.fusioncompute.virt.huaweiapi import ops_task_base
from nova.fusioncompute.virt.huaweiapi import constant
from nova.fusioncompute.virt.huaweiapi import exception as fc_exc
from nova.fusioncompute.virt.huaweiapi import utils
from nova.fusioncompute.virt.huaweiapi.utils import LOG
from nova.fusioncompute.virt.huaweiapi.fcinstance import FC_INSTANCE_MANAGER as FC_MGR

from FSComponentUtil import crypt

class VmCreateBase(ops_task_base.OpsTaskBase):
    """vm controller class"""
    def __init__(self, fc_client, task_ops, instance):
        super(VmCreateBase, self).__init__(fc_client, task_ops)
        self._instance = instance
        self._key_data = self._instance.get('key_data')
        self._metadata = self._instance.get('metadata')

        self._vm_create_body = {}
        self._volume_ops = None
        self._location = None
        self._vifs = []
        self._block_device_info = {}
        self._root_device_name = None
        self._image_meta = {}
        self._injected_files = []
        self._admin_password = None
        self._extra_specs = {}
        self._context = {}
        self._customization = {}

    def __call__(self, context, volume_ops, location,
                 vifs, block_device_info, image_meta,
                 injected_files, admin_password, extra_specs, customization):
        self._volume_ops = volume_ops
        self._location = location
        self._vifs = vifs
        self._block_device_info = block_device_info
        self._root_device_name = block_device_info.get('root_device_name')
        self._image_meta = image_meta
        self._injected_files = injected_files
        self._admin_password = admin_password
        self._extra_specs = extra_specs
        self._context = context
        self._customization = customization

    @property
    def image_properties(self):
        """
        image mate properties
        :return:
        """
        if self._image_meta:
            return self._image_meta.get('properties', {})
        else:
            return {}

    def check_input(self):
        """
        check function input params
        :return:
        """
        os_option = self.get_os_options()
        LOG.debug(_('os option: %s .'), jsonutils.dumps(os_option))
        if not (os_option['osType'] and os_option['osVersion']):
            LOG.error('Invalid os option for vm %s!', self._instance['name'])
            raise fc_exc.InvalidOsOption()

    def get_body_ext(self):
        """
        if body not enough, child class can extend
        :return:
        """
        raise NotImplementedError()

    def build_para(self):
        """build create body"""
        self._vm_create_body = {
            'name': self._instance['display_name'],
            'description': self._instance['name'],
            'group': constant.VM_GROUP_FLAG,
            'uuid': self._instance['uuid'],
            'location': self._location,
            'autoBoot': self.is_auto_boot(),
            'vmConfig': self.get_vm_config(),
            'osOptions': self.get_os_options(),
            'vmCustomization': self.get_vm_customization(),
            'publickey': self._key_data
        }
        self.get_body_ext()

    def extend_ops_before_start(self):
        """
        vm is created in stopped state, do something before start
        :return:
        """
        pass

    def create_and_boot_vm(self):
        """
        create vm interface func
        :return:
        """
        self.check_input()
        self.build_para()
        self.create_vm()

        # VM is created in stopped state in some cases,
        # do the extended ops in subclass and start it at last
        if not self.is_auto_boot():
            self.inject_files()

            #Other opeation when vm stoped
            self.extend_ops_before_start()
            self.start_vm()

    def get_cpu_info(self):
        """get vm cpu info"""
        cpu_info = {'quantity': self._instance['vcpus']}
        cpu_qos = utils.dict_filter_and_convert(self._extra_specs,
                                                constant.CPU_QOS_NOVA_KEY,
                                                constant.CPU_QOS_FC_KEY)
        cpu_info = utils.dict_add(cpu_info, cpu_qos)
        return cpu_info

    def get_memory_info(self):
        """get vm memory info"""
        return {
            'quantityMB': self._instance['memory_mb']
        }

    def get_disks_info(self):
        """get vm disk specific info"""
        raise NotImplementedError()

    def get_nic_info(self):
        """get vm nic info"""
        return [
            {
                'name': vif['network_info']['id'],
                'portId': vif['network_info']['id'],
                'mac': vif['network_info']['address'],
                'portGroupUrn': vif['pg_urn'],
                'sequenceNum': vif['sequence_num']
            }
            for vif in self._vifs
        ]

    def get_fc_os_options(self, os_type, os_version):
        """
        get fc options
        :param os_type:
        :param os_version:
        :return:
        """
        try:
            fc_os_type = constant.HUAWEI_OS_TYPE_MAP[os_type.lower()]
            fc_os_version = \
                constant.HUAWEI_OS_VERSION_INT[os_type][os_version.lower()]
        #ignore pylint:disable=W0703
        except Exception as excp:
            LOG.warn(_("use default os type and version %s."), excp)
            fc_os_type, fc_os_version = constant.DEFAULT_HUAWEI_OS_CONFIG

        return {
            'osType': fc_os_type,
            'osVersion': fc_os_version
        }

    def get_os_options(self):
        """
        get vm os info
        get os Type from mata
        :return:
        """
        os_type = self._metadata.get(constant.HUAWEI_OS_TYPE)
        os_version = self._metadata.get(constant.HUAWEI_OS_VERSION)
        return self.get_fc_os_options(os_type, os_version)

    def get_properties(self):
        """get vm property"""
        return {
            'bootOption': utils.get_boot_option_from_metadata(self._metadata)
        }

    def get_vm_config(self):
        """get vm config info"""
        vm_config_body = {
            'cpu': self.get_cpu_info(),
            'memory': self.get_memory_info(),
            'disks': self.get_disks_info(),
            'nics': self.get_nic_info(),
            'properties': self.get_properties()
        }
        return vm_config_body

    def _get_vm_customization_nics(self):
        """get vm customization nics"""
        cus_nics = []
        for vif in self._vifs:
            if vif['enable_dhcp']:
                cus_nic = {
                    'sequenceNum': vif['sequence_num'] + 1
                }
                cus_nics.append(cus_nic)
                continue

            network = vif['network_info']['network']
            subnet_ipv4_list = [s for s in network['subnets']
                                if s['version'] == constant.IPV4_VERSION]
            if len(subnet_ipv4_list) > 0:
                ip_ipv4 = None

                dns = [None, None]
                if len(subnet_ipv4_list[0]['ips']) > 0:
                    ip_ipv4 = subnet_ipv4_list[0]['ips'][0]

                dns_len = len(subnet_ipv4_list[0]['dns'])
                for index in range(0, min(2, dns_len)):
                    dns[index] = subnet_ipv4_list[0]['dns'][index]['address']

                netmask_ipv4 = str(subnet_ipv4_list[0].as_netaddr().netmask)
                gateway_ipv4 = subnet_ipv4_list[0]['gateway']['address']

                cus_nic = {'sequenceNum': vif['sequence_num'] + 1,
                           'ip':  ip_ipv4 and ip_ipv4['address'] or '',
                           'gateway': gateway_ipv4,
                           'netmask': netmask_ipv4,
                           'ipVersion': constant.IPV4_VERSION,
                           'setdns': dns[0],
                           'adddns': dns[1]}
                cus_nics.append(cus_nic)

        LOG.debug(_('cus_nic: %s.'), jsonutils.dumps(cus_nics))
        return cus_nics

    def _validate_customization(self, customization):
        """

        :return:
        """

        valid_customizations = [
            'hostname',
            'workgroup',
            'domain',
            'domainName',
            'domainPassword',
            'ouName'
        ]

        for key in customization.keys():
            if key not in valid_customizations:
                msg = _("Invalid key: %s") % key
                raise fc_exc.InvalidCustomizationInfo(reason=msg)

    def get_vm_customization(self):
        """get vm custom info"""
        if self.get_os_options()['osType'] == 'Other':
            return None

        vm_custom_body = {
            'osType': self.get_os_options()['osType'],
            'password': self._admin_password,
            'nicSpecification': self._get_vm_customization_nics()
        }

        self._validate_customization(self._customization)
        for key in self._customization.keys():
            vm_custom_body[key] = self._customization[key]

        return vm_custom_body

    def is_auto_boot(self):
        """get auto boot"""
        if len(self._injected_files):
            return False
        else:
            return True

    def inject_files(self):
        """

        :return:
        """

        fc_vm = FC_MGR.get_vm_by_uuid(self._instance)
        for (path, contents) in self._injected_files:
            body = {
                'fileName': path,
                'vmData': contents
            }
            self.post(fc_vm.get_vm_action_uri('set_vm_data'), data=body)
            LOG.debug(_('inject file %s succeed.') % path)

    def create_vm(self):
        """
        create vm interface
        :return:
        """
        raise NotImplementedError()

    def start_vm(self):
        """

        :return:
        """
        fc_vm = FC_MGR.get_vm_by_uuid(self._instance)
        self.post(fc_vm.get_vm_action_uri('start'),
                  excp=exception.InstancePowerOnFailure)

class VmCreateByImport(VmCreateBase):
    """
    create vm use import vm interface
    """
    def get_protocol(self):
        """get nfs or null"""
        raise NotImplementedError()

    def create_vm(self):
        """
        create vm by import interface
        :return:
        """
        self.post(self.site.import_vm_uri, data=self._vm_create_body,
                  excp=fc_exc.FusionComputeReturnException)

    def get_body_ext(self):
        """
        import vm extend params
        :return:
        """
        self._vm_create_body['protocol'] = self.get_protocol()

class VmCreateWithVolume(VmCreateByImport):
    """create vm with volume"""

    def get_protocol(self):
        """get null"""
        return "null"

    def get_disks_info(self):
        """override get vm disk specific info"""

        LOG.debug(_('prepare volume'))

        disks_info = []
        for disk in self._volume_ops.ensure_volume(self._block_device_info):
            disk_info = {
                'pciType': disk['pci'],
                'volumeUrn': disk['urn'],
                'isThin': constant.FC_DRIVER_JOINT_CFG['volume_is_thin']
            }

            if disk['mount_device'] == self._root_device_name:
                disk_info['sequenceNum'] = 1
            else:
                disk_info['sequenceNum'] = \
                    constant.MOUNT_DEVICE_SEQNUM_MAP[disk['mount_device']]

            disks_info.append(disk_info)
        return disks_info

    def get_os_options(self):
        """get vm os info"""
        # get os Type from mata
        meta_data = self._volume_ops.\
            get_block_device_meta_data(self._context, self._block_device_info)
        if meta_data:
            volume_meta_data = meta_data.get('volume_image_metadata')
            if volume_meta_data:
                os_type = volume_meta_data.get(constant.HUAWEI_OS_TYPE)
                os_version = volume_meta_data.get(constant.HUAWEI_OS_VERSION)
                if os_type:
                    return self.get_fc_os_options(os_type, os_version)

        return super(VmCreateWithVolume, self).get_os_options()

class VmCreateWithImage(VmCreateByImport):
    """create vm with image"""

    def get_protocol(self):
        """default protocol is glance"""
        return "glance"

    def get_os_options(self):
        """get vm os info"""

        # get os Type from mata
        os_type = self.image_properties.get(constant.HUAWEI_OS_TYPE)
        os_version = self.image_properties.get(constant.HUAWEI_OS_VERSION)
        if os_type:
            return self.get_fc_os_options(os_type, os_version)
        else:
            return super(VmCreateWithImage, self).get_os_options()

    def _get_image_size(self):
        """get image size info"""
        image_size = self._image_meta.get('size')
        if image_size:
            return utils.image_size_to_gb(image_size)
        else:
            return 0

    def check_input(self):
        """
        create vm image detail check
        :return:
        """
        super(VmCreateWithImage, self).check_input()

        disk_quantity_gb = self._instance['root_gb']
        image_size = self._get_image_size()
        if image_size > disk_quantity_gb:
            LOG.error(_("image is larger than sys-vol."))
            raise fc_exc.ImageTooLarge

    def get_disks_info(self):
        """get image disk detail info"""

        LOG.debug(_('prepare volume'))

        disks_info = []

        # sys vol info
        sys_disk_info = {
            'sequenceNum': 1,
            'quantityGB': self._instance['root_gb'],
            'isThin': constant.FC_DRIVER_JOINT_CFG['volume_is_thin']
        }
        disks_info.append(sys_disk_info)

        # user vol info
        for disk in self._volume_ops.ensure_volume(self._block_device_info):
            user_disk_info = {
                'pciType': disk['pci'],
                'volumeUrn': disk['urn'],
                'sequenceNum':
                    constant.MOUNT_DEVICE_SEQNUM_MAP[disk['mount_device']],
                'isThin': constant.FC_DRIVER_JOINT_CFG['volume_is_thin']
            }
            disks_info.append(user_disk_info)

        return disks_info

class VmCreateWithNfsImage(VmCreateWithImage):
    """create vm with nfs image"""

    def get_protocol(self):
        """get nfs protocol"""
        return "nfs"

    def _get_template_url(self):
        """get nfs location"""
        return self.image_properties[constant.HUAWEI_IMAGE_LOCATION]

    def get_body_ext(self):
        """
        create vm with image, extend url info
        :return:
        """
        super(VmCreateWithNfsImage, self).get_body_ext()
        self._vm_create_body['url'] = self._get_template_url()

class VmCreateWithUdsImage(VmCreateWithImage):
    """create vm with uds image"""

    """
    create vm use import vm interface
    """
    def __init__(self, fc_client, task_ops, instance):
        super(VmCreateWithUdsImage, self).__init__(fc_client, task_ops, instance)
        self.usd_image_server_ip = None
        self.usd_image_port = None
        self.usd_image_bucket_name = None
        self.usd_image_key = None

    def _get_uds_image_info(self, image_location):
        """
        :param image_location: {ip}:{port}:{buket name}:{key}
        192.168.0.1:5443:region1.glance:001
        """

        if image_location:
            uds_image_info = image_location.strip()
            str_array = re.split(":", uds_image_info)
            if len(str_array) == 4:
                return str_array[0], \
                       str_array[1], \
                       str_array[2], \
                       str_array[3]
        reason = _("Invalid uds image info,invalid image_location!")
        raise fc_exc.InvalidUdsImageInfo(reason=reason)

    def check_input(self):
        super(VmCreateWithUdsImage, self).check_input()

        properties = self._image_meta.get('properties')
        if properties:
            try:
                self.usd_image_server_ip,  \
                self.usd_image_port, \
                self.usd_image_bucket_name, \
                self.usd_image_key = \
                    self._get_uds_image_info\
                        (properties.get(constant.HUAWEI_IMAGE_LOCATION))
            except Exception:
                reason = _("Invalid uds image info,invalid loaction!")
                raise fc_exc.InvalidUdsImageInfo(reason=reason)

        if constant.CONF.fusioncompute.uds_access_key is '' \
                or constant.CONF.fusioncompute.uds_secret_key is '':
            reason = _("Invalid uds image info,invalid AK SK!")
            raise fc_exc.InvalidUdsImageInfo(reason=reason)

    def get_protocol(self):
        """get uds protocol"""
        return "uds"

    def get_body_ext(self):
        """
        create vm with image, extend uds info
        :return:
        """
        super(VmCreateWithUdsImage, self).get_body_ext()
        self._vm_create_body['s3Config'] = {
            'serverIp': self.usd_image_server_ip,
            'port': self.usd_image_port,
            'accessKey': crypt.decrypt(constant.CONF.fusioncompute.uds_access_key),
            'secretKey': crypt.decrypt(constant.CONF.fusioncompute.uds_secret_key),
            'bucketName': self.usd_image_bucket_name,
            'key': self.usd_image_key
        }

class VmCreateWithGlanceImage(VmCreateWithImage):
    """create vm with glance image"""

    def check_input(self):
        super(VmCreateWithGlanceImage, self).check_input()

        if constant.CONF.fusioncompute.glance_server_ip is '':
            reason = _("Invalid glance image info,invalid server ip!")
            raise fc_exc.InvalidGlanceImageInfo(reason=reason)

    def get_body_ext(self):
        """
        create vm with image, extend glance info
        :return:
        """
        super(VmCreateWithGlanceImage, self).get_body_ext()
        self._vm_create_body['glanceConfig'] = {
            'endPoint': ':'.join([str(constant.CONF.glance.host),
                                  str(constant.CONF.glance.port)]),
            'serverIp': constant.CONF.fusioncompute.glance_server_ip,
            'token': self._context.auth_token,
            'imageID': self._image_meta['id']
        }

class VmCreateByClone(VmCreateBase):
    """
    create vm use import vm interface
    """
    def __init__(self, fc_client, task_ops, instance):
        super(VmCreateByClone, self).__init__(fc_client, task_ops, instance)
        self._need_attach_user_vols = False
        self._cloned_source_vm_or_tpl = None

    def is_auto_boot(self):
        """

        :return:
        """
        if len(self._block_device_info.get('block_device_mapping')):
            self._need_attach_user_vols = True
            return False
        else:
            return super(VmCreateByClone, self).is_auto_boot()

    def get_os_options(self):
        """get vm os info"""

        # get os Type from mata
        os_type = self.image_properties.get(constant.HUAWEI_OS_TYPE)
        os_version = self.image_properties.get(constant.HUAWEI_OS_VERSION)
        if os_type:
            return self.get_fc_os_options(os_type, os_version)
        else:
            return super(VmCreateByClone, self).get_os_options()

    def get_disks_info(self):
        """
        FC itself will clone disks belonging to this tpl/vm(it should and
        must has only one sys volume).
        """
        LOG.debug(_('prepare volume'))
        disks_info = []
        disk_sequence = 1

        # sys vol info
        sys_disk_info = {
            'sequenceNum': disk_sequence,
            'quantityGB': self._instance['root_gb'],
            'isThin': constant.FC_DRIVER_JOINT_CFG['volume_is_thin']
        }
        disks_info.append(sys_disk_info)

        return disks_info

    def get_body_ext(self):
        """
        if body not enough, child class can extend
        :return:
        """
        if self._vm_create_body.has_key("uuid"):
            self._vm_create_body.pop("uuid")
        self._vm_create_body["clonedVmUUID"] = self._instance['uuid']


    def extend_ops_before_start(self):
        """
        create by clone, user vol should attach when vm stoped
        :return:
        """
        if self._need_attach_user_vols:
            self._attach_user_vols()

    def _attach_user_vols(self):
        """

        :return:
        """
        fc_vm = FC_MGR.get_vm_by_uuid(self._instance)
        for disk in self._volume_ops.ensure_volume(self._block_device_info):
            body = {
                'volUrn': disk['urn'],
                'sequenceNum':
                    constant.MOUNT_DEVICE_SEQNUM_MAP[disk['mount_device']]
            }
            LOG.debug(_("begin attach user vol: %s"), disk['urn'])
            self._volume_ops.attach_volume(fc_vm, vol_config=body)

    def create_vm(self):
        self.post(self._cloned_source_vm_or_tpl.get_vm_action_uri('clone'),
                  data=self._vm_create_body,
                  excp=fc_exc.InstanceCloneFailure)

class VmCreateWithTemplate(VmCreateByClone):
    """create vm with image"""

    def check_input(self):
        super(VmCreateWithTemplate, self).check_input()

        properties = self._image_meta.get('properties')
        if properties:
            try:
                self._cloned_source_vm_or_tpl = \
                    self._get_vm_by_template_url(
                        properties.get(constant.HUAWEI_IMAGE_LOCATION))
                self._validate_template(self._cloned_source_vm_or_tpl)
            except Exception:
                LOG.error(_("Invalid FusionCompute template !"))
                raise fc_exc.InstanceCloneFailure

    def get_body_ext(self):
        """
        if body not enough, child class can extend
        :return:
        """
        super(VmCreateWithTemplate, self).get_body_ext()
        self._vm_create_body['isTemplate'] = False

        is_link_clone = self._metadata.get(constant.HUAWEI_IS_LINK_CLONE)
        if is_link_clone:
            self._vm_create_body['isLinkClone'] = is_link_clone

    def _get_vm_by_template_url(self, template_url):
        """
        :param template_url: {vrm site id}:{vm id}
        239d8a8e:i-00000061
        """

        vm_id = None
        if template_url:
            url = template_url.strip()
            str_array = re.split(":", url)
            if len(str_array) == 2:
                vm_id = str_array[1]

        if vm_id is not None:
            return FC_MGR.get_vm_by_id(vm_id)
        return None

    def _validate_template(self, instance):
        """

        :param instance: fc vm
        :return:
        """
        if instance is not None and instance.isTemplate is not True:
            raise fc_exc.InstanceCloneFailure

        for disk in instance['vmConfig']['disks']:
            if disk['sequenceNum'] not in [0, 1]:
                raise fc_exc.InstanceCloneFailure

def get_vm_create(fc_client, task_ops, instance, image_meta=None):
    """get create vm object"""
    if instance.get('image_ref'):
        image_type = None
        if image_meta:
            properties = image_meta.get('properties')
            if properties:
                image_type = properties.get(constant.HUAWEI_IMAGE_TYPE)

        if image_type == 'nfs':
            vm_class = VmCreateWithNfsImage
        elif image_type == 'uds':
            vm_class = VmCreateWithUdsImage
        elif image_type == 'template':
            vm_class = VmCreateWithTemplate
        elif image_type == 'glance' or image_type == None:
            vm_class = VmCreateWithGlanceImage
        else:
            LOG.error(_("image type is error %s."), image_type)
            raise fc_exc.InvalidImageDir
    else:
        vm_class = VmCreateWithVolume

    return vm_class(fc_client, task_ops, instance)
