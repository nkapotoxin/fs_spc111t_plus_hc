# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# All Rights Reserved.
# Copyright (c) 2010 Citrix Systems, Inc.
# Copyright (c) 2011 Piston Cloud Computing, Inc
# Copyright (c) 2012 University Of Minho
# (c) Copyright 2013 Hewlett-Packard Development Company, L.P.
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
A connection to a hypervisor through libvirt.

Supports KVM, LXC, QEMU, UML, and XEN.

"""

import os
import re
import shutil
import six
import time
import commands
import random
import inspect
import copy
import thread
import operator
import traceback
import uuid
from nova.virt.libvirt import config as vconfig
from oslo.config import cfg
from lxml import etree

from nova import context as nova_context
from nova.compute import power_state
from nova.compute import task_states
from nova import exception
from nova import block_device
from nova.i18n import _
from nova.i18n import _LE
from nova.i18n import _LI
from nova.i18n import _LW
from nova import objects
from nova.openstack.common import excutils
from nova.openstack.common import fileutils
from nova.openstack.common import importutils
from nova.openstack.common import jsonutils
from nova.openstack.common import log as logging
from nova.openstack.common import loopingcall
from nova.openstack.common import timeutils
from nova import utils
from nova.virt import hardware
from nova.virt.libvirt import blockinfo
from nova.virt.libvirt import driver as libvirt_driver
from nova.virt.libvirt import lvm
from nova.huawei import utils as hw_utils
from nova.huawei.virt.libvirt import custom_xml
from nova.huawei.virt.libvirt import utils as libvirt_ext_utils
from nova.huawei.scheduler import utils as hwutils
from nova.virt.libvirt import utils as libvirt_utils
from nova.virt.libvirt.driver import LIBVIRT_POWER_STATE
from nova.virt import driver
from nova.virt import netutils
from nova.virt import event as virtevent
from nova.virt.disk import api as disk
from nova.huawei.virt.libvirt import vif as libvirt_vif
from nova.huawei.virt.libvirt import event as hw_event
from nova.virt.libvirt import config as config_original
from nova.huawei.console import type
from nova import hooks
from nova.pci import pci_manager
from nova.compute import utils as compute_utils

interval_opts = [
    cfg.ListOpt('huawei_volume_drivers',
                default=[
                    'iscsi=nova.huawei.virt.libvirt.volume.LibvirtISCSIVolumeDriver',
                    'dsware=nova.huawei.virt.libvirt.volume.LibvirtDswareVolumeDriver',
                    'fibre_channel=nova.huawei.virt.libvirt.volume.LibvirtFibreChannelVolumeDriver',
                ],
                help='DEPRECATED. Libvirt handlers for remote volumes. '
                     'This option is deprecated and will be removed in the '
                     'Kilo release.'),
    cfg.BoolOpt('instance_memory_qos',
                default=False,
                help='add the min_guarantee to xml'),
    cfg.BoolOpt('nic_suspension',
                default=False,
                help='add nics suspension to xml'),
    cfg.StrOpt('instances_console0_log_path',
               default='/var/log/fusionsphere/uvp/qemu',
               help='instance_console0_log_path for uvp'),
    cfg.BoolOpt('instance_console_log',
                default=False,
                help='instances console log switch'),
    cfg.StrOpt('guest_os_driver_path',
               default="/opt/patch/programfiles/vmtools/driverupdate.iso",
               help=('driver disk for Guest to upgrade during boot')),
    cfg.BoolOpt('use_kbox',
                default=False,
                help='use kbox in libvirt'),
    cfg.BoolOpt('use_nonvolatile_ram',
                default=False,
                help='use nonvolatile ram in kbox'),
    cfg.BoolOpt('instance_vwatchdog',
                default=False,
                help='instances watchdog switch'),
    cfg.IntOpt('wdt_start_time',
               default=10,
               help='time out for starting instance, set to 10s default'),
    cfg.IntOpt('wdt_reboot_time',
               default=480,
               help='time out for rebooting instance, set to 480s default'),
    cfg.BoolOpt('instance_panic_reboot',
                default=False,
                help='is need to reboot instance when kernel panic, '
                     'set to false to disable.'),
    cfg.BoolOpt('send_nmi_message',
                default=False,
                help='inject nmi when reboot/power-off instance'),
    cfg.IntOpt('nmi_max_wait_time',
               default=20,
               help='time out for nmi operation'),
    cfg.StrOpt('instances_ha_info_record_path',
               default='/var/log',
               help='instances ha_info file record path'),
    cfg.BoolOpt('close_instance_memballoon',
                default=True,
                help='The UVP is not allowed to open the memballoon.'),
    cfg.BoolOpt('local_resume_instance',
                default=True,
                help='Auto start the instance when stop itself'),
    cfg.IntOpt('vnc_password_expire',
               default=600,
               help='the expire time of vnc password.'),
    cfg.BoolOpt('rebuild_extdata_keep',
                default=False,
                help='Keep the ext date while rebuild'),
    cfg.StrOpt("emulator_pin_bindcpu",
               default="",
               help="emulator_pin_bindcpu"),
]

libvirt_opts = [
    cfg.IntOpt('live_migrate_max_time',
               default=3600 * 24,
               help='live-migrate max time'),
]

reserved_host_mem_dict_opt = cfg.DictOpt('reserved_host_mem_dict',
                                         default={'node0': '0'},
                                         help='Amount of memory in MB to '
                                              'reserve for NUMA node')

CONF = cfg.CONF
CONF.register_opts(interval_opts)
CONF.register_opts(libvirt_opts, 'libvirt')
CONF.register_opt(reserved_host_mem_dict_opt)
CONF.import_opt('evs_pci_whitelist', 'nova.huawei.virt.libvirt.utils')

LOG = logging.getLogger(__name__)

libvirt = __import__('libvirt')

MAX_VIRTIO_SCSI_CONTROLLER_NUM = 4
MIN_LIBVIRT_VERSION = (0, 9, 11)
# When the above version matches/exceeds this version
# delete it & corresponding code using it
MIN_LIBVIRT_DEVICE_CALLBACK_VERSION = (1, 1, 1)
# Live snapshot requirements
REQ_HYPERVISOR_LIVESNAPSHOT = "QEMU"
MIN_LIBVIRT_LIVESNAPSHOT_VERSION = (1, 3, 0)
MIN_QEMU_LIVESNAPSHOT_VERSION = (1, 3, 0)
# block size tuning requirements
MIN_LIBVIRT_BLOCKIO_VERSION = (0, 10, 2)
# BlockJobInfo management requirement
MIN_LIBVIRT_BLOCKJOBINFO_VERSION = (1, 1, 1)
# Relative block commit (feature is detected,
# this version is only used for messaging)
MIN_LIBVIRT_BLOCKCOMMIT_RELATIVE_VERSION = (1, 2, 7)
# libvirt discard feature
MIN_LIBVIRT_DISCARD_VERSION = (1, 0, 6)
MIN_QEMU_DISCARD_VERSION = (1, 6, 0)
REQ_HYPERVISOR_DISCARD = "QEMU"
# libvirt numa topology support
MIN_LIBVIRT_NUMA_TOPOLOGY_VERSION = (1, 0, 4)

def add_driver_dict_from_config(driver_registry, named_driver_config, *args, **kwargs):
    for driver_str in named_driver_config:
        driver_type, _sep, driver = driver_str.partition('=')
        driver_class = importutils.import_class(driver)
        driver_registry[driver_type] = driver_class(*args, **kwargs)

    return driver_registry


class LibvirtDriver(libvirt_driver.LibvirtDriver):
    capabilities = {
        "has_imagecache": True,
        "supports_recreate": True,
        "supports_emulatorpin_update": True,
        "supports_vnc_passwd": True
    }

    def __init__(self, virtapi, read_only=False):
        super(LibvirtDriver, self).__init__(virtapi, read_only)
        self.host = CONF.host
        # add huawei volume driver to libvirt.volume_drivers
        add_driver_dict_from_config(self.volume_drivers,
                                    CONF.huawei_volume_drivers, self)
        self.vif_driver = libvirt_vif.LibvirtGenericVIFDriver(
            self._get_connection)
        self.vnc_passwd_dict = {}
        self._resource_tracker = None

    @property
    def host_state(self):
        if not self._host_state:
            self._host_state = HostState(self)
        return self._host_state

    def _get_vcpu_total(self):
        """Overwrite parent method for:
            1.pcpu fault
        """
        if self._vcpu_total != 0:
            return self._vcpu_total

        try:
            total_pcpus = self._conn.getInfo()[2]
        except libvirt.libvirtError:
            LOG.warn(_LW("Cannot get the number of cpu, because this "
                         "function is not implemented for this platform. "))
            return 0

        if CONF.vcpu_pin_set is None:
            self._vcpu_total = total_pcpus
            return self._vcpu_total

        available_ids = hardware.get_vcpu_pin_set()
        if available_ids is None:
            raise exception.Invalid(_("Invalid vcpu_pin_set config, "
                                      "no cpus available."))
        if len(available_ids) > total_pcpus:
            raise exception.Invalid(_("Invalid vcpu_pin_set config, "
                                      "out of hypervisor cpu range."))
        pcpu_ids = self._get_pcpu_ids_from_cpuinfo()
        LOG.info("pcpu_ids : %s" % pcpu_ids)
        for available_id in available_ids:
            if available_id not in pcpu_ids:
                raise exception.Invalid(_("Invalid vcpu_pin_set config, "
                                          "out of hypervisor cpu range."))

        self._vcpu_total = len(available_ids)
        return self._vcpu_total

    def _get_pcpu_ids_from_cpuinfo(self):
        pcpu_ids = list()
        cmd = "cat /proc/cpuinfo | grep -w 'processor'"
        status, output = commands.getstatusoutput(cmd)
        if status != 0:
            pass
        else:
            try:
                processors = output.split("\n")
                for processor in processors:
                    pcpu_id = processor.split(":")[1].strip()
                    pcpu_ids.append(int(pcpu_id))
            except Exception, msg:
                LOG.error("parse cpuinfo failed, msg = %s" % msg)
        return pcpu_ids

    def _update_boot_option(self, instance, diff):
        try:
            domain = self._lookup_by_name(instance['name'])
        except exception.NotFound:
            LOG.error(
                "instance %s disappeared while update boot option"
                % instance['uuid'])
            return
        xml = domain.XMLDesc(0)
        root = etree.fromstring(xml)
        if diff is None or '__bootDev' not in diff:
            return
        opt = diff['__bootDev'][0]
        if opt == '-':
            LOG.debug("delete instance metadata __bootDev")
            self.disable_boot_order_options(root, domain)
            self.set_default_boot_order(root, domain)
            return
        boot_option = diff['__bootDev'][1]
        if not hw_utils.is_valid_boot_option(boot_option):
            return
        boot_option_list = boot_option.split(',')
        self.disable_boot_order_options(root, domain)
        self.update_boot_order_option(root, domain, boot_option_list)
        xml = domain.XMLDesc(0)
        instance_path = libvirt_utils.get_instance_path(instance)
        xml_path = os.path.join(instance_path, 'libvirt.xml')
        libvirt_utils.write_to_file(xml_path, xml, 31)

    def disable_boot_order_options(self, root_node, domain):
        device_node = root_node.find('devices')
        child_nodes = device_node.iterchildren()
        for child_node in child_nodes:
            if child_node.tag == 'disk' or child_node.tag == 'interface':
                boot_order_node = child_node.find('boot')
                if boot_order_node is not None:
                    if boot_order_node.get('order') != '-1':
                        boot_order_node.set('order', '-1')
                        domain.updateDeviceFlags(
                            etree.tostring(child_node, pretty_print=True),
                            flags=3)

    def set_default_boot_order(self, root_node, domain):
        default_boot_option = ['hd', 'cdrom', 'network']
        self.update_boot_order_option(root_node, domain, default_boot_option)

    def update_boot_order_option(self, root_node, domain, boot_option_list):
        device_node = root_node.find('devices')
        disk_node_disk = list()
        disk_node_cdrom = list()
        disk_nodes = device_node.findall('disk')
        interface_nodes = device_node.findall('interface')
        for disk_node in disk_nodes:
            if disk_node.get('device') == 'disk':
                disk_node_disk.append(disk_node)
            elif disk_node.get('device') == 'cdrom':
                disk_node_cdrom.append(disk_node)
        boot_order = 1
        for boot_dev in boot_option_list:
            if boot_dev == 'hd':
                if disk_node_disk:
                    disk_bus_type = self._get_disk_bus_type(disk_node_disk[0])
                    disk_node_disk.sort(key=self._get_disk_dev_name)
                    for disk_node in disk_node_disk:
                        if self._get_disk_bus_type(disk_node) != disk_bus_type:
                            continue
                        boot_order_node = disk_node.find('boot')
                        if boot_order_node is not None:
                            boot_order_node.set('order', str(boot_order))
                        else:
                            disk_node.append(
                                etree.Element('boot', order=str(boot_order)))
                        domain.updateDeviceFlags(
                            etree.tostring(disk_node, pretty_print=True),
                            flags=3)
                        boot_order += 1
                        break
            elif boot_dev == 'network':
                for interface_node in interface_nodes:
                    # hostdev device shall not set boot order
                    if (interface_node.get('type') == 'hostdev'):
                        continue

                    boot_order_node = interface_node.find('boot')
                    if boot_order_node is not None:
                        boot_order_node.set('order', str(boot_order))
                    else:
                        interface_node.append(
                            etree.Element('boot', order=str(boot_order)))
                    domain.updateDeviceFlags(
                        etree.tostring(interface_node, pretty_print=True),
                        flags=3)
                    boot_order += 1
            elif boot_dev == 'cdrom':
                if disk_node_cdrom:
                    disk_node_cdrom.sort(key=self._get_disk_dev_name)
                    for disk_node in disk_node_cdrom:
                        source = disk_node.find('source')
                        if source is None or not source.get('file'):
                            continue
                        boot_order_node = disk_node.find('boot')
                        if boot_order_node is not None:
                            boot_order_node.set('order', str(boot_order))
                        else:
                            disk_node.append(
                                etree.Element('boot', order=str(boot_order)))
                        domain.updateDeviceFlags(
                            etree.tostring(disk_node, pretty_print=True),
                            flags=3)
                        boot_order += 1

    def _get_disk_bus_type(self, disk_node):
        target = disk_node.find('target')
        return target.get('bus')

    def _get_disk_dev_name(self, disk_node):
        target = disk_node.find('target')
        return target.get('dev')

    def change_instance_metadata(self, context, instance, diff):
        self._update_boot_option(instance, diff)

        # put func record_ha_info_to_file at the end,
        # because it maybe raise exception
        self.record_ha_info_to_file(context, instance, diff)

    @staticmethod
    def _get_console0_log_path(instance_uuid):
        """ get console0_log_path """
        path = os.path.join(CONF.instances_console0_log_path, instance_uuid)
        if not os.path.exists(path):
            os.makedirs(path)
        return os.path.join(path,'console.log')

    # allow we to do custom xml changes
    def _get_guest_xml(self, context, instance, network_info, disk_info,
                       image_meta=None, rescue=None,
                       block_device_info=None, write_to_disk=False):
        original_xml = super( LibvirtDriver, self )._get_guest_xml(
            context, instance, network_info, disk_info, image_meta=image_meta,
            rescue=rescue, block_device_info=block_device_info,
            write_to_disk=write_to_disk)

        LOG.debug('Start post_to_xml.')

        new_xml = custom_xml.post_to_xml(original_xml, context, instance,
                                         network_info=network_info,
                                         disk_info=disk_info,
                                         block_device_info=block_device_info,
                                         driver=self)

        def _format_safe_xml(new_xml):
            clone_xml = new_xml
            doc = etree.fromstring(clone_xml)
            graphics = doc.findall('./devices/graphics[@type=\'vnc\']')
            if graphics:
                graphics[0].set('passwd', '')
                clone_xml = etree.tostring(doc)
                return clone_xml

        if write_to_disk:
            instance_dir = libvirt_utils.get_instance_path(instance)
            xml_path = os.path.join(instance_dir, 'libvirt.xml')
            libvirt_utils.write_to_file(xml_path, _format_safe_xml(new_xml), 31)
            utils.execute('chmod', '640', xml_path, run_as_root=True)

        LOG.debug('End post_to_xml xml=%(xml)s',
                  {'xml': re.sub(r'(?<=passwd=").+?(?=")', '', new_xml)},
                  instance=instance)

        #add/remove ha_info file for avoiding split-brain
        ha_info_file = self._get_ha_info_path(instance)
        sign = self._get_ha_info_from_metadata(instance)
        self.modify_ha_info_file(ha_info_file, sign, catch_exception=True)

        return new_xml

    def get_all_block_devices_ext(self, is_ultrapath=False):
        if not is_ultrapath:
            files = []
            dir = "/dev/disk/by-path/"
            if os.path.isdir(dir):
                files = os.listdir(dir)
            devices = []
            for file in files:
                devices.append(dir + file)
            return devices

        files = []
        dir = "/dev/disk/by-path/"
        if os.path.isdir(dir):
            files = os.listdir(dir)
        devices = []
        template = "scsi-\d:\d:\d:\d+$"
        func = lambda x: re.match(template, x)
        return [dir + f for f in files if func(f)]

    def _inject_data(self, instance, network_info, admin_pass, files, suffix):
        """
        Injects data in a disk image

        Helper used for injecting data in a disk image file system.

        Keyword arguments:
          instance -- a dict that refers instance specifications
          network_info -- a dict that refers network speficications
          admin_pass -- a string used to set an admin password
          files -- a list of files needs to be injected
          suffix -- a string used as an image name suffix

        ADD: Inject the files into fs if the instance is booted from a remote cinder volume.
        """
        # Handles the partition need to be used.
        target_partition = None
        if not instance['kernel_id']:
            target_partition = CONF.libvirt.inject_partition
            if target_partition == 0:
                target_partition = None
        if CONF.libvirt.virt_type == 'lxc':
            target_partition = None

        # Handles the key injection.
        if CONF.libvirt.inject_key and instance.get('key_data'):
            key = str(instance['key_data'])
        else:
            key = None

        # Handles the admin password injection.
        if not CONF.libvirt.inject_password:
            admin_pass = None

        # Handles the network injection.
        net = netutils.get_injected_network_template(
                network_info, libvirt_virt_type=CONF.libvirt.virt_type)

        # Handles the metadata injection
        metadata = instance.get('metadata')

        image_type = CONF.libvirt.images_type
        if any((key, net, metadata, admin_pass, files)):
            # NOTE(Inject file for volume): Check if instance boot from volume.
            disk_mapping = instance['disk_mapping']
            booted_from_volume = self._is_booted_from_volume(
                instance, disk_mapping)
            if not booted_from_volume:
                injection_image = self.image_backend.image(
                    instance,
                    'disk' + suffix,
                    image_type)
                img_id = instance['image_ref']

                if not injection_image.check_image_exists():
                    LOG.warn(_LW('Image %s not found on disk storage. '
                             'Continue without injecting data'),
                             injection_image.path, instance=instance)
                    return
                try:
                    disk.inject_data(injection_image.path,
                                     key, net, metadata, admin_pass, files,
                                     partition=target_partition,
                                     use_cow=CONF.use_cow_images,
                                     mandatory=('files',))
                except Exception as e:
                    with excutils.save_and_reraise_exception():
                        LOG.error(_LE('Error injecting data into image '
                                      '%(img_id)s (%(e)s)'),
                                  {'img_id': img_id, 'e': e},
                                  instance=instance)
            else:
                # NOTE(Inject file for volume): If boot from volume, get volume info to inject file.
                bdm_info = driver.block_device_info_get_mapping(instance['block_device_info'])
                root_disk = block_device.get_root_bdm(bdm_info)
                connection_info = root_disk['connection_info']
                disk_info = disk_mapping[block_device.prepend_dev(root_disk['mount_device'])]
                volume_config = self._connect_volume(connection_info, disk_info)
                LOG.info(_LI("The booted_from_volume injection_path is : %(path)s"),
                         {'path': volume_config.source_path})
                try:
                    disk.inject_data(volume_config.source_path,
                                     key, net, metadata, admin_pass, files,
                                     partition=target_partition,
                                     use_cow=(CONF.use_cow_images and not booted_from_volume),
                                     mandatory=('files',))
                except Exception as e:
                    with excutils.save_and_reraise_exception():
                        LOG.error(_LE('Error injecting data into image '
                                      '%(conn_info)s (%(e)s)'),
                                  {'conn_info': connection_info, 'e': e},
                                  instance=instance)

    def _create_image(self, context, instance,
                      disk_mapping, suffix='',
                      disk_images=None, network_info=None,
                      block_device_info=None, files=None,
                      admin_pass=None, inject_files=True):
        """
        Rewrite the method to inject files into fs if the instance is booted from a remote cinder volume.
        """
        # NOTE(Inject file for volume): Set the block_device_info and disk_mapping of instance.
        instance['disk_mapping'] = disk_mapping
        instance['block_device_info'] = block_device_info

        super(LibvirtDriver, self)._create_image(context, instance,
                                                 disk_mapping, suffix,
                                                 disk_images, network_info,
                                                 block_device_info, files,
                                                 admin_pass, inject_files)

    def _correct_numa(self, old_xml_str, numa_new):
        doc = etree.fromstring(old_xml_str)
        numa = doc.findall('numatune')
        for nm in numa:
            doc.remove(nm)

        # add new numa affinity info
        if numa_new != -1:
            new = etree.Element("numatune")
            subNew = etree.Element("memory", mode="strict", nodeset=str(numa_new))
            new.append(subNew)
            doc.append(new)
        else:
            new = etree.Element("numatune")
            subNew = etree.Element("memory", mode="preferred", placement="auto")
            new.append(subNew)
            doc.append(new)

        return etree.tostring(doc, pretty_print=True)

    def _correct_cpu_bind_set(self, old_xml_str, cpubind, cpuset, sibling=None):

        def _is_sriov_instance(xml):
            doc = etree.fromstring(xml)
            interfaces = doc.findall('./devices/interface')
            for interface in interfaces:
                if "type" in interface.keys():
                    if interface.attrib['type'] == 'hostdev':
                        return True
            return False

        def _get_hyper_thread_affinity(xml):
            doc = etree.fromstring(xml)
            ns_prefix = 'nova'
            nova_ns = 'http://openstack.org/xmlns/libvirt/nova/1.0'
            hyperThreadAffinity = doc.find(
                "./metadata/nova:instance/nova:schedulerHints/nova:hyperThreadAffinity",
                namespaces={ns_prefix: nova_ns})
            if hyperThreadAffinity is None:
                return 'any'
            else:
                return str(hyperThreadAffinity.text).strip()

        def _update_numa_cell(doc, bind_info):
            cells = doc.findall('./cpu/numa/cell')
            for cell in cells:
                cell.attrib['cpus'] = ','.join([str(vcpu) for vcpu in bind_info.keys()])

        doc = etree.fromstring(old_xml_str)
        cpu = doc.findall('cputune')

        #add for share mode
        if not cpubind or not cpu:
            vcpus = doc.findall('vcpu')
            vcpu_num = 0
            for vcpu in vcpus:
                vcpu_num += int(vcpu.text)
                doc.remove(vcpu)

            vcpu_element = etree.Element("vcpu",
                           placement='static', cpuset=','.join([str(i) for i in cpuset]))
            vcpu_element.text = str(vcpu_num)
            doc.append(vcpu_element)
            return etree.tostring(doc, pretty_print=True)

        for c in cpu:
            doc.remove(c)

        if not cpubind:
            return

        emulator_pin_bindcpu = None
        ht = _get_hyper_thread_affinity(old_xml_str)
        all_siblings = sibling
        if ht == 'lock':
            if CONF.emulator_pin_bindcpu and _is_sriov_instance(old_xml_str):
                emulator_pin_bindcpu = CONF.emulator_pin_bindcpu
            else:
                if len(cpubind) > 2:
                    last_cpu_idx = cpubind[sorted(cpubind.keys())[-1]][0]
                    for core in all_siblings:
                        if last_cpu_idx in core:
                            for (k, v) in cpubind.items():
                                if v[0] in core:
                                    del cpubind[k]
                            emulator_pin_bindcpu = ",".join(
                                [str(c) for c in core])
                            break
                    new_bind_info = {}
                    sorted_keys = sorted(cpubind.keys())
                    for idx, key in enumerate(sorted_keys):
                        new_bind_info[idx] = cpubind[key]
                    cpubind = new_bind_info

        # add new cpu affinity info
        emulatorpin_cpuset = []
        cputune = etree.Element("cputune")
        for cpu in cpubind:
            cpuset = ""
            for phyCpuId in cpubind[cpu]:
                cpuset = cpuset + str(phyCpuId) + ","
            cpuset = cpuset.strip(',')
            cputune.append(etree.Element("vcpupin", vcpu=str(cpu), cpuset=cpuset))
            emulatorpin_cpuset.extend(cpubind[cpu])

        emulatorpin_cpuset = list(set(emulatorpin_cpuset))
        emulatorpin_cpuset.sort()
        emulator_pin_bindcpu_default = ','.join(map(lambda x: str(x), emulatorpin_cpuset))
        LOG.debug("live migrate emulatorpin_cpuset is %s", emulator_pin_bindcpu)
        cputune.append(etree.Element("emulatorpin", cpuset=emulator_pin_bindcpu or emulator_pin_bindcpu_default))
        doc.append(cputune)

        _update_numa_cell(doc, cpubind)

        return etree.tostring(doc, pretty_print=True)

    def _correct_dest_xml(self, xml_str, **kwargs):
        """
        Modify xml affinity info before live-migrate.
        Now we dispose with:
        1.vnc_listen_ip
        2.numa
        3.cpu-binding
        4.cpu-set
        """
        listen_addrs = kwargs.get('vncip', None)
        numa = kwargs.get('numa', None)
        cpubind = kwargs.get('cpubind', None)
        cpset = kwargs.get('cpuset', None)
        sibling = kwargs.get('sibling', None)

        if listen_addrs:
            xml_str = self._correct_listen_addr(xml_str,
                                                listen_addrs)
        if numa == None:
            numa_node = -1
        else:
            numa_node = numa

        xml_str = self._correct_numa(xml_str, numa_node)

        xml_str = self._correct_cpu_bind_set(xml_str, copy.deepcopy(cpubind),
                                             cpset, sibling)

        return xml_str

    def _is_shared_block_storage(self, instance, dest_check_data):
        """
        rewrite
        if vm booted with cinder-lvm volume. openstack will return FALSE.
        modefy if is_volume_backed is True, return True.
        """
        if (CONF.libvirt.images_type == dest_check_data.get('image_type') and
                self.image_backend.backend().is_shared_block_storage()):
            return True

        if (dest_check_data.get('is_shared_instance_path') and
                self.image_backend.backend().is_file_in_instance_path()):
            # NOTE(): file based image backends (Raw, Qcow2)
            # place block device files under the instance path
            return True

        if (dest_check_data.get('is_volume_backed') and
                not bool(jsonutils.loads(
                    self.get_instance_disk_info(instance['name'])))):
            # pylint: disable E1120
            return True

        if dest_check_data.get('is_volume_backed'):
            return True

        return False

    @staticmethod
    def _event_lifecycle_callback(conn, dom, event, detail, opaque):
        """If the local_resume_instance is True, use the Extend_LifecycleEvent.
        """
        if not CONF.local_resume_instance:
            return libvirt_driver.LibvirtDriver._event_lifecycle_callback(
                       conn, dom, event, detail, opaque)

        self = opaque

        uuid = dom.UUIDString()
        transition = None
        if event == libvirt.VIR_DOMAIN_EVENT_STOPPED:
            transition = virtevent.EVENT_LIFECYCLE_STOPPED
        elif event == libvirt.VIR_DOMAIN_EVENT_STARTED:
            transition = virtevent.EVENT_LIFECYCLE_STARTED
        elif event == libvirt.VIR_DOMAIN_EVENT_SUSPENDED:
            transition = virtevent.EVENT_LIFECYCLE_PAUSED
        elif event == libvirt.VIR_DOMAIN_EVENT_RESUMED:
            transition = virtevent.EVENT_LIFECYCLE_RESUMED

        if transition is not None:
            self._queue_event(hw_event.Extend_LifecycleEvent(uuid, transition, detail))

    def pre_live_migration(self, context, instance, block_device_info,
                           network_info, disk_info, migrate_data=None):
        """do it in dest node.
           rewrite for get numa and cpu_binding info
        """
        data = super(LibvirtDriver, self).pre_live_migration(context, instance,
                                 block_device_info, network_info,
                                 disk_info, migrate_data)

        def _get_all_cpu_siblings():
            all_siblings_tmp = []
            all_siblings = []
            caps = self._get_host_capabilities()
            caps_cells = caps.host.topology.cells
            for cell_cap in caps_cells:
                cell_cpus = cell_cap.cpus
                for cell_cpu in cell_cpus:
                    if cell_cpu.siblings is None:
                        siblings = list((cell_cpu.id,))
                    else:
                        siblings = sorted(list(cell_cpu.siblings))
                    all_siblings_tmp.append(siblings)
            for sibling in [set(i) for i in all_siblings_tmp]:
                if sibling not in all_siblings:
                    all_siblings.append(sibling)
            return [list(sibling) for sibling in all_siblings]

        #add seabios dir
        qemu_cmd_line_path = os.path.join(CONF.instances_console0_log_path,
                                          instance['uuid'])
        if not os.path.exists(qemu_cmd_line_path):
            os.makedirs(qemu_cmd_line_path)

        # calculate new numa and core_bind info here
        try:
            # we hope get the cpu_set info anywary
            allowed_cpus = hardware.get_vcpu_pin_set()
            data['cpu_set'] = list(allowed_cpus)
            data['sibling'] = _get_all_cpu_siblings()
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE('get new cpu-numa info error.'))

        return data

    def rollback_live_migration_at_destination(self, context, instance,
                                               network_info,
                                               block_device_info,
                                               destroy_disks=True,
                                               migrate_data=None):
        """rewrite for delete seabios path."""
        super(LibvirtDriver, self).rollback_live_migration_at_destination(context,
            instance, network_info, block_device_info, destroy_disks, migrate_data)

        # delete seabios path for live-migrate fail.
        qemu_cmd_line_path = os.path.join(CONF.instances_console0_log_path,
                                          instance['uuid'])
        if os.path.exists(qemu_cmd_line_path):
            shutil.rmtree(qemu_cmd_line_path)

    def post_live_migration_at_destination(self, context,
                                           instance,
                                           network_info,
                                           block_migration=False,
                                           block_device_info=None):
        """rewrite for use xml in-memory instead of recreate"""
        # Define migrated instance, otherwise, suspend/destroy does not work.
        dom_list = self._conn.listDefinedDomains()
        if instance["name"]:
            dom = self._lookup_by_name(instance["name"])
            if instance["name"] not in dom_list:
                # In case of block migration, destination does not have
                # libvirt.xml
                disk_info = blockinfo.get_disk_info(
                    CONF.libvirt.virt_type, instance, block_device_info)

                self._conn.defineXML(dom.XMLDesc(1))

            xml = dom.XMLDesc(0)
            instance_dir = libvirt_utils.get_instance_path(instance)
            xml_path = os.path.join(instance_dir, 'libvirt.xml')
            libvirt_utils.write_to_file(xml_path, xml, 31)
            utils.execute('chmod', '640', xml_path, run_as_root=True)
            LOG.debug("live_migration xml is %s" % xml)

        #touch ha_info file for avoiding split-brain
        ha_info_file = self._get_ha_info_path(instance)
        sign = self._get_ha_info_from_metadata(instance)
        self.modify_ha_info_file(ha_info_file, sign, catch_exception=True)

    def _live_migration(self, context, instance, dest, post_method,
                        recover_method, block_migration=False,
                        migrate_data=None):
        """Do live migration.

        :param context: security context
        :param instance:
            nova.db.sqlalchemy.models.Instance object
            instance object that is migrated.
        :param dest: destination host
        :param post_method:
            post operation method.
            expected nova.compute.manager._post_live_migration.
        :param recover_method:
            recovery method when any exception occurs.
            expected nova.compute.manager._rollback_live_migration.
        :param block_migration: if true, do block migration.
        :param migrate_data: implementation specific params
        """
        def rollback_instance_position(ctxt, inst_org, migrate_data=None):
            inst_ck = objects.Instance.get_by_uuid(ctxt,
                                                   inst_org['uuid'])
            if inst_ck['host'] == self.host:
                LOG.info("LivMig-The host'position don't change")
            else:
                LOG.info("LivMig-The host's position have already changed.")
                inst_ck.node = inst_org['node']
                inst_ck.host = self.host

            inst_ck.task_state = None
            inst_ck.save(expected_task_state=task_states.MIGRATING)
            # rollback port['host'] info
            migrate_data = migrate_data or {}
            migrate_data['rollback_port'] = True
            # don't need try-catch it.
            recover_method(context, instance, dest,
                           block_migration, migrate_data)

        migFlag = [0]
        dom = None
        timeout = CONF.libvirt.live_migrate_max_time/5

        ov_timer = loopingcall.FixedIntervalLoopingCall(f=None)
        def timeout_check():
            if migFlag[0] >= timeout:
                LOG.error(_LE("live-migration timeout.Abort job."))
                if dom:
                    dom.abortJob()
                ov_timer.stop()
            else:
                migFlag[0] += 1

        # Do live migration.
        try:
            if block_migration:
                flaglist = CONF.libvirt.block_migration_flag.split(',')
            else:
                flaglist = CONF.libvirt.live_migration_flag.split(',')
            flagvals = [getattr(libvirt, x.strip()) for x in flaglist]
            logical_sum = reduce(lambda x, y: x | y, flagvals)

            dom = self._lookup_by_name(instance["name"])

            pre_live_migrate_data = (migrate_data or {}).get(
                                        'pre_live_migration_result', {})
            LOG.info("pre_live_migrate_data %s " % pre_live_migrate_data)
            listen_addrs = pre_live_migrate_data.get('graphics_listen_addrs')
            numa = migrate_data.get('numa')
            cpubind = migrate_data.get('cpu')
            cpuset = pre_live_migrate_data.get('cpu_set')
            sibling = pre_live_migrate_data.get('sibling')

            migratable_flag = getattr(libvirt, 'VIR_DOMAIN_XML_MIGRATABLE',
                                      None)

            get_migrate_obj = objects.HuaweiLiveMigration.get_by_instance_uuid
            obj_migrate = get_migrate_obj(context, instance['uuid'])
            dest_ip = obj_migrate.dest_addr

            ov_timer.f = timeout_check
            ov_timer.start(interval=5)

            if migratable_flag is None or listen_addrs is None:
                self._check_graphics_addresses_can_live_migrate(listen_addrs)
                dom.migrateToURI(CONF.libvirt.live_migration_uri % dest_ip,
                                 logical_sum,
                                 None,
                                 CONF.libvirt.live_migration_bandwidth)
            else:
                old_xml_str = dom.XMLDesc(migratable_flag)

                new_xml_str = self._correct_dest_xml(old_xml_str,
                                                     vncip=listen_addrs,
                                                     numa=numa,
                                                     cpubind=cpubind,
                                                     cpuset=cpuset,
                                                     sibling=sibling)
                uri = "tcp://%s" % dest_ip
                try:
                    LOG.info("Begin to migrate instance %s " % instance['uuid'])
                    dom.migrateToURI2(CONF.libvirt.live_migration_uri % dest_ip,
                                      uri,
                                      new_xml_str,
                                      logical_sum,
                                      None,
                                      CONF.libvirt.live_migration_bandwidth)
                except libvirt.libvirtError as ex:
                    # NOTE(): There is a bug in older versions of
                    # libvirt where the VIR_DOMAIN_XML_MIGRATABLE flag causes
                    # virDomainDefCheckABIStability to not compare the source
                    # and target domain xml's correctly for the CPU model.
                    # We try to handle that error here and attempt the legacy
                    # migrateToURI path, which could fail if the console
                    # addresses are not correct, but in that case we have the
                    # _check_graphics_addresses_can_live_migrate check in place
                    # to catch it.
                    # TODO(): Remove this workaround when
                    # Red Hat BZ #1141838 is closed.
                    error_code = ex.get_error_code()
                    if error_code == libvirt.VIR_ERR_CONFIG_UNSUPPORTED:
                        LOG.warn(_LW('An error occurred trying to live '
                                     'migrate. Falling back to legacy live '
                                     'migrate flow. Error: %s'), ex,
                                 instance=instance)
                        self._check_graphics_addresses_can_live_migrate(
                            listen_addrs)
                        dom.migrateToURI(
                            CONF.libvirt.live_migration_uri % dest_ip,
                            logical_sum,
                            None,
                            CONF.libvirt.live_migration_bandwidth)
                    else:
                        raise

        except Exception as e:
            with excutils.save_and_reraise_exception():
                try:
                    if dom:
                        dom.abortJob()
                except:
                    LOG.exception("Abort job failed")
                LOG.exception(_LE("Live Migration failure: %s"), e,
                              instance=instance)
                try:
                    recover_method(context, instance, dest, block_migration,
                                   migrate_data)
                except Exception as e:
                    LOG.exception(_LE("recover_method exception: %s"), e,
                                  instance=instance)
                    rollback_instance_position(context, instance)
                    raise
                finally:
                    ov_timer.stop()
                    obj_migrate.destroy(context)

        # Waiting for completion of live_migration.
        timer = loopingcall.FixedIntervalLoopingCall(f=None)

        def wait_for_live_migration():
            """waiting for live migration completion."""
            try:
                self.get_info(instance)['state']
            except exception.InstanceNotFound:
                timer.stop()
                ov_timer.stop()
                try:
                    post_method(context, instance, dest, block_migration,
                                migrate_data)
                except Exception as e:
                    LOG.exception(_LE("post_method exception: %s"), e,
                                  instance=instance)
                    rollback_instance_position(context, instance,
                                               migrate_data=migrate_data)
                    obj_migrate.destroy(context)
                    raise

        timer.f = wait_for_live_migration
        timer.start(interval=0.5).wait()

    def get_pci_slots_from_xml(self, instance):
        virt_dom = self._lookup_by_name(instance['name'])
        virt_xml = virt_dom.XMLDesc(0)
        xml_doc = etree.fromstring(virt_xml)
        pci_slots = libvirt_ext_utils.get_address_from_xml(xml_doc)

        return pci_slots

    @hooks.add_hook("attach_interface_hook")
    def attach_interface(self, instance, image_meta, vif):
        virt_dom = self._lookup_by_name(instance['name'])
        flavor = objects.Flavor.get_by_id(
            nova_context.get_admin_context(read_deleted='yes'),
            instance['instance_type_id'])
        self.vif_driver.plug(instance, vif)
        self.firewall_driver.setup_basic_filtering(instance, [vif])
        cfg = self.vif_driver.get_config(instance, vif, image_meta,
                                         flavor, CONF.libvirt.virt_type)
        if cfg is None:
            return
        try:
            flags = libvirt.VIR_DOMAIN_AFFECT_CONFIG
            state = libvirt_driver.LIBVIRT_POWER_STATE[virt_dom.info()[0]]
            if state == power_state.RUNNING or state == power_state.PAUSED:
                flags |= libvirt.VIR_DOMAIN_AFFECT_LIVE
            free_pci = vif["meta"]["pci_slotnum"]
            LOG.debug("free_pci:%s" % free_pci)
            cfg_xml = libvirt_ext_utils.modify_device_xml(cfg.to_xml(), free_pci)
            LOG.debug("cfg_xml:%s" % cfg_xml)
            virt_dom.attachDeviceFlags(cfg_xml, flags)
        except libvirt.libvirtError:
            LOG.error(_LE('attaching network adapter failed.'),
                     instance=instance)
            self.vif_driver.unplug(instance, vif)
            raise exception.InterfaceAttachFailed(
                    instance_uuid=instance['uuid'])

    def detach_interface(self, instance, vif):
        virt_dom = self._lookup_by_name(instance['name'])
        flavor = objects.Flavor.get_by_id(
            nova_context.get_admin_context(read_deleted='yes'),
            instance['instance_type_id'])
        cfg = self.vif_driver.get_config(instance, vif, None, flavor,
                                         CONF.libvirt.virt_type)
        try:
            self.vif_driver.unplug(instance, vif)
            if cfg is None:
                return
            flags = libvirt.VIR_DOMAIN_AFFECT_CONFIG
            state = libvirt_driver.LIBVIRT_POWER_STATE[virt_dom.info()[0]]
            if state == power_state.RUNNING or state == power_state.PAUSED:
                flags |= libvirt.VIR_DOMAIN_AFFECT_LIVE
            virt_dom.detachDeviceFlags(cfg.to_xml(), flags)
        except libvirt.libvirtError as ex:
            error_code = ex.get_error_code()
            if error_code == libvirt.VIR_ERR_NO_DOMAIN:
                LOG.warn(_LW("During detach_interface, "
                             "instance disappeared."),
                         instance=instance)
            else:
                LOG.error(_LE('detaching network adapter failed.'),
                          instance=instance, exc_info=True)
                raise exception.InterfaceDetachFailed(
                    instance_uuid=instance['uuid'])

    def _get_ha_info_from_metadata(self, instance):
        sign = 1
        if 'metadata' in instance:
            metadata = instance['metadata']
            if isinstance(metadata, dict):
                for key, value in metadata.iteritems():
                    if '_ha_policy_type' == key:
                        if 'remote_rebuild' == value:
                            sign = 1
                        elif 'close' == value:
                            sign = -1
                        else:
                            sign = 0
            elif isinstance(metadata, list):
                for element in metadata:
                    if '_ha_policy_type' == element.get("key", None):
                        if 'remote_rebuild' == element.get("value", None):
                            sign = 1
                        elif 'close' == element.get("value", None):
                            sign = -1
                        else:
                            sign = 0
            else:
                sign = 0
        return sign

    def _get_ha_info_path(self, instance):
        return os.path.join(CONF.instances_ha_info_record_path,
                            instance['uuid'] + '_' + instance['name'])

    def _modify_ha_info_file(self, file, sign):
        ha_info_file = file
        if sign == 1:
            #touch file
            if os.path.exists(ha_info_file):
                libvirt_utils.file_delete(ha_info_file)

            LOG.info("touch instance ha_info file %s!", ha_info_file)
            libvirt_utils.file_open(ha_info_file, 'a').close()
            utils.execute('chmod', '640', ha_info_file, run_as_root=True)
        elif sign == -1:
            #remove file
            if os.path.exists(ha_info_file):
                LOG.info("delete instance ha_info file %s!", ha_info_file)
                libvirt_utils.file_delete(ha_info_file)
        else:
            LOG.info("ignore ha_info file %s!", ha_info_file)

    def modify_ha_info_file(self, file, sign, catch_exception=False):
        if catch_exception:
            try:
                self._modify_ha_info_file(file, sign)
            except Exception, msg:
                LOG.error(
                    "modify_ha_info_file has exception, msg = %s" % msg)
        else:
            self._modify_ha_info_file(file, sign)

    def record_ha_info_to_file(self, context, instance, diff):
        if diff is not None and '_ha_policy_type' in diff:
            LOG.info(
                "enter into record_ha_info_to_file, msg = %s" % diff)
            opt = diff['_ha_policy_type'][0]
            '''
            {'_ha_policy_type':[-]}
            {'_ha_policy_type':[+, 'remote_rebuild']}
            {'_ha_policy_type':[+, 'close']}
            '''
            if '-' == opt:
                sign = 1
            elif '+' == opt:
                ha_policy_type = diff['_ha_policy_type'][1]
                if ha_policy_type == 'remote_rebuild':
                    sign = 1
                elif ha_policy_type == 'close':
                    sign = -1
                else:
                    LOG.info("Ha_policy_type is not legal")
                    return
            else:
                LOG.info("opt is not legal")
                return

            ha_info_file = self._get_ha_info_path(instance)
            self.modify_ha_info_file(ha_info_file, sign, catch_exception=False)

    def delete_instance_files(self, instance, force_delete=False):
        #cleanup ha info file for brain split
        ha_info_file = self._get_ha_info_path(instance)
        #delete ha_info file
        sign = -1
        self.modify_ha_info_file(ha_info_file, sign, catch_exception=True)

        target_ephemeral = None
        if CONF.rebuild_extdata_keep and not force_delete and instance[
            'task_state'] == 'rebuilding':
            target = libvirt_utils.get_instance_path(instance)
            if os.path.exists(target):
                try:
                    for filename in os.listdir(target):
                        if filename == 'disk.local':
                            utils.execute('mkdir', '-p', target + '_ephemeral')
                            target_ephemeral = target + '_ephemeral'
                            utils.execute('mv', os.path.join(target, filename),
                                          target_ephemeral)
                            break
                except Exception as e:
                    LOG.error(_LE('Failed to move ephemeral disk to '
                                  '%(target)s: %(e)s'),
                              {'target': target_ephemeral, 'e': e},
                              instance=instance)

        result = super( LibvirtDriver, self ).delete_instance_files(instance)

        if target_ephemeral:
            try:
                utils.execute('mkdir', '-p', target)
                utils.execute('mv',
                              os.path.join(target_ephemeral, 'disk.local'),
                              target)
            except Exception as e:
                LOG.error(_LE('Failed to move ephemeral disk back: '
                              '%(e)s'), {'e': e}, instance=instance)
            try:
                shutil.rmtree(target_ephemeral)
            except OSError as e:
                LOG.error(_LE('Failed to cleanup directory %(target)s: '
                              '%(e)s'), {'target': target_ephemeral, 'e': e},
                          instance=instance)
        return result

    def _chown_console_log_for_instance(self, instance):
        super(LibvirtDriver, self)._chown_console_log_for_instance(instance)
        console_log = self._get_console_log_path(instance)
        if os.path.exists(console_log):
            libvirt_utils.execute('chmod', '640', console_log)
        console0_log = self._get_console0_log_path(instance['uuid'])
        if os.path.exists(console0_log):
            libvirt_utils.chown(console0_log, os.getuid())
            libvirt_utils.execute('chmod', '640', console0_log)

    def _is_virtio_scsi_model(self,hw_disk_bus=None,hw_scsi_model=None):
        if ((hw_disk_bus=='scsi' and hw_scsi_model==None) or
                   (hw_disk_bus==None and hw_scsi_model=='virtio-scsi') or
                   (hw_disk_bus=='scsi' and hw_scsi_model=='virtio-scsi')):
            return True
        return False

    def _get_bus_and_model(self,image_meta=None,block_device_info=None):
        hw_disk_bus = None
        hw_scsi_model = None

        block_device_mapping = driver.block_device_info_get_mapping(block_device_info)
        bootable_scsi_bdm = filter(lambda x: x['boot_index'] is not None
                                   and x['boot_index'] == 0,
                                   block_device_mapping)

        for x in bootable_scsi_bdm:
            hw_disk_bus = x.get('disk_bus',None)
            if x.get('volume_image_metadata'):
                hw_scsi_model = x['volume_image_metadata'].get('hw_scsi_model',None)
                if hw_disk_bus == None:
                    hw_disk_bus = x['volume_image_metadata'].get('hw_disk_bus',None)

        if  image_meta and image_meta.get('properties', None)!=None:
            if hw_disk_bus == None:
                hw_disk_bus = image_meta['properties'].get('hw_disk_bus',None)
            if hw_scsi_model == None:
                hw_scsi_model = image_meta['properties'].get('hw_scsi_model',None)

        return (hw_disk_bus,hw_scsi_model)

    def _get_guest_storage_config(self, instance, image_meta,
                                  disk_info,
                                  rescue, block_device_info,
                                  inst_type):
        devices = super(LibvirtDriver, self)._get_guest_storage_config(
            instance, image_meta, disk_info, rescue,
            block_device_info, inst_type)

        #determine whether prebuild 4 virtio-scsi controllers
        pre_build_controller = 0
        is_virtio_scsi = False
        for device in devices:
            if (isinstance(device,config_original.LibvirtConfigGuestController) and
                        device.type == 'scsi' and device.model == 'virtio-scsi'):
                device.index = pre_build_controller
                pre_build_controller = pre_build_controller + 1
                is_virtio_scsi = True
                LOG.debug("image boot,set default controller index=%d "%device.index,instance=instance)

        if is_virtio_scsi == False:
            hw_disk_bus,hw_scsi_model = self._get_bus_and_model(image_meta,block_device_info)
            is_virtio_scsi = self._is_virtio_scsi_model(hw_disk_bus,hw_scsi_model)

        #pre build 4 virtio-scsi controller
        if is_virtio_scsi==True and 4-pre_build_controller > 0:
            for i in range(4 - pre_build_controller):
                scsi_controller = config_original.LibvirtConfigGuestController()
                scsi_controller.type = 'scsi'
                scsi_controller.model = 'virtio-scsi'
                scsi_controller.index = i + pre_build_controller
                devices.append(scsi_controller)
                LOG.debug("nova add controllers, index=%d "%scsi_controller.index,instance=instance)

        return devices

    def cold_migrate_revert_for_blockstorage_except(self, context, instance,
                                                    dest):
        """Cold Migrate Revert for blockstorage exception."""
        LOG.debug("Starting cold_migrate_revert_for_blockstorage_except",
                   instance=instance)

        inst_base = libvirt_utils.get_instance_path(instance)
        inst_base_resize = inst_base + "_resize"
        shared_storage = self._is_storage_shared_with(dest, inst_base_resize)
        self._cleanup_remote_migration(dest, inst_base,
                                       inst_base_resize, shared_storage)

    def _change_vnc_passwd(self, name):
        """set a random vnc password into instance domain"""

        upper_num = random.randint(1, 2)
        lower_num = random.randint(1, 2)
        digit_num = 8 - upper_num - lower_num
        vnc_password = hw_utils.get_random_passwd(upper_num=upper_num,
                                                  lower_num=lower_num,
                                                  digit_num=digit_num)
        try:
            dom = self._lookup_by_name(name)
            doc = etree.fromstring(dom.XMLDesc(0))
            graphics = doc.findall('./devices/graphics')

            #get the vnc in graphic node
            for graphic in graphics:
                if graphic.get('type') == 'vnc':
                    graphic.set('passwd', vnc_password)
                    xml = etree.tostring(graphic)
                    dom.updateDeviceFlags(xml, 0)
        except exception.InstanceNotFound:
            LOG.warn(_("instance %s does not exist"), name)
            self.vnc_passwd_dict.pop(name)
            return None
        except Exception as ex:
            LOG.error(_("set vnc passwd failed: %s"), ex)
            return None

        return vnc_password

    def cycle_change_vnc_passwd(self):
        """change to a random password cycle"""
        instance_list = self.vnc_passwd_dict.keys()
        for instance in instance_list:
            self._set_vnc_passwd(instance, "cycle")

    def _set_vnc_passwd(self, instance_name, action):
        #using instance uuid for locking thread.
        @utils.synchronized(instance_name)
        def _set_passwd():
            """get a vnc password or cycle to change password"""
            if "once" == action:
                return self._change_vnc_passwd(instance_name)
            elif "cycle" == action:
                start_time = self.vnc_passwd_dict[instance_name]
                delta = timeutils.utcnow() - start_time
                if delta.seconds >= CONF.vnc_password_expire:
                    LOG.debug(_("timeout, change %s vnc passwd"),
                              instance_name)
                    vnc_pwd = self._change_vnc_passwd(instance_name)
                    if vnc_pwd:
                        self.vnc_passwd_dict.pop(instance_name)

        return _set_passwd()

    def get_vnc_console(self, context, instance):
        """get vnc console"""
        LOG.debug(_("start to get vnc console for %s"), instance['name'])
        console_vnc = super(LibvirtDriver, self).get_vnc_console(
            context, instance)

        # return password only in called by manager.get_vnc_console
        # if called by manager.validate_console_port, return without password
        stack_list = inspect.stack()
        if str(stack_list[1][3]) != "get_vnc_console":
            return console_vnc

        self.vnc_passwd_dict[instance["name"]] = timeutils.utcnow()
        password = self._set_vnc_passwd(instance["name"], "once")
        LOG.debug(_("The vnc_passwd_dict is %s"), self.vnc_passwd_dict)

        return type.HuaweiConsoleVNC(console_vnc.host, console_vnc.port,
                                     password,
                                     console_vnc.internal_access_path)

    def suspend(self, context, instance):
        """Suspend the specified instance."""
        dom = self._lookup_by_name(instance['name'])
        self._detach_pci_devices(dom,
                                 pci_manager.get_instance_pci_devs(instance))
        self._detach_sriov_ports(context, instance, dom)
        dom.managedSave(0)

    def _detach_sriov_ports(self, context, instance, dom):
        #TODO() this code may will be remove if
        # https://review.openstack.org/#/c/149913/ merged
        network_info = instance.info_cache.network_info
        if network_info is None:
            return
        from nova.network import model as network_model
        MIN_LIBVIRT_DEVICE_CALLBACK_VERSION = (1, 1, 1)
        if self._has_sriov_port(network_info):
            # for libvirt version < 1.1.1, this is race condition
            # so forbid detach if it's an older version
            if not self._has_min_version(
                    MIN_LIBVIRT_DEVICE_CALLBACK_VERSION):
                reason = (_("Detaching SR-IOV ports with"
                            " libvirt < %(ver)s is not permitted") %
                          {'ver': MIN_LIBVIRT_DEVICE_CALLBACK_VERSION})
                raise exception.PciDeviceDetachFailed(reason=reason,
                                                      dev=network_info)

            flavor, image_meta = self._prepare_args_for_get_config(context,
                                                                   instance)
            for vif in network_info:
                if vif['vnic_type'] == network_model.VNIC_TYPE_DIRECT:
                    try:
                        cfg = self.vif_driver.get_config(instance,
                                                     vif,
                                                     image_meta,
                                                     flavor,
                                                     CONF.libvirt.virt_type)
                        dom.detachDeviceFlags(cfg.to_xml(),
                                          libvirt.VIR_DOMAIN_AFFECT_LIVE)
                    except libvirt.libvirtError as ex:
                        error_code = ex.get_error_code()
                        if error_code == libvirt.VIR_ERR_CONFIG_UNSUPPORTED:
                            LOG.error("live detach direct vif is unsupported!")
                            raise ex
                        else:
                            raise


    def _get_guest_numa_config(self, context, instance, flavor,
                               allowed_cpus=None):
        """Returns the config objects for the guest NUMA specs.

        Determines the CPUs that the guest can be pinned to if the guest
        specifies a cell topology and the host supports it. Constructs the
        libvirt XML config object representing the NUMA topology selected
        for the guest. Returns a tuple of:

            (cpu_set, guest_cpu_tune, guest_cpu_numa)

        With the following caveats:

            a) If there is no specified guest NUMA topology, then
               guest_cpu_tune and guest_cpu_numa shall be None. cpu_set
               will be populated with the chosen CPUs that the guest
               allowed CPUs fit within, which could be the supplied
               allowed_cpus value if the host doesn't support NUMA
               topologies.

            b) If there is a specified guest NUMA topology, then
               cpu_set will be None and guest_cpu_numa will be the
               LibvirtConfigGuestCPUNUMA object representing the guest's
               NUMA topology. If the host supports NUMA, then guest_cpu_tune
               will contain a LibvirtConfigGuestCPUTune object representing
               the optimized chosen cells that match the host capabilities
               with the instance's requested topology. If the host does
               not support NUMA, then guest_cpu_tune will be None.
        """
        topology = self._get_host_numa_topology()
        # We have instance NUMA so translate it to the config class
        guest_cpu_numa_config = self._get_cpu_numa_config_from_instance(
                context, instance)

        if not guest_cpu_numa_config:
            # No NUMA topology defined for instance
            vcpus = flavor.vcpus
            memory = flavor.memory_mb
            if topology:
                # Host is NUMA capable so try to keep the instance in a cell
                viable_cells_cpus = []
                for cell in topology.cells:
                    if vcpus <= len(cell.cpuset) and memory <= cell.memory:
                        viable_cells_cpus.append(cell.cpuset)

                if not viable_cells_cpus:
                    # We can't contain the instance in a cell - do nothing for
                    # now.
                    # TODO(): Attempt to spread the instance accross
                    # NUMA nodes and expose the topology to the instance as an
                    # optimisation
                    return allowed_cpus, None, None, None
                else:
                    pin_cpuset = random.choice(viable_cells_cpus)
                    return pin_cpuset, None, None, None
            else:
                # We have no NUMA topology in the host either
                return allowed_cpus, None, None, None
        else:
            if topology:
                # Now get the CpuTune configuration from the numa_topology
                guest_cpu_tune = vconfig.LibvirtConfigGuestCPUTune()
                guest_numa_tune = vconfig.LibvirtConfigGuestNUMATune()
                allpcpus = []
                numa_mem = vconfig.LibvirtConfigGuestNUMATuneMemory()
                numa_memnodes = [vconfig.LibvirtConfigGuestNUMATuneMemNode()
                                 for _ in guest_cpu_numa_config.cells]
                for host_cell in topology.cells:
                    for guest_node_id, guest_config_cell in enumerate(
                            guest_cpu_numa_config.cells):
                        if guest_config_cell.id == host_cell.id:
                            node = numa_memnodes[guest_node_id]
                            node.cellid = guest_config_cell.id
                            node.nodeset = [host_cell.id]
                            node.mode = "strict"

                            numa_mem.nodeset.append(host_cell.id)

                            allpcpus.extend(host_cell.cpuset)

                            for cpu in guest_config_cell.cpus:
                                pin_cpuset = (
                                    vconfig.LibvirtConfigGuestCPUTuneVCPUPin())
                                pin_cpuset.id = cpu
                                pin_cpuset.cpuset = host_cell.cpuset
                                guest_cpu_tune.vcpupin.append(pin_cpuset)
                guest_cpu_tune.vcpupin.sort(key=operator.attrgetter("id"))

                guest_numa_tune.memory = numa_mem
                guest_numa_tune.memnodes = numa_memnodes
                # normalize cell.id
                for i, (cell, memnode) in enumerate(
                                            zip(guest_cpu_numa_config.cells,
                                                guest_numa_tune.memnodes)):
                    cell.id = i
                    memnode.cellid = i
                return None, guest_cpu_tune, guest_cpu_numa_config, guest_numa_tune
            else:
                return allowed_cpus, None, guest_cpu_numa_config, None

    @hooks.add_hook("hard_reboot_hook")
    def _hard_reboot(self, context, instance, network_info,
                     block_device_info=None):
        """Reboot a virtual machine, given an instance reference.

        Performs a Libvirt reset (if supported) on the domain.

        If Libvirt reset is unavailable this method actually destroys and
        re-creates the domain to ensure the reboot happens, as the guest
        OS cannot ignore this action.

        If xml is set, it uses the passed in xml in place of the xml from the
        existing domain.
        """
        if not os.path.exists(libvirt_utils.get_instance_path(instance)):
            LOG.debug("instance %s path does not exist" % instance['uuid'])
            reason = _("instance path does not exist")
            raise exception.InstanceRebootFailure(reason=reason)

        self._destroy(instance)
        instance.refresh()
        if instance['task_state'] in(task_states.SOFT_DELETING,
                                     task_states.POWERING_OFF,
                                     task_states.MIGRATING,
                                     task_states.DELETING):
            LOG.warning("instance should not reboot", instance=instance)
            return
        if instance['host'] != CONF.host:
            LOG.warning("instance's host changed", instance=instance)
            return
        # Get the system metadata from the instance
        system_meta = utils.instance_sys_meta(instance)

        # Convert the system metadata to image metadata
        image_meta = utils.get_image_from_system_metadata(system_meta)
        if not image_meta:
            image_ref = instance.get('image_ref')
            image_meta = compute_utils.get_image_metadata(context,
                                                          self._image_api,
                                                          image_ref,
                                                          instance)

        disk_info = blockinfo.get_disk_info(CONF.libvirt.virt_type,
                                            instance,
                                            block_device_info,
                                            image_meta)
        # NOTE(): This could generate the wrong device_format if we are
        #             using the raw backend and the images don't exist yet.
        #             The create_images_and_backing below doesn't properly
        #             regenerate raw backend images, however, so when it
        #             does we need to (re)generate the xml after the images
        #             are in place.
        xml = self._get_guest_xml(context, instance, network_info, disk_info,
                                  image_meta=image_meta,
                                  block_device_info=block_device_info,
                                  write_to_disk=True)

        # NOTE (): Re-populate any missing backing files.
        disk_info_json = self._get_instance_disk_info(instance['name'], xml,
                                                      block_device_info)
        instance_dir = libvirt_utils.get_instance_path(instance)
        self._create_images_and_backing(context, instance, instance_dir,
                                        disk_info_json)

        # Initialize all the necessary networking, block devices and
        # start the instance.
        self._create_domain_and_network(context, xml, instance, network_info,
                                        block_device_info, reboot=True,
                                        vifs_already_plugged=True)
        self._prepare_pci_devices_for_use(
            pci_manager.get_instance_pci_devs(instance, 'all'))
        wait_reboot_timer = [200]

        def _wait_for_reboot():
            """Called at an interval until the VM is running again."""
            state = self.get_info(instance)['state']
            wait_reboot_timer[0] -= 1
            if state == power_state.RUNNING:
                LOG.info(_LI("Instance rebooted successfully."),
                         instance=instance)
                raise loopingcall.LoopingCallDone()
            if wait_reboot_timer[0] == 0:
                LOG.error(_LI("Instance rebooted time out."),
                          instance=instance)
                raise loopingcall.LoopingCallDone()

        timer = loopingcall.FixedIntervalLoopingCall(_wait_for_reboot)
        timer.start(interval=0.5).wait()

    def _get_instance_disk_info(self, instance_name, xml,
                                block_device_info=None):
        block_device_mapping = driver.block_device_info_get_mapping(
            block_device_info)

        volume_devices = set()
        for vol in block_device_mapping:
            disk_dev = vol['mount_device'].rpartition("/")[2]
            volume_devices.add(disk_dev)

        public_file_paths = set ()
        # Other disks not need to calculate, e.g. GuestOs update ISO
        if CONF.guest_os_driver_path:
            public_file_paths.add(CONF.guest_os_driver_path)

        disk_info = []
        doc = etree.fromstring(xml)
        disk_nodes = doc.findall('.//devices/disk')

        for cnt, disk_node in enumerate(disk_nodes):
            disk_type = disk_node.get('type')
            path_node = disk_node.find('source')
            if path_node is None:
                path = None
            else:
                path = path_node.get('file') or path_node.get('dev')
            target_node = disk_node.find('target')
            if target_node is None:
                continue
            target = target_node.get('dev')

            if not path:
                LOG.debug('skipping disk for %s as it does not have a path',
                          instance_name)
                continue
            if path in public_file_paths:
                LOG.debug('skipping disk %s because it is a public file', path)
                continue

            if disk_type not in ['file', 'block']:
                LOG.debug('skipping disk %s because it looks like a volume', path)
                continue

            if target in volume_devices:
                LOG.debug('skipping disk %(path)s (%(target)s) as it is a '
                          'volume', {'path': path, 'target': target})
                continue

            # get the real disk size or
            # raise a localized error if image is unavailable
            if disk_type == 'file':
                try:
                    dk_size = int(os.path.getsize(path))
                except:
                    LOG.warning("Failed to get file size of %s" % path)
                    dk_size = 0
            elif disk_type == 'block':
                try:
                    dk_size = lvm.get_volume_size(path)
                except:
                    LOG.warning("Failed to get volume size of %s" % path)
                    dk_size = 0

            disk_type = disk_node.find('driver').get('type')
            if disk_type == "qcow2":
                backing_file = libvirt_utils.get_disk_backing_file(path)
                try:
                    virt_size = disk.get_disk_size(path)
                except:
                    LOG.warning("Failed to get virt size of file %s" % path)
                    virt_size = 0
                over_commit_size = int(virt_size) - dk_size
            else:
                backing_file = ""
                virt_size = dk_size
                over_commit_size = 0


            disk_info.append({'type': disk_type,
                              'path': path,
                              'virt_disk_size': virt_size,
                              'backing_file': backing_file,
                              'disk_size': dk_size,
                              'over_committed_disk_size': over_commit_size})
        return jsonutils.dumps(disk_info)

    def update_emulatorpin(self, instance, default_emulatorpin):
        domain = self._lookup_by_name(instance['name'])
        emulator_pin_info = domain.emulatorPinInfo()
        LOG.info(_LE("emulatorPinInfo: %(emu)s %(name)s"),
                 {"emu": emulator_pin_info, "name": instance['name']})
        emulator_in_conf = []
        if CONF.emulator_pin_bindcpu:
            emulator_in_conf = CONF.emulator_pin_bindcpu.split(',')
        else:
            emulator_in_conf = default_emulatorpin

        emulator_in_conf = [int(i) for i in emulator_in_conf]
        pin_emulator_list = []
        for cpu_index in range(0, len(emulator_pin_info)):
            if cpu_index in emulator_in_conf:
                pin_emulator_list.append(True)
            else:
                pin_emulator_list.append(False)
        pin_emulator_tuple = tuple(pin_emulator_list)
        if pin_emulator_tuple != emulator_pin_info:
            domain.pinEmulator(pin_emulator_tuple)
            xml = domain.XMLDesc(0)
            instance_path = libvirt_utils.get_instance_path(instance)
            xml_path = os.path.join(instance_path, 'libvirt.xml')
            libvirt_utils.write_to_file(xml_path, xml, 31)

    def register_resource_tracker(self, resource_tracker):
        self._resource_tracker = resource_tracker

    def _clean_shutdown(self, instance, timeout, retry_interval):
        """Attempt to shutdown the instance gracefully.

        :param instance: The instance to be shutdown
        :param timeout: How long to wait in seconds for the instance to
                        shutdown
        :param retry_interval: How often in seconds to signal the instance
                               to shutdown while waiting

        :returns: True if the shutdown succeeded
        """

        # List of states that represent a shutdown instance
        SHUTDOWN_STATES = [power_state.SHUTDOWN,
                           power_state.CRASHED]

        try:
            dom = self._lookup_by_name(instance["name"])
        except exception.InstanceNotFound:
            # If the instance has gone then we don't need to
            # wait for it to shutdown
            return True

        (state, _max_mem, _mem, _cpus, _t) = dom.info()
        state = LIBVIRT_POWER_STATE[state]
        if state in SHUTDOWN_STATES:
            LOG.info(_LI("Instance already shutdown."),
                     instance=instance)
            return True

        LOG.debug("Shutting down instance from state %s", state,
                  instance=instance)
        try:
            dom.shutdown()
        except libvirt.libvirtError:
            LOG.debug("Ignoring libvirt exception from shutdown "
                      "request.", instance=instance)
        retry_countdown = retry_interval

        for sec in six.moves.range(timeout):

            dom = self._lookup_by_name(instance["name"])
            (state, _max_mem, _mem, _cpus, _t) = dom.info()
            state = LIBVIRT_POWER_STATE[state]

            if state in SHUTDOWN_STATES:
                LOG.info(_LI("Instance shutdown successfully after %d "
                              "seconds."), sec, instance=instance)
                return True

            # Note(): We can't assume that the Guest was able to process
            #              any previous shutdown signal (for example it may
            #              have still been startingup, so within the overall
            #              timeout we re-trigger the shutdown every
            #              retry_interval
            if retry_countdown == 0:
                retry_countdown = retry_interval
                # Instance could shutdown at any time, in which case we
                # will get an exception when we call shutdown
                try:
                    LOG.debug("Instance in state %s after %d seconds - "
                              "resending shutdown", state, sec,
                              instance=instance)
                    dom.shutdown()
                except libvirt.libvirtError:
                    # Assume this is because its now shutdown, so loop
                    # one more time to clean up.
                    LOG.debug("Ignoring libvirt exception from shutdown "
                              "request.", instance=instance)
                    continue
            else:
                retry_countdown -= 1

            time.sleep(1)

        LOG.info(_LI("Instance failed to shutdown in %d seconds."),
                 timeout, instance=instance)
        return False


    def snapshot(self, context, instance, image_id, update_task_state):
        """Create snapshot from a running VM instance.

        This command only works with qemu 0.14+
        """
        try:
            virt_dom = self._lookup_by_name(instance['name'])
        except exception.InstanceNotFound:
            raise exception.InstanceNotRunning(instance_id=instance['uuid'])

        base_image_ref = instance['image_ref']

        base = compute_utils.get_image_metadata(
            context, self._image_api, base_image_ref, instance)

        snapshot = self._image_api.get(context, image_id)

        disk_path = libvirt_utils.find_disk(virt_dom)
        source_format = libvirt_utils.get_disk_type(disk_path)

        image_format = CONF.libvirt.snapshot_image_format or source_format

        # NOTE(): save lvm and rbd as raw
        if image_format == 'lvm' or image_format == 'rbd':
            image_format = 'raw'

        metadata = self._create_snapshot_metadata(base,
                                                  instance,
                                                  image_format,
                                                  snapshot['name'])

        snapshot_name = uuid.uuid4().hex

        state = LIBVIRT_POWER_STATE[virt_dom.info()[0]]

        # NOTE(): Live snapshots require QEMU 1.3 and Libvirt 1.0.0.
        #            These restrictions can be relaxed as other configurations
        #            can be validated.
        # NOTE(): Instances with LVM encrypted ephemeral storage require
        #               cold snapshots. Currently, checking for encryption is
        #               redundant because LVM supports only cold snapshots.
        #               It is necessary in case this situation changes in the
        #               future.
        if (self._has_min_version(MIN_LIBVIRT_LIVESNAPSHOT_VERSION,
                                  MIN_QEMU_LIVESNAPSHOT_VERSION,
                                  REQ_HYPERVISOR_LIVESNAPSHOT)
             and source_format not in ('lvm', 'rbd')
             and not CONF.ephemeral_storage_encryption.enabled):
            live_snapshot = True
            # Abort is an idempotent operation, so make sure any block
            # jobs which may have failed are ended. This operation also
            # confirms the running instance, as opposed to the system as a
            # whole, has a new enough version of the hypervisor (bug 1193146).
            try:
                virt_dom.blockJobAbort(disk_path, 0)
            except libvirt.libvirtError as ex:
                error_code = ex.get_error_code()
                if error_code == libvirt.VIR_ERR_CONFIG_UNSUPPORTED:
                    live_snapshot = False
                else:
                    pass
        else:
            live_snapshot = False

        # NOTE(): We cannot perform live snapshots when a managedSave
        #            file is present, so we will use the cold/legacy method
        #            for instances which are shutdown.
        if state == power_state.SHUTDOWN:
            live_snapshot = False

        # NOTE(): managedSave does not work for LXC
        if CONF.libvirt.virt_type != 'lxc' and not live_snapshot:
            if state == power_state.RUNNING or state == power_state.PAUSED:
                try:
                    self._detach_pci_devices(virt_dom,
                        pci_manager.get_instance_pci_devs(instance))
                    self._detach_sriov_ports(context, instance, virt_dom)
                except libvirt.libvirtError as ex:
                    error_code = ex.get_error_code()
                    if error_code == libvirt.VIR_ERR_CONFIG_UNSUPPORTED:
                        LOG.error(
                            "image-create from VM with direct vif is unsupported!")
                        raise ex
                virt_dom.managedSave(0)

        snapshot_backend = self.image_backend.snapshot(instance,
                disk_path,
                image_type=source_format)

        if live_snapshot:
            LOG.info(_LI("Beginning live snapshot process"),
                     instance=instance)
        else:
            LOG.info(_LI("Beginning cold snapshot process"),
                     instance=instance)

        update_task_state(task_state=task_states.IMAGE_PENDING_UPLOAD)
        snapshot_directory = CONF.libvirt.snapshots_directory
        fileutils.ensure_tree(snapshot_directory)
        with utils.tempdir(dir=snapshot_directory) as tmpdir:
            try:
                out_path = os.path.join(tmpdir, snapshot_name)
                if live_snapshot:
                    # NOTE(): libvirt needs o+x in the temp directory
                    os.chmod(tmpdir, 0o701)
                    self._live_snapshot(virt_dom, disk_path, out_path,
                                        image_format)
                else:
                    snapshot_backend.snapshot_extract(out_path, image_format)
            finally:
                new_dom = None
                # NOTE(): because previous managedSave is not called
                #              for LXC, _create_domain must not be called.
                if CONF.libvirt.virt_type != 'lxc' and not live_snapshot:
                    if state == power_state.RUNNING:
                        new_dom = self._create_domain(domain=virt_dom)
                    elif state == power_state.PAUSED:
                        new_dom = self._create_domain(domain=virt_dom,
                                launch_flags=libvirt.VIR_DOMAIN_START_PAUSED)
                    if new_dom is not None:
                        self._attach_pci_devices(new_dom,
                            pci_manager.get_instance_pci_devs(instance))
                        self._attach_sriov_ports(context, instance, new_dom)
                LOG.info(_LI("Snapshot extracted, beginning image upload"),
                         instance=instance)

            # Upload that image to the image service

            update_task_state(task_state=task_states.IMAGE_UPLOADING,
                     expected_state=task_states.IMAGE_PENDING_UPLOAD)
            with libvirt_utils.file_open(out_path) as image_file:
                self._image_api.update(context,
                                       image_id,
                                       metadata,
                                       image_file)
                LOG.info(_LI("Snapshot image upload complete"),
                         instance=instance)

    def detach_volume(self, connection_info, instance, mountpoint,
                      encryption=None):
        instance_name = instance['name']
        disk_dev = mountpoint.rpartition("/")[2]
        try:
            virt_dom = self._lookup_by_name(instance_name)
            xml = self._get_disk_xml(virt_dom.XMLDesc(0), disk_dev)
            if not xml:
                LOG.warning("Device %s disappeard before detaching", disk_dev,
                            instance=instance)
            else:
                # NOTE(): We can always affect config because our
                #             domains are persistent, but we should only
                #             affect live if the domain is running.
                flags = libvirt.VIR_DOMAIN_AFFECT_CONFIG
                state = LIBVIRT_POWER_STATE[virt_dom.info()[0]]
                if state in (power_state.RUNNING, power_state.PAUSED):
                    flags |= libvirt.VIR_DOMAIN_AFFECT_LIVE
                virt_dom.detachDeviceFlags(xml, flags)
                if encryption:
                    # The volume must be detached from the VM before
                    # disconnecting it from its encryptor. Otherwise, the
                    # encryptor may report that the volume is still in use.
                    encryptor = self._get_volume_encryptor(connection_info,
                                                           encryption)
                    encryptor.detach_volume(**encryption)
        except exception.InstanceNotFound:
            # NOTE(): If the instance does not exist, _lookup_by_name()
            #                will throw InstanceNotFound exception. Need to
            #                disconnect volume under this circumstance.
            LOG.warn(_LW("During detach_volume, instance disappeared."))
        except libvirt.libvirtError as ex:
            # NOTE(): This is called to cleanup volumes after live
            #             migration, so we should still disconnect even if
            #             the instance doesn't exist here anymore.
            error_code = ex.get_error_code()
            if error_code == libvirt.VIR_ERR_NO_DOMAIN:
                # NOTE():
                LOG.warn(_LW("During detach_volume, instance disappeared."))
            else:
                raise

        self._disconnect_volume(connection_info, disk_dev)


class HostState(libvirt_driver.HostState):
    """Manages information about the compute node through libvirt."""
    def __init__(self, driver):
        super(HostState, self).__init__(driver)

    def update_status(self):
        """ This method rewrited from the update_status method of libvirt
        """
        def _add_cells_cpu_siblings(numa_topology):
            """add cpu siblings info to numa_topology to adapt hyperthread case,
            before this adding, the numa_topology is like:
            {
                "cells": [{
                    "mem": {
                        "total": 12008,
                        "used": 2048
                    },
                    "cpu_usage": 4,
                    "cpus": "0,1,2,3,8,9,10,11",
                    "id": 0
                }]
            }
            after this change, the numa_topology is like:
            {
                "cells": [{
                    "mem": {
                        "total": 12008,
                        "used": 0
                    },
                    "siblings": [[3,11],[0,8],[1,9],[2,10]],
                    "cpu_usage": 0,
                    "cpus": "0,1,2,3,8,9,10,11",
                    "id": 0
                }]
            }
            ::param numa_topology: the numa_topology json
            """
            cells = numa_topology.get('nova_object.data', {}).get('cells', [])
            if not cells:
                return numa_topology
            caps = self.driver._get_host_capabilities()
            caps_cells = caps.host.topology.cells

            for cell, cell_cap in zip(cells, caps_cells):
                cell_data = cell.get('nova_object.data')
                cell_data['siblings'] = []
                cell_cpus = cell_cap.cpus
                for cpu in cell_cpus:
                    if cpu.siblings is None:
                        siblings = (cpu.id,)
                    else:
                        siblings = tuple(sorted(list(cpu.siblings)))
                    cell_data['siblings'].append(siblings)
                cell_data['siblings'] = list(set(cell_data['siblings']))
            return numa_topology

        def _handle_numa_reserved_mem(numa_topology, total_mem):
            """
            :returns (numa_topology, total_mem)
            """
            cells = numa_topology.get('nova_object.data', {}).get('cells', [])
            if cells:
                total_mem = 0
                for cell in cells:
                    cell_data = cell.get('nova_object.data')
                    total_mem += cell_data['memory']   

            reserved_numa_mem = CONF.reserved_host_mem_dict or {}
            reserved = {}
            total_reserved = 0
            for k, v in reserved_numa_mem.items():
                if (not isinstance(k, six.string_types) or not
                k.startswith('node') or not k[4:].isdigit() or
                        (not isinstance(v, six.string_types))):
                    LOG.error(_LE("Invalid configure option "
                                  "reserved_host_mem_dict_opt: %s"),
                              reserved_numa_mem)
                    return numa_topology, total_mem

                # deal with the default "node0:0"
                if v == '0':
                    v = '{"4k":0}'
                # ex: k= 'node0',v ='{"4k":2250;"2m":512}'
                # here, need to convert  ";" to ","
                v = jsonutils.loads(v.replace(";", ","))
                numa_reserved_sum = sum(v.values())
                reserved[int(k[4:])] = v
                total_reserved += numa_reserved_sum
            if total_reserved > total_mem:
                LOG.error(_LE("Invalid configure option reserved_host_mem_"
                              "dict_opt: %s, reserved memory is larger than"
                              " total memory"),
                          reserved_numa_mem)
                return numa_topology, total_mem

            total_mem -= total_reserved
            if not cells:
                return numa_topology, total_mem
            for cell in cells:
                cell_data = cell.get('nova_object.data')
                cell_reserved = reserved.get(cell_data['id'], {})
                cell_data['memory'] -= sum(cell_reserved.values())or 0
                cell_mem_pages = cell_data.get('mempages', [])
                unit_transform = {4: '4k', 2048: '2m', 1024*1024: '1g'}
                for cell_mem_page in cell_mem_pages:
                    cell_page_data = cell_mem_page.get('nova_object.data')
                    cell_page_data['used'] += \
                        cell_reserved.get(
                            unit_transform.get(cell_page_data['size_kb'], ''),
                            0) * 1024 / cell_page_data['size_kb']

            return numa_topology, total_mem

        data = super(HostState, self).update_status()

        numa_topology = jsonutils.loads(data['numa_topology'])
        numa_topology = _add_cells_cpu_siblings(numa_topology)
        numa_topology, total_mem = _handle_numa_reserved_mem(
            numa_topology, data['memory_mb'])

        data['numa_topology'] = jsonutils.dumps(numa_topology)
        data['memory_mb'] = total_mem
        data['network'] = self.get_physical_network_info()
        self._stats = data

        return data

    def get_physical_network_info(self):
        physical_network_info = []

        for white_list_dev in CONF.evs_pci_whitelist:
            pci_dev = jsonutils.loads(white_list_dev)
            physical_network_info.append(pci_dev)
        for white_list_dev in CONF.pci_passthrough_whitelist:
            pci_dev = jsonutils.loads(white_list_dev)
            physical_network_info.append(pci_dev)

        return physical_network_info