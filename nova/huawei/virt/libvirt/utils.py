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
 
import commands
import os
from lxml import etree
from oslo.config import cfg

from nova.openstack.common.gettextutils import _
from nova.openstack.common import jsonutils
from nova.openstack.common import log as logging
from nova import exception
from nova import utils
from nova import objects
from nova.virt.libvirt import lvm

interval_opts = [
    cfg.MultiStrOpt('evs_pci_whitelist',
                            default=[],
                            help='White list of white PCI devices available to VMs. '
                            )
    ]

CONF = cfg.CONF
CONF.register_opts(interval_opts)
CONF.import_opt('ram_allocation_ratio', 'nova.scheduler.filters.ram_filter')
CONF.import_opt('vcpu_pin_set', 'nova.virt.hardware')

LOG = logging.getLogger(__name__)
VIRTIO_SCSI_CONTROLLER_MAX_DISK_NUM = 15

_bandwidth_cache = {}

def get_address_from_xml(xmldoc):
    pci_slots = []
    
    for c in xmldoc.getchildren():
        if c.tag == 'address' and c.get('type') == 'pci':
            pci_slots.append(int(c.get('slot'), 16))
        elif 'bus=pci.0,addr=' in c.get('value', ''):
            pci_slots.append(int(c.get('value')[-4:], 16))
        child_pci_slots = get_address_from_xml(c)
        pci_slots.extend(child_pci_slots)
    
    return pci_slots

def get_free_pci_slot_from_xml(xml):
    """
    Get the pci slot no used in vm xml.
    """
    xml_doc = etree.fromstring(xml)
    pci_slots = get_address_from_xml(xml_doc)
    LOG.debug("The used pci slots is : %s" % (pci_slots))
    # All of pci slot in libvirt, only slot 3 ~ slot 31 can set by user.
    for i in range(3, 32):
        if i not in pci_slots:
            return i
        
def modify_device_xml(sourceXml, pciSlot):
    xml_doc = etree.fromstring(sourceXml)
    xml_doc.append(etree.Element("address", 
                                 type = "pci", 
                                 domain = "0x0000", 
                                 bus = "0x00", 
                                 slot = "0x%x" % pciSlot, 
                                 function = "0x0"))
    xml_str = etree.tostring(xml_doc, pretty_print = True)
    
    return xml_str
    

def get_bandwidth(phynet, realPort = False, cached = True):
    if not realPort:
        name = get_port_name(phynet)
    else:
        name = phynet
    
    if cached:
        bandwidth = _bandwidth_cache.get(name)
        if bandwidth:
            return bandwidth
        
    status, output = commands.getstatusoutput("ethtool %s |grep Speed" % name)
    if 0 != status:
        LOG.warn("Not get bandwidth, ethtool %s failed, ret:%s" % (name, status >> 8))
        if cached:
            _bandwidth_cache[name] = '0'
        return '0'
    end = output.find('Mb')
    if -1 == end:
        LOG.info("Not get bandwidth, itf:%s" % name)
        if cached:
            _bandwidth_cache[name] = '0'
        return '0'
    else:        
        begin = output.find('Speed: ') + len('Speed: ')
        bandwidth = output[begin:end]
    try:
        int(bandwidth)
    except ValueError:
        LOG.error("Not get bandwidth, invalid bandwidth: %s, itf:%s" % (bandwidth, name))
        if cached:
            _bandwidth_cache[name] = '0'
        return '0'
    
    if cached:
        _bandwidth_cache[name] = bandwidth
      
    LOG.info("Got net:%s bandwidth: %s" % (name, bandwidth))
    return bandwidth

def get_port_name(name):
    status, output = commands.getstatusoutput("cat /usr/bin/ports_info")
    if 0 != status:
        LOG.error("ERROR in cat /usr/bin/ports_info")
        return None
    output = jsonutils.loads(output)
    return output['Logic-phyMapInfo'][name]

def get_trunk_bandwidth(name, bond):
    for trunk in bond:
        if name == trunk.get('name'):
            slaves = trunk.get('slaves')
            mode = trunk.get('bond_mode')
            if 'nobond' in mode.lower():
                status, output = commands.getstatusoutput("cat /sys/class/net/%s/bonding/active_slave" % name)
                if 0 != status:
                    LOG.error("ERROR in cat trunk slave %s" % name)
                    return None
                LOG.debug("the slave is %s" % output)
                return get_bandwidth(output, realPort = True)
            else:
                total_bandwidth = 0
                for slave in slaves:
                    bandwidth = get_bandwidth(slave)
                    if not bandwidth:
                        continue
                    total_bandwidth += int(bandwidth)
                return str(total_bandwidth)

def get_qos_info(sysintfnw): 
    qos = {}
    for p in sysintfnw:
        name = p.get('name')
        single_qos = p.get('qos')
        decrease_qos = single_qos.get('tx_limit', '0')
        qos[name] = decrease_qos
    return qos

def _is_bond(interface, network_json):
    bond_list = network_json.get("bond", [])
    for bond in bond_list:
        if bond.get("name") == interface:
            return True
    return False


def execute(*args, **kwargs):
    return utils.execute(*args, **kwargs)

def logical_volume_size(path):
    """Get logical volume size in bytes.

    :param path: logical volume path
    """
    # TODO() POssibly replace with the more general
    # use of blockdev --getsize64 in future
    out, _err = execute('lvs', '-o', 'lv_size', '--noheadings', '--units',
                        'b', '--nosuffix', path, run_as_root=True)
    return int(out)

def create_lvm_image(vg, lv, size, sparse=False):
    """Create LVM image.

    Creates a LVM image with given size.

    :param vg: existing volume group which should hold this image
    :param lv: name for this image (logical volume)
    :size: size of image in bytes
    :sparse: create sparse logical volume
    """
    vg_info = lvm.get_volume_group_info(vg)
    free_space = vg_info['free']

    def check_size(vg, lv, size):
        if size > free_space:
            raise RuntimeError(_('Insufficient Space on Volume Group %(vg)s.'
                                 ' Only %(free_space)db available,'
                                 ' but %(size)db required'
                                 ' by volume %(lv)s.') %
                               {'vg': vg,
                                'free_space': free_space,
                                'size': size,
                                'lv': lv})

    if sparse:
        preallocated_space = 64 * 1024 * 1024
        check_size(vg, lv, preallocated_space)
        if free_space < size:
            LOG.warning(_('Volume group %(vg)s will not be able'
                          ' to hold sparse volume %(lv)s.'
                          ' Virtual volume size is %(size)db,'
                          ' but free space on volume group is'
                          ' only %(free_space)db.'),
                        {'vg': vg,
                         'free_space': free_space,
                         'size': size,
                         'lv': lv})

        cmd = ('lvcreate', '-L', '%db' % preallocated_space,
                '--virtualsize', '%db' % size, '-n', lv, vg)
    else:
        check_size(vg, lv, size)
        cmd = ('lvcreate', '-L', '%db' % size, '-n', lv, vg)
    execute(*cmd, run_as_root=True, attempts=3)


def get_pci_info_by_dict(**kwargs):
    """
    get pci device information from CONF.evs_pci_whitelist
    :param kwargs: like {"physical_network":'net01',...}
    :return: the suitable list of pci device dict.
    """

    pci_dev_list = []
    for white_list_dev in CONF.evs_pci_whitelist:
        pci_dev = jsonutils.loads(white_list_dev)
        suitable = True
        for key in kwargs:
            if pci_dev.get(key, None) != kwargs[key]:
                suitable = False
                break

        if suitable:
            pci_dev_list.append(pci_dev)

    return pci_dev_list


def get_numa_id_by_physical_network(physnet):
    """
    get numa id by physical logic plane
    :param physnet:
    :return:
    """
    #TODO may be can get from database
    pci_dev = get_pci_info_by_dict(physical_network=physnet)
    if pci_dev:
        numa_id = pci_dev[0].pop("numa_id")
    else:
        numa_id = None

    return numa_id


def get_physical_network(network_info):

    physical_planes = []
    for vif in network_info:
        physical_plane = vif.get("details",{}).get("physical_network", None)
        if physical_plane:
            physical_planes.append(physical_plane)

    return physical_planes


def has_virtio_scsi(domain_xml):
    try:
        doc = etree.fromstring(domain_xml)
    except Exception:
        LOG.error('etree xml error')
        return False

    devices = doc.find('devices')
    if devices == None:
        LOG.error('The xml doc has no devices element.')
        return False
    controllers = devices.findall('controller')
    if controllers == None:
        return False

    has_virtio_scsi = False
    for controller in controllers:
        type = controller.get('type')
        if type == 'scsi':
            model = controller.get('model')
            if model == 'virtio-scsi':
                has_virtio_scsi = True
                break
    return has_virtio_scsi


def get_virtio_scsi_index(device_name):
    """
    device_name: expected as 'sda','sdah' .etc
    """
    tail = device_name[2:]
    index = ord(tail[-1]) - ord('a')
    if len(tail) > 1:
        index = index + 26 * (ord(tail[-2]) - ord('a') + 1)

    if index >= 60:
        raise exception.NovaException("Nova supports 60 virtio-scsi disks."
                                      "and there are already %s." % index)
    return index


def add_address_for_virtio_scsi_disk(domain_xml, disk_xml):
    """
    domain_xml: a string of xml of a domain
    disk_xml: a string of xml of a disk to be attached
    return: new disk_xml with <address> specified
    """
    LOG.debug("Old disk_xml=%s" % disk_xml)
    if not has_virtio_scsi(domain_xml):
        return disk_xml

    disk_doc = etree.fromstring(disk_xml)
    target = disk_doc.find('target')
    if target == None:
        return disk_xml

    device_name = target.get('dev')
    if device_name == None:
        return disk_xml

    bus = target.get('bus')
    if bus != 'scsi':
        return disk_xml

    scsi_index = get_virtio_scsi_index(device_name)

    address = disk_doc.find('address')
    if address == None:
        address = etree.Element('address', type='drive')
        disk_doc.append(address)

    address.set('controller', str(scsi_index / 15))
    address.set('target', str(scsi_index % 15))

    new_disk_xml = etree.tostring(disk_doc, pretty_print=True)
    LOG.debug("Finished adding address for virtio-scsi disk, disk_xml=%s"
              % new_disk_xml)

    return new_disk_xml
