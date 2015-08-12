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

import os
import re
import six
import random

from functools import wraps
from lxml import etree
from oslo.config import cfg

from nova.compute import task_states
from nova import context as nova_context
from nova import exception
from nova.i18n import _
from nova import objects
from nova.huawei import utils as hw_utils
from nova.huawei.virt.libvirt import utils as libvirt_ext_utils
from nova.huawei.scheduler import utils as hw_shed_utils
from nova.huawei import exception as h_exc
from nova.openstack.common import jsonutils
from nova.openstack.common import log as logging
from nova.openstack.common import units
from nova.virt.libvirt import config as config_original
from nova import utils


LOG = logging.getLogger(__name__)
vmtools_device_opts = [
    cfg.StrOpt('guest_os_driver_path',
               default="/opt/patch/programfiles/vmtools/driverupdate.iso",
               help=('driver disk for Guest to upgrade during boot')),
]

emulator_opts = [
    cfg.StrOpt("emulator_pin_bindcpu",
               default="",
               help="emulator_pin_bindcpu")
]

CONF = cfg.CONF
CONF.register_opts(vmtools_device_opts)
CONF.register_opts(emulator_opts)

VIF_TYPE_NETMAP = 'netmap'

OS_TYPE_WINDOWS = 'windows'
OS_TYPE_LINUX = 'linux'


#modify VM's XML for min_guarantee
def _modify_min_guarantee_xml(xml, min_guarantee):
    oldxml = xml
    xml = xml.replace("\n","")
    regex = "> +<"
    xml = re.subn(regex, "><", xml)[0]

    try:
        doc = etree.fromstring(xml)
    except Exception as e:
        LOG.warn('can not convert xml to doc: %s' %e)
        return oldxml
    newstr = "<memtune><min_guarantee>" + min_guarantee + \
             "</min_guarantee></memtune><memory>"
    xml = xml.replace("<memory>", newstr)

    try:
        doc = etree.fromstring(xml)
    except Exception as e:
        LOG.warn('can not convert xml to doc: %s' %e)
        return oldxml

    return etree.tostring(doc, pretty_print=True)


def update_cpu_bind_info_to_xml(xml, instance, driver, network_info):

    admin_context = nova_context.get_admin_context()
    inst_extra = objects.HuaweiInstanceExtra.get_by_instance_uuid(
        admin_context,
        instance.uuid)
    scheduler_hints = jsonutils.loads(inst_extra.scheduler_hints or '{}')

    def _is_sriov_instance(xml):
        doc = etree.fromstring(xml)
        interfaces = doc.findall('./devices/interface')
        for interface in interfaces:
            if "type" in interface.keys():
                if interface.attrib['type'] == 'hostdev':
                    return True
        return False

    LOG.debug("Instance %s in %s task_state, get binding_info from db"
              % (instance.uuid, instance.task_state))
    bind_info = jsonutils.loads(inst_extra.core_bind or '[]')
    vcpus = [cell['vcpu'] for cell in bind_info]
    pcpus = [cell['pcpus'] for cell in bind_info]
    bind_info = dict(zip(vcpus, pcpus))
    enable_bind, enable_ht, any_mode, numa_opts = \
        hw_shed_utils.get_inst_affinity_mask(
            dict(scheduler_hints=scheduler_hints))
    if instance.numa_topology:
        cell = instance.numa_topology.cells[0]
        instance_numa = {"cells": [{"mem": {"total": cell.memory},
                                    "cpuset": list(cell.cpuset),
                                    "id": cell.id,
                                    "pagesize": cell.pagesize}]}
        if numa_opts:
            instance_numa['cells'][0]['is_huawei'] = True
    else:
        instance_numa = None

    # if existed vhostuser port, we should change the xml
    if libvirt_ext_utils.get_physical_network(network_info):

        # modify xml for evs vhostuser port, if the vif details exist physical
        # network, we think the port is vhostuser port.
        xml = modify_xml_for_evs_vhostuser(xml)
        LOG.debug(_("modify_xml_for_evs_vhostuser is %s"), xml)

    LOG.debug("Binding cpu, the bind_info is %(bind_info)s, the instance"
              " numa is %(instance_numa)s", {'bind_info': bind_info,
                                             'instance_numa': instance_numa})

    if not bind_info:
        return xml

    doc = etree.fromstring(xml)
    cpu_element = doc.find("cpu")
    vcpu_topo = (cpu_element.find("topology") if cpu_element is not None else
                None)


    ht = scheduler_hints.get('hyperThreadAffinity', 'any')
    db_vcpu_topo = {}
    sockets = vcpu_topo.get("sockets")
    cores = vcpu_topo.get("cores")
    threads = vcpu_topo.get("threads")
    if vcpu_topo is not None:
        if ht == 'lock' and enable_ht and len(bind_info) > 2 and not _is_sriov_instance(xml):
            threads = 2
            cores = 1
            if len(bind_info) % 2 == 0:
                sockets = len(bind_info) / (threads * cores) - 1
                vcpu_topo.set("sockets", str(sockets))
                vcpu_topo.set("threads", str(threads))
                vcpu_topo.set("cores", str(cores))
            else:
                msg = ("Cannot set vcpu topology in sync mode, the bind_info"
                       " is %(bind_info)s, the instance numa is %(instance_numa"
                       ")s" % {'bind_info': bind_info,
                               'instance_numa': instance_numa})
                raise Exception(msg)
        else:
            if threads == '1' and enable_ht:
                if int(sockets) % 2 == 0:
                    sockets = str(int(sockets) / 2)
                    vcpu_topo.set("sockets", sockets)
                    threads = str(int(threads) * 2)
                    vcpu_topo.set("threads", threads)
                elif int(cores) % 2 == 0:
                    cores = str(int(cores) / 2)
                    vcpu_topo.set("cores", cores)
                    threads = str(int(threads) * 2)
                    vcpu_topo.set("threads", threads)
                else:
                    msg = ("Cannot set vcpu topology in sync mode, the bind_info"
                           " is %(bind_info)s, the instance numa is %(instance_numa"
                           ")s" % {'bind_info': bind_info,
                                   'instance_numa': instance_numa})
                    raise Exception(msg)

        db_vcpu_topo = {'sockets': int(sockets), 'cores': int(cores),
                        'threads': int(threads)}
    hw_shed_utils.update_cpu_bind_info_to_db(bind_info, instance.uuid,
                                             instance_numa,
                                             vcpu_topo=db_vcpu_topo)

    cpu = doc.findall('cputune')
    for c in cpu:
        doc.remove(c)

    emulator_pin_bindcpu = None
    if ht == 'lock':
        if CONF.emulator_pin_bindcpu and _is_sriov_instance(xml):
            emulator_pin_bindcpu = CONF.emulator_pin_bindcpu
        else:
            cells = jsonutils.loads(
                driver.host_state._stats['numa_topology']).get(
                    'nova_object.data', {}).get('cells', [])

            all_siblings = []
            for cell in cells:
                _siblings = cell.get('nova_object.data', {}).get('siblings', [])
                all_siblings = all_siblings + _siblings

            if len(bind_info) > 2:
                last_cpu_idx = bind_info[sorted(bind_info.keys())[-1]][0]
                for core in all_siblings:
                    if last_cpu_idx in core:
                        for (k, v) in bind_info.items():
                            if v[0] in core:
                                del bind_info[k]

                        emulator_pin_bindcpu = ",".join([str(c) for c in core])
                        break

                new_bind_info = {}
                sorted_keys = sorted(bind_info.keys())
                for idx, key in enumerate(sorted_keys):
                    new_bind_info[idx] = bind_info[key]

                bind_info = new_bind_info

    emulatorpin_cpuset = []
    cputune = etree.Element("cputune")
    for k, v in bind_info.items():
        cpuset = ','.join([str(c) for c in v])
        cputune.append(etree.Element("vcpupin", vcpu=str(k), cpuset=cpuset))
        emulatorpin_cpuset.extend(v)
    emulatorpin_cpuset = list(set(emulatorpin_cpuset))
    emulatorpin_cpuset.sort()
    default_emulatorpin_cpuset_str = ','.join(map(lambda x: str(x),
                                                  emulatorpin_cpuset))
    LOG.debug("emulatorpin_cpuset is %s",
              emulator_pin_bindcpu or default_emulatorpin_cpuset_str)
    cputune.append(etree.Element("emulatorpin", cpuset=emulator_pin_bindcpu or default_emulatorpin_cpuset_str))
    doc.append(cputune)
    # NOTE: when use huawei numa or bind, we should clean the cpuset of
    # vcpu element, if bind_info isn't {}, that means we shouldn't specify
    # the cpuset of vcpu element, if bind_info is {}, it will be returned
    # above.
    vcpu_element = doc.findall('vcpu')
    for vcpu_e in vcpu_element:
        doc.remove(vcpu_e)
    vcpu_element = etree.Element("vcpu")
    vcpu_element.text = str(len(bind_info))
    doc.append(vcpu_element)
    if instance_numa and instance_numa['cells'][0].get('is_huawei'):
        numa = doc.findall('numatune')
        for nm in numa:
            doc.remove(nm)
        numatune = etree.Element("numatune")
        cell_id = instance_numa['cells'][0]['id']
        cell_e = etree.Element("memory", mode="strict", nodeset=str(cell_id))
        numatune.append(cell_e)
        doc.append(numatune)

    def _update_numa_cell(doc, bind_info):
        cells = doc.findall('./cpu/numa/cell')
        for cell in cells:
            cell.attrib['cpus'] = ','.join([str(vcpu) for vcpu in bind_info.keys()])

    _update_numa_cell(doc, bind_info)
    return etree.tostring(doc, pretty_print=True)


def _modify_xml_for_qemu_commandline(xml, instance, network_info, driver):
    instance_uuid = instance['uuid']
    oldxml = xml
    xml = xml.replace("\n","")
    regex = "> +<"
    xml, number = re.subn(regex, "><", xml)
    try:
        doc = etree.fromstring(xml)
    except Exception:
        return oldxml
    xml = xml.replace('''<domain ''',
    '''<domain xmlns:qemu='http://libvirt.org/schemas/domain/qemu/1.0' ''')
    LOG.info("replace 1 %s", xml)
    qemu_commandline_begin = '<qemu:commandline>'
    qemu_commandline_end = '</qemu:commandline></domain>'
    qemu_set = qemu_commandline_begin
    if CONF.nic_suspension:
        NIC_xml = '''<qemu:arg value='-NetInterruptAutobind'/>'''
        qemu_set += NIC_xml

    netmap_flag = False
    addr_num = 30
    for vif in network_info:
        vif_type = vif['type']
        if vif_type == VIF_TYPE_NETMAP:
            netmap_flag = True
            nnif_num = vif['nmif'][0][:-1]
            nmifpath = "/dev/nm_device/%s" % nnif_num
            addr = hex(addr_num)
            netmap_xml = '''<qemu:arg value='-device'/><qemu:arg value='netmap,nmifpath=%s,bus=pci.0,addr=%s'/>''' % (nmifpath, addr)
            qemu_set += netmap_xml
            addr_num -= 1
    if netmap_flag:
        addr = hex(addr_num)
        netmap_end_xml = '''<qemu:arg value='-device'/><qemu:arg value='netmapmem,''' + \
                             '''hppath=/mnt/huge/libvirt/qemu,size=1g,shm=%s,index=1,bus=pci.0,addr=%s'/>''' % (instance['name'], addr)
        qemu_set += netmap_end_xml

    instance_metadata = instance.get("metadata", None)
    vwatchdog_flag = None
    if instance_metadata is None:
        vwatchdog_flag = None
    elif isinstance(instance_metadata, list):
        for metadict in instance_metadata:
            if metadict.get("key", None) == "__instance_vwatchdog":
                vwatchdog_flag = metadict.get("value", None)
    elif isinstance(instance_metadata, dict):
        vwatchdog_flag = instance_metadata.get("__instance_vwatchdog", None)
    else:
        vwatchdog_flag = None
    #priority: __instance_vwatchdog in metadata > CONF.instance_vwatchdog
    vwatchdog_enable = CONF.instance_vwatchdog
    if vwatchdog_flag is not None:
        if vwatchdog_flag.lower() == "true":
            vwatchdog_enable = True
        elif vwatchdog_flag.lower() == "false":
            vwatchdog_enable = False
    if vwatchdog_enable:
        start_time = CONF.wdt_start_time
        reboot_time = CONF.wdt_reboot_time
        watchdog_xml = '''<qemu:arg value='-device'/>\
        <qemu:arg value='isa-ipmi,chardev=mychar,iobase=0x0ca2,wdt_reboot=''' + \
                       str(reboot_time) + ''',start_time=''' + str(start_time) + \
                       ''''/><qemu:arg value='-device'/><qemu:arg value='pv_channel,bus=pci.0,addr=0x1f'/>'''
        qemu_set += watchdog_xml

    if CONF.instance_console_log:
        bios_log_path = os.path.join('/var/log/fusionsphere/uvp/qemu',
                                     instance_uuid)
        if not os.path.exists(bios_log_path):
            os.makedirs(bios_log_path)

        bios_log_xml = '''<qemu:arg value='-chardev'/><qemu:arg value='file,id=seabios,path=''' + bios_log_path + '/' + instance_uuid + '''.seabios,mux=off'/>
        <qemu:arg value='-device'/><qemu:arg value='isa-debugcon,iobase=0x402,chardev=seabios'/>'''

        console0_log_path = driver._get_console0_log_path(instance_uuid)
        console0_log_xml = '''<qemu:arg value='-consolelog'/><qemu:arg value='path=''' + console0_log_path + ''''/>'''
        qemu_set += bios_log_xml + console0_log_xml

    qemu_set += qemu_commandline_end
    xml = xml.replace('''</domain>''', qemu_set)
    xml, number = re.subn(regex, "><", xml)
    LOG.info("replace 2 %s", xml)
    try:
        doc = etree.fromstring(xml)
    except Exception:
        return oldxml

    return etree.tostring(doc, pretty_print=True)


def _modify_xml_for_kbox(xml, instance):
    doc = etree.fromstring(xml)
    if CONF.use_kbox:
        devices = doc.find("devices")
        ivshmem = etree.Element("ivshmem", role="master")
        ivshmem.append(etree.Element("memory", name="ramkbox_%s" % instance["uuid"], size="16"))
        devices.append(ivshmem)
        if CONF.use_nonvolatile_ram:
            utils.execute('kboxram-ctl', 'create', instance['name'], run_as_root=True)
            ivshmem = etree.Element("ivshmem", role="master")
            ivshmem.append(etree.Element("memory", name="/dev/kbox/control", size="2"))
            devices.append(ivshmem)
    return etree.tostring(doc, pretty_print=True)


def ensure_pae_tag(xml):
    """ Ensure pae tag in vm xml. """
    old_xml = xml
    xml = xml.replace("\n", "")
    regex = "> +<"
    xml = re.subn(regex, "><", xml)[0]

    xml = xml.replace('<features>', '<features><pae/>')

    try:
        doc = etree.fromstring(xml)
    except Exception:
        return old_xml

    return etree.tostring(doc, pretty_print=True)


def close_instance_memballoon(xml):
    """ Close memballoon config ion vm xml. """
    old_xml = xml
    xml = xml.replace("\n", "")
    regex = "> +<"
    xml = re.subn(regex, "><", xml)[0]

    begin = xml.find('<memballoon model=')
    if begin != -1:
        token_end = begin + xml[begin:].find('</memballoon>')
        token = xml[begin: token_end + len('</memballoon>')]
        xml = xml.replace(token, '<memballoon model="none"/>')

    try:
        doc = etree.fromstring(xml)
    except Exception:
        return old_xml

    return etree.tostring(doc, pretty_print=True)


def modify_rtc_clock_track(xml):
    """ Modify rct clock track to "guest" in xm xml. """
    old_xml = xml
    xml = xml.replace("\n", "")
    regex = "> +<"
    xml = re.subn(regex, "><", xml)[0]

    xml = xml.replace('<timer name="rtc"',
                      '<timer name="rtc" track="guest"')

    try:
        doc = etree.fromstring(xml)
    except Exception:
        return old_xml

    return etree.tostring(doc, pretty_print=True)


def update_cpu_mode_to_host_passthrough(xml):
    """ Modify cpu mode to host-passthrough for improving cpu performance. """
    old_xml = xml
    xml = xml.replace("\n", "")
    regex = "> +<"
    xml = re.subn(regex, "><", xml)[0]

    begin = xml.find('<cpu mode=')
    if begin != -1:
        token_end = begin + xml[begin:].find('>')
        token = xml[begin: token_end + len('>')]
        if 'host-passthrough' not in token:
            xml = xml.replace(token, '<cpu mode="host-passthrough">')

    try:
        doc = etree.fromstring(xml)
    except Exception:
        return old_xml

    return etree.tostring(doc, pretty_print=True)


def modify_uvp_socket_xml(xml, instance):
    """ Modify VM's XML for UVP channel. """
    old_xml = xml
    xml = xml.replace("\n", "")
    regex = "> +<"
    xml, number = re.subn(regex, "><", xml)

    try:
        doc = etree.fromstring(xml)
    except Exception:
        return old_xml

    name = ""
    all_name_nodes = doc.findall('name')
    for name_node in all_name_nodes:
        name = name_node.text
        LOG.info("name = %s", name)
        break

    #channel for upgrade
    new_xml = '''<devices><channel type='unix'><source mode='bind' \
    path='/var/run/libvirt/qemu/''' + name + '''.upgraded'/><target \
    type='virtio' name='org.qemu.guest_agent.3'/><address \
    type='virtio-serial' controller='0' bus='0' port='4'/></channel>'''
    xml = xml.replace('''<devices>''', new_xml)

    #short route message
    new_xml = '''<devices><channel type='unix'><source mode='bind' \
    path='/var/run/libvirt/qemu/''' + name + '''.hostd'/><target \
    type='virtio' name='org.qemu.guest_agent.2'/><address \
    type='virtio-serial' controller='0' bus='0' port='3'/></channel>'''
    xml = xml.replace('''<devices>''', new_xml)

    new_xml = '''<devices><channel type='unix'><source mode='bind' \
    path='/var/run/libvirt/qemu/''' + name + '''.agent'/><target \
    type='virtio' name='org.qemu.guest_agent.0'/><address \
    type='virtio-serial' controller='0' bus='0' port='2'/></channel>'''
    xml = xml.replace('''<devices>''', new_xml)

    new_xml = '''<devices><channel type='unix'><source mode='bind' \
    path='/var/run/libvirt/qemu/''' + name + '''.extend'/><target \
    type='virtio' name='org.qemu.guest_agent.1'/><address \
    type='virtio-serial' controller='0' bus='0' port='1'/></channel>'''
    xml = xml.replace('''<devices>''', new_xml)

    LOG.info("replace 2 %s", xml)

    try:
        doc = etree.fromstring(xml)
    except Exception:
        return old_xml

    return etree.tostring(doc, pretty_print=True)


def modify_xml_for_on_crash(xml):
    old_xml = xml

    try:
        doc = etree.fromstring(xml)
    except Exception:
        return old_xml

    on_crash_element = etree.Element("on_crash")
    on_crash_element.text = 'restart'
    doc.append(on_crash_element)

    new_xml = etree.tostring(doc, pretty_print=True)
    return new_xml

def modify_xml_for_device_io(xml):
    # NOTE: local storage io should be threads,otherwise should be native
    # the libvirt devices xml format is as follow:
    # <devices>
    # <disk type="file" device="disk">
    # <driver name="qemu" type="qcow2" cache="none" io="threads"/>

    oldxml = xml

    try:
        doc = etree.fromstring(xml)
    except Exception:
        return oldxml

    devices = doc.find("devices")
    if devices == None:
        LOG.error("The xml doc has not devices element.")
        return oldxml

    disks = devices.findall('disk')
    for disk in disks:
        driver = disk.find('driver')

        if driver is not None:
            file_type = None

            # type="file" means local storage,the io should be threads
            if 'file' == disk.get("type"):
                file_type = 'threads'

            # type="block" means share storage,the io should be native
            if 'block' == disk.get("type"):
                file_type = 'native'

            if file_type is not None:
                driver.set("io", file_type)

    return etree.tostring(doc, pretty_print=True)


def optimize_for_os_type(xml, image_meta, **kwargs):
    """add xml tag <hirmd:vminfo /> if necessary for VM OS performance
     optimize, including specification of 'os_class', 'os_type'
    :param xml: domain xml
    :param image_meta: metadata from image
    :param kwargs:
    :return: modified domain xml
    """
    image_meta_prop = image_meta.get('properties', {})
    os_class_name = image_meta_prop.get('__os_type', None)
    os_type_name = image_meta_prop.get('__os_version', None)

    if not (os_class_name and os_type_name):
        return xml

    os_class_name = os_class_name.lower()
    if os_class_name != OS_TYPE_WINDOWS and os_class_name != OS_TYPE_LINUX:
        LOG.warn(_('unsupported os type: %s'), os_class_name)
        return xml

    os_type_name = os_type_name.strip().replace(' ', '_')

    elmt_tree = etree.fromstring(xml)
    metadata = elmt_tree.find('metadata')

    # this condition barely exist, but anyway, just check it for ensure
    if metadata is None:
        LOG.warn(_('missing <metadata> tag in domain xml'))
        return xml

    hirmd_ns = 'http://hirmd.com/'
    nsmap = {'hirmd': hirmd_ns}

    vm_info = etree.SubElement(metadata, '{%s}vminfo' % hirmd_ns, nsmap=nsmap)
    etree.SubElement(vm_info, '{%s}os_class' % hirmd_ns, name=os_class_name)
    etree.SubElement(vm_info, '{%s}os_type' % hirmd_ns, name=os_type_name)

    LOG.debug(_('+ xml to <metadata>: %s'), etree.tostring(vm_info))

    if os_class_name == OS_TYPE_WINDOWS:
        features = elmt_tree.find('features')
        clock = elmt_tree.find('clock')

        if features is None or clock is None:
            LOG.warn(_('missing <%s> tag in domain xml'),
                     'features' if features is None else 'clock')
            return etree.tostring(elmt_tree)

        hyperv = etree.SubElement(features, 'hyperv')
        etree.SubElement(hyperv, 'relaxed', state='on')
        etree.SubElement(hyperv, 'vapic', state='on')
        etree.SubElement(hyperv, 'spinlocks', state='on', retries='4096')

        timer = etree.SubElement(clock, 'timer', name='hypervclock',
                                 present='yes')

        LOG.debug(_('+ xml to <features>: %s'), etree.tostring(hyperv))
        LOG.debug(_('+ xml to <clock>: %s'), etree.tostring(timer))

    return etree.tostring(elmt_tree)


def inject_vnc_pwd(xml):
    vnc_password = (str(chr(ord('a') + random.randrange(0, 25))) +
                    str(random.randrange(1000000, 9999999)))

    doc = etree.fromstring(xml)
    graphics = doc.findall('./devices/graphics[@type=\'vnc\']')

    if not graphics:
        return xml

    graphics[0].set('passwd', vnc_password)

    new_xml = etree.tostring(doc)
    return new_xml

def modify_xml_for_evs_vhostuser(xml):
    """
    if the evs affinity is enabled, should do the following things
    1.add memAccess='shared' in ./cpu/numa/cell if the evs affinity is enabled.
    2.add size="2" unit="M" nodeset="0,1"/ in ./memoryBacking/hugepages/page
    :param xml:
    :return: a new xml string
    """

    # start to modifromstringfy xml config
    doc = etree.fromstring(xml)

    # modify cpu numa cells
    cells = doc.findall("./cpu/numa/cell")
    for cell in cells:
        cell.set("memAccess", "shared")

    return etree.tostring(doc, pretty_print=True)


def _update_boot_option(xml, metadata):
    root = etree.fromstring(xml)
    remove_boot_dev_options(root)
    remove_boot_order_options(root)
    set_default_boot_order(root)
    if metadata is None:
        return etree.tostring(root, pretty_print=True)
    boot_option = None
    if isinstance(metadata, dict):
        boot_option = metadata.get('__bootDev', None)
    else:
        for item in metadata:
            if item['key'] == '__bootDev':
                boot_option = item['value']
                break
    if boot_option is None or not hw_utils.is_valid_boot_option(boot_option):
        return etree.tostring(root, pretty_print=True)
    boot_option_list = boot_option.split(',')
    remove_boot_order_options(root)
    update_boot_order_option(root, boot_option_list)
    return etree.tostring(root, pretty_print=True)


def remove_boot_dev_options(root_node):
    os_node = root_node.find('os')
    boot_dev_nodes = os_node.findall('boot')
    for boot_dev_node in boot_dev_nodes:
        os_node.remove(boot_dev_node)


def remove_boot_order_options(root_node):
    device_node = root_node.find('devices')
    child_nodes = device_node.iterchildren()
    for child_node in child_nodes:
        if child_node.tag == 'disk' or child_node.tag == 'interface':
            boot_order_node = child_node.find('boot')
            if boot_order_node is not None:
                child_node.remove(boot_order_node)


def set_default_boot_order(root_node):
    default_boot_option = ['hd', 'cdrom', 'network']
    update_boot_order_option(root_node, default_boot_option)


def update_boot_order_option(root_node, boot_option_list):
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
                disk_bus_type = get_disk_bus_type(disk_node_disk[0])
                disk_node_disk.sort(key=get_disk_dev_name)
                for disk_node in disk_node_disk:
                    if get_disk_bus_type(disk_node) != disk_bus_type:
                        continue
                    boot_order_node = disk_node.find('boot')
                    if boot_order_node is None:
                        disk_node.append(
                            etree.Element('boot', order=str(boot_order)))
                    else:
                        boot_order_node.set('order', str(boot_order))
                    boot_order += 1
                    break
        elif boot_dev == 'network':
            for interface_node in interface_nodes:
                # hostdev device shall not set boot order
                if (interface_node.get('type') == 'hostdev'):
                    continue

                boot_order_node = interface_node.find('boot')
                if boot_order_node is None:
                    interface_node.append(
                        etree.Element('boot', order=str(boot_order)))
                else:
                    boot_order_node.set('order', str(boot_order))
                boot_order += 1
        elif boot_dev == 'cdrom':
            if disk_node_cdrom:
                disk_node_cdrom.sort(key=get_disk_dev_name)
                for disk_node in disk_node_cdrom:
                    source = disk_node.find('source')
                    if source is None or not source.get('file'):
                        continue
                    boot_order_node = disk_node.find('boot')
                    if boot_order_node is None:
                        disk_node.append(
                            etree.Element('boot', order=str(boot_order)))
                    else:
                        boot_order_node.set('order', str(boot_order))
                    boot_order += 1


def get_disk_bus_type(disk_node):
    target = disk_node.find('target')
    return target.get('bus')


def get_disk_dev_name(disk_node):
    target = disk_node.find('target')
    return target.get('dev')


def _get_mac_profile_dict(network_info):
    '''
        dic format:
        {'fa: 16: 3e: 66: 7d: 0c': {'queues':1, 'vringbuf'=256},
        'a: 16: 3e: 2b: f8: 23': {'queues':2, 'vringbuf'=512}}
    '''
    dic = {}
    for vif in network_info:
        mac = vif.get('address', None)
        profile = vif.get('profile', None)
        if mac is not None:
            if profile:
                dic.update({mac: profile})
    return dic


def modify_xml_for_nic_multi_queue(xml, network_info):
    '''
     the format of multiple Nic field in the libvirt xml :
        <driver name='vhost' queues='2' vringbuf='256'/>
    '''
    source_xml = xml

    try:
        doc = etree.fromstring(xml)
    except Exception:
        LOG.error('etree xml error')
        return source_xml

    devices = doc.find("devices")
    if devices is None:
        LOG.error('The xml doc has no devices element.')
        return source_xml

    dic = _get_mac_profile_dict(network_info)
    interfaces = devices.findall('interface')
    for interface in interfaces:
        model = interface.find('model')
        mac = interface.find('mac')
        if model is not None and mac is not None:
            model_type = model.get('type')
            if 'virtio' not in model_type:
                continue
            mac_address = mac.get('address')
            if dic.has_key(mac_address):
                driver_node=None
                if dic[mac_address].has_key('queues') and \
                        dic[mac_address].has_key('vringbuf'):
                    driver_node = etree.Element('driver', name='vhost',
                                        queues=dic[mac_address]['queues'],
                                        vringbuf=dic[mac_address]['vringbuf'])

                if dic[mac_address].has_key('queues') \
                        and not dic[mac_address].has_key('vringbuf'):
                    driver_node = etree.Element('driver', name='vhost',
                                        queues=dic[mac_address]['queues'])

                if dic[mac_address].has_key('vringbuf') \
                        and not dic[mac_address].has_key('queues'):
                    driver_node = etree.Element('driver', name='vhost',
                                        vringbuf=dic[mac_address]['vringbuf'])
                if driver_node:
                    interface.append(driver_node)
    return etree.tostring(doc, pretty_print=True)


def modify_xml_for_vmtools_cdrom(xml, instance):
    def _next_disk_name(dev_name):
        disk_prefix = dev_name[0:2]
        disk_name = dev_name[2:3]
        if disk_name < 'a' or disk_name >= 'z':
            raise exception.NovaException(
                _("No free disk device names for prefix 'hd'"))
        return disk_prefix + chr(ord(disk_name) + 1)

    def _generate_cdrom_xml(instance):
        meta = instance.get("metadata", {})
        set_source = False
        if meta.get("__loading_update_driver_image", "") == "enable":
            set_source = True
        source = None
        if CONF.guest_os_driver_path and \
                os.path.exists(CONF.guest_os_driver_path) and set_source:
            source = CONF.guest_os_driver_path
        cdrom = config_original.LibvirtConfigGuestDisk()
        # source_path null
        cdrom.source_device = "cdrom"
        cdrom.driver_name = "qemu"
        cdrom.driver_format = "raw"
        cdrom.driver_cache = "none"
        cdrom.target_dev = "hdb"
        cdrom.target_bus = "ide"
        cdrom.source_path = source or ""
        # io use threads default
        cdrom.readonly = True
        return cdrom.format_dom()

    try:
        doc = etree.fromstring(xml)
    except Exception:
        return xml
    ret = doc.findall('./devices/disk')
    original_ide_disks = []

    for node in ret:
        for child in node.getchildren():
            if child.tag == 'target':
                if child.get('bus') == "ide":
                    dev_name = child.get('dev')
                    if not dev_name or len(dev_name) != 3 or\
                            dev_name[0:2] != "hd":
                        continue
                    original_ide_disks.append(dev_name)
    original_ide_disks = sorted(original_ide_disks)
    ide_disks = ["hdb"]
    ide_disk_maps = {}
    for disk in original_ide_disks:
        dev = disk
        if disk in ide_disks:
            dev = _next_disk_name(disk)
        ide_disk_maps[disk] = dev
        ide_disks.append(dev)

    for node in ret:
        for child in node.getchildren():
            if child.tag == 'target':
                if child.get('bus') == "ide":
                    dev_name = child.get('dev')
                    if not dev_name or len(dev_name) != 3 or\
                            dev_name[0:2] != "hd":
                        continue
                    # vmtools use hdb, so change dev after hda
                    dev_name = ide_disk_maps.get(dev_name, "hdb")
                    child.set('dev', dev_name)

    if len(ide_disks) > 4:
        LOG.error('Too Many ide devices for ide bus, vm might boot with error')
    # add cdrom
    cdrom = _generate_cdrom_xml(instance)

    devices = doc.find('./devices')
    devices.append(cdrom)
    return etree.tostring(doc, pretty_print=True)


def post_to_xml(xml, context, instance, network_info=None, disk_info=None,
                block_device_info=None, driver=None, **kwargs):
    new_xml = xml
    instance.obj_load_attr("metadata")
    flavor = objects.Flavor.get_by_id(
        nova_context.get_admin_context(read_deleted='yes'),
        instance['instance_type_id'])

    image_meta = utils.get_image_from_system_metadata(
        instance['system_metadata'])

    # update cpu bind info to xml
    new_xml = update_cpu_bind_info_to_xml(new_xml, instance, driver,
                                                   network_info)

    # DRM rewrite VM's XML for min_guarantee
    if CONF.instance_memory_qos:
        memory = flavor['memory_mb'] * units.Ki
        new_xml = _modify_min_guarantee_xml(new_xml, str(memory))

    # modify qemu
    new_xml = _modify_xml_for_qemu_commandline(new_xml, instance,
                                               network_info, driver)
    # modify for kbox
    new_xml = _modify_xml_for_kbox(new_xml, instance)

    if CONF.libvirt.virt_type != "lxc" and CONF.libvirt.virt_type != "uml":
        new_xml = ensure_pae_tag(new_xml)

    if CONF.close_instance_memballoon:
        new_xml = close_instance_memballoon(new_xml)

    new_xml = modify_rtc_clock_track(new_xml)

    new_xml = update_cpu_mode_to_host_passthrough(new_xml)

    # DRM rewrite VM's XML for an empty cdrom
    new_xml = modify_xml_for_vmtools_cdrom(new_xml, instance)
    #DRM rewrite VM's XML for UVP channel
    new_xml = modify_uvp_socket_xml(new_xml, instance)
    #DRM rewrite VM's XML for on_crash
    new_xml = modify_xml_for_on_crash(new_xml)

    new_xml = modify_xml_for_device_io(new_xml)

    new_xml = optimize_for_os_type(new_xml, image_meta)

    # update boot option
    new_xml = _update_boot_option(new_xml, instance.get('metadata', None))

    #add for nic multi queue
    new_xml = modify_xml_for_nic_multi_queue(new_xml, network_info)

    #add address and target number for each virtio-scsi disk
    new_xml = modify_xml_for_virtio_scsi_disk(new_xml)

    new_xml = inject_vnc_pwd(new_xml)

    new_xml = _modify_xml_for_scheduler_hints(new_xml, instance)

    return new_xml

def modify_xml_for_virtio_scsi_disk(domain_xml):
    """
    domain_xml: expected as a string of a domain's xml
    """
    source_xml = domain_xml

    if not libvirt_ext_utils.has_virtio_scsi(domain_xml):
        return source_xml
    try:
        doc = etree.fromstring(domain_xml)
    except Exception:
        LOG.error('etree xml error')
        return source_xml

    devices = doc.find('devices')
    if devices == None:
        LOG.error('The xml doc has no devices element.')
        return source_xml

    disks = devices.findall('disk')

    for disk in disks:
        target = disk.find('target')
        if target == None:
            continue
        bus = target.get('bus')
        if bus != 'scsi':
            continue
        device_name = target.get('dev')
        scsi_index = libvirt_ext_utils.get_virtio_scsi_index(device_name)

        address = disk.find('address')
        if address == None:
            address = etree.Element('address', type='drive')
            disk.append(address)

        address.set('controller', str(scsi_index / 15))
        address.set('target', str(scsi_index % 15))

        LOG.debug("Added address for virtio-scsi disk[%s], scsi_index=%s."
                  % (device_name, scsi_index))

    return etree.tostring(doc, pretty_print=True)


def _modify_xml_for_scheduler_hints(xml, instance):
    admin_context = nova_context.get_admin_context()
    inst_extra = objects.HuaweiInstanceExtra.get_by_instance_uuid(admin_context,
                                                                      instance.uuid)
    inst_scheduler_hints = jsonutils.loads(inst_extra.scheduler_hints or '{}')
    ht = inst_scheduler_hints.get('hyperThreadAffinity', 'any')
    nova_ns = 'http://openstack.org/xmlns/libvirt/nova/1.0'
    ns_prefix = 'nova'
    doc = etree.fromstring(xml)
    instance_node = doc.find('./metadata/nova:instance',
                        namespaces={ns_prefix: nova_ns})
    scheduler_hints_node = etree.Element('{' + nova_ns + '}schedulerHints',
                                   nsmap={ns_prefix: nova_ns})
    hyperthread_affinity_node = etree.Element('{' + nova_ns + '}hyperThreadAffinity',
                                        nsmap={ns_prefix: nova_ns})
    hyperthread_affinity_node.text = ht
    scheduler_hints_node.append(hyperthread_affinity_node)
    instance_node.append(scheduler_hints_node)
    return etree.tostring(doc, pretty_print=True)