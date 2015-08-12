#
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

"""huawei extend VIF drivers for libvirt."""

from oslo.config import cfg
from nova.virt.libvirt import designer
from nova.virt.libvirt import vif as libvirt_vif
from nova.openstack.common import log as logging
from nova.network import model as network_model
from nova.pci import pci_utils
from eventlet.green import subprocess
import time
import commands

from nova.network import linux_net
from nova.openstack.common import processutils
from nova.huawei.virt.libvirt import utils
LOG = logging.getLogger(__name__)

CONF = cfg.CONF
EVS_BRIDGE = 'evs_bridge'
PHYSICAL_NETWORK = "physical_network"
EBR_INT = 'ebr-int'
QOS_SUPPORTED_VENDORS_LIST = ["8086:10ed"]

class LibvirtGenericVIFDriver(libvirt_vif.LibvirtGenericVIFDriver):
    """Huawei Generic VIF driver for libvirt networking."""

    def __init__(self, get_connection):
        super( LibvirtGenericVIFDriver, self ).__init__(get_connection)
        self.get_connection = get_connection


    def get_config_evs(self, instance, vif, image_meta,
                       inst_type, virt_type):
        conf = self.get_base_config(instance, vif, image_meta,
                                    inst_type, virt_type)

        bridge = vif['details'].get(EVS_BRIDGE,False)
        designer.set_vif_host_backend_ovs_config(
            conf, bridge,
            self.get_ovs_interfaceid(vif),
            self.get_vif_devname(vif))

        designer.set_vif_bandwidth_config(conf, inst_type)

        return conf

    def get_config_netmap(self, instance, vif, image_meta,
                            inst_type, virt_type):
        profile = vif["profile"]
        pf_eth = pci_utils.get_pf_by_vfpci(profile['pci_slot'])
        vf_index = pci_utils.get_vf_index(profile['pci_slot'])
        vif_details = vif["details"]
        mac = vif.get("address", None)
        vlan = vif_details[network_model.VIF_DETAILS_VLAN]
        try:
            pci_driver = utils.execute('lspci', '-s', profile['pci_slot'], '-k', run_as_root=True)
        except processutils.ProcessExecutionError:
            LOG.error("get pci_driver failed")
        if not pci_driver[0].strip():
            LOG.error("no driver loaded")
            return
        LOG.debug("plug_netmap:mac:%s,vlan:%s,profile['pci_slot']:%s,pf_eth:%s,vf_index:%s" %
                  (mac, vlan, profile['pci_slot'], pf_eth, vf_index))
        try:
            utils.execute('nm_ioctl', '%s.vf%s' % (pf_eth, vf_index), 'unreg', run_as_root=True)
        except processutils.ProcessExecutionError:
            LOG.debug("no need to unregister %s.vf%s" % (pf_eth, vf_index))
        try:
            utils.execute('ip', 'link', 'set', pf_eth, 'vf', vf_index, 'mac', mac, run_as_root=True)
            utils.execute('ip', 'link', 'set', pf_eth, 'vf', vf_index, 'vlan', vlan, run_as_root=True)
            if 'Kernel driver in use' in pci_driver[0]:
                uninstall_cmd = "sudo sh -c 'echo %s > /sys/bus/pci/devices/%s/driver/unbind'" \
                                % (profile['pci_slot'], profile['pci_slot'])
                self.execute_cmd(uninstall_cmd)
            if '82599' in pci_driver[0]:
                install_cmd = "sudo sh -c 'echo %s > /sys/bus/pci/drivers/nm_ixgbevf/bind'" % profile['pci_slot']
            elif 'Mellanox ' in pci_driver[0]:
                install_cmd = "sudo sh -c 'echo %s > /sys/bus/pci/drivers/mlx4_core/bind'" % profile['pci_slot']
            self.execute_cmd(install_cmd)
            pfup_cmd = "sudo /sbin/ifconfig %s up" % pf_eth
            self.execute_cmd(pfup_cmd)
            vfup_cmd = "sudo /sbin/ifconfig %s.vf%s up" % (pf_eth, vf_index)
            self.execute_cmd(vfup_cmd)
            nmif_index = utils.execute('nm_ioctl', '%s.vf%s' % (pf_eth, vf_index), 'reg', run_as_root=True)
            vif["nmif"] = nmif_index
        except processutils.ProcessExecutionError:
            LOG.error("create netmap device failed")
            self.unplug_netmap(instance, vif)
        return None

    def execute_cmd(self, cmd):
        count = 5
        while True:
            try:
                subprocess.check_call(cmd, shell=True)
                LOG.debug("executing cmd %s success" % cmd)
                return
            except subprocess.CalledProcessError:
                if count == 0:
                    LOG.error("executing cmd %s failed" % cmd)
                    return
                time.sleep(0.5)
                count -= 1

    def set_vif_profile_config(self, conf, profile):
        spec_attr = ["queues", "vringbuf"]
        for attr in spec_attr:
            if attr in profile.keys():
                setattr(conf, "vif_profile_" + attr, profile[attr])   

    def get_config_ovs(self, instance, vif, image_meta,
                       inst_type, virt_type):
        conf = super( LibvirtGenericVIFDriver, self ).get_config_ovs(instance, vif, image_meta,
                                                              inst_type, virt_type)

        self.set_vif_profile_config(conf, vif['profile'])
        
        return conf        
        
    def plug_vhostuser(self, instance, vif):
        """Plug using hybrid strategy

        Create a per-VIF linux bridge, then link that bridge to the OVS
        integration bridge via an ovs internal port device. Then boot the
        VIF on the linux bridge using standard libvirt mechanisms.
        """
        iface_id = self.get_ovs_interfaceid(vif)
        ebr_int_name = EBR_INT
        vm_ebr_pcy_name = self.get_vm_pcy_ebr_name(vif['id'])
        vm_pcy_tap_name = self.get_vm_pcy_tap_name(vif['id'])
        pcy_patch_port_name, int_patch_port_name = self.get_ebr_veth_pair_names(vif['id'])

        numa_id =None
        physnet = vif['details'].get(PHYSICAL_NETWORK,None)
        if physnet != None:
            numa_id = utils.get_numa_id_by_physical_network(physnet)

        try:
            if not linux_net.device_exists(ebr_int_name):
                LOG.error("evs intergragation bridge %s doesnot exist !" % ebr_int_name)
                raise Exception

            if not linux_net.device_exists(vm_ebr_pcy_name):
                linux_net.create_evs_dpdk_br(vm_ebr_pcy_name)
                linux_net.create_evs_patch_port(ebr_int_name, int_patch_port_name, pcy_patch_port_name)
                linux_net.create_evs_patch_port(vm_ebr_pcy_name, pcy_patch_port_name, int_patch_port_name)

            if numa_id != None and numa_id != -1:
                linux_net.create_evs_virtio_port_bind_numa(vm_ebr_pcy_name,
                                       vm_pcy_tap_name, numa_id, iface_id,
                                      vif['address'], instance['uuid'],
                                       internal=False)
            else:
                linux_net.create_evs_virtio_port(vm_ebr_pcy_name,
                                 vm_pcy_tap_name, iface_id,
                                  vif['address'], instance['uuid'],
                                 internal=False)

        except processutils.ProcessExecutionError,e:
            LOG.error("create ebr-pcy bridge or attatch virtio port failed! error is %s "%e)

    def plug_evs(self, instance, vif):
        pass

    def plug_netmap(self, instance, vif):
        pass

    def unplug_evs(self, instance, vif):
        pass

    def unplug_netmap(self, instance, vif):
        FREE_MAC = "00:00:00:00:00:01"
        vlan = 0
        rate = 0
        mac = vif.get("address", None)
        profile = vif["profile"]
        if not profile['pci_slot']:
            return
        pci_vendor = profile['pci_vendor_info']
        pf_eth = pci_utils.get_pf_by_vfpci(profile['pci_slot'])
        vf_index = pci_utils.get_vf_index(profile['pci_slot'])
        # need check default value
        LOG.debug("unplug_netmap:mac:%s,vlan:%s,profile['pci_slot']:%s,pf_eth:%s,vf_index:%s" %
                  (mac, vlan, profile['pci_slot'], pf_eth, vf_index))
        try:
            utils.execute('ip', 'link', 'set', pf_eth, 'vf', vf_index, 'mac', FREE_MAC, run_as_root=True)
            utils.execute('ip', 'link', 'set', pf_eth, 'vf', vf_index, 'vlan', vlan, run_as_root=True)
            pci_driver = utils.execute('lspci', '-s', profile['pci_slot'], '-k', run_as_root=True)
            if 'Kernel driver in use' in pci_driver[0]:
                utils.execute('nm_ioctl', '%s.vf%s' % (pf_eth, vf_index), 'unreg', run_as_root=True)
                uninstall_cmd = "sudo sh -c 'echo %s > /sys/bus/pci/devices/%s/driver/unbind'" \
                                % (profile['pci_slot'], profile['pci_slot'])
                self.execute_cmd(uninstall_cmd)
            if pci_vendor in QOS_SUPPORTED_VENDORS_LIST:
                utils.execute('ip', 'link', 'set', pf_eth, 'vf', vf_index, 'rate', rate, run_as_root=True)
        except processutils.ProcessExecutionError:
            LOG.error("Failed while unplug_netmap vif of %s" % instance)

    def unplug_hw_veb(self, instance, vif):
        try:
            rate = 0
            mac = vif.get("address",None)
            profile = vif["profile"]
            if not profile['pci_slot']:
                return
            if not mac:
                return
            pci_vendor = profile['pci_vendor_info']
            pf_eth = pci_utils.get_pf_by_vfpci(profile['pci_slot'])
            if not pf_eth:
                return
            vf_index = pci_utils.get_vf_index(profile['pci_slot'])
            result = commands.getoutput('ip link show %s | grep "vf %s MAC %s"' %(pf_eth, vf_index, mac))
            LOG.debug("Find result = %s" % result)
            if not result:
                return
            # need check default value
            super(LibvirtGenericVIFDriver, self).unplug_hw_veb(instance, vif)
            if pci_vendor in QOS_SUPPORTED_VENDORS_LIST:
                utils.execute('ip', 'link', 'set', pf_eth, 'vf', vf_index, 'rate', rate, run_as_root=True)
        except processutils.ProcessExecutionError:
            LOG.error("Failed while unplug_hw_veb vif rate of %s" % instance)
