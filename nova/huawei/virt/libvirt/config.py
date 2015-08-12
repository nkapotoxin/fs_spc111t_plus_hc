
from nova.virt.libvirt import config as config_original
from nova.openstack.common import log as logging
from nova.pci import pci_utils
from lxml import etree


LOG = logging.getLogger(__name__)
class LibvirtConfigGuestCPU(config_original.LibvirtConfigObject):
    def __init__(self, **kwargs):
        super(LibvirtConfigGuestCPU, self).__init__(root_name='cpu',
                                               **kwargs)

        self.arch = None
        self.vendor = None
        self.model =  None
        self.mode =  None
        self.vcpuTopo = kwargs.get('vcpu_topology', '{}')
        self.sockets = self.vcpuTopo['sockets']
        self.cores = self.vcpuTopo['cores']
        self.threads = self.vcpuTopo['threads']

        self.features = []

    def parse_dom(self, xmldoc):
        super(LibvirtConfigGuestCPU, self).parse_dom(xmldoc)

        for c in xmldoc.getchildren():
            if c.tag == "arch":
                self.arch = c.text
            elif c.tag == "model":
                self.model = c.text
            elif c.tag == "vendor":
                self.vendor = c.text
            elif c.tag == "topology":
                self.sockets = int(c.get("sockets"))
                self.cores = int(c.get("cores"))
                self.threads = int(c.get("threads"))
            elif c.tag == "feature":
                f = config_original.LibvirtConfigCPUFeature()
                f.parse_dom(c)
                self.add_feature(f)

    def format_dom(self):
        cpu = super(LibvirtConfigGuestCPU, self).format_dom()

        if self.arch is not None:
            cpu.append(self._text_node("arch", self.arch))
        if self.model is not None:
            cpu.append(self._text_node("model", self.model))
        if self.vendor is not None:
            cpu.append(self._text_node("vendor", self.vendor))

        if (self.sockets is not None and
            self.cores is not None and
                self.threads is not None):
            top = etree.Element("topology")
            top.set("sockets", str(self.sockets))
            top.set("cores", str(self.cores))
            top.set("threads", str(self.threads))
            cpu.append(top)
        
        if self.mode is not None:
            cpu.set("mode", str(self.mode))
        
        for f in self.features:
            cpu.append(f.format_dom())

        return cpu

    def add_feature(self, feat):
        self.features.append(feat)
        
class LibvirtConfigGuestNetmap(config_original.LibvirtConfigObject):
    def __init__(self, **kwargs):
        super(LibvirtConfigGuestNetmap, self).\
                __init__(root_name="netmap", **kwargs)
        self.nmifpath = kwargs.get('nmifpath')
        self.mac = kwargs.get('address')

    def format_dom(self):
        dev = super(LibvirtConfigGuestNetmap, self).format_dom()

        nmifpath = etree.Element("netmap",
                                nmifpath=self.nmifpath, address=self.mac)
        dev.append(nmifpath)
        return dev

    def parse_dom(self, xmldoc):
        childs = super(LibvirtConfigGuestNetmap, self).parse_dom(xmldoc)
        for c in childs:
            if c.tag == "netmap":
                self.nmifpath = c.get('nmifpath')
                self.mac = c.get('address')

class LibvirtConfigGuestMemballoon(config_original.LibvirtConfigGuestDevice):
    """
    The default model of memballoon is none.
    """
    def __init__(self, **kwargs):
        super(LibvirtConfigGuestMemballoon, self).\
                __init__(root_name="memballoon", **kwargs)
        self.model = "none"
        
    def format_dom(self):
        dev = super(LibvirtConfigGuestMemballoon, self).format_dom()
        dev.set("model", self.model)
        
        return dev

    def parse_dom(self, xmldoc):
        super(LibvirtConfigGuestMemballoon, self).parse_dom(xmldoc)
        self.model = xmldoc.get('model')


class LibvirtConfigGuestInterface(config_original.LibvirtConfigGuestDevice):

    def __init__(self, **kwargs):
        super(LibvirtConfigGuestInterface, self).__init__(
            root_name="interface",
            **kwargs)

        self.net_type = None
        self.target_dev = None
        self.model = None
        self.mac_addr = None
        self.script = None
        self.source_dev = None
        self.source_mode = "private"
        self.source_path = None
        self.vporttype = None
        self.vportparams = []
        self.filtername = None
        self.filterparams = []
        self.driver_name = None
        self.vif_inbound_peak = None
        self.vif_inbound_burst = None
        self.vif_inbound_average = None
        self.vif_outbound_peak = None
        self.vif_outbound_burst = None
        self.vif_outbound_average = None
        self.vlan = None
        self.vif_profile_queues = None
        self.vif_profile_vringbuf = None

    def format_dom(self):
        dev = super(LibvirtConfigGuestInterface, self).format_dom()

        dev.set("type", self.net_type)
        if self.net_type == "hostdev":
            dev.set("managed", "yes")
        dev.append(etree.Element("mac", address=self.mac_addr))
        if self.model:
            dev.append(etree.Element("model", type=self.model))

        if self.driver_name:
            driver_elem = etree.Element("driver", name=self.driver_name)
            dev.append(driver_elem)

        #multi_nic
        if self.vif_profile_queues or self.vif_profile_vringbuf:
            if not self.driver_name:
                driver_elem = etree.Element("driver", name="vhost")
                dev.append(driver_elem)
            if self.vif_profile_queues:
                driver_elem.set("queues", str(self.vif_profile_queues))
            if self.vif_profile_vringbuf:
                driver_elem.set("vringbuf", str(self.vif_profile_vringbuf))

        if self.net_type == "ethernet":
            if self.script is not None:
                dev.append(etree.Element("script", path=self.script))
        elif self.net_type == "direct":
            dev.append(etree.Element("source", dev=self.source_dev,
                                     mode=self.source_mode))
        elif self.net_type == "vhostuser":
            dev.append(etree.Element("source", type="unix", path=self.source_path,
                                     mode=self.source_mode))
        elif self.net_type == "hostdev":
            source_elem = etree.Element("source")
            domain, bus, slot, func = \
                pci_utils.get_pci_address_fields(self.source_dev)
            addr_elem = etree.Element("address", type='pci')
            addr_elem.set("domain", "0x%s" % (domain))
            addr_elem.set("bus", "0x%s" % (bus))
            addr_elem.set("slot", "0x%s" % (slot))
            addr_elem.set("function", "0x%s" % (func))
            source_elem.append(addr_elem)
            dev.append(source_elem)
        else:
            dev.append(etree.Element("source", bridge=self.source_dev))

        if self.vlan and self.net_type in ("direct", "hostdev","bridge"):
            vlan_elem = etree.Element("vlan")
            tag_elem = etree.Element("tag", id=self.vlan)
            vlan_elem.append(tag_elem)
            dev.append(vlan_elem)

        if self.target_dev is not None:
            dev.append(etree.Element("target", dev=self.target_dev))

        if self.vporttype is not None:
            vport = etree.Element("virtualport", type=self.vporttype)
            for p in self.vportparams:
                param = etree.Element("parameters")
                param.set(p['key'], p['value'])
                vport.append(param)
            dev.append(vport)

        if self.filtername is not None:
            filter = etree.Element("filterref", filter=self.filtername)
            for p in self.filterparams:
                filter.append(etree.Element("parameter",
                                            name=p['key'],
                                            value=p['value']))
            dev.append(filter)

        if self.vif_inbound_average or self.vif_outbound_average:
            bandwidth = etree.Element("bandwidth")
            if self.vif_inbound_average is not None:
                vif_inbound = etree.Element("inbound",
                average=str(self.vif_inbound_average))
                if self.vif_inbound_peak is not None:
                    vif_inbound.set("peak", str(self.vif_inbound_peak))
                if self.vif_inbound_burst is not None:
                    vif_inbound.set("burst", str(self.vif_inbound_burst))
                bandwidth.append(vif_inbound)

            if self.vif_outbound_average is not None:
                vif_outbound = etree.Element("outbound",
                average=str(self.vif_outbound_average))
                if self.vif_outbound_peak is not None:
                    vif_outbound.set("peak", str(self.vif_outbound_peak))
                if self.vif_outbound_burst is not None:
                    vif_outbound.set("burst", str(self.vif_outbound_burst))
                bandwidth.append(vif_outbound)
            dev.append(bandwidth)

        #this if added by huawei for network order
        if self.pci_slot is not None:
            dev.append(etree.Element("address",
                type = "pci",
                domain = "0x0000",
                bus = "0x00",
                slot = "0x%x" % self.pci_slot,
                function = "0x0"))

        return dev

    def add_filter_param(self, key, value):
        self.filterparams.append({'key': key, 'value': value})

    def add_vport_param(self, key, value):
        self.vportparams.append({'key': key, 'value': value})

