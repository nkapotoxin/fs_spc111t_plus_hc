# -*- coding: UTF-8 -*-

from neutron.plugins.openvswitch.common.localbus.bus_client import BusClientFactory
from oslo.config import cfg
from neutron.agent.linux import ovs_lib
from neutron.common import utils as q_utils
from neutron.openstack.common import jsonutils
from neutron.openstack.common import log as logging
from optparse import OptionParser
import json
#import socket
from eventlet.green import socket
from struct import pack
import os

LOG = logging.getLogger(__name__)

ARPING_PORT_PREFIX = 'arping-'

class NeutronInterface():
    def __init__(self):
        self.bus = None
        self.cached_topology = {}
        self.providers = []

        try:
            bridge_mappings = q_utils.parse_mappings(cfg.CONF.OVS.bridge_mappings)
        except ValueError as e:
            raise ValueError(_("Parsing bridge_mappings failed: %s.") % e)

        self.integ_br = cfg.CONF.OVS.integration_bridge
        self.bridge_mappings = bridge_mappings
        self.root_helper = cfg.CONF.AGENT.root_helper

        self.int_br = ovs_lib.OVSBridge(self.integ_br, self.root_helper)

    def _init_arping_port(self, physical_network, interface):
        bridge = self.bridge_mappings.get(physical_network)
        if not bridge:
            LOG.error(_("physical_network: %(physical_network)s "
                      "in not in bridge_mappings: (bridge_mappings)s"),
                      {'physical_network': physical_network,
                      'bridge_mappings': self.bridge_mappings})
        br = ovs_lib.OVSBridge(bridge, self.root_helper)
        port_name = ARPING_PORT_PREFIX + physical_network
        arping_port = br.add_port_for_bus(port_name)
        interface_port = br.get_port_ofport(interface)
        actions = "output:%s" % interface_port
        br.add_flow(priority=101,
                    dl_type="0x0806",
                    in_port=arping_port,
                    actions=actions)

    def _find_port_info(self, physical_network):
        # return a[port_id][mac], a[port_id][vlan]
        port_names = set(self.int_br.get_port_name_list())
        ovs_bridges = set(ovs_lib.get_bridges(self.root_helper))
        for bridge in ovs_bridges:
            if bridge[0:3] == 'tbr':
                res = self.int_br.run_vsctl(["list-ports", bridge], check_error=True)
                tbr_ports = []
                if res:
                    tbr_ports = res.strip().split("\n")
                port_names.update(set(tbr_ports))
        port_infos = dict()
        args = ['--format=json', '--', '--columns=name,external_ids,ofport,other_config',
                'list', 'Interface']
        result = self.int_br.run_vsctl(args, check_error=True)
        if not result:
            return port_infos
        for row in jsonutils.loads(result)['data']:
            name = row[0]
            if name not in port_names:
                continue
            external_ids = dict(row[1][1])
            other_config = dict(row[3][1])
            # Do not consider VIFs which aren't yet ready
            # This can happen when ofport values are either [] or ["set", []]
            # We will therefore consider only integer values for ofport
            ofport = row[2]
            try:
                int_ofport = int(ofport)
            except (ValueError, TypeError):
                LOG.warn(_("Found not yet ready openvswitch port: %s"), row)
            else:
                if int_ofport > 0:
                    if ("iface-id" in external_ids and
                        "attached-mac" in external_ids and
                        "segmentation_id" in other_config and
                        physical_network == other_config.get("physical_network")):
                        port_infos[external_ids['iface-id']] = dict()
                        port_infos[external_ids['iface-id']]['mac'] = external_ids['attached-mac']
                        port_infos[external_ids['iface-id']]['vlan'] = other_config['segmentation_id']
                else:
                    LOG.warn(_("Found failed openvswitch port: %s"), row)
        return port_infos

    def _send_arp(self, device, sender_mac, tag):
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.SOCK_RAW)
        sock.bind((device, socket.SOCK_RAW))

        ARPOP_REQUEST = pack('!H', 0x0001)

        source_mac = pack('!6B', *[int(x,16) for x in sender_mac.split(':')])
        target_mac = pack('!6B', *(0xFF,)*6)

        src_ip = "0.0.0.0"
        dst_ip = "0.0.0.0"
        sender_ip = pack('!4B', *[int(x) for x in src_ip.split('.')])
        target_ip = pack('!4B', *[int(x) for x in dst_ip.split('.')])

        fill = pack('!18B', *(0x00,)*18)
        if(int(tag) != 0):
            arpframe = [
            ### ETHERNET
            # destination MAC addr
            target_mac,
            # source MAC addr
            source_mac,
            pack('!H', 0x8100),
            pack('!H', int(tag)),
            # protocol type (=ARP)
            pack('!H', 0x0806),

            ### ARP
            # logical protocol type (Ethernet/IP)
            pack('!HHBB', 0x0001, 0x0800, 0x0006, 0x0004),
            # operation type
            ARPOP_REQUEST,
            # sender MAC addr
            source_mac,
            # sender IP addr
            sender_ip,
            # target hardware addr
            target_mac,
            # target IP addr
            target_ip,
            pack('!30B', *(0x00,)*30)
            ]
        else:
            arpframe = [
            ### ETHERNET
            # destination MAC addr
            target_mac,
            # source MAC addr
            source_mac,
            # protocol type (=ARP)
            pack('!H', 0x0806),

            ### ARP
            # logical protocol type (Ethernet/IP)
            pack('!HHBB', 0x0001, 0x0800, 0x0006, 0x0004),
            # operation type
            ARPOP_REQUEST,
            # sender MAC addr
            source_mac,
            # sender IP addr
            sender_ip,        # target hardware addr
            target_mac,
            # target IP addr        target_ip,
            pack('!30B', *(0x00,)*30)
            ]
        # send the ARP
        sock.send(''.join(arpframe))
        sock.send(''.join(arpframe))
        sock.send(''.join(arpframe))

    def set_bus(self, bus):
        self.bus = bus

    def trans_port_info_to_str(self, port_infos):
        str_mac_vlan = ""
        for port_id in port_infos:
            mac = port_infos[port_id]['mac']
            vlan = port_infos[port_id]['vlan']
            str_mac_vlan = str_mac_vlan + mac + "," + vlan + ";"
        return str_mac_vlan

    def bond_failover(self, interface_name, provider_name):
        LOG.debug("starting send_arp_by_physnet: %s, interface: %s." % (provider_name, interface_name))
        self._init_arping_port(provider_name, interface_name)
        port_infos = self._find_port_info(provider_name)
        port_name = ARPING_PORT_PREFIX + provider_name
        str_mac_vlan = self.trans_port_info_to_str(port_infos)
        LOG.info("port_name: %s, str_mac_vlan: %s" % (port_name, str_mac_vlan))
        cmd = 'sudo python /usr/lib64/python2.6/site-packages/neutron/plugins/openvswitch/agent/send_arp.py "%s" "%s"' % (port_name, str_mac_vlan)
        os.system(cmd)
        """
        for port_id in port_infos:
            mac = port_infos[port_id]['mac']
            vlan = port_infos[port_id]['vlan']
            LOG.info(_("port_name: %(port_name)s, "
                        "mac: %(mac)s,"
                        "vlan: %(vlan)s."),
                      {'port_name': port_name,
                       'mac': mac,
                       'vlan': vlan})
            self._send_arp(port_name, mac, vlan)
        """
        return


class NeutronBusClient():
    def __init__(self):
        self.bus = None
        self.interface = None
        pass

    def connect(self):
        clientFact = BusClientFactory()
        self.interface = NeutronInterface()

        clientFact.setInterface(self.interface)
        clientFact.setName("neutron")
        self.bus = clientFact.createClient()
        self.interface.set_bus(self.bus)
