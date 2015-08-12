# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2011 X.commerce, a business unit of eBay Inc.
# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# All Rights Reserved.
# Copyright 2013 IBM Corp.
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

import itertools
import math

import netaddr
from oslo.config import cfg

from nova.huawei.db import affinity_db_api as huawei_db
from nova import context
from nova import exception
from nova.i18n import _, _LE
from nova.network import driver
from nova.huawei import exception as huawei_exception
from nova.network import manager as core_manager
from nova.openstack.common.gettextutils import _
from nova.openstack.common import log as logging
from nova.openstack.common import uuidutils
from nova import db
from nova import objects
from nova.objects import base as obj_base
from nova import utils
from nova.openstack.common import uuidutils
from nova.openstack.common import periodic_task

LOG = logging.getLogger(__name__)


network_opts = [
    cfg.StrOpt('flat_network_bridge',
               help='Bridge for simple network instances'),
    cfg.BoolOpt('flat_injected',
                default=False,
                help='Whether to attempt to inject network setup into guest'),
    cfg.StrOpt('flat_interface',
               help='FlatDhcp will bridge into this interface if set'),
    cfg.IntOpt('vlan_start',
               default=100,
               help='First VLAN for private networks'),
    cfg.IntOpt('num_networks',
               default=1,
               help='Number of networks to support'),
    cfg.StrOpt('vpn_ip',
               default='$my_ip',
               help='Public IP for the cloudpipe VPN servers'),
    cfg.IntOpt('vpn_start',
               default=1000,
               help='First Vpn port for private networks'),
    cfg.IntOpt('network_size',
               default=256,
               help='Number of addresses in each private subnet'),
    cfg.StrOpt('fixed_range_v6',
               default='fd00::/48',
               help='Fixed IPv6 address block'),
    cfg.StrOpt('gateway',
               help='Default IPv4 gateway'),
    cfg.StrOpt('gateway_v6',
               help='Default IPv6 gateway'),
    cfg.IntOpt('cnt_vpn_clients',
               default=0,
               help='Number of addresses reserved for vpn clients'),
    cfg.IntOpt('create_unique_mac_address_attempts',
               default=5,
               help='Number of attempts to create unique mac address'),
    cfg.BoolOpt('fake_call',
                default=False,
                help='If True, skip using the queue and make local calls'),
    cfg.BoolOpt('teardown_unused_network_gateway',
                default=False,
                help='If True, unused gateway devices (VLAN and bridge) are '
                     'deleted in VLAN network mode with multi hosted '
                     'networks'),
    cfg.BoolOpt('force_dhcp_release',
                default=True,
                help='If True, send a dhcp release on instance termination'),
    cfg.BoolOpt('update_dns_entries',
                default=False,
                help='If True, when a DNS entry must be updated, it sends a '
                     'fanout cast to all network hosts to update their DNS '
                     'entries in multi host mode'),
    cfg.IntOpt("dns_update_periodic_interval",
               default=-1,
               help='Number of seconds to wait between runs of updates to DNS '
                    'entries.'),
    cfg.StrOpt('l3_lib',
               default='nova.network.l3.LinuxNetL3',
               help="Indicates underlying L3 management library"),
    ]

CONF = cfg.CONF
CONF.register_opts(network_opts)
CONF.import_opt('use_ipv6', 'nova.netconf')
CONF.import_opt('my_ip', 'nova.netconf')
CONF.import_opt('network_topic', 'nova.network.rpcapi')
CONF.import_opt('flat_network_dns', 'nova.network.manager')
CONF.import_opt('vlan_interface', 'nova.network.manager')
CONF.import_opt('fixed_ip_disassociate_timeout', 'nova.network.manager')
CONF.import_opt('dhcp_domain', 'nova.network.manager')
CONF.import_opt('fake_network', 'nova.network.linux_net')
CONF.import_opt('share_dhcp_address', 'nova.objects.network')
CONF.import_opt('network_device_mtu', 'nova.objects.network')


class HuaweiVlanManager(core_manager.VlanManager):

    def __init__(self, network_driver=None, *args, **kwargs):
        super(HuaweiVlanManager, self).__init__(network_driver=network_driver,
                                                *args, **kwargs)

    def update_interface_address(self, context, instance_uuid, vif_uuid,
                                 network_uuid, address):
        """Update address of virtual interfaces."""
        try:
            netaddr.IPAddress(address)
        except netaddr.core.AddrFormatError:
            msg = _("'%s' is not a valid IP address") % address
            LOG.exception(msg)
            raise exception.InvalidIpAddressError(address)

        if not uuidutils.is_uuid_like(network_uuid):
            raise exception.InvalidUUID(id=network_uuid)

        if not uuidutils.is_uuid_like(vif_uuid):
            raise exception.InvalidUUID(id=vif_uuid)

        is_diff_net = False
        try:
            network = self.get_network(context, network_uuid)
            host = None
            if not network['multi_host']:
                host = network['host']
            if not host:
                network_p = obj_base.obj_to_primitive(network)
                self.network_rpcapi.set_network_host(context, network_p)
            fixed_ip_ref = objects.FixedIP.get_by_address(context, address)
            if fixed_ip_ref['instance_uuid']:
                raise exception.FixedIpAlreadyInUse(address=address,
                                                    instance_uuid=instance_uuid)
            if fixed_ip_ref['network_id'] != network['id']:
                raise exception.FixedIpNotFoundForNetwork(address=address,
                                                          network_uuid=network_uuid)
            if fixed_ip_ref['reserved']:
                raise exception.FixedIpInvalid(address=address)
            vif_ref = objects.VirtualInterface.get_by_uuid(context,
                                                            vif_uuid)
            if vif_ref:
                if network['id'] != vif_ref['network_id']:
                    is_diff_net = True
                    old_network = objects.Network.get_by_id(context.elevated(),
                                                      vif_ref['network_id'])
                    obj_base.obj_to_primitive(old_network)

                vif_id = vif_ref['id']

                fixed_ips = objects.FixedIPList.get_by_virtual_interface_id(
                    context, vif_id)                
                for fixed_ip in fixed_ips:
                    if not fixed_ip or not fixed_ip.address:
                        continue
                    old_address = fixed_ip.address    
                    objects.FixedIP.disassociate_by_address(context, old_address)
                    values = {'network_id': network['id']}
                    huawei_db.virtual_interface_update(context, vif_id, values)
                    fixed_ip.virtual_interface = None
                    fixed_ip.virtual_interface_id = None
                    fixed_ip.allocated = False
                    fixed_ip.save(context)
                    new_fixed_ip = objects.FixedIP.associate(context, address,
                                                        instance_uuid,
                                                        network_id=network['id'])
                    new_fixed_ip.virtual_interface = vif_ref
                    new_fixed_ip.virtual_interface_id = vif_id
                    new_fixed_ip.allocated = True                    
                    new_fixed_ip.save(context)
            else:
                raise huawei_exception.VirtualInterfaceNotFound(id=vif_uuid)
        except exception.NetworkNotFoundForUUID as e:
            raise e
        except exception.FixedIpNotFoundForAddress as e:
            raise e
        except TypeError:
            raise huawei_exception.VirtualInterfaceNotInUse(vif_id=vif_uuid)
        except Exception as e:
            LOG.exception(e)
            raise e

        if is_diff_net:
            self._teardown_network_on_host(context, old_network)
        self._setup_network_on_host(context, network)

    def _do_create_networks(self, context,
                            label, cidr, multi_host, num_networks,
                            network_size, cidr_v6, gateway, gateway_v6, bridge,
                            bridge_interface, dns1=None, dns2=None,
                            fixed_cidr=None, mtu=None, dhcp_server=None,
                            enable_dhcp=None, share_address=None,
                            allowed_start=None, allowed_end=None, **kwargs):
        """Create networks based on parameters."""
        # NOTE(): these are dummy values to make sure iter works
        # TODO(): disallow carving up networks
        fixed_net_v4 = netaddr.IPNetwork('0/32')
        fixed_net_v6 = netaddr.IPNetwork('::0/128')
        subnets_v4 = []
        subnets_v6 = []

        if kwargs.get('ipam'):
            if cidr_v6:
                subnets_v6 = [netaddr.IPNetwork(cidr_v6)]
            if cidr:
                subnets_v4 = [netaddr.IPNetwork(cidr)]
        else:
            subnet_bits = int(math.ceil(math.log(network_size, 2)))
            if cidr_v6:
                fixed_net_v6 = netaddr.IPNetwork(cidr_v6)
                prefixlen_v6 = 128 - subnet_bits
                # smallest subnet in IPv6 ethernet network is /64
                if prefixlen_v6 > 64:
                    prefixlen_v6 = 64
                subnets_v6 = fixed_net_v6.subnet(prefixlen_v6,
                                                 count=num_networks)
            if cidr:
                fixed_net_v4 = netaddr.IPNetwork(cidr)
                prefixlen_v4 = 32 - subnet_bits
                subnets_v4 = list(fixed_net_v4.subnet(prefixlen_v4,
                                                      count=num_networks))

        if cidr:
            # NOTE(): This replaces the _validate_cidrs call and
            #                 prevents looping multiple times
            try:
                nets = objects.NetworkList.get_all(context)
            except exception.NoNetworksFound:
                nets = []
            num_used_nets = len(nets)
            used_subnets = [net.cidr for net in nets]

            def find_next(subnet):
                next_subnet = subnet.next()
                while next_subnet in subnets_v4:
                    next_subnet = next_subnet.next()
                if next_subnet in fixed_net_v4:
                    return next_subnet

            for subnet in list(subnets_v4):
                if subnet in used_subnets:
                    next_subnet = find_next(subnet)
                    if next_subnet:
                        subnets_v4.remove(subnet)
                        subnets_v4.append(next_subnet)
                        subnet = next_subnet
                    else:
                        raise exception.CidrConflict(cidr=subnet,
                                                     other=subnet)
                for used_subnet in used_subnets:
                    if subnet in used_subnet:
                        raise exception.CidrConflict(cidr=subnet,
                                                     other=used_subnet)
                    if used_subnet in subnet:
                        next_subnet = find_next(subnet)
                        if next_subnet:
                            subnets_v4.remove(subnet)
                            subnets_v4.append(next_subnet)
                            subnet = next_subnet
                        else:
                            raise exception.CidrConflict(cidr=subnet,
                                                         other=used_subnet)

        networks = objects.NetworkList(context=context, objects=[])
        subnets = itertools.izip_longest(subnets_v4, subnets_v6)
        for index, (subnet_v4, subnet_v6) in enumerate(subnets):
            net = objects.Network(context=context)
            net.bridge = bridge
            net.bridge_interface = bridge_interface
            net.multi_host = multi_host

            net.dns1 = dns1
            net.dns2 = dns2
            net.mtu = mtu
            net.enable_dhcp = enable_dhcp
            net.share_address = share_address

            net.project_id = kwargs.get('project_id')

            if num_networks > 1:
                net.label = '%s_%d' % (label, index)
            else:
                net.label = label

            bottom_reserved = self._bottom_reserved_ips
            top_reserved = self._top_reserved_ips
            extra_reserved = []
            if cidr and subnet_v4:
                current = subnet_v4[1]
                if allowed_start:
                    val = self._index_of(subnet_v4, allowed_start)
                    current = netaddr.IPAddress(allowed_start)
                    bottom_reserved = val
                if allowed_end:
                    val = self._index_of(subnet_v4, allowed_end)
                    top_reserved = subnet_v4.size - 1 - val
                net.cidr = str(subnet_v4)
                net.netmask = str(subnet_v4.netmask)
                net.broadcast = str(subnet_v4.broadcast)
                if gateway:
                    net.gateway = gateway
                else:
                    net.gateway = current
                    current += 1
                if not dhcp_server:
                    dhcp_server = net.gateway
                net.dhcp_start = current
                current += 1
                if str(net.dhcp_start) == dhcp_server:
                    net.dhcp_start = current
                net.dhcp_server = dhcp_server
                extra_reserved.append(str(net.dhcp_server))
                extra_reserved.append(str(net.gateway))

            if cidr_v6 and subnet_v6:
                net.cidr_v6 = str(subnet_v6)
                if gateway_v6:
                    # use a pre-defined gateway if one is provided
                    net.gateway_v6 = str(gateway_v6)
                else:
                    net.gateway_v6 = str(subnet_v6[1])

                net.netmask_v6 = str(subnet_v6.netmask)

            vlan_mgr = 'nova.network.manager.VlanManager'
            huawei_vlan_mgr = 'nova.huawei.network.manager.HuaweiVlanManager'
            if CONF.network_manager == vlan_mgr or \
                            CONF.network_manager == huawei_vlan_mgr:
                vlan = kwargs.get('vlan', None)
                if not vlan:
                    index_vlan = index + num_used_nets
                    vlan = kwargs['vlan_start'] + index_vlan
                    used_vlans = [x.vlan for x in nets]
                    if vlan in used_vlans:
                        # That vlan is used, try to get another one
                        used_vlans.sort()
                        vlan = used_vlans[-1] + 1

                net.vpn_private_address = net.dhcp_start
                extra_reserved.append(str(net.vpn_private_address))
                net.dhcp_start = net.dhcp_start + 1
                net.vlan = vlan
                net.bridge = 'br%s' % vlan

                # NOTE(): This makes ports unique across the cloud, a more
                #             robust solution would be to make them uniq per ip
                index_vpn = index + num_used_nets
                net.vpn_public_port = kwargs['vpn_start'] + index_vpn

            net.create()
            networks.objects.append(net)

            if cidr and subnet_v4:
                self._create_fixed_ips(context, net.id, fixed_cidr,
                                       extra_reserved, bottom_reserved,
                                       top_reserved)
        # NOTE(): Remove this in RPC API v2.0
        return obj_base.obj_to_primitive(networks)

    @periodic_task.periodic_task(spacing=60)
    def recovery_dnsmasql(self, context_arg):
        LOG.debug("recovery_dnsmasql start.")
        ctxt = context.get_admin_context()
        for network in objects.NetworkList.get_by_host(ctxt, self.host):
            cmd = ['ps -ewwf | grep dns | grep %s | wc -l' % network.label]
            result = utils.execute(*cmd, shell=True)
            LOG.debug("query dnsmasq thread result is %s", result[0])
            if int(result[0]) <= 1:
                LOG.warn("rebuild network : %s", network.label)
                self._setup_network_on_host(ctxt, network)
                if CONF.update_dns_entries:
                    dev = self.driver.get_dev(network)
                    self.driver.update_dns(ctxt, dev, network)
        LOG.debug("recovery_dnsmasql end.")
		
    @utils.synchronized('setup_network', external=True)
    def _setup_network_on_host(self, context, network):
        """Sets up network on this host."""
        if context.is_admin: 
            if not objects.Network.in_use_on_host(context, network['id'],
                                                  None):
                return 
        
        if not network.vpn_public_address:
            address = CONF.vpn_ip
            network.vpn_public_address = address
            network.save()
        else:
            address = network.vpn_public_address
        network.dhcp_server = self._get_dhcp_ip(context, network)

        self._initialize_network(network)

        # NOTE(): only ensure this forward if the address hasn't been set
        #             manually.
        if address == CONF.vpn_ip and hasattr(self.driver,
                                               "ensure_vpn_forward"):
            self.l3driver.add_vpn(CONF.vpn_ip,
                    network.vpn_public_port,
                    network.vpn_private_address)
        if not CONF.fake_network:
            dev = self.driver.get_dev(network)
            # NOTE(): dhcp DB queries require elevated context
            if network.enable_dhcp:
                elevated = context.elevated()
                self.driver.update_dhcp(elevated, dev, network)
            if CONF.use_ipv6:
                self.driver.update_ra(context, dev, network)
                gateway = utils.get_my_linklocal(dev)
                network.gateway_v6 = gateway
                network.save()

    @utils.synchronized('setup_network', external=True)
    def _teardown_network_on_host(self, context, network):
        if not CONF.fake_network:
            network['dhcp_server'] = self._get_dhcp_ip(context, network)
            dev = self.driver.get_dev(network)

            # NOTE(): For multi hosted networks, if the network is no
            # more used on this host and if VPN forwarding rule aren't handed
            # by the host, we delete the network gateway.
            vpn_address = network['vpn_public_address']
            if (CONF.teardown_unused_network_gateway and
                not objects.Network.in_use_on_host(context, network['id'],
                                                   self.host)):
                LOG.debug("Remove unused gateway %s", network['bridge'])
                if network.enable_dhcp:
                    self.driver.kill_dhcp(dev)
                self.l3driver.remove_gateway(network)
                if not self._uses_shared_ip(network):
                    fip = objects.FixedIP.get_by_address(context,
                                                         network.dhcp_server)
                    fip.allocated = False
                    fip.host = None
                    fip.save()
            # NOTE(): if dhcp server is not set then don't dhcp
            elif network.enable_dhcp:
                # NOTE(): dhcp DB queries require elevated context
                elevated = context.elevated()
                self.driver.update_dhcp(elevated, dev, network)