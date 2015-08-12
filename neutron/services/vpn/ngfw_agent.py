# Copyright 2013, Nachi Ueno, NTT I3, Inc.
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
from oslo.config import cfg

from neutron.agent import l3_agent
from neutron.extensions import vpnaas
from neutron.openstack.common import importutils
from neutron.openstack.common import log as logging
from neutron.agent.common import config

vpn_agent_opts = [
    cfg.MultiStrOpt(
        'vpn_device_driver',
        default=['neutron.services.vpn.device_drivers.'
                 'ngfw_ipsec.NGFWDriver'],
        help=_("The vpn device drivers Neutron will use")),
    cfg.StrOpt(
        'static_route_priority',
        default='63',
        help=_("ngfw static route priority")),
    cfg.StrOpt(
        'vpn_ngfw_private_interface',
        default='GigabitEthernet1/0/1',
        help=_("ngfw private network gateway interface name")),
    cfg.StrOpt(
        'vpn_ngfw_public_interface',
        default='GigabitEthernet1/0/3',
        help=_("ngfw public network gateway interface name")),
    cfg.ListOpt('vpn_ip_pool',
                default=[],
                help=_("vpn public ip pool."
                       "Comma-separated list of <ip_min>:<ip_max> tuples")),
    cfg.ListOpt('vlan_ranges',
                default=[],
                help=_("vlan connectted with ngfw."
                       "Comma-separated list of <vlan_min>:<vlan_max> tuples")),
    cfg.ListOpt('vsys_ranges',
                default=[],
                help=_("ngfw vsys ranges."
                       "Comma-separated list of <vsys_min>:<vsys_max> tuples")),
    cfg.StrOpt('vpn_nexthop',
                default='',
                help=_("vpn_nexthop")),
    cfg.StrOpt(
        'ngfw_vrrp_ip',
        default='169.254.192.5',
        help=_("ngfw vrrp ip address")),
    cfg.StrOpt(
        'tenant_ext_net_prefix',
        default='ngfw_external_vlan_',
        help=_("external network prefix"))
]



LOG = logging.getLogger(__name__)
class VPNAgent(l3_agent.L3NATAgentWithStateReport):
    """VPNAgent class which can handle vpn service drivers."""
    def __init__(self, host, conf=None):
        super(VPNAgent, self).__init__(host=host, conf=conf)
        self.root_helper = config.get_root_helper(cfg.CONF)
        cfg.CONF.register_opts(vpn_agent_opts, 'ngfw')
        self.setup_device_drivers(host)
        for device in self.devices:
            device.sync(self.context, [])

    def _check_config_params(self):
        """Check items in configuration files.

        Check for required and invalid configuration items.
        The actual values are not verified for correctness.
        """
        if not self.conf.interface_driver:
            msg = _('An interface driver must be specified')
            LOG.error(msg)
            raise SystemExit(1)

    def setup_device_drivers(self, host):
        """Setting up device drivers.

        :param host: hostname. This is needed for rpc
        Each devices will stays as processes.
        They will communicate with
        server side service plugin using rpc with
        device specific rpc topic.
        :returns: None
        """
        device_drivers = cfg.CONF.ngfw.vpn_device_driver
        self.devices = []
        for device_driver in device_drivers:
            try:
                self.devices.append(
                    importutils.import_object(device_driver, self, host))
            except ImportError:
                raise vpnaas.DeviceDriverImportError(
                    device_driver=device_driver)

    def _router_added(self, router_id, router):
        """Router added event.

        This method overwrites parent class method.
        :param router_id: id of added router
        :param router: dict of rotuer
        """
        super(VPNAgent, self)._router_added(router_id, router)
        for device in self.devices:
            device.create_router(router_id)

    def _router_removed(self, router_id):
        """Router removed event.

        This method overwrites parent class method.
        :param router_id: id of removed router
        """
        super(VPNAgent, self)._router_removed(router_id)
        for device in self.devices:
            device.destroy_router(router_id)

    def _process_routers(self, routers, all_routers=False):
        """Router sync event.

        This method overwrites parent class method.
        :param routers: list of routers
        """
        super(VPNAgent, self)._process_routers(routers, all_routers)
        for device in self.devices:
            device.sync(self.context, routers)

class ngfwL3NATAgentWithStateReport(VPNAgent,
                                       l3_agent.L3NATAgentWithStateReport):
    def __init__(self, host, conf=None):
        super(ngfwL3NATAgentWithStateReport, self).__init__(host=host, conf=conf)
        self.agent_state['binary'] = 'neutron-vpn-agent'


    def _report_state(self):
        configurations = self.agent_state['configurations']
        configurations['vpn_ip_pool'] = self.conf.ngfw.vpn_ip_pool
        configurations['vsys_ranges'] = self.conf.ngfw.vsys_ranges
        configurations['vlan_ranges'] = self.conf.ngfw.vlan_ranges
        super(ngfwL3NATAgentWithStateReport, self)._report_state()

def main():
    l3_agent.main(
        manager='neutron.services.vpn.ngfw_agent.ngfwL3NATAgentWithStateReport')
