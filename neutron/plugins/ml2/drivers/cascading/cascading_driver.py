# Copyright (c) 2013 OpenStack Foundation.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from neutron import context as n_context
from neutron.openstack.common import log as logging
from neutron.plugins.ml2 import driver_api as api
from neutron import manager
from neutron.plugins.ml2.drivers.cascading import rpc as cascading2_rpc
from neutron.db import models_v2
from neutron.common import constants as const
from neutron.common import utils as commonutils
from neutron.api.v2 import attributes
from neutron.db import api as db_api
from oslo.config import cfg

LOG = logging.getLogger(__name__)


class Cascading2MechanismDriver(api.MechanismDriver):
    def __init__(self):
        super(Cascading2MechanismDriver, self).__init__()
        self.Cascading2AgentNotify = cascading2_rpc.Cascading2AgentNotifyAPI()
        self.cxt = n_context.get_admin_context()
        self.dhcp_agents_per_network = 1 if cfg.CONF.dhcp_distributed else cfg.CONF.dhcp_agents_per_network
        self.dhcp_network_filter = cfg.CONF.dhcp_network_filter
        LOG.debug('myCascading2MechanismDriver')

    def initialize(self):
        LOG.debug(_("Experimental L2 population driver"))
        self.rpc_ctx = n_context.get_admin_context_without_session()
        self.migrated_ports = {}
        self.original_subnet = {}

    def update_network_postcommit(self, context):
        n_context = context._plugin_context
        network = context._network
        self.Cascading2AgentNotify.network_update(n_context, network)

    def create_subnet_precommit(self, context):
        subnet = context._subnet
        if not cfg.CONF.dhcp_distributed:
            if subnet['enable_dhcp'] and self._dhcp_filter(subnet):
                self._check_and_update_dhcp_port(context._plugin_context, subnet)

    def update_subnet_precommit(self, context):
        self.original_subnet = context._original_subnet
        subnet = context._subnet
        if not cfg.CONF.dhcp_distributed:
            if self._dhcp_filter(subnet):
                self._check_and_update_dhcp_port(context._plugin_context, subnet)

    def update_subnet_postcommit(self, context):
        n_context = context._plugin_context
        subnet = context._subnet
        original_subnet = self.original_subnet
        self.Cascading2AgentNotify.subnet_update(n_context, subnet, original_subnet)

    def delete_subnet_postcommit(self, context):
        n_context = context._plugin_context
        subnet_id = context._subnet['id']
        self.Cascading2AgentNotify.subnet_delete(n_context, subnet_id)

    def _dhcp_filter(self, subnet):
        if not self.dhcp_network_filter:
            return False
        session = db_api.get_session()
        network = session.query(models_v2.Network).filter(
            models_v2.Network.id == subnet['network_id']).one()
        if network.name in self.dhcp_network_filter:
            return False
        else:
            return True

    def _check_and_update_dhcp_port(self, context, subnet):
        core_plugin = manager.NeutronManager.get_plugin()
        filters = {'network_id': [subnet['network_id']], 'device_owner': [const.DEVICE_OWNER_DHCP]}
        dhcp_ports = core_plugin.get_ports(context, filters)
        filters = {'network_id': [subnet['network_id']]}
        subnets_for_net = core_plugin.get_subnets(context, filters)
        if not dhcp_ports or len(dhcp_ports) < self.dhcp_agents_per_network:
            curr_dhcp_num = 0 if not dhcp_ports else len(dhcp_ports)
            for i in range(self.dhcp_agents_per_network - curr_dhcp_num):
                port_dict = dict(
                    admin_state_up=True,
                    device_id=commonutils.get_dhcp_agent_device_id(subnet['network_id'], ''),
                    network_id=subnet['network_id'],
                    tenant_id=subnet['tenant_id'],
                    mac_address=attributes.ATTR_NOT_SPECIFIED,
                    name='dhcp_port',
                    device_owner=const.DEVICE_OWNER_DHCP,
                    fixed_ips=[dict(subnet_id=s['id']) for s in subnets_for_net if s['enable_dhcp'] is True])
                dhcp_port_dict = {'port': port_dict}
                core_plugin.create_port(context, dhcp_port_dict)
        if dhcp_ports:
            dhcp_ports = dhcp_ports[:self.dhcp_agents_per_network]
            for dhcp_port in dhcp_ports:
                dhcp_subnets = [dict(subnet_id=s['id']) for s in subnets_for_net if s['enable_dhcp'] is True]
                if len(dhcp_subnets) == 0:
                    core_plugin.delete_port(context, dhcp_port['id'])
                else:
                    subnet_ids = set(fixed_ip['subnet_id'] for fixed_ip in dhcp_port['fixed_ips'])
                    if subnet['id'] not in subnet_ids and subnet['enable_dhcp']:
                        dhcp_port['fixed_ips'] += [dict(subnet_id=subnet['id'])]
                        core_plugin.update_port(context, dhcp_port['id'], {'port': dhcp_port})

    def update_port_postcommit(self, context):
        n_context = context._plugin_context
        port = context.current
        LOG.debug(_("Updating port %(port)s"), {'port': port})
        if (port['binding:profile'].get('refresh_notify')):
            LOG.debug(_("Get notify message, updating port %(port)s"), {'port': port})
            self.Cascading2AgentNotify.port_update(n_context, port)

    def create_port_postcommit(self, context):
        n_context = context._plugin_context
        port = context.current
        if port['binding:host_id']:
            LOG.debug(_("create_port_postcommit %(port)s"), {'port': port})
            self.Cascading2AgentNotify.port_update(n_context, port, port['binding:host_id'])

    def delete_port_postcommit(self, context):
        n_context = context._plugin_context
        port = context.current
        if port['binding:host_id']:
            LOG.debug(_("create_port_postcommit %(port)s"), {'port': port})
            self.Cascading2AgentNotify.port_delete(n_context, port, port['binding:host_id'])
