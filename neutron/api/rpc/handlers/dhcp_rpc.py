# Copyright (c) 2012 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from oslo.config import cfg
from oslo.db import exception as db_exc

from neutron.api.v2 import attributes
from neutron.common import constants
from neutron.common import exceptions as n_exc
from neutron.common import rpc as n_rpc
from neutron.common import utils
from neutron.extensions import portbindings
from neutron import manager
from neutron.openstack.common import excutils
from neutron.openstack.common import log as logging
from neutron.db import agentschedulers_db
from neutron.db import agents_db
from sqlalchemy import sql
from neutron.extensions import dhcpagentscheduler

LOG = logging.getLogger(__name__)


class DhcpRpcCallback(n_rpc.RpcCallback):
    """DHCP agent RPC callback in plugin implementations."""

    # API version history:
    #     1.0 - Initial version.
    #     1.1 - Added get_active_networks_info, create_dhcp_port,
    #           and update_dhcp_port methods.
    RPC_API_VERSION = '1.1'

    def _get_active_networks(self, context, **kwargs):
        """Retrieve and return a list of the active networks."""
        host = kwargs.get('host')
        plugin = manager.NeutronManager.get_plugin()
        if utils.is_extension_supported(
            plugin, constants.DHCP_AGENT_SCHEDULER_EXT_ALIAS):
            if cfg.CONF.network_auto_schedule:
                plugin.auto_schedule_networks(context, host)
            nets = plugin.list_active_networks_on_active_dhcp_agent(
                context, host)
        else:
            filters = dict(admin_state_up=[True])
            nets = plugin.get_networks(context, filters=filters)
        return nets

    def _port_action(self, plugin, context, port, action):
        """Perform port operations taking care of concurrency issues."""
        try:
            if action == 'create_port':
                return plugin.create_port(context, port)
            elif action == 'update_port':
                return plugin.update_port(context, port['id'], port)
            else:
                msg = _('Unrecognized action')
                raise n_exc.Invalid(message=msg)
        except (db_exc.DBError, n_exc.NetworkNotFound,
                n_exc.SubnetNotFound, n_exc.IpAddressGenerationFailure) as e:
            with excutils.save_and_reraise_exception(reraise=False) as ctxt:
                if isinstance(e, n_exc.IpAddressGenerationFailure):
                    # Check if the subnet still exists and if it does not,
                    # this is the reason why the ip address generation failed.
                    # In any other unlikely event re-raise
                    try:
                        subnet_id = port['port']['fixed_ips'][0]['subnet_id']
                        plugin.get_subnet(context, subnet_id)
                    except n_exc.SubnetNotFound:
                        pass
                    else:
                        ctxt.reraise = True
                net_id = port['port']['network_id']
                LOG.warn(_("Action %(action)s for network %(net_id)s "
                           "could not complete successfully: %(reason)s")
                         % {"action": action, "net_id": net_id, 'reason': e})

    def get_active_networks(self, context, **kwargs):
        """Retrieve and return a list of the active network ids."""
        # NOTE(arosen): This method is no longer used by the DHCP agent but is
        # left so that neutron-dhcp-agents will still continue to work if
        # neutron-server is upgraded and not the agent.
        host = kwargs.get('host')
        LOG.debug(_('get_active_networks requested from %s'), host)
        nets = self._get_active_networks(context, **kwargs)
        return [net['id'] for net in nets]

    def auto_schedule_networks(self, context, **kwargs):
        host = kwargs.get('host')
        LOG.debug(_('auto_schedule_networks from %s'), host)
        plugin = manager.NeutronManager.get_plugin()
        if utils.is_extension_supported(
            plugin, constants.DHCP_AGENT_SCHEDULER_EXT_ALIAS):
            if cfg.CONF.network_auto_schedule:
                plugin.auto_schedule_networks(context, host)
        return True
        
    def get_active_networks_info(self, context, **kwargs):
        """Returns all the networks/subnets/ports in system."""
        # remove auto_schedule_networks function cause RPC time out when 4000+ networks
        # rebuild networks in dhcp-agent, not in neutron-server
        host = kwargs.get('host')
        LOG.debug(_('get_active_networks_info from %s'), host)
        plugin = manager.NeutronManager.get_plugin()
        if utils.is_extension_supported(
            plugin, constants.DHCP_AGENT_SCHEDULER_EXT_ALIAS):
            networks = plugin.list_active_networks_on_active_dhcp_agent(
                context, host)
        else:
            filters = dict(admin_state_up=[True])
            networks = plugin.get_networks(context, filters = filters)
        filters = {'network_id': [network['id'] for network in networks]}
        ports = plugin.get_ports(context, filters=filters)
        filters['enable_dhcp'] = [True]
        subnets = plugin.get_subnets(context, filters=filters)

        ret = dict()
        ret['networks'] = networks
        ret['subnets'] = subnets
        ret['ports'] = ports
        return ret

    def get_distributed_active_networks_info(self, context, **kwargs):
        host = kwargs.get('host')
        LOG.debug('get_distributed_active_networks_info_host:%s', host)
        plugin = manager.NeutronManager.get_plugin()
        networks = plugin.list_active_networks_on_active_dhcp_agent(
            context, host)

        subnet_filters = {'network_id': [network['id'] for network in networks], 'enable_dhcp': [True]}
        subnets = plugin.get_subnets(context, filters = subnet_filters)
        LOG.debug('get_distributed_active_networks_info_subnets:%s', [s['id'] for s in subnets])

        port_filters = {'network_id': [network['id'] for network in networks],
                        'binding:host_id': [host],
                        'fixed_ips': {'subnet_id': [s['id'] for s in subnets]}
                       }
        ports = plugin.get_ports(context, filters = port_filters)

        reserved_filter = {'network_id': [network['id'] for network in networks],
                           'device_owner': [constants.DEVICE_OWNER_DHCP]
                           }
        reserved_ports = plugin.get_ports(context, filters = reserved_filter)

        ports += reserved_ports
        LOG.debug('get_distributed_active_networks_info_ports:%s,%s',
                  [p['id'] for p in ports], [p['fixed_ips'] for p in ports])

        ret = dict()
        ret['networks'] = networks
        ret['subnets'] = subnets
        ret['ports'] = ports
        return ret

    def get_distributed_network_info(self, context, **kwargs):
        host = kwargs.get('host')
        network_id = kwargs.get('network_id')
        LOG.debug('get_distributed_network_info_host:%s, network_id:%s', host, network_id)
        plugin = manager.NeutronManager.get_plugin()
        try:
            network = plugin.get_network(context, network_id)
        except n_exc.NetworkNotFound:
            LOG.warn(_("Network %s could not be found, it might have "
                       "been deleted concurrently."), network_id)
            return
        filters = {'network_id': [network_id], 'enable_dhcp': [True]}
        network['subnets'] = plugin.get_subnets(context, filters=filters)

        filters = {'network_id': [network_id],
                   'fixed_ips': {'subnet_id': [s['id'] for s in network['subnets']]},
                   'binding:host_id': [host]}
        ports = plugin.get_ports(context, filters=filters)
        if not ports:
            return None

        reserved_filter = {'network_id': [network_id],
                           'device_owner': [constants.DEVICE_OWNER_DHCP],
                           }
        reserved_ports = plugin.get_ports(context, filters = reserved_filter)
        ports += reserved_ports
        LOG.debug('ports_for_network_id:%s, %s', network_id, [p['id'] for p in ports])

        network['ports'] = ports
        return network


    def get_network_info(self, context, **kwargs):
        """Retrieve and return a extended information about a network."""
        network_id = kwargs.get('network_id')
        host = kwargs.get('host')
        LOG.debug(_('Network %(network_id)s requested from '
                    '%(host)s'), {'network_id': network_id,
                                  'host': host})
        plugin = manager.NeutronManager.get_plugin()
        try:
            network = plugin.get_network(context, network_id)
        except n_exc.NetworkNotFound:
            LOG.warn(_("Network %s could not be found, it might have "
                       "been deleted concurrently."), network_id)
            return
        filters = dict(network_id=[network_id])
        network['subnets'] = plugin.get_subnets(context, filters=filters)
        network['ports'] = plugin.get_ports(context, filters=filters)
        return network

    def get_dhcp_port(self, context, **kwargs):
        """Allocate a DHCP port for the host and return port information.

        This method will re-use an existing port if one already exists.  When a
        port is re-used, the fixed_ip allocation will be updated to the current
        network state. If an expected failure occurs, a None port is returned.

        """
        host = kwargs.get('host')
        network_id = kwargs.get('network_id')
        device_id = kwargs.get('device_id')
        # There could be more than one dhcp server per network, so create
        # a device id that combines host and network ids

        LOG.debug(_('Port %(device_id)s for %(network_id)s requested from '
                    '%(host)s'), {'device_id': device_id,
                                  'network_id': network_id,
                                  'host': host})
        plugin = manager.NeutronManager.get_plugin()
        retval = None

        filters = dict(network_id=[network_id])
        subnets = dict([(s['id'], s) for s in
                        plugin.get_subnets(context, filters=filters)])

        dhcp_enabled_subnet_ids = [s['id'] for s in
                                   subnets.values() if s['enable_dhcp']]

        try:
            filters = dict(network_id=[network_id], device_id=[device_id])
            ports = plugin.get_ports(context, filters=filters)
            if ports:
                # Ensure that fixed_ips cover all dhcp_enabled subnets.
                port = ports[0]
                for fixed_ip in port['fixed_ips']:
                    if fixed_ip['subnet_id'] in dhcp_enabled_subnet_ids:
                        dhcp_enabled_subnet_ids.remove(fixed_ip['subnet_id'])
                port['fixed_ips'].extend(
                    [dict(subnet_id=s) for s in dhcp_enabled_subnet_ids])

                retval = plugin.update_port(context, port['id'],
                                            dict(port=port))

        except n_exc.NotFound as e:
            LOG.warning(e)

        if retval is None:
            # No previous port exists, so create a new one.
            LOG.debug(_('DHCP port %(device_id)s on network %(network_id)s '
                        'does not exist on %(host)s'),
                      {'device_id': device_id,
                       'network_id': network_id,
                       'host': host})
            try:
                network = plugin.get_network(context, network_id)
            except n_exc.NetworkNotFound:
                LOG.warn(_("Network %s could not be found, it might have "
                           "been deleted concurrently."), network_id)
                return

            port_dict = dict(
                admin_state_up=True,
                device_id=device_id,
                network_id=network_id,
                tenant_id=network['tenant_id'],
                mac_address=attributes.ATTR_NOT_SPECIFIED,
                name='',
                device_owner=constants.DEVICE_OWNER_DHCP,
                fixed_ips=[dict(subnet_id=s) for s in dhcp_enabled_subnet_ids])

            retval = self._port_action(plugin, context, {'port': port_dict},
                                       'create_port')
            if not retval:
                return

        # Convert subnet_id to subnet dict
        for fixed_ip in retval['fixed_ips']:
            subnet_id = fixed_ip.pop('subnet_id')
            fixed_ip['subnet'] = subnets[subnet_id]

        return retval

    def release_dhcp_port(self, context, **kwargs):
        """Release the port currently being used by a DHCP agent."""
        host = kwargs.get('host')
        network_id = kwargs.get('network_id')
        device_id = kwargs.get('device_id')

        LOG.debug(_('DHCP port deletion for %(network_id)s request from '
                    '%(host)s'),
                  {'network_id': network_id, 'host': host})
        plugin = manager.NeutronManager.get_plugin()
        plugin.delete_ports_by_device_id(context, device_id, network_id)

    def release_port_fixed_ip(self, context, **kwargs):
        """Release the fixed_ip associated the subnet on a port."""
        host = kwargs.get('host')
        network_id = kwargs.get('network_id')
        device_id = kwargs.get('device_id')
        subnet_id = kwargs.get('subnet_id')

        LOG.debug(_('DHCP port remove fixed_ip for %(subnet_id)s request '
                    'from %(host)s'),
                  {'subnet_id': subnet_id, 'host': host})
        plugin = manager.NeutronManager.get_plugin()
        filters = dict(network_id=[network_id], device_id=[device_id])
        ports = plugin.get_ports(context, filters=filters)

        if ports:
            port = ports[0]

            fixed_ips = port.get('fixed_ips', [])
            for i in range(len(fixed_ips)):
                if fixed_ips[i]['subnet_id'] == subnet_id:
                    del fixed_ips[i]
                    break
            plugin.update_port(context, port['id'], dict(port=port))

    def update_lease_expiration(self, context, **kwargs):
        """Release the fixed_ip associated the subnet on a port."""
        # NOTE(arosen): This method is no longer used by the DHCP agent but is
        # left so that neutron-dhcp-agents will still continue to work if
        # neutron-server is upgraded and not the agent.
        host = kwargs.get('host')

        LOG.warning(_('Updating lease expiration is now deprecated. Issued  '
                      'from host %s.'), host)

    def create_dhcp_port(self, context, **kwargs):
        """Create and return dhcp port information.

        If an expected failure occurs, a None port is returned.

        """
        host = kwargs.get('host')
        port = kwargs.get('port')
        LOG.debug(_('Create dhcp port %(port)s '
                    'from %(host)s.'),
                  {'port': port,
                   'host': host})

        port['port']['device_owner'] = constants.DEVICE_OWNER_DHCP
        port['port'][portbindings.HOST_ID] = host
        if 'mac_address' not in port['port']:
            port['port']['mac_address'] = attributes.ATTR_NOT_SPECIFIED
        plugin = manager.NeutronManager.get_plugin()
        return self._port_action(plugin, context, port, 'create_port')

    def update_dhcp_port(self, context, **kwargs):
        """Update the dhcp port."""
        host = kwargs.get('host')
        port = kwargs.get('port')
        port['id'] = kwargs.get('port_id')
        LOG.debug(_('Update dhcp port %(port)s '
                    'from %(host)s.'),
                  {'port': port,
                   'host': host})
        plugin = manager.NeutronManager.get_plugin()
        return self._port_action(plugin, context, port, 'update_port')

    def convert_from_centralized_to_distributed(self, context, **kargs):
        """thread safe converting from centralized dhcp to distributed"""
        host = kargs.get('host_id')
        plugin = manager.NeutronManager.get_plugin()
        centralized_filter = {'binding:host_id': [host], 'device_owner': [constants.DEVICE_OWNER_DHCP]}
        centralized_ports = plugin.get_ports(context, centralized_filter)
        if not centralized_ports:
            return True
        LOG.info('convert_from_centralized_to_distributed, host:%s begin', host)
        finished_nets = set()
        for port in centralized_ports:
            net_id = port['network_id']
            if net_id in finished_nets:
                continue
            dhcp_port_filter = {'network_id': [net_id], 'device_owner': [constants.DEVICE_OWNER_DHCP]}
            dhcp_ports = plugin.get_ports(context, dhcp_port_filter, sorts = [('id', constants.SORT_DIRECTION_ASC)])
            if not dhcp_ports:
                continue
            min_port = dhcp_ports[0]
            if not self._is_distributed_dhcp_port(min_port):
                min_port['binding:host_id'] = ''
                min_port['device_id'] = utils.get_dhcp_agent_device_id(min_port['network_id'], '')
                if min_port['name'] is None or not min_port['name'].startswith('port@'):
                    min_port['name'] = 'distributed_dhcp_port'
                plugin.update_port(context, min_port['id'], {'port': min_port})
            rest_ports = dhcp_ports[1:]
            for p in rest_ports:
                try:
                    if p.get('binding:host_id') == host or not p.get('binding:host_id'):
                        plugin.delete_port(context, p['id'])
                except n_exc.PortNotFound as e:
                    LOG.warning('convert_from_centralized_to_distributed, port :%s already deleted', p['id'])
            finished_nets.add(net_id)
        LOG.info('convert_from_centralized_to_distributed, host:%s finish!', host)
        return True


    def _is_distributed_dhcp_port(self, port):
        device_id = utils.get_dhcp_agent_device_id(port['network_id'], '')
        return device_id == port['device_id']


    def distributed_schedule_networks(self, context, **kargs):
        """Distributed schedule network to hosts who hosting vms belong to the network"""
        host = kargs.get('host')
        plugin = manager.NeutronManager.get_plugin()
        bindings_to_add = []
        LOG.debug('distributed_schedule_networks, host:%s', host)
        with context.session.begin(subtransactions=True):
            agent = plugin.get_enabled_agent_on_host(context, constants.AGENT_TYPE_DHCP, host)
            if not agent:
                return False
            nets = plugin.list_networks_on_dhcp_agent(context, agent.id)
            all_net_ids = set(n['id'] for n in nets['networks'])
            LOG.debug('distributed_schedule_networks, all_net_ids:%s', all_net_ids)

            fields = ['network_id', 'enable_dhcp']
            subnets = plugin.get_subnets(context, fields=fields)
            dhcp_net_ids = set(s['network_id'] for s in subnets if s['enable_dhcp'])
            LOG.debug('distributed_schedule_networks, dhcp_net_ids:%s', dhcp_net_ids)

            """get net-ids by vms' host-id in current host"""
            filters = {'binding:host_id': [agent.host]}
            fields = ['network_id']
            ports = plugin.get_ports(context, filters = filters, fields = fields)
            host_net_ids = set(p['network_id'] for p in ports)
            need_binding_net_ids = dhcp_net_ids & host_net_ids

            for net_id in all_net_ids - need_binding_net_ids:
                try:
                    plugin.remove_network_from_dhcp_agent(context, agent.id, net_id)
                except dhcpagentscheduler.NetworkNotHostedByDhcpAgent:
                    LOG.warning(_('NetworkNotHostedByDhcpAgent,netid:%s, host:%s'), net_id, agent.host)

            query = context.session.query(agents_db.Agent)
            query = query.filter(agents_db.Agent.agent_type ==
                                 constants.AGENT_TYPE_DHCP,
                                 agents_db.Agent.host == agent.host,
                                 agents_db.Agent.admin_state_up == sql.true())
            dhcp_agents = query.all()
            if dhcp_agents and len(dhcp_agents) == 1:
                dhcp_agent = dhcp_agents[0]
                if not agents_db.AgentDbMixin.is_agent_down(dhcp_agent.heartbeat_timestamp):
                    for net_id in need_binding_net_ids:
                        bindings_to_add.append((dhcp_agent, net_id))
                else:
                    LOG.error(_('DHCP agent on host %s is not active'), dhcp_agent.host)
            else:
                LOG.error(_('No DHCP agent for host %s', agent.host))

        for agent, net_id in bindings_to_add:
            self._schedule_bind_network(context, [agent], net_id)
        return True

    def _schedule_bind_network(self, context, agents, network_id):
        for agent in agents:
            context.session.begin(subtransactions=True)
            try:
                agent_id = agent.id
                binding = agentschedulers_db.NetworkDhcpAgentBinding()
                binding.dhcp_agent_id = agent_id
                binding.network_id = network_id
                context.session.add(binding)

                # try to actually write the changes and catch integrity
                # DBDuplicateEntry
                context.session.commit()
            except db_exc.DBDuplicateEntry:
                # it's totally ok, someone just did our job!
                context.session.rollback()
                LOG.info(_('Agent %s already present'), agent_id)
            LOG.debug(_('Network %(network_id)s is scheduled to be '
                        'hosted by DHCP agent %(agent_id)s'),
                      {'network_id': network_id,
                       'agent_id': agent_id})





