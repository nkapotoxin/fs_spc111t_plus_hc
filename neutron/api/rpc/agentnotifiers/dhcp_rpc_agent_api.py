# Copyright (c) 2013 OpenStack Foundation.
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
from neutron.common import constants
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.common import utils
from neutron import manager
from neutron.openstack.common import log as logging
from neutron.common import utils as commonutils
from neutron.api.v2 import attributes

LOG = logging.getLogger(__name__)


class DhcpAgentNotifyAPI(n_rpc.RpcProxy):
    """API for plugin to notify DHCP agent."""
    BASE_RPC_API_VERSION = '1.0'
    # It seems dhcp agent does not support bulk operation
    VALID_RESOURCES = ['network', 'subnet', 'port']
    VALID_METHOD_NAMES = ['network.create.end',
                          'network.update.end',
                          'network.delete.end',
                          'subnet.create.end',
                          'subnet.update.end',
                          'subnet.delete.end',
                          'port.create.end',
                          'port.update.end',
                          'port.delete.end']

    def __init__(self, topic=topics.DHCP_AGENT, plugin=None):
        super(DhcpAgentNotifyAPI, self).__init__(
            topic=topic, default_version=self.BASE_RPC_API_VERSION)
        self._plugin = plugin
        self.conf = cfg.CONF

    @property
    def plugin(self):
        if self._plugin is None:
            self._plugin = manager.NeutronManager.get_plugin()
        return self._plugin

    def _schedule_network(self, context, network, existing_agents):
        """Schedule the network to new agents

        :return: all agents associated with the network
        """
        new_agents = self.plugin.schedule_network(context, network) or []
        if new_agents:
            for agent in new_agents:
                self._cast_message(
                    context, 'network_create_end',
                    {'network': {'id': network['id']}}, agent['host'])
        elif not existing_agents:
            LOG.warn(_('Unable to schedule network %s: no agents available; '
                       'will retry on subsequent port creation events.'),
                     network['id'])
        return new_agents + existing_agents

    def _get_enabled_agents(self, context, network, agents, method, payload):
        """Get the list of agents whose admin_state is UP."""
        network_id = network['id']
        enabled_agents = [x for x in agents if x.admin_state_up]
        active_agents = [x for x in agents if x.is_active]
        len_enabled_agents = len(enabled_agents)
        len_active_agents = len(active_agents)
        if len_active_agents < len_enabled_agents:
            LOG.warn(_("Only %(active)d of %(total)d DHCP agents associated "
                       "with network '%(net_id)s' are marked as active, so "
                       " notifications may be sent to inactive agents.")
                     % {'active': len_active_agents,
                        'total': len_enabled_agents,
                        'net_id': network_id})
        if not enabled_agents:
            num_ports = self.plugin.get_ports_count(
                context, {'network_id': [network_id]})
            notification_required = (
                num_ports > 0 and len(network['subnets']) >= 1)
            if notification_required:
                LOG.error(_("Will not send event %(method)s for network "
                            "%(net_id)s: no agent available. Payload: "
                            "%(payload)s")
                          % {'method': method,
                             'net_id': network_id,
                             'payload': payload})
        return enabled_agents

    def _is_reserved_dhcp_port(self, port):
        return port.get('device_id') == constants.DEVICE_ID_RESERVED_DHCP_PORT

    def _is_dhcp_port(self, port):
        return port.get('device_owner') == constants.DEVICE_OWNER_DHCP

    def _notify_agents(self, context, method, payload, network_id):
        """Notify all the agents that are hosting the network."""
        # fanout is required as we do not know who is "listening"
        no_agents = not utils.is_extension_supported(
            self.plugin, constants.DHCP_AGENT_SCHEDULER_EXT_ALIAS)
        fanout_required = method == 'network_delete_end' or no_agents

        # we do nothing on network creation because we want to give the
        # admin the chance to associate an agent to the network manually
        cast_required = method != 'network_create_end'

        if fanout_required:
            self._fanout_message(context, method, payload)
        elif cast_required:
            admin_ctx = (context if context.is_admin else context.elevated())
            network = self.plugin.get_network(admin_ctx, network_id)
            agents = self.plugin.get_dhcp_agents_hosting_networks(
                context, [network_id])
            # schedule the network first, if needed
            schedule_required = (
                method == 'port_create_end' and
                not self._is_reserved_dhcp_port(payload['port']))
            if schedule_required:
                agents = self._schedule_network(admin_ctx, network, agents)
            enabled_agents = self._get_enabled_agents(
                context, network, agents, method, payload)
            for agent in enabled_agents:
                self._cast_message(
                    context, method, payload, agent.host, agent.topic)

    def _notify_port_create_or_update(self, context, port, method, payload, network_id):
        host_id = port.get('binding:host_id', '')
        if self.plugin.distributed_add_network_to_host(context, network_id, host_id):
            self._cast_message(context, method, payload, host_id, topics.DHCP_AGENT)

    def _notify_port_delete(self, context, port, method, payload, network_id):
        host_id = port.get('binding:host_id', '')
        if host_id:
            self._cast_message(context, 'port_delete_end', {'port_id': port['id']}, host_id)
            self._remove_network_from_host(context, network_id, host_id)

    def _distributed_notify_agents(self, context, method, payload, network_id):
        LOG.debug('_distributed_notify_agents_method:%s, payload:%s, network_id:%s',
                  method, payload, network_id)
        if method == 'port_create_end':
            port = payload['port']
            self._notify_port_create_or_update(context, port, method, payload, network_id)
        elif method == 'port_update_end':
            port = payload['port']
            self._notify_port_create_or_update(context, port, method, payload, network_id)
            """for migration scene"""
            if payload.has_key('old_port'):
                old_port = payload['old_port']
                self._notify_port_delete(context, old_port, 'port_delete_end', {'port_id': old_port['id']}, network_id)
        elif method == 'port_delete_end':
            port = payload['port']
            self._notify_port_delete(context, port, 'port_delete_end', payload, network_id)
        elif method == 'subnet_update_end':
            self._fanout_message(context, method, payload)
        elif method == 'subnet_delete_end':
            self._fanout_message(context, method, {'subnet_id': payload['subnet']['id']})
        elif method == 'network_delete_end':
            network = payload['network']
            host = network.get('host', '')
            if host:
                self._cast_message(context, 'network_delete_end', {'network_id': payload['network']['id']}, host)
            else:
                self._fanout_message(context, method, {'network_id': payload['network']['id']})

    def _remove_network_from_host(self, context, network_id, host_id):
        port_filters = {
            'network_id': [network_id],
            'binding:host_id': [host_id]
        }
        if self.plugin.get_ports_count(context, port_filters) == 0:
            self.plugin.distributed_remove_network_from_host(context, network_id, host_id)

    def _cast_message(self, context, method, payload, host,
                      topic=topics.DHCP_AGENT):
        """Cast the payload to the dhcp agent running on the host."""
        self.cast(
            context, self.make_msg(method,
                                   payload=payload),
            topic='%s.%s' % (topic, host))

    def _fanout_message(self, context, method, payload):
        """Fanout the payload to all dhcp agents."""
        self.fanout_cast(
            context, self.make_msg(method,
                                   payload=payload),
            topic=topics.DHCP_AGENT)

    def network_removed_from_agent(self, context, network_id, host):
        self._cast_message(context, 'network_delete_end',
                           {'network_id': network_id}, host)

    def network_added_to_agent(self, context, network_id, host):
        self._cast_message(context, 'network_create_end',
                           {'network': {'id': network_id}}, host)

    def agent_updated(self, context, admin_state_up, host):
        self._cast_message(context, 'agent_updated',
                           {'admin_state_up': admin_state_up}, host)

    def _distributed_notify(self, context, data, method_name):
        if data.has_key('network'):
            network_id = data['network']['id']
        elif data.has_key('port'):
            network_id = data['port']['network_id']
        elif data.has_key('subnet'):
            network_id = data['subnet']['network_id']
        else:
            return
        method_name = method_name.replace(".", "_")
        self._distributed_notify_agents(context, method_name, data, network_id)

    def notify(self, context, data, method_name):
        # data is {'key' : 'value'} with only one key
        if method_name not in self.VALID_METHOD_NAMES:
            return

        if self.conf.dhcp_distributed:
            self._distributed_notify(context, data, method_name)
            return

        obj_type = data.keys()[0]
        if obj_type not in self.VALID_RESOURCES:
            return
        obj_value = data[obj_type]
        network_id = None
        if obj_type == 'network' and 'id' in obj_value:
            network_id = obj_value['id']
        elif obj_type in ['port', 'subnet'] and 'network_id' in obj_value:
            network_id = obj_value['network_id']
        if not network_id:
            return
        method_name = method_name.replace(".", "_")

        if method_name.endswith("_delete_end"):
            if 'id' in obj_value:
                self._notify_agents(context, method_name,
                                    {obj_type + '_id': obj_value['id']},
                                    network_id)
        else:
            self._notify_agents(context, method_name, data, network_id)
