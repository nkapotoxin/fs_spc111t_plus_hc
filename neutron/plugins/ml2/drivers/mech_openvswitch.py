# Copyright (c) 2013 OpenStack Foundation
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
import copy

from neutron.agent import securitygroups_rpc
from neutron.common import constants
from neutron.common import topics
from neutron.extensions import portbindings
from neutron.openstack.common import log
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers import mech_agent
from neutron.plugins.ml2 import rpc

LOG = log.getLogger(__name__)


class OpenvswitchMechanismDriver(mech_agent.SimpleAgentMechanismDriverBase):
    """Attach to networks using openvswitch L2 agent.

    The OpenvswitchMechanismDriver integrates the ml2 plugin with the
    openvswitch L2 agent. Port binding with this driver requires the
    openvswitch agent to be running on the port's host, and that agent
    to have connectivity to at least one segment of the port's
    network.
    """


    DEV_NAME_LEN = 14
    DEV_NAME_PREFIX = 'tap'

    def __init__(self):
        sg_enabled = securitygroups_rpc.is_firewall_enabled()
        vif_details = {portbindings.CAP_PORT_FILTER: sg_enabled,
                       portbindings.OVS_HYBRID_PLUG: sg_enabled}
        super(OpenvswitchMechanismDriver, self).__init__(
            constants.AGENT_TYPE_OVS,
            portbindings.VIF_TYPE_OVS,
            vif_details)
        self.notifier = rpc.AgentNotifierApi(topics.AGENT)

    def check_segment_for_agent(self, segment, agent):
        mappings = agent['configurations'].get('bridge_mappings', {})
        tunnel_types = agent['configurations'].get('tunnel_types', [])
        LOG.debug(_("Checking segment: %(segment)s "
                    "for mappings: %(mappings)s "
                    "with tunnel_types: %(tunnel_types)s"),
                  {'segment': segment, 'mappings': mappings,
                   'tunnel_types': tunnel_types})
        network_type = segment[api.NETWORK_TYPE]
        if network_type == 'local':
            return True
        elif network_type in tunnel_types:
            return True
        elif network_type in ['flat', 'vlan']:
            return segment[api.PHYSICAL_NETWORK] in mappings
        else:
            return False

    def try_to_bind_segment_for_agent(self, context, segment, agent):
        if self.check_segment_for_agent(segment, agent):
            if context.current.get('trunkport:type') == 'trunk':
                vif_details = copy.deepcopy(self.vif_details)
                vif_details[portbindings.OVS_TRUNK_PLUG] = True

                context.set_binding(segment[api.ID],
                                    self.vif_type,
                                    vif_details)
            else:
                context.set_binding(segment[api.ID],
                                    self.vif_type,
                                    self.vif_details)
            return True
        else:
            return False
