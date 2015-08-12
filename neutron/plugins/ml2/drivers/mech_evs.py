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

from neutron.common import constants
from neutron.extensions import portbindings
from neutron.openstack.common import log
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers import mech_agent
from neutron.plugins.ml2 import rpc
from neutron.common import topics

LOG = log.getLogger(__name__)

EVS_BRIDGE = 'evs_bridge'
PHYSICAL_NETWORK = 'physical_network'

class evsMechanismDriver(mech_agent.SimpleAgentMechanismDriverBase):
    """Attach to networks using evs L2 agent.

    The evsMechanismDriver integrates the ml2 plugin with the
    evs L2 agent. Port binding with this driver requires the
    evs agent to be running on the port's host, and that agent
    to have connectivity to at least one segment of the port's
    network.
    """
    DEV_NAME_LEN = 14
    DEV_NAME_PREFIX = 'tap'

    def __init__(self):
        super(evsMechanismDriver, self).__init__(
            agent_type = constants.AGENT_TYPE_EVS,
            vif_type = portbindings.VIF_TYPE_VHOSTUSER,
            vif_details = {EVS_BRIDGE : False},
            supported_vnic_types = [portbindings.VNIC_VHOSTUSER]
            )
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
            port = context.current
            LOG.debug(_("Log mech_evs.try_to_bind_segment_for_agent port=%s"), port)
            context.set_binding(segment[api.ID],
                                self.vif_type,
                                {EVS_BRIDGE : agent['configurations'].get('bridge_mappings', {}).get(segment[api.PHYSICAL_NETWORK]),
                                 PHYSICAL_NETWORK :segment[api.PHYSICAL_NETWORK] })



            return True
        else:
            return False


