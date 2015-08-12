# Copyright (c) 2011 OpenStack Foundation
# Copyright (c) 2012 Justin Santa Barbara
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

from oslo.config import cfg
from nova.i18n import _LW
from nova.openstack.common import log as logging
from nova.scheduler import filters

LOG = logging.getLogger(__name__)

CONF = cfg.CONF


class PhysicalNetworkFilter(filters.BaseHostFilter):

    def host_passes(self, host_state, filter_properties):
        """Return True if host has sufficient Physical network resource."""
        if filter_properties.get("stats") == None:
            LOG.debug(_LW("filter_properties get stats is None, return ok"))
            return True

        instance_physical_network = filter_properties.get(
            "stats").get("network")

        if not instance_physical_network:
            LOG.debug(_LW("instance physical network not set, return ok"))
            return True

        host_networks = host_state.physical_networks
        if not host_networks:
            # Fail safe
            LOG.warning(_LW("host physical network not set, return false"))
            return False

        host_state.limits['network'] = {}
        # get all physical network
        for phy_net in instance_physical_network:
            request_count = int(instance_physical_network[phy_net])
            if phy_net not in host_networks.keys():
                LOG.debug(_LW("physical network %s is not in host %s "),
                          phy_net, host_networks)
                return False

            candidate_net = host_networks[phy_net]
            if request_count > int(candidate_net['total']) - int(
                    candidate_net['used']):
                LOG.debug(_LW("physical network %s , request is %s, "
                              "but stats is %s"), phy_net, request_count,
                          host_networks)
                return False

            # save the total for claim test
            host_state.limits['network'][phy_net] = int(candidate_net['total'])
        return True
