# Copyright (c) 2013 Hewlett-Packard Development Company, L.P.
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

from nova.compute.resources import base
from nova.openstack.common import jsonutils
from nova.openstack.common import log as logging
from nova import objects
from nova import context

LOG = logging.getLogger(__name__)

PHYSICAL_NETWORK = "physical_network"


class PhysicalNetwork(base.Resource):
    """physical network compute resource plugin.

    This is effectively a simple counter based on the physical network
    requirement of each instance.
    """
    def __init__(self):
        # initialize to a 'zero' resource.
        # reset will be called to set real resource values
        self._total = {}
        self._used = {}
        self.details = {}
        self.instance_cache = {}

    def reset(self, resources, driver):
        # total physical network is reset to the value taken from resources.
        network_info = resources.pop("network", [])
        for phy_net in network_info:
            phy_name = phy_net.pop(PHYSICAL_NETWORK)
            self._total[phy_name] = int(phy_net.pop('count', 0))
            self._used[phy_name] = 0
            self.details[phy_name] = phy_net

    def _get_requested(self, usage):
        requested_count = {}

        if not usage:
            return requested_count

        for req in usage:
            requested_count[req] = int(requested_count.get(
                req, 0)) + int(usage[req])

        return requested_count

    def _get_limit(self, limits):
        limit_count = {}

        # no limit
        if not limits or not limits.get('network'):
            return limit_count

        network_limits = limits.get('network', {})
        for phy_net in network_limits:
            limit_count[phy_net] = int(limit_count.get(
                phy_net, 0)) + int(network_limits[phy_net])

        return limit_count

    def test(self, usage, limits):

        LOG.debug("the usage is %s, limits is %s", usage, limits)
        network_info = self._get_instance_network(usage)
        requested = self._get_requested(network_info)
        limit = self._get_limit(limits)

        LOG.debug('Total Physical Networks: %(total)s, used: %(used)s, '
                  'requested: %(requested)s, limit: %(limit)s' %
                  {'total': self._total, 'used': self._used,
                   'requested':requested, 'limit': limit })

        if len(limit) < 1:
            # treat resource as unlimited:
            LOG.debug('instance physical networks limit not specified, '
                      'defaulting to unlimited')
            return

        if len(requested) < 1:
            LOG.debug('instance physical networks is not requested, return')
            return

        for req in network_info:
            free = limit[req] - self._used[req]

            # Oversubscribed resource policy info:
            LOG.debug('Physical Networks limit: %(limit)s, free: %(free)s' %
                      {'limit': limit[req],
                       'free': free})

            if requested[req] > free:
                return ('Free Physical Networks %(free)s < '
                        'requested %(requested)s' %
                        {'free': free,
                         'requested': requested[req]})

    def add_instance(self, usage):
        network_info = self._get_instance_network(usage)
        for phy_net in network_info:
            requested = int(network_info.get(phy_net, 0))
            self._used[phy_net] += requested

    def remove_instance(self, usage):
        network_info = self._get_instance_network(usage)
        for phy_net in network_info:
            requested = int(network_info.get(phy_net, 0))
            self._used[phy_net] -= requested

    def write(self, resources):
        network_info = {'network':{}}
        for phy_net, count in self._total.iteritems():
            network_info['network'][phy_net] = {
                                    'total': count,
                                    'used':self._used[phy_net]
                                }

            network_info['network'][phy_net].update(
                self.details.get(phy_net,{}))

        network_info['network'] = jsonutils.dumps(network_info['network'])
        # write to stats in compute node
        resources['stats'].update(network_info)
        if "network" in resources:
            del resources['network']

        LOG.debug("write to resources is %s", resources)

    def report_free(self):
        free_physical_network = {}
        for phy_net, count in self._total.iteritems():
            free_physical_network[
                phy_net] = self._total[phy_net] - self._used[phy_net]

        LOG.debug('Free Physical Networks: %s' % str(free_physical_network))

    # TODO: if the physcial network stored in instance object, we will get the
    # information from nova object.
    def _get_instance_network(self, usage):
        if not isinstance(usage, dict):
            instance_uuid = usage.uuid
        else:
            # this precess resize sense
            instance_uuid = usage['instance_uuid']

        if instance_uuid not in self.instance_cache:
            admin_context = context.get_admin_context()
            # get from database
            inst_extra = objects.HuaweiInstanceExtra.get_by_instance_uuid(
                admin_context, instance_uuid)

            stats = jsonutils.loads(inst_extra.stats or '{}')
            self.instance_cache[instance_uuid] = stats.get('network',{})

        return self.instance_cache[instance_uuid]