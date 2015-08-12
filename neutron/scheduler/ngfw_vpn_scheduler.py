# Copyright (c) 2013 OpenStack Foundation.
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

import abc
import itertools
import random

from oslo.config import cfg
from oslo.db import exception as db_exc
import six
from sqlalchemy import sql

from neutron.common import constants
from neutron.common import utils
from neutron.db import l3_agentschedulers_db
from neutron.db import l3_db
from neutron.db import l3_hamode_db
from neutron.openstack.common.gettextutils import _LE
from neutron.openstack.common import log as logging
from neutron.scheduler import l3_agent_scheduler
from neutron.services.firewall import ngfw_plugin


LOG = logging.getLogger(__name__)

vpn_agent_opts = [
    cfg.ListOpt('vpn_network_name',
                default=[],
                help=_("vpn network name."
                       "Comma-separated list of <network_min>:<network_max> tuples")),
]

cfg.CONF.register_opts(vpn_agent_opts)                       

class ngfwVPNScheduler(l3_agent_scheduler.L3Scheduler):
    """allocate an ngfw VPN agent for a router."""

    def _valid_vpn_ip_pool_scheduler(self, sync_router, candidates):
        if not candidates:
            LOG.error(_("_valid_vpn_ip_pool_scheduler schedule111 "))
            return []
        router_id = sync_router['id']
        external_gateway_info = sync_router['external_gateway_info']
        external_fixed_ips = (external_gateway_info or {}).get('external_fixed_ips')
        if external_fixed_ips and len(external_fixed_ips) > 0:
            ip_address = (external_fixed_ips[0] or {}).get('ip_address')
        else:
            ip_address = None
        pluginutils = ngfw_plugin.NGFWPluginUtils()
        ret = pluginutils.get_proper_agent_by_ip(ngfw_plugin.PLUGIN_UTILS_TYPE_VPN, ip_address)
        LOG.error(_("_valid_vpn_ip_pool_scheduler schedule %s %s %s" % (ret, ip_address, candidates)))
        if (None, None) == ret:
            LOG.error(_("_valid_vpn_ip_pool_scheduler no agent hold %s" % router_id))            
            return []
        else:
            for candidate in candidates:
                if ret[0] in candidate.id:
                    LOG.debug(_("_valid_vpn_ip_pool_scheduler get agent uuid %s hold %s" %
                              (candidate.id, router_id)))
                    return [candidate]
            LOG.error(_("_valid_vpn_ip_pool_scheduler no agent match %s !!!" % router_id))
            return []

    def wether_vpn_scheduler(self, plugin, context, sync_router):
        external_gateway_info = sync_router.get('external_gateway_info')
        if external_gateway_info:
            external_network_id = (external_gateway_info or {}).get('network_id')
            if external_network_id:
                network = plugin._core_plugin.get_network(context, external_network_id)
                if network['name'] in cfg.CONF.vpn_network_name:
                    LOG.debug(_("wether_vpn_scheduler return True"))
                    return True
                LOG.debug(_("wether_vpn_scheduler return False"))
        return False
    
    def get_candidates(self, plugin, context, sync_router):
        """Return L3 agents where a router could be scheduled."""
        with context.session.begin(subtransactions=True):
            # allow one router is hosted by just
            # one enabled l3 agent hosting since active is just a
            # timing problem. Non-active l3 agent can return to
            # active any time
            l3_agents = plugin.get_l3_agents_hosting_routers(
                context, [sync_router['id']], admin_state_up=True)
            if l3_agents and not sync_router.get('distributed', False):
                LOG.debug(_('Router %(router_id)s has already been hosted'
                            ' by L3 agent %(agent_id)s'),
                          {'router_id': sync_router['id'],
                           'agent_id': l3_agents[0]['id']})
                return

            active_l3_agents = plugin.get_l3_agents(context, active=True)
            if not active_l3_agents:
                LOG.warn(_('No active L3 agents'))
                return

            if self.wether_vpn_scheduler(plugin, context, sync_router):
                LOG.debug(_("before vpn scheduler %s" % active_l3_agents))
                new_l3agents = self._valid_vpn_ip_pool_scheduler(sync_router,
                                                               active_l3_agents)
                LOG.debug(_("after vpn scheduler %s" % new_l3agents))
            else:
                new_l3agents = plugin.get_l3_agent_candidates(context,
                                                              sync_router,
                                                              active_l3_agents)                

            old_l3agentset = set(l3_agents)
            if sync_router.get('distributed', False):
                new_l3agentset = set(new_l3agents)
                candidates = list(new_l3agentset - old_l3agentset)
            else:
                candidates = new_l3agents
                if not candidates:
                    LOG.warn(_('No L3 agents can host the router %s'),
                             sync_router['id'])

            return candidates
        		
    def schedule(self, plugin, context, router_id,
                 candidates=None):
        return self._schedule_router(
            plugin, context, router_id, candidates=candidates)

    def _choose_router_agent(self, plugin, context, candidates):
        return random.choice(candidates)

    def _choose_router_agents_for_ha(self, plugin, context, candidates):
        num_agents = self.get_num_of_agents_for_ha(len(candidates))
        return random.sample(candidates, num_agents)

