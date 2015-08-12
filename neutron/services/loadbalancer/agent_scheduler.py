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

import random

import sqlalchemy as sa
from sqlalchemy import orm
from sqlalchemy.orm import joinedload

from neutron.common import constants
from neutron.db import agents_db
from neutron.db import agentschedulers_db
from neutron.db import model_base
from neutron.extensions import lbaas_agentscheduler
from neutron.openstack.common import log as logging
from sqlalchemy.orm import exc

LOG = logging.getLogger(__name__)


class PoolLoadbalancerAgentBinding(model_base.BASEV2):
    """Represents binding between neutron loadbalancer pools and agents."""

    pool_id = sa.Column(sa.String(36),
                        sa.ForeignKey("pools.id", ondelete='CASCADE'),
                        primary_key=True)
    agent = orm.relation(agents_db.Agent)
    agent_id = sa.Column(sa.String(36), sa.ForeignKey("agents.id",
                                                      ondelete='CASCADE'),
                         nullable=False)


class LbaasAgentSchedulerDbMixin(agentschedulers_db.AgentSchedulerDbMixin,
                                 lbaas_agentscheduler
                                 .LbaasAgentSchedulerPluginBase):

    def get_lbaas_agent_hosting_pool(self, context, pool_id, active=None):
        query = context.session.query(PoolLoadbalancerAgentBinding)
        query = query.options(joinedload('agent'))
        binding = query.get(pool_id)

        if (binding and self.is_eligible_agent(
                active, binding.agent)):
            return {'agent': self._make_agent_dict(binding.agent)}

    def get_lbaas_agents(self, context, active=None, filters=None):
        query = context.session.query(agents_db.Agent)
        query = query.filter_by(agent_type=constants.AGENT_TYPE_LOADBALANCER)
        if active is not None:
            query = query.filter_by(admin_state_up=active)
        if filters:
            for key, value in filters.iteritems():
                column = getattr(agents_db.Agent, key, None)
                if column:
                    query = query.filter(column.in_(value))

        return [agent
                for agent in query
                if self.is_eligible_agent(active, agent)]

    def add_pool_to_lbaas_agent(self, context, agent_id, pool_id):
        """Add a lbaas agent to host a pool."""
        
        with context.session.begin(subtransactions=True):
            agent_db = self._get_agent(context, agent_id)
            if (agent_db['agent_type'] != constants.AGENT_TYPE_LOADBALANCER or
                not agent_db['admin_state_up'] or 
                not self.get_lbaas_agents(context, active=True)):
                raise lbaas_agentscheduler.InvalidLbaasAgent(id=agent_id)
            query = context.session.query(PoolLoadbalancerAgentBinding)
            try:
                binding = query.filter_by(pool_id=pool_id).one()
                
                raise lbaas_agentscheduler.PoolHostedByLbaasAgent(
                    pool_id = pool_id, 
                    agent_id = binding.agent_id)
            except exc.NoResultFound:
                pass
            binding = PoolLoadbalancerAgentBinding()
            binding.agent = agent_db
            binding.pool_id = pool_id
            binding.default = True
            context.session.add(binding)
        return agent_db

    def remove_pool_from_lbaas_agent(self, context, agent_id, pool_id):
        """Remove the router from lbaas agent.

        After removal, the pool will be non-hosted until there is update
        which leads to re-schedule or be added to another agent manually.
        """
        with context.session.begin(subtransactions=True):
            query = context.session.query(PoolLoadbalancerAgentBinding)
            query = query.filter(
                PoolLoadbalancerAgentBinding.pool_id == pool_id,
                PoolLoadbalancerAgentBinding.agent_id == agent_id)
            try:
                binding = query.one()
            except exc.NoResultFound:
                raise lbaas_agentscheduler.PoolNotHostedByLbaasAgent(
                    pool_id=pool_id, agent_id=agent_id)
            context.session.delete(binding)
       
    def list_pools_on_lbaas_agent(self, context, id):
        query = context.session.query(PoolLoadbalancerAgentBinding.pool_id)
        query = query.filter_by(agent_id=id)
        pool_ids = [item[0] for item in query]
        if pool_ids:
            return {'pools': self.get_pools(context, filters={'id': pool_ids})}
        else:
            return {'pools': []}

    def get_lbaas_agent_candidates(self, device_driver, active_agents):
        candidates = []
        for agent in active_agents:
            agent_conf = self.get_configuration_dict(agent)
            if device_driver in agent_conf['device_drivers']:
                candidates.append(agent)
        return candidates

    def get_lb_agent_with_min_lbs(self, context, candidates):
        
        lb_agent_with_min_lbs = ''
        lb_agent_with_lbs = 0xffff
        for i in candidates:
            query = context.session.query(func.count(
                            PoolLoadbalancerAgentBinding.pool_id)).filter(PoolLoadbalancerAgentBinding.agent_id == i)
            
            if lb_agent_with_min_lbs == ''  or query.scalar() < lb_agent_with_lbs:
                lb_agent_with_min_lbs = i
                lb_agent_with_lbs = query.scalar()
                
        query = context.session.query(agents_db.Agent).filter(
                            agents_db.Agent.id == lb_agent_with_min_lbs).first()
        return query 

class ChanceScheduler(object):
    """Allocate a loadbalancer agent for a vip in a random way."""

    def schedule(self, plugin, context, pool, device_driver):
        """Schedule the pool to an active loadbalancer agent if there
        is no enabled agent hosting it.
        """
        with context.session.begin(subtransactions=True):
            lbaas_agent = plugin.get_lbaas_agent_hosting_pool(
                context, pool['id'])
            if lbaas_agent:
                LOG.debug(_('Pool %(pool_id)s has already been hosted'
                            ' by lbaas agent %(agent_id)s'),
                          {'pool_id': pool['id'],
                           'agent_id': lbaas_agent['id']})
                return

            active_agents = plugin.get_lbaas_agents(context, active=True)
            if not active_agents:
                LOG.warn(_('No active lbaas agents for pool %s'), pool['id'])
                return

            candidates = plugin.get_lbaas_agent_candidates(device_driver,
                                                           active_agents)
            if not candidates:
                LOG.warn(_('No lbaas agent supporting device driver %s'),
                         device_driver)
                return

            chosen_agent = random.choice(candidates)
            binding = PoolLoadbalancerAgentBinding()
            binding.agent = chosen_agent
            binding.pool_id = pool['id']
            context.session.add(binding)
            LOG.debug(_('Pool %(pool_id)s is scheduled to '
                        'lbaas agent %(agent_id)s'),
                      {'pool_id': pool['id'],
                       'agent_id': chosen_agent['id']})
            return chosen_agent

class LeastLoaderBalancesScheduler(object):
    """Allocate a loadbalancer agent for a vip in a random way."""

    def schedule(self, plugin, context, pool):
        """Schedule the pool to an active loadbalancer agent if there
        is no enabled agent hosting it.
        """
        with context.session.begin(subtransactions=True):
            lbaas_agent = plugin.get_lbaas_agent_hosting_pool(
                context, pool['id'])
            if lbaas_agent:
                LOG.debug(_('Pool %(pool_id)s has already been hosted'
                            ' by lbaas agent %(agent_id)s'),
                          {'pool_id': pool['id'],
                           'agent_id': lbaas_agent['id']})
                return

            candidates = plugin.get_lbaas_agents(context, active=True)
            if not candidates:
                LOG.warn(_('No active lbaas agents for pool %s'), pool['id'])
                return

            candidate_ids = [candidate['id'] for candidate in candidates]
            chosen_agent = plugin.get_lb_agent_with_min_lbs(
                context, candidate_ids)
            binding = PoolLoadbalancerAgentBinding()
            binding.agent = chosen_agent
            binding.pool_id = pool['id']
            context.session.add(binding)
            LOG.debug(_('Pool %(pool_id)s is scheduled to '
                        'lbaas agent %(agent_id)s'),
                      {'pool_id': pool['id'],
                       'agent_id': chosen_agent['id']})
            return chosen_agent
