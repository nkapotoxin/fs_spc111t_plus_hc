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
import datetime
import random
import time

from oslo.config import cfg
from oslo.db import exception as db_exc
import sqlalchemy as sa
from sqlalchemy import func
from sqlalchemy import orm
from sqlalchemy.orm import exc
from sqlalchemy.orm import joinedload
from sqlalchemy import sql

from neutron.common import constants
from neutron.common import rpc as n_rpc
from neutron.common import utils as n_utils
from neutron import context as n_ctx
from neutron.db import agents_db
from neutron.db import agentschedulers_db
from neutron.db import l3_attrs_db
from neutron.db import model_base
from neutron.extensions import l3agentscheduler
from neutron import manager
from neutron.openstack.common.gettextutils import _LE, _LI, _LW
from neutron.openstack.common import log as logging
from neutron.openstack.common import loopingcall
from neutron.openstack.common import timeutils


LOG = logging.getLogger(__name__)

L3_AGENTS_SCHEDULER_OPTS = [
    cfg.StrOpt('router_scheduler_driver',
               default='neutron.scheduler.l3_agent_scheduler.ChanceScheduler',
               help=_('Driver to use for scheduling '
                      'router to a default L3 agent')),
    cfg.BoolOpt('router_auto_schedule', default=True,
                help=_('Allow auto scheduling of routers to L3 agent.')),
    cfg.BoolOpt('allow_automatic_l3agent_failover', default=False,
                help=_('Automatically reschedule routers from offline L3 '
                       'agents to online L3 agents.')),
]

cfg.CONF.register_opts(L3_AGENTS_SCHEDULER_OPTS)


class RouterL3AgentBinding(model_base.BASEV2):
    """Represents binding between neutron routers and L3 agents."""

    router_id = sa.Column(sa.String(36),
                          sa.ForeignKey("routers.id", ondelete='CASCADE'),
                          primary_key=True)
    l3_agent = orm.relation(agents_db.Agent)
    l3_agent_id = sa.Column(sa.String(36),
                            sa.ForeignKey("agents.id", ondelete='CASCADE'),
                            primary_key=True)


class L3AgentSchedulerDbMixin(l3agentscheduler.L3AgentSchedulerPluginBase,
                              agentschedulers_db.AgentSchedulerDbMixin):
    """Mixin class to add l3 agent scheduler extension to plugins
    using the l3 agent for routing.
    """

    router_scheduler = None

    def start_periodic_agent_status_check(self):
        if not cfg.CONF.allow_automatic_l3agent_failover:
            LOG.info(_LI("Skipping period L3 agent status check because "
                         "automatic router rescheduling is disabled."))
            return

        self.periodic_agent_loop = loopingcall.FixedIntervalLoopingCall(
            self.reschedule_routers_from_down_agents)
        interval = max(cfg.CONF.agent_down_time / 2, 1)
        # add random initial delay to allow agents to check in after the
        # neutron server first starts. random to offset multiple servers
        self.periodic_agent_loop.start(interval=interval,
            initial_delay=random.randint(interval, interval * 2))

    def reschedule_routers_from_down_agents(self):
        """Reschedule routers from down l3 agents if admin state is up."""

        # give agents extra time to handle transient failures
        agent_dead_limit = cfg.CONF.agent_down_time * 2

        # check for an abrupt clock change since last check. if a change is
        # detected, sleep for a while to let the agents check in.
        tdelta = timeutils.utcnow() - getattr(self, '_clock_jump_canary',
                                              timeutils.utcnow())
        if timeutils.total_seconds(tdelta) > cfg.CONF.agent_down_time:
            LOG.warn(_LW("Time since last L3 agent reschedule check has "
                         "exceeded the interval between checks. Waiting "
                         "before check to allow agents to send a heartbeat "
                         "in case there was a clock adjustment."))
            time.sleep(agent_dead_limit)
        self._clock_jump_canary = timeutils.utcnow()

        context = n_ctx.get_admin_context()
        cutoff = timeutils.utcnow() - datetime.timedelta(
            seconds=agent_dead_limit)
        down_bindings = (
            context.session.query(RouterL3AgentBinding).
            join(agents_db.Agent).
            filter(agents_db.Agent.heartbeat_timestamp < cutoff,
                   agents_db.Agent.admin_state_up).
            outerjoin(l3_attrs_db.RouterExtraAttributes,
                      l3_attrs_db.RouterExtraAttributes.router_id ==
                      RouterL3AgentBinding.router_id).
            filter(sa.or_(l3_attrs_db.RouterExtraAttributes.ha == sql.false(),
                          l3_attrs_db.RouterExtraAttributes.ha == sql.null())))
        try:
            for binding in down_bindings:
                LOG.warn(_LW(
                    "Rescheduling router %(router)s from agent %(agent)s "
                    "because the agent did not report to the server in "
                    "the last %(dead_time)s seconds."),
                    {'router': binding.router_id,
                     'agent': binding.l3_agent_id,
                     'dead_time': agent_dead_limit})
                try:
                    self.reschedule_router(context, binding.router_id)
                except (l3agentscheduler.RouterReschedulingFailed,
                        n_rpc.RemoteError):
                    # Catch individual router rescheduling errors here
                    # so one broken one doesn't stop the iteration.
                    LOG.exception(_LE("Failed to reschedule router %s"),
                                  binding.router_id)
        except db_exc.DBError:
            # Catch DB errors here so a transient DB connectivity issue
            # doesn't stop the loopingcall.
            LOG.exception(_LE("Exception encountered during router "
                              "rescheduling."))

    def validate_agent_router_combination(self, context, agent, router):
        """Validate if the router can be correctly assigned to the agent.

        :raises: RouterL3AgentMismatch if attempting to assign DVR router
          to legacy agent, or centralized router to compute's L3 agents.
        :raises: InvalidL3Agent if attempting to assign router to an
          unsuitable agent (disabled, type != L3, incompatible configuration)
        :raises: DVRL3CannotAssignToDvrAgent if attempting to assign DVR
          router from one DVR Agent to another dvr agent.
        :raises: DVRL3CannotAssignRouterWithNoGateway if attempting to
          assign DVR router to dvr_snat agent when there is no gateway
          associated with the DVR router.
        """
        is_distributed = router.get('distributed')
        agent_conf = self.get_configuration_dict(agent)
        agent_mode = agent_conf.get('agent_mode', 'legacy')
        router_type = ('distributed' if is_distributed else 'centralized')
        is_agent_router_types_incompatible = (
            agent_mode == 'dvr' and not is_distributed
            or agent_mode == 'legacy' and is_distributed
        )
        if is_agent_router_types_incompatible:
            raise l3agentscheduler.RouterL3AgentMismatch(
                router_type=router_type, router_id=router['id'],
                agent_mode=agent_mode, agent_id=agent['id'])
        assign_to_dvr_agent = agent_mode == 'dvr'
        if assign_to_dvr_agent and is_distributed:
            raise l3agentscheduler.DVRL3CannotAssignToDvrAgent(
                router_type=router_type, router_id=router['id'],
                agent_mode=agent_mode, agent_id=agent['id'])
        assign_to_dvr_agent = agent_mode == 'dvr_snat'
        assign_router_with_no_gateway = not (
            router.get('external_gateway_info', None))
        if (assign_to_dvr_agent and is_distributed and
            assign_router_with_no_gateway):
            raise l3agentscheduler.DVRL3CannotAssignRouterWithNoGateway(
                router_type=router_type, router_id=router['id'],
                agent_mode=agent_mode, agent_id=agent['id'])

        is_suitable_agent = (
            self.get_l3_agent_candidates(context, router, [agent]) or
            self.get_snat_candidates(router, [agent])
        )
        is_wrong_type = (
            agent['agent_type'] != constants.AGENT_TYPE_L3
        )
        if is_wrong_type or not is_suitable_agent:
            raise l3agentscheduler.InvalidL3Agent(id=agent['id'])

    def check_agent_router_scheduling_needed(self, context, agent, router):
        """Check if the router scheduling is needed.

        :raises: RouterHostedByL3Agent if router is already assigned
          to a different agent.
        :returns: True if scheduling is needed, otherwise False
        """
        router_id = router['id']
        agent_id = agent['id']
        if router.get('distributed'):
            if router['external_gateway_info']:
                return not self.get_snat_bindings(context, router['id'])
            return False
        query = context.session.query(RouterL3AgentBinding)
        bindings = query.filter_by(router_id=router_id).all()
        if not bindings:
            return True
        for binding in bindings:
            if binding.l3_agent_id == agent_id:
                # router already bound to the agent we need
                return False
        # non-dvr case: centralized router is already bound to some agent
        raise l3agentscheduler.RouterHostedByL3Agent(
            router_id=router_id,
            agent_id=bindings[0].l3_agent_id)

    def create_router_to_agent_binding(self, context, agent, router):
        """Create router to agent binding."""
        router_id = router['id']
        agent_id = agent['id']
        if self.router_scheduler:
            try:
                if router['external_gateway_info'] and (
                        router.get('distributed')):
                    self.bind_snat_router(context, router['id'], agent)
                    self.bind_dvr_router_servicenode(context,
                                                     router['id'], agent)
                else:
                    self.router_scheduler.bind_router(context,
                                                      router_id, agent)
            except db_exc.DBError:
                raise l3agentscheduler.RouterSchedulingFailed(
                    router_id=router_id, agent_id=agent_id)

    def add_router_to_l3_agent(self, context, agent_id, router_id):
        """Add a l3 agent to host a router."""
        with context.session.begin(subtransactions=True):
            router = self.get_router(context, router_id)
            agent = self._get_agent(context, agent_id)
            self.validate_agent_router_combination(context, agent, router)
            if self.check_agent_router_scheduling_needed(
                context, agent, router):
                self.create_router_to_agent_binding(context, agent, router)
            else:
                return

        l3_notifier = self.agent_notifiers.get(constants.AGENT_TYPE_L3)
        if l3_notifier:
            l3_notifier.router_added_to_agent(
                context, [router_id], agent.host)

    def remove_router_from_l3_agent(self, context, agent_id, router_id):
        """Remove the router from l3 agent.

        After removal, the router will be non-hosted until there is update
        which leads to re-schedule or be added to another agent manually.
        """
        agent = self._get_agent(context, agent_id)
        self._unbind_router(context, router_id, agent_id)
        l3_notifier = self.agent_notifiers.get(constants.AGENT_TYPE_L3)
        if l3_notifier:
            l3_notifier.router_removed_from_agent(
                context, router_id, agent.host)

    def _unbind_router(self, context, router_id, agent_id):
        with context.session.begin(subtransactions=True):
            query = context.session.query(RouterL3AgentBinding)
            query = query.filter(
                RouterL3AgentBinding.router_id == router_id,
                RouterL3AgentBinding.l3_agent_id == agent_id)
            try:
                binding = query.one()
            except exc.NoResultFound:
                raise l3agentscheduler.RouterNotHostedByL3Agent(
                    router_id=router_id, agent_id=agent_id)
            context.session.delete(binding)

    def reschedule_router(self, context, router_id, candidates=None):
        """Reschedule router to a new l3 agent

        Remove the router from the agent(s) currently hosting it and
        schedule it again
        """
        cur_agents = self.list_l3_agents_hosting_router(
            context, router_id)['agents']
        with context.session.begin(subtransactions=True):
            for agent in cur_agents:
                self._unbind_router(context, router_id, agent['id'])

            self.schedule_router(context, router_id,
                                             candidates=candidates)

        l3_notifier = self.agent_notifiers.get(constants.AGENT_TYPE_L3)
        new_agents = self.list_l3_agents_hosting_router(
            context, router_id)['agents']
        if l3_notifier:
            for agent in cur_agents:
                l3_notifier.router_removed_from_agent(
                    context, router_id, agent['host'])
            for agent in new_agents:
                l3_notifier.router_added_to_agent(
                    context, [router_id], agent['host'])

    def list_routers_on_l3_agent(self, context, agent_id):
        query = context.session.query(RouterL3AgentBinding.router_id)
        query = query.filter(RouterL3AgentBinding.l3_agent_id == agent_id)

        router_ids = [item[0] for item in query]
        if router_ids:
            return {'routers':
                    self.get_routers(context, filters={'id': router_ids})}
        else:
            return {'routers': []}

    def list_active_sync_routers_on_active_l3_agent(
            self, context, host, router_ids):
        agent = self._get_agent_by_type_and_host(
            context, constants.AGENT_TYPE_L3, host)
        if not agent.admin_state_up:
            return []
        query = context.session.query(RouterL3AgentBinding.router_id)
        query = query.filter(
            RouterL3AgentBinding.l3_agent_id == agent.id)

        if router_ids:
            query = query.filter(
                RouterL3AgentBinding.router_id.in_(router_ids))
        router_ids = [item[0] for item in query]
        if router_ids:
            if n_utils.is_extension_supported(self,
                                              constants.L3_HA_MODE_EXT_ALIAS):
                return self.get_ha_sync_data_for_host(context, host,
                                                      router_ids=router_ids,
                                                      active=True)
            else:
                return self.get_sync_data(context, router_ids=router_ids,
                                          active=True)
        else:
            return []

    def get_l3_agents_hosting_routers(self, context, router_ids,
                                      admin_state_up=None,
                                      active=None):
        if not router_ids:
            return []
        query = context.session.query(RouterL3AgentBinding)
        if len(router_ids) > 1:
            query = query.options(joinedload('l3_agent')).filter(
                RouterL3AgentBinding.router_id.in_(router_ids))
        else:
            query = query.options(joinedload('l3_agent')).filter(
                RouterL3AgentBinding.router_id == router_ids[0])
        if admin_state_up is not None:
            query = (query.filter(agents_db.Agent.admin_state_up ==
                                  admin_state_up))
        l3_agents = [binding.l3_agent for binding in query]
        if active is not None:
            l3_agents = [l3_agent for l3_agent in
                         l3_agents if not
                         agents_db.AgentDbMixin.is_agent_down(
                             l3_agent['heartbeat_timestamp'])]
        return l3_agents

    def _get_l3_bindings_hosting_routers(self, context, router_ids):
        if not router_ids:
            return []
        query = context.session.query(RouterL3AgentBinding)
        if len(router_ids) > 1:
            query = query.options(joinedload('l3_agent')).filter(
                RouterL3AgentBinding.router_id.in_(router_ids))
        else:
            query = query.options(joinedload('l3_agent')).filter(
                RouterL3AgentBinding.router_id == router_ids[0])
        return query.all()

    def list_l3_agents_hosting_router(self, context, router_id):
        with context.session.begin(subtransactions=True):
            bindings = self._get_l3_bindings_hosting_routers(
                context, [router_id])
            results = []
            for binding in bindings:
                l3_agent_dict = self._make_agent_dict(binding.l3_agent)
                results.append(l3_agent_dict)
            if results:
                return {'agents': results}
            else:
                return {'agents': []}

    def get_l3_agents(self, context, active=None, filters=None):
        query = context.session.query(agents_db.Agent)
        query = query.filter(
            agents_db.Agent.agent_type == constants.AGENT_TYPE_L3)
        if active is not None:
            query = (query.filter(agents_db.Agent.admin_state_up == active))
        if filters:
            for key, value in filters.iteritems():
                column = getattr(agents_db.Agent, key, None)
                if column:
                    query = query.filter(column.in_(value))

        return [l3_agent
                for l3_agent in query
                if agentschedulers_db.AgentSchedulerDbMixin.is_eligible_agent(
                    active, l3_agent)]

    def check_ports_exist_on_l3agent(self, context, l3_agent, router_id):
        """
        This function checks for existence of dvr serviceable
        ports on the host, running the input l3agent.
        """
        subnet_ids = self.get_subnet_ids_on_router(context, router_id)
        if not subnet_ids:
            return False

        core_plugin = manager.NeutronManager.get_plugin()
        filter = {'fixed_ips': {'subnet_id': subnet_ids}}
        ports = core_plugin.get_ports(context, filters=filter)
        for port in ports:
            if (n_utils.is_dvr_serviced(port['device_owner']) and
                l3_agent['host'] == port['binding:host_id']):
                    return True

        return False

    def get_snat_candidates(self, sync_router, l3_agents):
        """Get the valid snat enabled l3 agents for the distributed router."""
        candidates = []
        is_router_distributed = sync_router.get('distributed', False)
        if not is_router_distributed:
            return candidates
        for l3_agent in l3_agents:
            if not l3_agent.admin_state_up:
                continue

            agent_conf = self.get_configuration_dict(l3_agent)
            agent_mode = agent_conf.get('agent_mode', 'legacy')
            if agent_mode != 'dvr_snat':
                continue

            router_id = agent_conf.get('router_id', None)
            use_namespaces = agent_conf.get('use_namespaces', True)
            if not use_namespaces and router_id != sync_router['id']:
                continue

            handle_internal_only_routers = agent_conf.get(
                'handle_internal_only_routers', True)
            gateway_external_network_id = agent_conf.get(
                'gateway_external_network_id', None)
            ex_net_id = (sync_router['external_gateway_info'] or {}).get(
                'network_id')
            if ((not ex_net_id and not handle_internal_only_routers) or
                (ex_net_id and gateway_external_network_id and
                 ex_net_id != gateway_external_network_id)):
                continue

            candidates.append(l3_agent)
        return candidates

    def get_l3_agent_candidates(self, context, sync_router, l3_agents):
        """Get the valid l3 agents for the router from a list of l3_agents."""
        candidates = []
        for l3_agent in l3_agents:
            if not l3_agent.admin_state_up:
                continue
            agent_conf = self.get_configuration_dict(l3_agent)
            router_id = agent_conf.get('router_id', None)
            use_namespaces = agent_conf.get('use_namespaces', True)
            handle_internal_only_routers = agent_conf.get(
                'handle_internal_only_routers', True)
            gateway_external_network_id = agent_conf.get(
                'gateway_external_network_id', None)
            agent_mode = agent_conf.get('agent_mode', 'legacy')
            if not use_namespaces and router_id != sync_router['id']:
                continue
            ex_net_id = (sync_router['external_gateway_info'] or {}).get(
                'network_id')
            if ((not ex_net_id and not handle_internal_only_routers) or
                (ex_net_id and gateway_external_network_id and
                 ex_net_id != gateway_external_network_id)):
                continue
            is_router_distributed = sync_router.get('distributed', False)
            if agent_mode in ('legacy', 'dvr_snat') and (
                not is_router_distributed):
                candidates.append(l3_agent)
            elif is_router_distributed and agent_mode.startswith('dvr') and (
                self.check_ports_exist_on_l3agent(
                    context, l3_agent, sync_router['id'])):
                candidates.append(l3_agent)
        return candidates

    def auto_schedule_routers(self, context, host, router_ids):
        if self.router_scheduler:
            return self.router_scheduler.auto_schedule_routers(
                self, context, host, router_ids)

    def schedule_router(self, context, router, candidates=None):
        if self.router_scheduler:
            return self.router_scheduler.schedule(
                self, context, router, candidates=candidates)

    def schedule_routers(self, context, routers):
        """Schedule the routers to l3 agents."""
        for router in routers:
            self.schedule_router(context, router, candidates=None)

    def get_l3_agent_with_min_routers(self, context, agent_ids):
        """Return l3 agent with the least number of routers."""
        query = context.session.query(
            agents_db.Agent,
            func.count(
                RouterL3AgentBinding.router_id
            ).label('count')).outerjoin(RouterL3AgentBinding).group_by(
                RouterL3AgentBinding.l3_agent_id, agents_db.Agent.id).order_by('count')
        res = query.filter(agents_db.Agent.id.in_(agent_ids)).first()
        return res[0]
