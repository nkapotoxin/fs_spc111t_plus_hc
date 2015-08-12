# Copyright 2013 Big Switch Networks, Inc.
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

from neutron.common import exceptions as n_exception
from neutron.api.v2 import attributes as attr
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron import manager
from neutron import context as neutron_context
from neutron.db.firewall import firewall_db
from neutron.db.firewall import firewall_router_insertion_db
from neutron.extensions import firewall as fw_ext
from neutron.openstack.common import log as logging
from neutron.plugins.common import constants as const


LOG = logging.getLogger(__name__)


class FirewallCallbacks(n_rpc.RpcCallback):
    RPC_API_VERSION = '1.0'

    def __init__(self, plugin):
        super(FirewallCallbacks, self).__init__()
        self.plugin = plugin

    def set_firewall_status(self, context, firewall_id, status, **kwargs):
        """Agent uses this to set a firewall's status."""
        LOG.debug(_("set_firewall_status() called"))
        with context.session.begin(subtransactions=True):
            fw_db = self.plugin._get_firewall(context, firewall_id)
            # ignore changing status if firewall expects to be deleted
            # That case means that while some pending operation has been
            # performed on the backend, neutron server received delete request
            # and changed firewall status to const.PENDING_DELETE
            if fw_db.status == const.PENDING_DELETE:
                LOG.debug(_("Firewall %(fw_id)s in PENDING_DELETE state, "
                            "not changing to %(status)s"),
                          {'fw_id': firewall_id, 'status': status})
                return False
            if status in (const.ACTIVE, const.DOWN, const.INACTIVE):
                fw_db.status = status
                return True
            else:
                fw_db.status = const.ERROR
                return False

    def firewall_deleted(self, context, firewall_id, **kwargs):
        """Agent uses this to indicate firewall is deleted."""
        LOG.debug(_("firewall_deleted() called"))
        with context.session.begin(subtransactions=True):
            try:
                fw_db = self.plugin._get_firewall(context, firewall_id)
            except fw_ext.FirewallNotFound:
                LOG.debug(_("Not found the firewall:%s"), firewall_id)
                return False

            # allow to delete firewalls in ERROR state
            if fw_db.status in (const.PENDING_DELETE, const.ERROR):
                self.plugin.delete_db_firewall_object(context, firewall_id)
                return True
            else:
                LOG.warn(_('Firewall %(fw)s unexpectedly deleted by agent, '
                           'status was %(status)s'),
                         {'fw': firewall_id, 'status': fw_db.status})
                fw_db.status = const.ERROR
                return False

    def get_firewalls_for_tenant(self, context, **kwargs):
        """Agent uses this to get all firewalls and rules for a tenant."""
        LOG.debug(_("get_firewalls_for_tenant() called"))
        fw_list = []

        for fw in self.plugin.get_firewalls(context):
            fw_with_rules = self.plugin._make_firewall_dict_with_rules(
                context, fw['id'])
            if fw['status'] == const.PENDING_DELETE:
                fw_with_rules['add-router-ids'] = []
                fw_with_rules['del-router-ids'] = (
                    self.plugin.get_firewall_routers(context, fw['id']))
            else:
                fw_with_rules['add-router-ids'] = (
                    self.plugin.get_firewall_routers(context, fw['id']))
                fw_with_rules['del-router-ids'] = []
            fw_list.append(fw_with_rules)

        return fw_list

    def get_firewalls_for_tenant_without_rules(self, context, **kwargs):
        """Agent uses this to get all firewalls for a tenant."""
        LOG.debug(_("get_firewalls_for_tenant_without_rules() called"))
        fw_list = [fw for fw in self.plugin.get_firewalls(context)]
        return fw_list

    def get_tenants_with_firewalls(self, context, **kwargs):
        """Agent uses this to get all tenants that have firewalls."""
        LOG.debug(_("get_tenants_with_firewalls() called"))
        ctx = neutron_context.get_admin_context()
        fw_list = self.plugin.get_firewalls(ctx)
        fw_tenant_list = list(set(fw['tenant_id'] for fw in fw_list))
        return fw_tenant_list

    def get_firewall_by_id(self, context, **kwargs):
        """Agent uses this to get specific firewall."""
        LOG.debug(_("get_firewall_by_id() called"))
        fw_id = kwargs.get('firewall_id')
        fw = self.plugin.get_firewall(context, fw_id)
        return fw

    def get_firewall_policy_by_id(self, context, **kwargs):
        """Agent uses this to get specific firewall policy."""
        LOG.debug(_("get_firewall_policy_by_id() called"))
        fwp_id = kwargs.get('firewall_policy_id')
        fwp = self.plugin.get_firewall_policy(context, fwp_id)
        return fwp

class FirewallAgentApi(n_rpc.RpcProxy):
    """Plugin side of plugin to agent RPC API."""

    API_VERSION = '1.0'

    def __init__(self, topic, host):
        super(FirewallAgentApi, self).__init__(topic, self.API_VERSION)
        self.host = host

    def create_firewall(self, context, firewall):
        return self.fanout_cast(
            context,
            self.make_msg('create_firewall', firewall=firewall,
                          host=self.host)
        )

    def update_firewall(self, context, firewall):
        return self.fanout_cast(
            context,
            self.make_msg('update_firewall', firewall=firewall,
                          host=self.host)
        )

    def delete_firewall(self, context, firewall):
        return self.fanout_cast(
            context,
            self.make_msg('delete_firewall', firewall=firewall,
                          host=self.host)
        )


class FirewallCountExceeded(n_exception.Conflict):

    """Reference implementation specific exception for firewall count.

    Only one firewall is supported per tenant. When a second
    firewall is tried to be created, this exception will be raised.
    """
    message = _("Exceeded allowed count of firewalls for tenant "
                "%(tenant_id)s. Only one firewall is supported per tenant.")


class FirewallPlugin(firewall_db.Firewall_db_mixin,
                     firewall_router_insertion_db.FirewallRouterInsertionDbMixin):

    """Implementation of the Neutron Firewall Service Plugin.

    This class manages the workflow of FWaaS request/response.
    Most DB related works are implemented in class
    firewall_db.Firewall_db_mixin.
    """
    supported_extension_aliases = ["fwaas", "fwaasrouterinsertion"]

    def __init__(self):
        """Do the initialization for the firewall service plugin here."""

        self.endpoints = [FirewallCallbacks(self)]

        self.conn = n_rpc.create_connection(new=True)
        self.conn.create_consumer(
            topics.FIREWALL_PLUGIN, self.endpoints, fanout=False)
        self.conn.consume_in_threads()

        self.agent_rpc = FirewallAgentApi(
            topics.L3_AGENT,
            cfg.CONF.host
        )

    def _make_firewall_dict_with_rules(self, context, firewall_id):
        firewall = self.get_firewall(context, firewall_id)
        fw_policy_id = firewall['firewall_policy_id']
        if fw_policy_id:
            fw_policy = self.get_firewall_policy(context, fw_policy_id)
            fw_rules_list = [self.get_firewall_rule(
                context, rule_id) for rule_id in fw_policy['firewall_rules']]
            firewall['firewall_rule_list'] = fw_rules_list
        else:
            firewall['firewall_rule_list'] = []
        # FIXME(Sumit): If the size of the firewall object we are creating
        # here exceeds the largest message size supported by rabbit/qpid
        # then we will have a problem.
        return firewall

    def _rpc_update_firewall(self, context, firewall_id, old_rule_list=[]):
        status_update = {"firewall": {"status": const.PENDING_UPDATE}}
        super(FirewallPlugin, self).update_firewall(context, firewall_id,
                                                    status_update)
        fw_with_rules = self._make_firewall_dict_with_rules(context,
                                                            firewall_id)
        # this is triggered on an update to fw rule or policy, no 
        # change in associated routers.
        fw_with_rules['add-router-ids'] = self.get_firewall_routers(
                context, firewall_id)
        fw_with_rules['del-router-ids'] = []
        fw_with_rules['delete-rule-list'] = old_rule_list
        self.agent_rpc.update_firewall(context, fw_with_rules)

    def _rpc_update_firewall_policy(self, context, firewall_policy_id, old_rule_list=[]):
        firewall_policy = self.get_firewall_policy(context, firewall_policy_id)
        if firewall_policy:
            for firewall_id in firewall_policy['firewall_list']:
                self._rpc_update_firewall(context, firewall_id, old_rule_list)

    def _ensure_update_firewall(self, context, firewall_id):
        fwall = self.get_firewall(context, firewall_id)
        if fwall['status'] in [const.PENDING_CREATE,
                               const.PENDING_UPDATE,
                               const.PENDING_DELETE]:
            raise fw_ext.FirewallInPendingState(firewall_id=firewall_id,
                                                pending_state=fwall['status'])

    def _ensure_update_firewall_policy(self, context, firewall_policy_id):
        firewall_policy = self.get_firewall_policy(context, firewall_policy_id)
        if firewall_policy and 'firewall_list' in firewall_policy:
            for firewall_id in firewall_policy['firewall_list']:
                self._ensure_update_firewall(context, firewall_id)

    def _ensure_update_firewall_rule(self, context, firewall_rule_id):
        fw_rule = self.get_firewall_rule(context, firewall_rule_id)
        if 'firewall_policy_id' in fw_rule and fw_rule['firewall_policy_id']:
            self._ensure_update_firewall_policy(context,
                                                fw_rule['firewall_policy_id'])

    def _get_routers_for_create_firewall(self, tenant_id, context, firewall):

        # pop router_id as this goes in the router association db 
        # and not firewall db 
        router_ids = firewall['firewall'].pop('router_ids', None)
        if router_ids == attr.ATTR_NOT_SPECIFIED:
            # old semantics router-ids keyword not specified pick up 
            # all routers on tenant. 
            l3_plugin = manager.NeutronManager.get_service_plugins().get(
                const.L3_ROUTER_NAT)
            ctx = neutron_context.get_admin_context()
            routers = l3_plugin.get_routers(ctx)
            router_ids = [
                router['id']
                for router in routers
                if router['tenant_id'] == tenant_id]
            # validation can still fail this if there is another fw 
            # which is associated with one of these routers. 
            self.validate_firewall_routers_not_in_use(context, router_ids)
            return router_ids
        else:
            if not router_ids:
                # This indicates that user specifies no routers. 
                return []
            else:
               # some router(s) provided. 
                self.validate_firewall_routers_not_in_use(context, router_ids)
                return router_ids

    def create_firewall(self, context, firewall):
        LOG.debug(_("create_firewall() called"))
        tenant_id = self._get_tenant_id_for_create(context,
                                                   firewall['firewall'])
        
        fw_new_rtrs = self._get_routers_for_create_firewall(
            tenant_id, context, firewall)

        if not fw_new_rtrs:
            # no messaging to agent needed, and fw needs to go 
            # to INACTIVE(no associated rtrs) state. 
            status = const.INACTIVE
            fw = super(FirewallPlugin, self).create_firewall(
                context, firewall, status)
            fw['router_ids'] = []
            return fw
        else:
            fw = super(FirewallPlugin, self).create_firewall(
                context, firewall)
            fw['router_ids'] = fw_new_rtrs
        
        fw_with_rules = (
            self._make_firewall_dict_with_rules(context, fw['id']))

        fw_with_rtrs = {'fw_id': fw['id'],
                        'router_ids': fw_new_rtrs}
        self.set_routers_for_firewall(context, fw_with_rtrs)
        fw_with_rules['add-router-ids'] = fw_new_rtrs
        fw_with_rules['del-router-ids'] = []

        self.agent_rpc.create_firewall(context, fw_with_rules)
        
        return fw

    def update_firewall(self, context, id, firewall):
        LOG.debug(_("update_firewall() called"))
        self._ensure_update_firewall(context, id)
        # pop router_id as this goes in the router association db 
        # and not firewall db 
        router_ids = firewall['firewall'].pop('router_ids', None)
        fw_current_rtrs = self.get_firewall_routers(context, id)
        fw_before = self.get_firewall(context, id)
        fw_before_policy = fw_before['firewall_policy_id']

        if router_ids is not None:
            if router_ids == []:
                # This indicates that user is indicating no routers. 
                fw_new_rtrs = []
            else:
                self.validate_firewall_routers_not_in_use(
                    context, router_ids, id)
                fw_new_rtrs = router_ids
            self.update_firewall_routers(context, {'fw_id': id,
                'router_ids': fw_new_rtrs})
        else:
            # router-ids keyword not specified for update pick up 
            # existing routers. 
            fw_new_rtrs = self.get_firewall_routers(context, id)

        if not fw_new_rtrs and not fw_current_rtrs:
            # no messaging to agent needed, and we need to continue 
            # in INACTIVE state 
            firewall['firewall']['status'] = const.INACTIVE
            fw = super(FirewallPlugin, self).update_firewall(
                context, id, firewall)
            fw['router_ids'] = []
            return fw
        else:
            firewall['firewall']['status'] = const.PENDING_UPDATE
            fw = super(FirewallPlugin, self).update_firewall(
                context, id, firewall)
            fw['router_ids'] = fw_new_rtrs

        fw_with_rules = (
            self._make_firewall_dict_with_rules(context, fw['id']))

        # determine rtrs to add fw to and del from 
        fw_with_rules['add-router-ids'] = fw_new_rtrs
        fw_with_rules['del-router-ids'] = list(
            set(fw_current_rtrs).difference(set(fw_new_rtrs)))
        
        # last-router drives agent to ack with status to set state to INACTIVE 
        fw_with_rules['last-router'] = not fw_new_rtrs
        if fw_with_rules['firewall_policy_id'] != fw_before_policy:
            old_rule_list = self._get_old_firewall_rules(context, fw_before_policy)
            fw_with_rules['delete-rule-list'] = old_rule_list
        LOG.debug("update_firewall(): Add Routers: %s, Del Routers: %s",
            fw_with_rules['add-router-ids'],
            fw_with_rules['del-router-ids'])
        
        self.agent_rpc.update_firewall(context, fw_with_rules)
        
        return fw

    def delete_db_firewall_object(self, context, id):
        firewall = self.get_firewall(context, id)
        if firewall['status'] == const.PENDING_DELETE:
            super(FirewallPlugin, self).delete_firewall(context, id)

    def delete_firewall(self, context, id):
        LOG.debug(_("delete_firewall() called"))
        status_update = {"firewall": {"status": const.PENDING_DELETE}}
        fw = super(FirewallPlugin, self).update_firewall(context, id,
                                                         status_update)
        fw_with_rules = (
            self._make_firewall_dict_with_rules(context, fw['id']))
        fw_with_rules['del-router-ids'] = self.get_firewall_routers(
            context, id)
        fw_with_rules['add-router-ids'] = []
        if not fw_with_rules['del-router-ids']:
            # no routers to delete on the agent side 
            self.delete_db_firewall_object(context, id)
        else:
            self.agent_rpc.delete_firewall(context, fw_with_rules)

    def update_firewall_policy(self, context, id, firewall_policy):
        LOG.debug(_("update_firewall_policy() called"))
        old_rule_list = self._get_old_firewall_rules(context, id)
        self._ensure_update_firewall_policy(context, id)
        fwp = super(FirewallPlugin,
                    self).update_firewall_policy(context, id, firewall_policy)
        self._rpc_update_firewall_policy(context, id, old_rule_list=old_rule_list)
        return fwp

    def update_firewall_rule(self, context, id, firewall_rule):
        LOG.debug(_("update_firewall_rule() called"))
        old_rule_list = []
        old_rule = self.get_firewall_rule(context, id)
        old_fwp_id = old_rule['firewall_policy_id']
        if old_fwp_id:
            old_rule_list = self._get_old_firewall_rules(context, old_fwp_id)
        self._ensure_update_firewall_rule(context, id)
        fwr = super(FirewallPlugin,
                    self).update_firewall_rule(context, id, firewall_rule)
        firewall_policy_id = fwr['firewall_policy_id']
        if firewall_policy_id:
            self._rpc_update_firewall_policy(context, firewall_policy_id, old_rule_list=old_rule_list)
        return fwr

    def insert_rule(self, context, id, rule_info):
        LOG.debug(_("insert_rule() called"))
        old_rule_list = self._get_old_firewall_rules(context, id)
        self._ensure_update_firewall_policy(context, id)
        fwp = super(FirewallPlugin,
                    self).insert_rule(context, id, rule_info)
        self._rpc_update_firewall_policy(context, id, old_rule_list=old_rule_list)
        return fwp

    def remove_rule(self, context, id, rule_info):
        LOG.debug(_("remove_rule() called"))
        old_rule_list = self._get_old_firewall_rules(context, id)
        self._ensure_update_firewall_policy(context, id)
        fwp = super(FirewallPlugin,
                    self).remove_rule(context, id, rule_info)
        self._rpc_update_firewall_policy(context, id, old_rule_list=old_rule_list)
        return fwp

    def _get_old_firewall_rules(self, context, firewall_policy_id):
        firewall_policy = self.get_firewall_policy(context, firewall_policy_id)
        fw_rules_list = [self.get_firewall_rule(
                context, rule_id) for rule_id in firewall_policy['firewall_rules']]
        return fw_rules_list
    
    def get_firewalls(self, context, filters=None, fields=None):
        LOG.debug("fwaas get_firewalls() called")
        fw_list = super(FirewallPlugin, self).get_firewalls(
                        context, filters, fields)
        for fw in fw_list:
            fw_current_rtrs = self.get_firewall_routers(context, fw['id'])
            fw['router_ids'] = fw_current_rtrs
        return fw_list

    def get_firewall(self, context, id, fields=None):
        LOG.debug("fwaas get_firewall() called")
        res = super(FirewallPlugin, self).get_firewall(
                        context, id, fields)
        fw_current_rtrs = self.get_firewall_routers(context, id)
        res['router_ids'] = fw_current_rtrs
        return res                                                                 
