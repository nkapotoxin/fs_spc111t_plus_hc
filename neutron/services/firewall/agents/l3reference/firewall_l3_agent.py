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

from oslo.config import cfg
from neutron.common import log
from neutron.agent.common import config
from neutron.agent.linux import ip_lib
from neutron.common import topics
from neutron import context
from neutron.extensions import firewall as fw_ext
from neutron.openstack.common import importutils
from neutron.openstack.common import log as logging
from neutron.plugins.common import constants
from neutron.services.firewall.agents import firewall_agent_api as api

LOG = logging.getLogger(__name__)


class FWaaSL3PluginApi(api.FWaaSPluginApiMixin):
    """Agent side of the FWaaS agent to FWaaS Plugin RPC API."""

    def __init__(self, topic, host):
        super(FWaaSL3PluginApi, self).__init__(topic, host)

    def get_firewalls_for_tenant(self, context, **kwargs):
        """Get the Firewalls with rules from the Plugin to send to driver."""
        LOG.debug(_("Retrieve Firewall with rules from Plugin"))

        return self.call(context,
                         self.make_msg('get_firewalls_for_tenant',
                                       host=self.host))

    def get_tenants_with_firewalls(self, context, **kwargs):
        """Get all Tenants that have Firewalls configured from plugin."""
        LOG.debug(_("Retrieve Tenants with Firewalls configured from Plugin"))

        return self.call(context,
                         self.make_msg('get_tenants_with_firewalls',
                                       host=self.host))


class FWaaSL3AgentRpcCallback(api.FWaaSAgentRpcCallbackMixin):
    """FWaaS Agent support to be used by Neutron L3 agent."""

    def __init__(self, conf):
        LOG.debug(_("Initializing firewall agent"))
        self.conf = conf
        fwaas_driver_class_path = cfg.CONF.fwaas.driver
        self.fwaas_enabled = cfg.CONF.fwaas.enabled

        # None means l3-agent has no information on the server
        # configuration due to the lack of RPC support.
        if self.neutron_service_plugins is not None:
            fwaas_plugin_configured = (constants.FIREWALL
                                       in self.neutron_service_plugins)
            if fwaas_plugin_configured and not self.fwaas_enabled:
                msg = _("FWaaS plugin is configured in the server side, but "
                        "FWaaS is disabled in L3-agent.")
                LOG.error(msg)
                raise SystemExit(1)
            self.fwaas_enabled = self.fwaas_enabled and fwaas_plugin_configured

        if self.fwaas_enabled:
            try:
                self.fwaas_driver = importutils.import_object(
                    fwaas_driver_class_path)
                LOG.debug(_("FWaaS Driver Loaded: '%s'"),
                          fwaas_driver_class_path)
            except ImportError:
                msg = _('Error importing FWaaS device driver: %s')
                raise ImportError(msg % fwaas_driver_class_path)
        self.services_sync = False
        self.root_helper = config.get_root_helper(conf)
        # setup RPC to msg fwaas plugin
        self.fwplugin_rpc = FWaaSL3PluginApi(topics.FIREWALL_PLUGIN,
                                             conf.host)
        super(FWaaSL3AgentRpcCallback, self).__init__(host=conf.host)

    def _has_router_insertion_fields(self, fw):
        return 'add-router-ids' in fw

    def _get_router_ids_for_fw(self, context, fw, to_delete=False):
        """Return the router_ids either from fw dict or tenant routers."""
        if self._has_router_insertion_fields(fw):
            # it is a new version of plugin 
            return (fw['del-router-ids'] if to_delete
                    else fw['add-router-ids'])
        else:
            # we are in a upgrade and msg from older version of plugin 
            try:
                routers = self.plugin_rpc.get_routers(context)
            except Exception:
                LOG.exception(
                    _("FWaaS RPC failure in _get_router_ids_for_fw "
                        "for firewall: %(fwid)s"),
                    {'fwid': fw['id']})
                self.services_sync = True
            return [
                router['id']
                for router in routers
                if router['tenant_id'] == fw['tenant_id']]

    def _get_router_info_list_for_tenant(self, router_ids, tenant_id):
        """Returns the list of router info objects on which to apply the fw."""
        root_ip = ip_lib.IPWrapper(self.root_helper)
        local_ns_list = root_ip.get_namespaces(
            self.root_helper) if self.conf.use_namespaces else []

        router_info_list = []
        # Pick up namespaces for Tenant Routers
        for rid in router_ids:
            # for routers without an interface - get_routers returns
            # the router - but this is not yet populated in router_info
            if rid not in self.router_info:
                continue
            self.router_info[rid].fip_exist = False
            rtr_2_fip_name = self.get_rtr_int_device_name(rid)
            if ip_lib.device_exists(rtr_2_fip_name, self.root_helper,
                                    namespace=self.router_info[rid].ns_name):
                self.router_info[rid].fip_exist = True
            if self.router_info[rid].use_namespaces:
                router_ns = self.router_info[rid].ns_name
                if router_ns in local_ns_list:
                    router_info_list.append(self.router_info[rid])
            else:
                router_info_list.append(self.router_info[rid])
        return router_info_list

    def _invoke_driver_for_sync_from_plugin(self, ctx, router_info_list, fw):
        """Invoke the delete driver method for status of PENDING_DELETE and
        update method for all other status to (re)apply on driver which is
        Idempotent.
        """
        if fw['status'] == constants.PENDING_DELETE:
            try:
                self.fwaas_driver.delete_firewall(
                    self.conf.agent_mode,
                    router_info_list,
                    fw)
                self.fwplugin_rpc.firewall_deleted(
                    ctx,
                    fw['id'])
            except fw_ext.FirewallInternalDriverError:
                LOG.error(_("Firewall Driver Error on fw state %(fwmsg)s "
                            "for fw: %(fwid)s"),
                          {'fwmsg': fw['status'], 'fwid': fw['id']})
                self.fwplugin_rpc.set_firewall_status(
                    ctx,
                    fw['id'],
                    constants.ERROR)
        else:
            # PENDING_UPDATE, PENDING_CREATE, ...
            try:
                self.fwaas_driver.update_firewall(
                    self.conf.agent_mode,
                    router_info_list,
                    fw)
                if fw['admin_state_up']:
                    status = constants.ACTIVE
                else:
                    status = constants.DOWN
            except fw_ext.FirewallInternalDriverError:
                LOG.error(_("Firewall Driver Error on fw state %(fwmsg)s "
                            "for fw: %(fwid)s"),
                          {'fwmsg': fw['status'], 'fwid': fw['id']})
                status = constants.ERROR

            self.fwplugin_rpc.set_firewall_status(
                ctx,
                fw['id'],
                status)

    def _process_router_add(self, ri):
        """On router add, get fw with rules from plugin and update driver."""
        LOG.debug(_("Process router add, router_id: '%s'"), ri.router['id'])
        router_ids = ri.router['id']

        router_info_list = self._get_router_info_list_for_tenant(
            [router_ids],
            ri.router['tenant_id'])
        if router_info_list:
            # Get the firewall with rules
            # for the tenant the router is on.
            ctx = context.Context('', ri.router['tenant_id'])
            fw_list = self.fwplugin_rpc.get_firewalls_for_tenant(ctx)
            for fw in fw_list:
                if self._has_router_insertion_fields(fw):
                    # if router extension present apply only if router in fw 
                    if (not (router_ids in fw['add-router-ids']) and
                        not (router_ids in fw['del-router-ids'])):
                        continue
                self._invoke_driver_for_sync_from_plugin(
                    ctx,
                    router_info_list,
                    fw)
                # router can be present only on one fw 
                return

    def process_router_add(self, ri):
        """On router add, get fw with rules from plugin and update driver.
        Handles agent restart, when a router is added, query the plugin to
        check if this router is in the router list for any firewall. If so
        install firewall rules on this router.
        """
        # avoid msg to plugin when fwaas is not configured
        if not self.fwaas_enabled:
            return
        try:
            # TODO(sridar): as per discussion with pc_m, we may want to hook 
            # this up to the l3 agent observer notification 
            self._process_router_add(ri)
        except Exception:
            LOG.exception(
                _("FWaaS RPC info call failed for '%s'."),
                ri.router['id'])
            self.services_sync = True

    def process_services_sync(self, ctx):
        """On RPC issues sync with plugin and apply the sync data."""
        # avoid msg to plugin when fwaas is not configured
        if not self.fwaas_enabled:
            return
        try:
            # get the list of tenants with firewalls configured
            # from the plugin
            tenant_ids = self.fwplugin_rpc.get_tenants_with_firewalls(ctx)
            LOG.debug(_("Tenants with Firewalls: '%s'"), tenant_ids)
            for tenant_id in tenant_ids:
                ctx = context.Context('', tenant_id)
                fw_list = self.fwplugin_rpc.get_firewalls_for_tenant(ctx)
                for fw in fw_list:
                    if fw['status'] == constants.PENDING_DELETE:
                        self.delete_firewall(ctx, fw, self.host)
                    # no need to apply sync data for ACTIVE fw 
                    elif fw['status'] != constants.ACTIVE:
                        self.update_firewall(ctx, fw, self.host)
                self.services_sync = False
        except Exception:
            LOG.exception(_("Failed fwaas process services sync"))
            self.services_sync = True

    @log.log
    def create_firewall(self, context, firewall, host):
        """Handle Rpc from plugin to create a firewall."""
        router_ids = self._get_router_ids_for_fw(context, firewall)
        if not router_ids:
            return
        router_info_list = self._get_router_info_list_for_tenant(
            router_ids,
            firewall['tenant_id'])
        LOG.debug("Create: Add firewall on Router List: '%s'",
            [ri.router['id'] for ri in router_info_list])
        # call into the driver 
        try:
            self.fwaas_driver.create_firewall(
                self.conf.agent_mode,
                router_info_list,
                firewall)
            if firewall['admin_state_up']:
                status = constants.ACTIVE
            else:
                status = constants.DOWN
        except fw_ext.FirewallInternalDriverError:
            LOG.error(_("Firewall Driver Error for create_firewall "
                          "for firewall: %(fwid)s"),
                          {'fwid': firewall['id']})
            status = constants.ERROR

        try:
            # send status back to plugin 
            self.fwplugin_rpc.set_firewall_status(
                context,
                firewall['id'],
                status)
        except Exception:
            LOG.exception(
                _("FWaaS RPC failure in create_firewall "
                    "for firewall: %(fwid)s"),
                    {'fwid': firewall['id']})
            self.services_sync = True

    @log.log
    def update_firewall(self, context, firewall, host):
        """Handle Rpc from plugin to update a firewall."""
        
        status = ""
        if self._has_router_insertion_fields(firewall):
            # with the router_ids extension, we may need to delete and add 
            # based on the list of routers. On the older version, we just 
            # update (add) all routers on the tenant - delete not needed.
            router_ids = self._get_router_ids_for_fw(
                context, firewall, to_delete=True)
            if router_ids:
                router_info_list = self._get_router_info_list_for_tenant(
                    router_ids,
                    firewall['tenant_id'])
                # remove the firewall from this set of routers 
                # but no ack sent yet, check if we need to add 
                LOG.debug("Update: Delete firewall on Router List: '%s'",
                    [ri.router['id'] for ri in router_info_list])
                try:
                    self.fwaas_driver.delete_firewall(
                        self.conf.agent_mode,
                        router_info_list,
                        firewall)
                    if firewall['last-router']:
                        status = constants.INACTIVE
                    elif firewall['admin_state_up']:
                        status = constants.ACTIVE
                    else:
                        status = constants.DOWN
                except fw_ext.FirewallInternalDriverError:
                    LOG.error(_("Firewall Driver Error for "
                                  "update_firewall for firewall: "
                                  "%(fwid)s"),
                        {'fwid': firewall['id']})
                    status = constants.ERROR
        # the add 
        if status not in (constants.ERROR, constants.INACTIVE):
            router_ids = self._get_router_ids_for_fw(context, firewall)
            if router_ids:
                router_info_list = self._get_router_info_list_for_tenant(
                    router_ids,
                    firewall['tenant_id'])
                LOG.debug("Update: Add firewall on Router List: '%s'",
                    [ri.router['id'] for ri in router_info_list])
                # call into the driver 
                try:
                    self.fwaas_driver.update_firewall(
                        self.conf.agent_mode,
                        router_info_list,
                        firewall)
                    if firewall['admin_state_up']:
                        status = constants.ACTIVE
                    else:
                        status = constants.DOWN
                except fw_ext.FirewallInternalDriverError:
                    LOG.error(_("Firewall Driver Error for "
                                  "update_firewall for firewall: "
                                  "%(fwid)s"),
                                  {'fwid': firewall['id']})
                    status = constants.ERROR

        try:
            # send status back to plugin 
            self.fwplugin_rpc.set_firewall_status(
                context,
                firewall['id'],
                status)
        except Exception:
            LOG.exception(
                _("FWaaS RPC failure in update_firewall "
                    "for firewall: %(fwid)s"),
                    {'fwid': firewall['id']})
            self.services_sync = True

    @log.log
    def delete_firewall(self, context, firewall, host):
        """Handle Rpc from plugin to delete a firewall."""
        
        router_ids = self._get_router_ids_for_fw(
            context, firewall, to_delete=True)
        if router_ids:
            router_info_list = self._get_router_info_list_for_tenant(
                router_ids,
                firewall['tenant_id'])
            LOG.debug("Delete: Delete firewall on Router List: '%s'",
                [ri.router['id'] for ri in router_info_list])
            # call into the driver 
            try:
                self.fwaas_driver.delete_firewall(
                    self.conf.agent_mode,
                    router_info_list,
                    firewall)
                if firewall['admin_state_up']:
                    status = constants.ACTIVE
                else:
                    status = constants.DOWN
            except fw_ext.FirewallInternalDriverError:
                LOG.error(_("Firewall Driver Error for delete_firewall "
                              "for firewall: %(fwid)s"),
                              {'fwid': firewall['id']})
                status = constants.ERROR

            try:
                # send status back to plugin 
                if status in [constants.ACTIVE, constants.DOWN]:
                    self.fwplugin_rpc.firewall_deleted(context, firewall['id'])
                else:
                    self.fwplugin_rpc.set_firewall_status(
                        context,
                        firewall['id'],
                        status)
            except Exception:
                LOG.exception(
                    _("FWaaS RPC failure in delete_firewall "
                        "for firewall: %(fwid)s"),
                        {'fwid': firewall['id']})
                self.services_sync = True 
