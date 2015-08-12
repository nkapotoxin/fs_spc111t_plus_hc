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

    def get_firewall_by_id(self, context, firewall_id):
        """Get the Firewalls with rules from the Plugin to send to driver."""
        LOG.debug(_("Retrieve Firewall from Plugin"))

        return self.call(context,
                         self.make_msg('get_firewall_by_id',
                                       firewall_id=firewall_id,
                                       host=self.host))

    def get_firewall_policy_by_id(self, context, fwp_id):
        """Get the Firewall policy with rules from the Plugin to send to driver."""
        LOG.debug(_("Retrieve Firewall policy with rules from Plugin"))

        return self.call(context,
                         self.make_msg('get_firewall_policy_by_id',
                                       firewall_policy_id=fwp_id,
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

        # cascade para
        self.firewall_rules_map = {}
        self.cache_firewall_rules_map()

        # in cascade situation, void second rpc message
        self.processed = False

        # setup RPC to msg fwaas plugin
        self.fwplugin_rpc = FWaaSL3PluginApi(topics.FIREWALL_PLUGIN,
                                             conf.host)
        super(FWaaSL3AgentRpcCallback, self).__init__(host=conf.host)

    def _invoke_process_cascaded_for_plugin_api(self, context, fw, func_name):
        """Invoke driver method for plugin API and provide status back."""
        LOG.debug(_("%(func_name)s from agent for fw: %(fwid)s"),
                  {'func_name': func_name, 'fwid': fw['id']})
        # void second rpc
        if self.processed is True:
            return
        self.processed = True
        try:
            # call into the driver
            try:
                # begin process
                if func_name == 'create_firewall':
                    self._create_firewall(context, fw)
                elif func_name == 'update_firewall':
                    self._update_firewall(context, fw)
                else:
                    self._delete_firewall(context, fw)

                if fw['admin_state_up']:
                    status = constants.ACTIVE
                else:
                    status = constants.DOWN

            except fw_ext.FirewallInternalDriverError:
                LOG.error(_("Firewall Driver Error for %(func_name)s "
                            "for fw: %(fwid)s"),
                          {'func_name': func_name, 'fwid': fw['id']})
                status = constants.ERROR
            # delete needs different handling
            if func_name == 'delete_firewall':
                if status in [constants.ACTIVE, constants.DOWN]:
                    self.fwplugin_rpc.firewall_deleted(context, fw['id'])

            if status == constants.DOWN:
                self.fwplugin_rpc.set_firewall_status(
                    context,
                    fw['id'],
                    status)

        except Exception:
            LOG.exception(
                _("FWaaS RPC failure in %(func_name)s for fw: %(fwid)s"),
                {'func_name': func_name, 'fwid': fw['id']})

        self.processed = False
        return

    def _create_firewall(self, ctx, fw):
        # create rules
        firewall_rule_list = fw['firewall_rule_list']
        self.create_cascaded_rules(firewall_rule_list)

        # create policy
        rules_id = [fr['id'] for fr in firewall_rule_list]
        self.create_cascaded_policy_with_rules(
            ctx, fw['firewall_policy_id'], rules_id)

        # create firewall
        self._create_cascaded_firewall(ctx, fw)

    def _update_firewall(self, ctx, fw):
        fwr_list = fw['firewall_rule_list']
        self.create_cascaded_rules(fwr_list)

        rules_id = [fr['id'] for fr in fwr_list]
        policy_ret = self.create_cascaded_policy_with_rules(
            ctx, fw['firewall_policy_id'], rules_id)

        cascaded_fwp_id = policy_ret.get('firewall_policy')['id']
        update_fw_req = {'firewall': {
            'firewall_policy_id': cascaded_fwp_id,
            'admin_state_up': fw['admin_state_up'],
            'description': fw['description']}}

        self._update_cascaded_firewall(fw['id'], update_fw_req)

    def _delete_firewall(self, ctx, fw):
        self._delete_cascaded_firewall(fw['id'])

    def create_firewall(self, context, firewall, host):
        """Handle Rpc from plugin to create a firewall."""
        return self._invoke_process_cascaded_for_plugin_api(
            context,
            firewall,
            'create_firewall')

    def update_firewall(self, context, firewall, host):
        """Handle Rpc from plugin to update a firewall."""
        return self._invoke_process_cascaded_for_plugin_api(
            context,
            firewall,
            'update_firewall')

    def delete_firewall(self, context, firewall, host):
        """Handle Rpc from plugin to delete a firewall."""
        return self._invoke_process_cascaded_for_plugin_api(
            context,
            firewall,
            'delete_firewall')

    def create_cascaded_rule(self, rule):
        rule_req = self.get_rule_req(rule)
        rule_ret = self.csd_client('create_firewall_rule', rule_req)
        if(not rule_ret or
          (rule_ret and (not rule_ret.get('firewall_rule')))):
            LOG.error(_("cascaded firewall rule created failed, "
                        "cascading rule id:%s"), rule)
            raise fw_ext.FirewallInternalDriverError("Create rule")

        LOG.debug(_('Create cascaded rule, Response:%s'),
                  str(rule_ret))

        cascaded_rule_name = self._get_cascaded_rule_name(rule['id'])
        self.firewall_rules_map[cascaded_rule_name] = rule_ret.get('firewall_rule')

        return

    def create_cascaded_rules(self, cascading_policy_rule_list):
        # create rules
        for rule in cascading_policy_rule_list:
            self.create_cascaded_rule(rule)

        LOG.debug(_("firewall_rules_map:%s"), self.firewall_rules_map)

        return

    def create_cascaded_policy_with_rules(
            self, ctx, cascading_policy_id, rules_id):

        rules_id_list = []
        LOG.debug(_("firewall_rules_map:%s"), self.firewall_rules_map)

        for rule_id in rules_id:
            rule_name = self._get_cascaded_rule_name(rule_id)
            cascaded_rule = self.firewall_rules_map.get(rule_name, None)
            rules_id_list.append(cascaded_rule['id'])
        fwp_info = self.list_cascading_policy_by_id(
            ctx, cascading_policy_id)

        policy_req = self.get_policy_req(
            fwp_info, rules_id_list)

        policy_ret = self.csd_client('create_firewall_policy', policy_req)
        if(not policy_ret or
          (policy_ret and (not policy_ret.get('firewall_policy')))):
            LOG.error(_("cascaded firewall policy created failed, "
                        "cascading policy id:%s"), fwp_info)
            raise fw_ext.FirewallInternalDriverError("Create cascaded policy")

        LOG.debug(_('Create cascaded policy with rules, Response:%s'),
                  str(policy_ret))

        return policy_ret

    def _create_cascaded_firewall(self, ctx, fw):
        fwp_id = fw['firewall_policy_id']
        cacaded_fwp_info = self._get_cascaded_policy_info(fwp_id)
        cacaded_fwp_id = cacaded_fwp_info['id']

        firewall_req = self.get_firewall_req(fw, cacaded_fwp_id)

        fw_ret = self.csd_client('create_firewall', firewall_req)

        if(not fw_ret or
          (fw_ret and (not fw_ret.get('firewall')))):
            LOG.error(_("cascaded firewall created failed, "
                        "cascading firewall id:%s"), fw)
            raise fw_ext.FirewallInternalDriverError("Create cascaded firewall")

        LOG.debug(_('Create cascaded fw, Response:%s'),
                  str(fw_ret))

        return

    def _update_cascaded_firewall(self, cascading_fw_id, update_fw_req):
        cascaded_fw_info = self._get_cascaded_firewall_info(cascading_fw_id)
        cascaded_fw_id = cascaded_fw_info.get('id')

        cascaded_fw = self.csd_client('update_firewall', cascaded_fw_id, update_fw_req)

        LOG.debug(_('Update cascaded fw, Response:%s'),
                  str(cascaded_fw))

        return

    def get_rule_req(self, rule):
        rule_req = {'firewall_rule': {
                    'protocol': rule['protocol'],
                    'description': rule['description'],
                    'ip_version': rule['ip_version'],
                    'tenant_id': rule['tenant_id'],
                    'enabled': rule['enabled'],
                    'source_ip_address': rule['source_ip_address'],
                    'destination_ip_address': rule['destination_ip_address'],
                    'action': rule['action'],
                    'shared': rule['shared'],
                    'source_port': rule['source_port'],
                    'destination_port': rule['destination_port'],
                    'name': self._get_cascaded_rule_name(rule['id'])}}

        return rule_req

    def get_policy_req(self, policy, rule_list):
        policy_req = {'firewall_policy': {
                      'name': self._get_cascaded_policy_name(policy['id']),
                      'firewall_rules': rule_list,
                      'tenant_id': policy['tenant_id'],
                      'audited': policy['audited'],
                      'shared': policy['shared'],
                      'description': policy['description']}}

        return policy_req

    def get_firewall_req(self, fw, fwp_id):
        firewall_req = {'firewall': {
                        'name': self._get_cascaded_firewall_name(fw['id']),
                        'admin_state_up': fw['admin_state_up'],
                        'tenant_id': fw['tenant_id'],
                        'firewall_policy_id': fwp_id,
                        'description': fw['description']}}

        return firewall_req

    def list_cascading_policy_by_id(self, ctx, policy_id):
        return self.fwplugin_rpc.get_firewall_policy_by_id(
            ctx, policy_id)

    def list_cascading_firewall_by_id(self, ctx, fw_id):
        return self.fwplugin_rpc.get_firewall_by_id(
            ctx, fw_id)

    def _get_cascaded_rule_name(self, id):
        return 'firewall_rule@'+id

    def _get_cascaded_policy_name(self, id):
        return 'firewall_policy@'+id

    def _get_cascaded_firewall_name(self, id):
        return 'firewall@'+id

    def _get_cascaded_rule_info(self, rule_id):
        rule_ret = self.csd_client('list_firewall_rules',
                                   **{'name': self._get_cascaded_rule_name(rule_id)})

        if len(rule_ret['firewall_rules']):
            return rule_ret['firewall_rules'][0]

        return None

    def _get_cascaded_policy_info(self, policy_id):
        policy_ret = self.csd_client('list_firewall_policies',
            **{'name': self._get_cascaded_policy_name(policy_id)})

        if len(policy_ret['firewall_policies']):
            return policy_ret['firewall_policies'][0]

        return None

    def _get_cascaded_firewall_info(self, firewall_id):
        firewall_ret = self.csd_client('list_firewalls',
            **{'name': self._get_cascaded_firewall_name(firewall_id)})

        if len(firewall_ret['firewalls']):
            return firewall_ret['firewalls'][0]

        return None

    def _delete_cascaded_firewall(self, cascading_fw_id):
        cascaded_fw_info = self._get_cascaded_firewall_info(cascading_fw_id)

        if cascaded_fw_info is None:
            LOG.error(_("cascaded firewall not found, "
                        "cascading firewall id:%s"), cascading_fw_id)
            return

        cascaded_fw_id = cascaded_fw_info.get('id')
        self.csd_client('delete_firewall', cascaded_fw_id)

        LOG.debug(_('Delete cascaded fw, Response:%s'),
                  str(cascaded_fw_id))

    def cache_firewall_rules_map(self):
        try:
            params_limit = self.get_params_limit()
            if params_limit:
                frs_ret = self.csd_client('list_firewall_rules', params_limit)
            else:
                frs_ret = self.csd_client('list_firewall_rules')

            if(not frs_ret or
                    (frs_ret and (not frs_ret.get('firewall_rules')))):
                return

            rules_info = frs_ret.get('firewall_rules')
            for rule in rules_info:
                if not self.validate_firewall_rule_name(rule['name']):
                    continue
                self.firewall_rules_map[rule['name']] = rule
            LOG.debug(_("recover the firewall_rules_map:%s"),
                      self.firewall_rules_map)
        except Exception:
            LOG.warn(_("Cascaded environment have not enable fw"))

    def validate_firewall_rule_name(self, name):
        if name and name.startswith('firewall_rule@'):
            return True
        return False

    def validate_firewall_policy_name(self, name):
        if name and name.startswith('firewall_policy@'):
            return True
        return False

    def _cascaded_clean_task(self, context):
        # avoid msg to plugin when fwaas is not configured
        if not self.fwaas_enabled:
            return
        try:
            fw_ret = self.csd_client('list_firewalls')
            LOG.debug(_("cascaded firewall:%s"), fw_ret)
            fwps_used_by_fw = []
            fw_info = fw_ret.get('firewalls')
            for fw in fw_info:
                fwps_used_by_fw.append(fw.get('firewall_policy_id'))
                fw_id = fw.get('name')[9:]
                status = fw.get('status')
                if status in (constants.ACTIVE, constants.DOWN, constants.ERROR):
                    self.fwplugin_rpc.set_firewall_status(context, fw_id, status)

            self._cascaded_clean_unused_policies_with_rules(context, fwps_used_by_fw)
        except Exception:
            pass

    def _cascaded_clean_unused_policies_with_rules(self, context, fwps_used_by_fw):
        # get the cascaded policies
        fwps_ret = self.csd_client('list_firewall_policies')
        LOG.debug(_("cascaded firewall policies:%s"), fwps_ret)
        if(not fwps_ret or
          (fwps_ret and (not fwps_ret.get('firewall_policies')))):
            return
        fwps_info = fwps_ret.get('firewall_policies')

        # Empty the unused policies and collect the related unused rules
        # then delete those unused policies
        fwp_clean_rules_req = {'firewall_policy': {u'firewall_rules': None}}
        fwrs_to_clean = []
        for fwp in fwps_info:
            if fwp['id'] in fwps_used_by_fw:
                continue
            if not self.validate_firewall_policy_name(fwp['name']):
                continue
            self.csd_client('update_firewall_policy',
                fwp['id'], fwp_clean_rules_req)
            fwrs_to_clean = fwrs_to_clean + fwp['firewall_rules']
            self.csd_client('delete_firewall_policy', fwp['id'])
        LOG.debug(_("Collect rules to be clean:%s"), fwrs_to_clean)

        # delete those collected unused rules
        for name, info in self.firewall_rules_map.items():
            cascaded_fwr_id = info.get('id')
            if cascaded_fwr_id not in fwrs_to_clean:
                continue
            self.csd_client('delete_firewall_rule', cascaded_fwr_id)
            del self.firewall_rules_map[name]
            fwrs_to_clean.remove(cascaded_fwr_id)

        for cascaded_fwr_id in fwrs_to_clean:
            self.csd_client('delete_firewall_rule', cascaded_fwr_id)
