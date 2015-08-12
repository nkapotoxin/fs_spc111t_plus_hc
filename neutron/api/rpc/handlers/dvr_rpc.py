# Copyright 2014, Hewlett-Packard Development Company, L.P.
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

from neutron.common import log
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron import manager
from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)


class DVRServerRpcApiMixin(object):
    """Agent-side RPC (stub) for agent-to-plugin interaction."""

    DVR_RPC_VERSION = "1.0"

    @log.log
    def get_dvr_mac_address_by_host(self, context, host):
        return self.call(context,
                         self.make_msg('get_dvr_mac_address_by_host',
                                       host=host),
                         version=self.DVR_RPC_VERSION)

    @log.log
    def get_dvr_mac_address_list(self, context):
        return self.call(context,
                         self.make_msg('get_dvr_mac_address_list'),
                         version=self.DVR_RPC_VERSION)

    @log.log
    def get_ports_on_host_by_subnet(self, context, host, subnet):
        return self.call(context,
                         self.make_msg(
                             'get_ports_on_host_by_subnet',
                             host=host,
                             subnet=subnet),
                         version=self.DVR_RPC_VERSION)

    @log.log
    def get_subnet_for_dvr(self, context, subnet):
        return self.call(context,
                         self.make_msg('get_subnet_for_dvr',
                                       subnet=subnet),
                         version=self.DVR_RPC_VERSION)


class DVRServerRpcCallback(n_rpc.RpcCallback):
    """Plugin-side RPC (implementation) for agent-to-plugin interaction."""

    # History
    #   1.0 Initial version

    RPC_API_VERSION = "1.0"

    @property
    def plugin(self):
        if not getattr(self, '_plugin', None):
            self._plugin = manager.NeutronManager.get_plugin()
        return self._plugin

    def get_dvr_mac_address_list(self, context):
        return self.plugin.get_dvr_mac_address_list(context)

    def get_dvr_mac_address_by_host(self, context, **kwargs):
        host = kwargs.get('host')
        LOG.debug("DVR Agent requests mac_address for host %s", host)
        return self.plugin.get_dvr_mac_address_by_host(context, host)

    def get_ports_on_host_by_subnet(self, context, **kwargs):
        host = kwargs.get('host')
        subnet = kwargs.get('subnet')
        LOG.debug("DVR Agent requests list of VM ports on host %s", host)
        return self.plugin.get_ports_on_host_by_subnet(context,
            host, subnet)

    def get_subnet_for_dvr(self, context, **kwargs):
        subnet = kwargs.get('subnet')
        return self.plugin.get_subnet_for_dvr(context, subnet)


class DVRAgentRpcApiMixin(object):
    """Plugin-side RPC (stub) for plugin-to-agent interaction."""

    DVR_RPC_VERSION = "1.0"

    def _get_dvr_update_topic(self):
        return topics.get_topic_name(self.topic,
                                     topics.DVR,
                                     topics.UPDATE)

    def dvr_mac_address_update(self, context, dvr_macs):
        """Notify dvr mac address updates."""
        if not dvr_macs:
            return
        self.fanout_cast(context,
                         self.make_msg('dvr_mac_address_update',
                                       dvr_macs=dvr_macs),
                         version=self.DVR_RPC_VERSION,
                         topic=self._get_dvr_update_topic())


class DVRAgentRpcCallbackMixin(object):
    """Agent-side RPC (implementation) for plugin-to-agent interaction."""

    dvr_agent = None

    def dvr_mac_address_update(self, context, **kwargs):
        """Callback for dvr_mac_addresses update.

        :param dvr_macs: list of updated dvr_macs
        """
        dvr_macs = kwargs.get('dvr_macs', [])
        LOG.debug("dvr_macs updated on remote: %s", dvr_macs)
        if not self.dvr_agent:
            LOG.warn(_("DVR agent binding currently not set."))
            return
        self.dvr_agent.dvr_mac_address_update(dvr_macs)
