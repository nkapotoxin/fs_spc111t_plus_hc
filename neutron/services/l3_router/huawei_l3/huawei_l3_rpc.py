# Copyright (c) 2012 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from neutron.common import rpc as n_rpc
from neutron import manager
from neutron.openstack.common import log as logging
from neutron.plugins.common import constants as plugin_constants



LOG = logging.getLogger(__name__)


class L3RpcCallback(n_rpc.RpcCallback):
    """L3 agent RPC callback in plugin implementations."""

    # 1.0  L3PluginApi BASE_RPC_API_VERSION
    # 1.1  Support update_floatingip_statuses
    # 1.2 Added methods for DVR support
    # 1.3 Added a method that returns the list of activated services
    # 1.4 Added L3 HA update_router_state
    RPC_API_VERSION = '1.4'

    @property
    def plugin(self):
        if not hasattr(self, '_plugin'):
            self._plugin = manager.NeutronManager.get_plugin()
        return self._plugin

    @property
    def l3plugin(self):
        if not hasattr(self, '_l3plugin'):
            self._l3plugin = manager.NeutronManager.get_service_plugins()[
                plugin_constants.L3_ROUTER_NAT]
        return self._l3plugin

    def update_router_status(self, context, **kwargs):
        router_id = kwargs.get('router_id')
        status = kwargs.get('status')
        #host = kwargs.get('host')

        return self.l3plugin.update_router_status(context, router_id, status)