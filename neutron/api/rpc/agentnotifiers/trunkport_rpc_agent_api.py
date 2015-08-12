#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.openstack.common import log as logging


LOG = logging.getLogger(__name__)


class TrunkportAgentNotifyAPI(n_rpc.RpcProxy):
    """API for plugin to notify Trunkport agent."""
    BASE_RPC_API_VERSION = '1.0'

    def __init__(self, topic=topics.AGENT):
        super(TrunkportAgentNotifyAPI, self).__init__(
            topic=topic, default_version=self.BASE_RPC_API_VERSION)
        self.topic_trunkport_update = topics.get_topic_name(topic,
                                                            topics.TRUNKPORT,
                                                            topics.UPDATE)

    def _notification_fanout(self, context, method, trunkport_ids):
        """Fanout port update all agents."""
        LOG.debug(_('Fanout notify agent topic %(topic)s the message '
                    '%(method)s on trunkports %(trunkport_ids)s'),
                  {'topic': topics.TRUNKPORT,
                   'method': method,
                   'trunkport_ids': trunkport_ids})
        self.fanout_cast(
            context, self.make_msg(method,
                                   trunkport_ids=trunkport_ids
                                   ),
            topic=self.topic_trunkport_update)
        LOG.debug('Fanout Done')

    def trunkports_updated(self, context, trunkport_ids):
        self._notification_fanout(context, 'trunkports_updated', trunkport_ids)
