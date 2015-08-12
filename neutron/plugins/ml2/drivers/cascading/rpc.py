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

from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.openstack.common import log as logging


LOG = logging.getLogger(__name__)


class Cascading2AgentNotifyAPI(n_rpc.RpcProxy):
    BASE_RPC_API_VERSION = '1.0'

    def __init__(self, topic=topics.AGENT):
        super(Cascading2AgentNotifyAPI, self).__init__(
            topic=topic, default_version=self.BASE_RPC_API_VERSION)

        self.topic_network_update = topics.get_topic_name(topic,
                                                          topics.NETWORK,
                                                          topics.UPDATE)

        self.topic_subnet_update = topics.get_topic_name(topic,
                                                          topics.SUBNET,
                                                          topics.UPDATE)

        self.topic_subnet_delete = topics.get_topic_name(topic,
                                                         topics.SUBNET,
                                                         topics.DELETE)

        self.topic_port_update = topics.get_topic_name(topic,
                                                         topics.PORT,
                                                         topics.UPDATE)

        self.topic_port_delete = topics.get_topic_name(topic,
                                                         topics.PORT,
                                                         topics.DELETE)


    def network_update(self, context, network):
        self.fanout_cast(context,
                         self.make_msg('network_update',
                                       network=network),
                         topic=self.topic_network_update)


    def subnet_update(self, context, subnet, original_subnet):
        self.fanout_cast(context,
                         self.make_msg('subnet_update',
                                       subnet=subnet, original_subnet = original_subnet),
                         topic=self.topic_network_update)

    def subnet_delete(self, context, subnet_id):
        self.fanout_cast(context,
                         self.make_msg('subnet_delete',
                                       subnet_id=subnet_id),
                         topic=self.topic_subnet_delete)

    def port_update(self, context, port, host=None):
        if host:
            LOG.debug(_("Port update notify to host:%(host)s, port:%(port)s"), {'port': port,'host':host})
            self.cast(context,
                  self.make_msg('port_update', port=port),
                  topic='%s.%s' % (self.topic_port_update, host))
        else:
            LOG.debug(_("Port update cast to all, port:%(port)s"), {'port': port})
            self.fanout_cast(context,
                  self.make_msg('port_update', port=port),
                  topic=self.topic_port_update)

    def port_delete(self, context, port, host=None):
        if host:
            LOG.debug(_("Port delete notify to host:%(host)s, port:%(port)s"), {'port': port,'host':host})
            self.cast(context,
                  self.make_msg('port_delete', port=port),
                  topic='%s.%s' % (self.topic_port_delete, host))
        else:
            LOG.debug(_("Port delete cast to all, port:%(port)s"), {'port': port})
            self.fanout_cast(context,
                  self.make_msg('port_update',port=port),
                  topic=self.topic_port_delete)

