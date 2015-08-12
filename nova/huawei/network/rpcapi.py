# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012, Red Hat, Inc.
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

"""
Client side of the network RPC API.
"""

from oslo.config import cfg

from nova.network import rpcapi as core_rpcapi

rpcapi_opts = [
    cfg.StrOpt('network_topic',
               default='network',
               help='the topic network nodes listen on'),
    cfg.BoolOpt('multi_host',
                default=False,
                help='Default value for multi_host in networks. Also, if set, '
                     'some rpc network calls will be sent directly to host.'),
    ]

CONF = cfg.CONF

rpcapi_cap_opt = cfg.StrOpt('network',
                            help='Set a version cap for messages sent to network services')
CONF.register_opt(rpcapi_cap_opt, 'upgrade_levels')


class HuaweiNetworkAPI(core_rpcapi.NetworkAPI):

    BASE_RPC_API_VERSION = '1.0'

    VERSION_ALIASES = {
        'grizzly': '1.9',
        }

    def __init__(self, topic=None):
        super(HuaweiNetworkAPI, self).__init__()

    def update_interface_address(self, ctxt, instance_uuid, vif_uuid,
                                 network_uuid, address, host=None):
        cctxt = self.client.prepare(server=host, version='1.2')
        return cctxt.call(ctxt, 'update_interface_address',
                          instance_uuid=instance_uuid,
                          vif_uuid=vif_uuid,
                          network_uuid=network_uuid,
                          address=address)
