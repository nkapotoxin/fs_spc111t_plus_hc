# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2014 OpenStack Foundation
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

from neutron.agent import l3_agent
from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils
from neutron.common import constants
from neutron.openstack.common import log as logging
from neutron.services.qos.drivers import qos_base


LOG = logging.getLogger(__name__)


class LinuxTcQoSDriver(qos_base.QoSDriver):
    def __init__(self, bridge_manager, root_helper):
        self.br_mgr = bridge_manager # not used currently
        self.root_helper = root_helper

    def delete_qos_for_network(self, network_id):
        # not support network QoS
        pass

    def network_qos_updated(self, policy, network_id):
        # not support network QoS
        pass

    def _get_interface_by_owner(self, port_id, device_owner):
        DEVNAMELEN = 14
        interface = None
        if device_owner == constants.DEVICE_OWNER_ROUTER_INTF:
            interface = (l3_agent.INTERNAL_DEV_PREFIX + port_id)[:DEVNAMELEN]
        elif device_owner == constants.DEVICE_OWNER_ROUTER_GW:
            interface = (l3_agent.EXTERNAL_DEV_PREFIX + port_id)[:DEVNAMELEN]
        return interface

    def _get_router_namespace(self, device_id):
        return l3_agent.NS_PREFIX + device_id

    def delete_qos_for_port(self, port_id, **kwargs):
        port = kwargs['port']
        interface = self._get_interface_by_owner(port_id,
                                                 port['device_owner'])
        if not interface:
            return
        namespace = self._get_router_namespace(port['device_id'])
        ns_wrapper = ip_lib.IPWrapper(self.root_helper,
                                      namespace=namespace)
        try:
            # check_exit_code=False because only RuntimeError is 
            # "qdisc not found" and it's OK.
            ns_wrapper.netns.execute(['tc', 'qdisc', 'delete',
                                      'dev', interface, 'root'],
                                     check_exit_code=False)
        except Exception as e:
            LOG.warn('failed to apply tc %s' % e)

    def port_qos_updated(self, policy, port_id, **kwargs):
        port = kwargs['port']
        interface = self._get_interface_by_owner(port_id,
                                                 port['device_owner'])
        if not interface:
            return
        namespace = self._get_router_namespace(port['device_id'])
        rate = policy[constants.TYPE_QOS_POLICY_TC_RATE]
        latency = policy[constants.TYPE_QOS_POLICY_TC_LATENCY]
        burst = policy[constants.TYPE_QOS_POLICY_TC_BURST]
        ns_wrapper = ip_lib.IPWrapper(self.root_helper,
                                      namespace=namespace)
        try:
            ns_wrapper.netns.execute(['tc', 'qdisc', 'replace',
                                      'dev', interface, 'root',
                                      'tbf', 'rate', rate, 'latency', latency,
                                      'burst', burst],
                                      check_exit_code=True)
        except Exception as e:
            LOG.warn('failed to apply tc %s' % e)