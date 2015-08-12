# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 OpenStack Foundation
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
#
# @author: Sean M. Collins, sean@coreitpro.com, Comcast #

from neutron.common import constants
from neutron.services.qos.drivers import sriov_qos_base as qos_base
from neutron.openstack.common import log as logging
from neutron.openstack.common import jsonutils
from neutron.agent.linux import ip_lib
from neutron.plugins.sriovnicagent.common import exceptions as exc

LOG = logging.getLogger(__name__)


class SRIOVQos:
    
    def __init__(self, eswitch_mgr, root_helper='sudo'):
        self.eswitch_mgr = eswitch_mgr
        self.root_helper = root_helper
    
    def set_qos_for_device(self, device, pci_slot, rate_limit):
        if self.eswitch_mgr.device_exists(device, pci_slot):
            try:
                self.eswitch_mgr.set_device_rate(device, pci_slot, rate_limit)
            except exc.SriovNicError:
                LOG.exception(_("Failed to set device %s rate"), device)
        else:
            LOG.error(_("Can not find device (%s)."), device)

    def delete_qos_for_device(self, device, pci_slot):
        self.set_qos_for_device(device, pci_slot, 0)


class MixingSriovQoSDriver(qos_base.SriovQoSDriver):
    
    def __init__(self, eswitch_mgr=None, root_helper='sudo'):
        # Quick lookup table for qoses that are
        # already present - help determine if it's a create
        # or update. RPC does not distinguish between updates and creates
        self.eswitch_mgr = eswitch_mgr
        self.root_helper = root_helper
        self.sriovQos = SRIOVQos(eswitch_mgr, root_helper)

    def create_qos_for_device(self, policy, device, pci_slot, **kwargs):
        
        tx_rate = policy.get(constants.TYPE_QOS_POLICY_TC_TX_RATE)
        tx_burst = policy.get(constants.TYPE_QOS_POLICY_TC_TX_BURST)
        rx_rate = policy.get(constants.TYPE_QOS_POLICY_TC_RX_RATE)
        rx_burst = policy.get(constants.TYPE_QOS_POLICY_TC_RX_BURST)

        if tx_rate:
            self.sriovQos.set_qos_for_device(device, pci_slot, int(tx_rate[:-7]) * 8)
        else:
            self.sriovQos.set_qos_for_device(device, pci_slot, 0)

    def delete_qos_for_device(self, device, pci_slot, **kwargs):
        LOG.debug(_("[delete qos for device] device: %s"), device)
        self.sriovQos.delete_qos_for_device(device, pci_slot)

    def device_qos_updated(self, policy, device, pci_slot, **kwargs):
        # Remove rate, create new one with the updated policy
        LOG.debug(_("[update qos for device] device: %s, qos_policy: %s"), device, policy)
        self.create_qos_for_device(policy, device, pci_slot, **kwargs)     

    def clear_all_qos(self):
        pci_slot_map = self.eswitch_mgr.get_pci_slot_map()
        if pci_slot_map:
            for pci_slot, embedded_switch in pci_slot_map.iteritems():
                try:
                    if embedded_switch.get_device_rate(pci_slot):
                        embedded_switch.set_device_rate(pci_slot, 0)
                except exc.SriovNicError:
                    LOG.exception(_("Failed to clear device %s rate"), pci_slot)

