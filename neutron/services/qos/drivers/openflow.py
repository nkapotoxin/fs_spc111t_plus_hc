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
from neutron.services.qos.drivers import qos_base
from neutron.openstack.common import log as logging
from neutron.openstack.common import jsonutils
from neutron.agent.linux import ovs_lib
from neutron.agent.linux import ip_lib

LOG = logging.getLogger(__name__)

class PortQos:
    def __init__(self, port_id, qos_id, other_config, queues, type):
        self.port_id = port_id
        self.qos_id = qos_id
        self.other_config = other_config
        self.queues = queues
        self.type = type

    def __str__(self):
        return ("port_id=" + self.port_id + ", qos_id=" +
                self.qos_id + ", other_config=" + self.other_config +
                ", queues=" + self.queues + ", type=" + self.type)

class OVSQos(ovs_lib.BaseOVS):

    def set_qos_for_interface(self, interface, rate_limit, burst_size):
        if not interface:
            return

        self.run_vsctl(['set', 'Interface', interface,
                        'ingress_policing_rate=%s'%rate_limit])
        self.run_vsctl(['set', 'Interface', interface,
                        'ingress_policing_burst=%s'%burst_size])

    def set_qos_for_port(self, port_name, port_id, rate_limit):
        #set qlen for interface if qlen equal zero
        if ip_lib.device_exists(port_name):
            device = ip_lib.IPDevice(port_name, self.root_helper)
            device.link.set_qlen(50000)
        else:
            LOG.error(_("Can not find device (%s)."), port_name)

        args = ['set', 'port', port_name, 'qos=@newqos', '--', '--id=@newqos',
                'create', 'qos', 'type=linux-htb',
                'other-config:max-rate=%s'%rate_limit,
                'external_ids:port-id=%s'%port_id,
                'queues=0=@q0', '--', '--id=@q0', 'create', 'queue',
                'other-config:min-rate=%s'%rate_limit,
                'other-config:max-rate=%s'%rate_limit]
        result = self.run_vsctl(args)
        if not result:
            LOG.error(_("Unable to set qos for %s(%s)."), (port_name, port_id))

        return result.split()

    def delete_qos_for_port(self, port_name, port_id):
        if port_name:
            self.run_vsctl(['set', 'port', port_name, 'qos=[]'])

        qos = self.get_qos_by_port(port_id)
        if not qos:
            return

        self.run_vsctl(['destroy', 'qos', qos.qos_id])
        for item in qos.queues.values():
            self.run_vsctl(['destroy', 'queue', item[1]])

    def get_qos_by_port(self, port_id):
        args = ['--format=json', '--', 'find', 'qos',
                'external_ids:port-id="%s"' % port_id]
        result = self.run_vsctl(args)
        if not result:
            return
        json_result = jsonutils.loads(result)
        try:
            # Retrieve the indexes of the columns we're looking for
            headings = json_result['headings']
            qos_idx = headings.index('_uuid')
            ext_ids_idx = headings.index('external_ids')
            other_idx = headings.index('other_config')
            queues_idx = headings.index('queues')
            type_idx = headings.index('type')
            # If data attribute is missing or empty the line below will raise
            # an exeception which will be captured in this block.
            # We won't deal with the possibility of ovs-vsctl return multiple
            # rows since the interface identifier is unique
            data = json_result['data'][0]
            qos_id = data[qos_idx][1]
            ext_id_dict = dict((item[0], item[1]) for item in
                               data[ext_ids_idx][1])
            port_id = ext_id_dict['port-id']
            other_dict = dict((item[0], item[1]) for item in
                               data[other_idx][1])
            queues_dict = dict((item[0], item[1]) for item in
                               data[queues_idx][1])
            type = data[type_idx]

            return PortQos(port_id, qos_id, other_dict, queues_dict, type)
        except Exception as e:
            LOG.warn(_("Unable to parse qos details. Exception: %s"), e)
            return


class OpenflowQoSVlanDriver(qos_base.QoSDriver):
    #TODO(scollins) - refactor into dynamic calls
    # 99% of the code is identical
    def __init__(self, ext_bridge, int_bridge, local_vlan_map, root_helper='sudo'):
        self.ext_bridge = ext_bridge
        self.int_bridge = int_bridge
        self.local_vlan_map = local_vlan_map
        # Quick lookup table for qoses that are
        # already present - help determine if it's a create
        # or update. RPC does not distinguish between updates and creates
        self.qoses = {}
        self.root_helper = root_helper
        self.ovsQos = OVSQos(self.root_helper)
        
        
    def get_net_uuid(self, vif_id):
        for network_id, vlan_mapping in self.local_vlan_map.iteritems():
            if vif_id in vlan_mapping.vif_ports:
                return network_id
            
    def get_vif_port_from_lvm(self, vif_id):
        
        net_uuid = self.get_net_uuid(vif_id)

        if not self.local_vlan_map.get(net_uuid):
            LOG.info(_('get_vif_port(): net_uuid %s not in local_vlan_map'),
                     net_uuid)
            return None

        lvm = self.local_vlan_map[net_uuid]

        if vif_id in lvm.vif_ports:
            vif_port = lvm.vif_ports[vif_id]
            return vif_port
        return None


    def _create_flow_statement_for_policy(self, policy):
        action = ""
        if constants.TYPE_QOS_DSCP in policy:
            action += "mod_nw_tos=%s" % (int(policy[constants.TYPE_QOS_DSCP])
                                         << 2)
        return action

    def create_qos_for_network(self, policy, network_id):
        if network_id not in self.local_vlan_map:
            return
        vlmap = self.local_vlan_map[network_id]
        mod_nw_tos = self._create_flow_statement_for_policy(policy)
        if vlmap.segmentation_id:
            # Add another action to existing
            # flow that rewrites the VLAN tag ID
            self.ext_bridge.mod_flow(dl_vlan=vlmap.vlan,
                                     actions="mod_vlan_vid=%s,%s,NORMAL" % (
                                         vlmap.segmentation_id, mod_nw_tos)
                                     )
        else:
            # Fallback to creating a new flow
            self.ext_bridge.add_flow(dl_vlan=vlmap.vlan, actions="%s,NORMAL" %
                                     mod_nw_tos)
        self.qoses[network_id] = True

    def delete_qos_for_network(self, network_id):
        if (network_id not in self.qoses or
                network_id not in self.local_vlan_map):
            return
        vlmap = self.local_vlan_map[network_id]
        if vlmap.segmentation_id:
            # Provider network - remove the mod_nw_tos key from
            # the flow
            self.ext_bridge.mod_flow(
                dl_vlan=vlmap.vlan,
                actions="mod_vlan_vid=%s,NORMAL" % vlmap.segmentation_id)
        else:
            self.ext_bridge.delete_flows(dl_vlan=vlmap.vlan)
        del self.qoses[network_id]

    def network_qos_updated(self, policy, network_id):
        # Remove old flow, create new one with the updated policy
        self.delete_qos_for_network(network_id)
        self.create_qos_for_network(policy, network_id)

    def create_qos_for_port(self, policy, port_id):
        #TODO(scollins) - create flow statments that will
        #ensure that a port qos policy overrides the qos policy
        #of a network
        ofport = self.int_bridge.get_vif_port_by_id(port_id).ofport
        action = "%s,NORMAL" % self._create_flow_statement_for_policy(policy)
        self.int_bridge.add_flow(in_port=ofport, actions=action,
                                 priority=65535)
        self.qoses[port_id] = True

    def delete_qos_for_port(self, port_id, **kwargs):
        if not port_id in self.qoses:
            return
        try:
            vif_port = self.get_vif_port_from_lvm(port_id)
            if vif_port:
                self.int_bridge.delete_flows(in_port=vif_port.ofport)
            else:
                LOG.error(_("Unable to get ofport for port %s"), port_id)
        except Exception as e:
            LOG.error(_("Unable to delete dscp flow. Exception: %s"), e)
        del self.qoses[port_id]

    def port_qos_updated(self, policy, port_id, **kwargs):
        # Remove flow, create new one with the updated policy
        self.delete_qos_for_port(port_id)
        self.create_qos_for_port(policy, port_id)

class MixingQoSVlanDriver(OpenflowQoSVlanDriver):

    def _get_interface_by_owner(self, port_id, device_owner):
        DEVNAMELEN = 14
        interface = None

        if device_owner == constants.DEVICE_OWNER_ROUTER_INTF:
            #can't support to set qos for router's interface currently
            pass
        elif device_owner == constants.DEVICE_OWNER_ROUTER_GW:
            #can't support to set qos for router's interface currently
            pass
        elif device_owner and constants.DEVICE_OWNER_COMPUTER in device_owner:
            interface = ("tap"+port_id)[:DEVNAMELEN]
        return interface

    def create_qos_for_port(self, policy, port_id, **kwargs):

        port = kwargs['port']
        interface = self._get_interface_by_owner(port_id, port['device_owner'])
        ovs_interface = self.int_bridge.get_vif_port_by_id(port_id)
        if not interface or not ovs_interface:
            LOG.warn('[create_qos_for_port] Can not find interface.')
            return

        if policy.get(constants.TYPE_QOS_DSCP):
            super(MixingQoSVlanDriver, self).create_qos_for_port(policy, port_id)

        tx_rate = policy.get(constants.TYPE_QOS_POLICY_TC_TX_RATE)
        tx_burst = policy.get(constants.TYPE_QOS_POLICY_TC_TX_BURST)
        rx_rate = policy.get(constants.TYPE_QOS_POLICY_TC_RX_RATE)
        rx_burst = policy.get(constants.TYPE_QOS_POLICY_TC_RX_BURST)

        ovs_interface = ovs_interface.port_name
        if interface == ovs_interface:
            if tx_rate and tx_burst:
                self.ovsQos.set_qos_for_interface(ovs_interface,
                                                  int(tx_rate[:-7])*8000, int(tx_burst[:-5])*8000)
            if rx_rate:
                self.ovsQos.set_qos_for_port(ovs_interface, port_id, int(rx_rate[:-7])*8*(10**6))
        else:
            if rx_rate and rx_burst:
                self.ovsQos.set_qos_for_interface(ovs_interface,
                                                  int(rx_rate[:-7])*8000, int(rx_burst[:-5])*8000)
            if tx_rate:
                self.ovsQos.set_qos_for_port(ovs_interface, port_id, int(tx_rate[:-7])*8*(10**6))

    def delete_qos_for_port(self, port_id, **kwargs):

        ovs_interface = self.int_bridge.get_vif_port_by_id(port_id)
        port_name = ovs_interface.port_name if ovs_interface else None

        super(MixingQoSVlanDriver, self).delete_qos_for_port(port_id, **kwargs)

        self.ovsQos.set_qos_for_interface(port_name, 0, 0)
        self.ovsQos.delete_qos_for_port(port_name, port_id)

    def port_qos_updated(self, policy, port_id, **kwargs):
        # Remove flow, create new one with the updated policy
        self.delete_qos_for_port(port_id, **kwargs)
        self.create_qos_for_port(policy, port_id, **kwargs)

    def clear_all_qos(self):
        ports = self.int_bridge.get_port_name_list()
        for port in ports:
            self.int_bridge.run_vsctl(['set', 'port', port, 'qos=[]'])
        self.int_bridge.run_vsctl(['--all', 'destroy', 'qos'])
        self.int_bridge.run_vsctl(['--all', 'destroy', 'queue'])
