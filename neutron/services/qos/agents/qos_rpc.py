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

from neutron.common import topics
from neutron.openstack.common import importutils
from neutron.openstack.common import log as logging
from oslo.config import cfg
from neutron.extensions import portbindings

LOG = logging.getLogger(__name__)
QOS_RPC_VERSION = "1.1"
QOS_SUPPORTED_VENDORS_LIST = ["8086:10ed"]

QoSOpts = [
    cfg.StrOpt(
        'qos_driver',
        default='neutron.services.qos.drivers.qos_base.NoOpQoSDriver'),
    cfg.StrOpt(
        'sriov_qos_driver',
        default='neutron.services.qos.drivers.sriov_qos_base.NoOpSriovQoSDriver')
]

cfg.CONF.register_opts(QoSOpts, "qos")


class QoSAgentRpcApiMixin(object):
    """Agent side of the QoS Plugin RPC API."""

    def _get_qos_topic(self):
        return topics.get_topic_name(self.topic,
                                     topics.QOS,
                                     topics.UPDATE)

    def network_qos_deleted(self, context, qos_id, network_id):
        self.fanout_cast(context,
                         self.make_msg('network_qos_deleted',
                                       qos_id=qos_id,
                                       network_id=network_id),
                         version=QOS_RPC_VERSION,
                         topic=self._get_qos_topic())

    def network_qos_updated(self, context, qos_id, network_id):
        self.fanout_cast(context,
                         self.make_msg('network_qos_updated',
                                       qos_id=qos_id,
                                       network_id=network_id),
                         version=QOS_RPC_VERSION,
                         topic=self._get_qos_topic())

    def port_qos_deleted(self, context, qos_id, port_id):
        self.fanout_cast(context,
                         self.make_msg('port_qos_deleted',
                                       port_id=port_id,
                                       qos_id=qos_id),
                         version=QOS_RPC_VERSION,
                         topic=self._get_qos_topic())

    def port_qos_updated(self, context, qos_id, port_id):
        self.fanout_cast(context,
                         self.make_msg('port_qos_updated',
                                       qos_id=qos_id,
                                       port_id=port_id),
                         version=QOS_RPC_VERSION,
                         topic=self._get_qos_topic())


class QoSServerRpcApiMixin(object):
    """A mix-in that enables QoS support in the plugin rpc."""

    def get_policy_for_qos(self, context, qos_id):
        LOG.debug(_("Get policy for QoS ID: %s"
                    "via RPC"), qos_id)
        return self.call(context,
                         self.make_msg('get_policy_for_qos',
                                       qos_id=qos_id),
                         version=QOS_RPC_VERSION,
                         topic=self.topic)
        
    def get_port_and_qos_policy(self, context, port_id, qos_id):
        LOG.debug(_("Get port and QoS policies of Port ID and Qos ID: %s %s"
                    " via RPC"), port_id, qos_id)
        return self.call(context,
                         self.make_msg('get_port_and_qos_policy',
                                       port_id=port_id, qos_id=qos_id),
                         version=QOS_RPC_VERSION,
                         topic=self.topic)

    def get_qos_details_by_port(self, context, port_id):
        LOG.debug(_("Get QoS details for port: %s"),
                  port_id)
        return self.call(context,
                         self.make_msg('get_qos_details_by_port',
                                       port_id=port_id),
                         version=QOS_RPC_VERSION,
                         topic=self.topic)
    
    def get_qos_by_network(self, context, network_id):
        LOG.debug(_("Checking for QoS policy for net: %s"),
                  network_id)

        return self.call(context,
                         self.make_msg('get_qos_by_network',
                                       network_id=network_id),
                         version=QOS_RPC_VERSION,
                         topic=self.topic)


class QoSAgentRpcMixin(object):

    def init_qos(self, *args, **kwargs):
        qos_driver = cfg.CONF.qos.qos_driver
        LOG.debug(_("Starting QoS driver %s"), qos_driver)
        self.qos = importutils.import_object(qos_driver, *args, **kwargs)
        if hasattr(self.qos, "clear_all_qos"):
            self.qos.clear_all_qos()

    def network_qos_deleted(self, context, qos_id, network_id):
        self.qos.delete_qos_for_network(network_id)

    def network_qos_updated(self, context, qos_id, network_id):
        qos_policy = self.plugin_rpc.get_policy_for_qos(context, qos_id)
        self.qos.network_qos_updated(qos_policy, network_id)

    def port_qos_updated(self, context, qos_id, port_id):
        result = self.plugin_rpc.get_port_and_qos_policy(context, port_id, qos_id)
        port = result.get('port')
        if port['binding:vif_type'] == portbindings.VIF_TYPE_OVS:
            LOG.debug(_('QoS %s updated on remote: %s'), qos_id, port_id)
            self.qos.port_qos_updated(result.get("qos_policy"), port_id, **result)

    def port_qos_deleted(self, context, qos_id, port_id):
        self.qos.delete_qos_for_port(port_id)


class QoSAgentRpcCallbackMixin(object):

    #TODO(scollins) See if we need this - copied from
    # SecurityGroupAgentRpcCallbackMixin
    qos_agent = None

    def network_qos_updated(self, context, **kwargs):
        qos_id = kwargs.get('qos_id', '')
        network_id = kwargs.get('network_id', '')
        LOG.debug(_('QoS %(qos_id)s updated on remote: %(network_id)s')
                  % kwargs)
        self.qos_agent.network_qos_updated(context, qos_id, network_id)

    def network_qos_deleted(self, context, **kwargs):
        qos_id = kwargs.get('qos_id', '')
        network_id = kwargs.get('network_id', '')
        LOG.debug(_('QoS %(qos_id)s updated on remote: %(network_id)s')
                  % kwargs)
        self.qos_agent.network_qos_deleted(context, qos_id, network_id)

    def port_qos_deleted(self, context, **kwargs):
        qos_id = kwargs.get('qos_id', '')
        port_id = kwargs.get('port_id', '')
        if self.int_br.get_vif_port_by_id(port_id):
            LOG.debug(_('QoS %(qos_id)s updated on remote: %(port_id)s')
                      % kwargs)
            self.qos_agent.port_qos_deleted(context, qos_id, port_id)

    def port_qos_updated(self, context, **kwargs):
        qos_id = kwargs.get('qos_id', '')
        port_id = kwargs.get('port_id', '')
        if self.int_br.get_vif_port_by_id(port_id):
            LOG.debug(_('QoS %(qos_id)s updated on remote: %(port_id)s')
                      % kwargs)
            self.qos_agent.port_qos_updated(context, qos_id, port_id)
            
            
class SriovQoSAgentRpcMixin(object):

    def init_qos(self, *args, **kwargs):
        self.eswitch_mgr = None
        if "eswitch_mgr" in kwargs:
            self.eswitch_mgr = kwargs['eswitch_mgr']
        qos_driver = cfg.CONF.qos.sriov_qos_driver
        LOG.debug(_("Starting QoS driver %s"), qos_driver)
        self.qos = importutils.import_object(qos_driver, *args, **kwargs)
        if hasattr(self.qos, "clear_all_qos"):
            self.qos.clear_all_qos()

    def port_qos_updated(self, context, qos_id, port_id):
        result = self.plugin_rpc.get_port_and_qos_policy(context, port_id, qos_id)
        port = result.get('port')
        if port['binding:vif_type'] == portbindings.VIF_TYPE_HW_VEB \
            or port['binding:vif_type'] == portbindings.VIF_TYPE_NETMAP:
            if self.eswitch_mgr \
                and self.eswitch_mgr.device_exists(port['mac_address'], port['binding:profile']['pci_slot']):
                if port['binding:profile']['pci_vendor_info'] in QOS_SUPPORTED_VENDORS_LIST:
                    LOG.debug(_('QoS %s updated on remote: %s'), qos_id, port_id)
                    self.qos.device_qos_updated(result.get("qos_policy"), 
                                                port['mac_address'], 
                                                port['binding:profile']['pci_slot'], 
                                                **result)
                else:
                    LOG.warn(_("Device with pci_vendor_info %s not supported"), 
                             port['binding:profile']['pci_vendor_info'])

    def port_qos_deleted(self, context, qos_id, port_id):
        result = self.plugin_rpc.get_port_and_qos_policy(context, port_id, qos_id)
        port = result.get('port')
        if port['binding:vif_type'] == portbindings.VIF_TYPE_HW_VEB \
            or port['binding:vif_type'] == portbindings.VIF_TYPE_NETMAP:
            if self.eswitch_mgr \
                and self.eswitch_mgr.device_exists(port['mac_address'], port['binding:profile']['pci_slot']):
                if port['binding:profile']['pci_vendor_info'] in QOS_SUPPORTED_VENDORS_LIST:
                    LOG.debug(_('QoS %s deleted on remote: %s'), qos_id, port_id)
                    self.qos.delete_qos_for_device(port['mac_address'], 
                                                   port['binding:profile']['pci_slot'])
                else:
                    LOG.warn(_("Device with pci_vendor_info %s not supported"), 
                             port['binding:profile']['pci_vendor_info'])
        

class SriovQoSAgentRpcCallbackMixin(object):

    # TODO(scollins) See if we need this - copied from
    # SecurityGroupAgentRpcCallbackMixin
    qos_agent = None

    def port_qos_deleted(self, context, **kwargs):
        qos_id = kwargs.get('qos_id', '')
        port_id = kwargs.get('port_id', '')
        self.qos_agent.qos_agent.port_qos_deleted(context, qos_id, port_id)

    def port_qos_updated(self, context, **kwargs):
        qos_id = kwargs.get('qos_id', '')
        port_id = kwargs.get('port_id', '')
        self.qos_agent.qos_agent.port_qos_updated(context, qos_id, port_id)
