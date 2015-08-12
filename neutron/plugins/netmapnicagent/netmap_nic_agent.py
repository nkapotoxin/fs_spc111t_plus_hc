# Copyright 2014 Mellanox Technologies, Ltd
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


import socket
import sys
import time

import eventlet
eventlet.monkey_patch()

from oslo.config import cfg

from neutron.agent import rpc as agent_rpc
from neutron.agent import securitygroups_rpc as sg_rpc
from neutron.common import config as common_config
from neutron.common import constants as q_constants
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.common import utils as q_utils
from neutron import context
from neutron.openstack.common import log as logging
from neutron.openstack.common import loopingcall
from neutron.plugins.netmapnicagent.common import config  # noqa
from neutron.plugins.netmapnicagent.common import exceptions as exc
from neutron.plugins.netmapnicagent import eswitch_manager as esm
from neutron.extensions import qos
from neutron.services.qos.agents import qos_rpc


LOG = logging.getLogger(__name__)


class NetmapNicSwitchRpcCallbacks(n_rpc.RpcCallback,
                                 sg_rpc.SecurityGroupAgentRpcCallbackMixin,
                                 qos_rpc.SriovQoSAgentRpcCallbackMixin):

    # Set RPC API version to 1.0 by default.
    # history
    #   1.1 Support Security Group RPC
    RPC_API_VERSION = '1.1'

    def __init__(self, context, agent):
        super(NetmapNicSwitchRpcCallbacks, self).__init__()
        self.context = context
        self.agent = agent
        self.sg_agent = agent
        self.qos_agent = agent

    def port_update(self, context, **kwargs):
        LOG.debug("port_update received")
        port = kwargs.get('port')
        # Put the port mac address in the updated_devices set.
        # Do not store port details, as if they're used for processing
        # notifications there is no guarantee the notifications are
        # processed in the same order as the relevant API requests.
        self.agent.updated_devices.add(port['mac_address'])
        LOG.debug(_("port_update RPC received for port: %s"), port['id'])
        if qos.QOS in port:
            self.qos_agent.qos_agent.port_qos_updated(self.context,
                                            port[qos.QOS],
                                            port['id'])


class NetmapNicSwitchPluginApi(agent_rpc.PluginApi,
                              sg_rpc.SecurityGroupServerRpcApiMixin,
                              qos_rpc.QoSServerRpcApiMixin):
    pass


class NetmapNicSwitchQoSAgent(qos_rpc.SriovQoSAgentRpcMixin):
    def __init__(self, context, plugin_rpc, root_helper):
        self.context = context
        self.plugin_rpc = plugin_rpc
        self.root_helper = root_helper


class NetmapNicSwitchAgent(sg_rpc.SecurityGroupAgentRpcMixin):
    def __init__(self, physical_devices_mappings, exclude_devices,
                 polling_interval, root_helper):

        self.polling_interval = polling_interval
        self.root_helper = root_helper
        self.setup_eswitch_mgr(physical_devices_mappings,
                               exclude_devices)
        configurations = {'device_mappings': physical_devices_mappings}
        self.agent_state = {
            'binary': 'neutron-netmap-nic-agent',
            'host': cfg.CONF.host,
            'topic': q_constants.L2_AGENT_TOPIC,
            'configurations': configurations,
            'agent_type': q_constants.AGENT_TYPE_NIC_NETMAP,
            'start_flag': True}

        # Stores port update notifications for processing in the main loop
        self.updated_devices = set()
        self._setup_rpc()
        self.init_firewall()
        self.init_qos()
        # Initialize iteration counter
        self.iter_num = 0

    def init_qos(self):
        # QoS agent support
        self.qos_agent = NetmapNicSwitchQoSAgent(self.context,
                                     self.plugin_rpc,
                                     self.root_helper)        
        if 'MixingSriovQoSDriver' in cfg.CONF.qos.sriov_qos_driver:
            self.qos_agent.init_qos(eswitch_mgr=self.eswitch_mgr,
                                    root_helper=self.root_helper
                                    )
        else:
            self.qos_agent.init_qos()

    def _setup_rpc(self):
        self.agent_id = 'netmap-switch-agent.%s' % socket.gethostname()
        LOG.info(_("RPC agent_id: %s"), self.agent_id)

        self.topic = topics.AGENT
        self.plugin_rpc = NetmapNicSwitchPluginApi(topics.PLUGIN)
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.PLUGIN)
        # RPC network init
        self.context = context.get_admin_context_without_session()
        # Handle updates from service
        self.endpoints = [NetmapNicSwitchRpcCallbacks(self.context, self)]
        # Define the listening consumers for the agent
        consumers = [[topics.PORT, topics.UPDATE],
                     [topics.NETWORK, topics.DELETE],
                     [topics.SECURITY_GROUP, topics.UPDATE],
                     [topics.QOS, topics.UPDATE]]
        self.connection = agent_rpc.create_consumers(self.endpoints,
                                                     self.topic,
                                                     consumers)

        report_interval = cfg.CONF.AGENT.report_interval
        if report_interval:
            heartbeat = loopingcall.FixedIntervalLoopingCall(
                self._report_state)
            heartbeat.start(interval=report_interval)

    def _report_state(self):
        try:
            devices = len(self.eswitch_mgr.get_assigned_devices())
            self.agent_state.get('configurations')['devices'] = devices
            self.state_rpc.report_state(self.context,
                                        self.agent_state)
            self.agent_state.pop('start_flag', None)
        except Exception:
            LOG.exception(_("Failed reporting state!"))

    def setup_eswitch_mgr(self, device_mappings, exclude_devices={}):
        self.eswitch_mgr = esm.ESwitchManager(device_mappings,
                                              exclude_devices,
                                              self.root_helper)

    def scan_devices(self, registered_devices, updated_devices):
        curr_devices = self.eswitch_mgr.get_assigned_devices()
        device_info = {}
        device_info['current'] = curr_devices
        device_info['added'] = curr_devices - registered_devices
        # we don't want to process updates for devices that don't exist
        device_info['updated'] = updated_devices & curr_devices
        # we need to clean up after devices are removed
        device_info['removed'] = registered_devices - curr_devices
        return device_info

    def _device_info_has_changes(self, device_info):
        return (device_info.get('added')
                or device_info.get('updated')
                or device_info.get('removed'))

    def process_network_devices(self, device_info):
        resync_a = False
        resync_b = False

        self.prepare_devices_filter(device_info.get('added'))

        if device_info.get('updated'):
            self.refresh_firewall()
        # Updated devices are processed the same as new ones, as their
        # admin_state_up may have changed. The set union prevents duplicating
        # work when a device is new and updated in the same polling iteration.
        devices_added_updated = (set(device_info.get('added'))
                                 | set(device_info.get('updated')))
        if devices_added_updated:
            resync_a = self.treat_devices_added_updated(devices_added_updated)

        if device_info.get('removed'):
            resync_b = self.treat_devices_removed(device_info['removed'])
        # If one of the above operations fails => resync with plugin
        return (resync_a | resync_b)

    def treat_device(self, device, pci_slot, admin_state_up):
        if self.eswitch_mgr.device_exists(device, pci_slot):
            try:
                self.eswitch_mgr.set_device_state(device, pci_slot,
                                                  admin_state_up)
            except exc.NetmapNicError:
                LOG.exception(_("Failed to set device %s state"), device)
            if admin_state_up:
                # update plugin about port status
                self.plugin_rpc.update_device_up(self.context,
                                                 device,
                                                 self.agent_id,
                                                 cfg.CONF.host)
            else:
                self.plugin_rpc.update_device_down(self.context,
                                                   device,
                                                   self.agent_id,
                                                   cfg.CONF.host)
        else:
            LOG.info(_("No device with MAC %s defined on agent."), device)

    def treat_devices_added_updated(self, devices):
        try:
            devices_details_list = self.plugin_rpc.get_devices_details_list(
                self.context, devices, self.agent_id)
        except Exception as e:
            LOG.debug("Unable to get port details for devices "
                      "with MAC address %(devices)s: %(e)s",
                      {'devices': devices, 'e': e})
            # resync is needed
            return True

        for device_details in devices_details_list:
            device = device_details['device']
            LOG.debug("Port with MAC address %s is added", device)

            if 'port_id' in device_details:
                LOG.info(_("Port %(device)s updated. Details: %(details)s"),
                         {'device': device, 'details': device_details})
                profile = device_details['profile']
                self.treat_device(device_details['device'],
                                  profile.get('pci_slot'),
                                  device_details['admin_state_up'])
                
                if device_details['qos_policies']:
                    result = {'port':device_details}
                    if profile.get('pci_vendor_info') in qos_rpc.QOS_SUPPORTED_VENDORS_LIST:
                        self.qos_agent.qos.device_qos_updated(device_details['qos_policies'], 
                                                              device_details['device'], 
                                                              profile.get('pci_slot'), 
                                                              **result)
                    else:
                        LOG.warn(_("Device with pci_vendor_info %s not supported"), profile.get('pci_vendor_info'))
            else:
                LOG.info(_("Device with MAC %s not defined on plugin"), device)
        return False

    def treat_devices_removed(self, devices):
        resync = False
        for device in devices:
            LOG.info(_("Removing device with mac_address %s"), device)
            try:
                dev_details = self.plugin_rpc.update_device_down(self.context,
                                                                 device,
                                                                 self.agent_id,
                                                                 cfg.CONF.host)
            except Exception as e:
                LOG.debug(_("Removing port failed for device %(device)s "
                          "due to %(exc)s"), {'device': device, 'exc': e})
                resync = True
                continue
            if dev_details['exists']:
                LOG.info(_("Port %s updated."), device)
            else:
                LOG.debug(_("Device %s not defined on plugin"), device)
        return resync

    def daemon_loop(self):
        sync = True
        devices = set()

        LOG.info(_("NETMAP NIC Agent RPC Daemon Started!"))

        while True:
            start = time.time()
            LOG.debug("Agent rpc_loop - iteration:%d started",
                      self.iter_num)
            if sync:
                LOG.info(_("Agent out of sync with plugin!"))
                devices.clear()
                sync = False
            device_info = {}
            # Save updated devices dict to perform rollback in case
            # resync would be needed, and then clear self.updated_devices.
            # As the greenthread should not yield between these
            # two statements, this will should be thread-safe.
            updated_devices_copy = self.updated_devices
            self.updated_devices = set()
            try:
                device_info = self.scan_devices(devices, updated_devices_copy)
                if self._device_info_has_changes(device_info):
                    LOG.debug(_("Agent loop found changes! %s"), device_info)
                    # If treat devices fails - indicates must resync with
                    # plugin
                    sync = self.process_network_devices(device_info)
                    devices = device_info['current']
            except Exception:
                LOG.exception(_("Error in agent loop. Devices info: %s"),
                              device_info)
                sync = True
                # Restore devices that were removed from this set earlier
                # without overwriting ones that may have arrived since.
                self.updated_devices |= updated_devices_copy

            # sleep till end of polling interval
            elapsed = (time.time() - start)
            if (elapsed < self.polling_interval):
                time.sleep(self.polling_interval - elapsed)
            else:
                LOG.debug(_("Loop iteration exceeded interval "
                            "(%(polling_interval)s vs. %(elapsed)s)!"),
                          {'polling_interval': self.polling_interval,
                           'elapsed': elapsed})
            self.iter_num = self.iter_num + 1


class NetmapNicAgentConfigParser(object):
    def __init__(self):
        self.device_mappings = {}
        self.exclude_devices = {}

    def parse(self):
        """Parses device_mappings and exclude_devices.

        Parse and validate the consistency in both mappings
        """
        self.device_mappings = q_utils.parse_mappings(
            cfg.CONF.NETMAP_NIC.physical_device_mappings)
        self.exclude_devices = config.parse_exclude_devices(
            cfg.CONF.NETMAP_NIC.exclude_devices)
        self._validate()

    def _validate(self):
        """ Validate configuration.

        Validate that network_device in excluded_device
        exists in device mappings
        """
        dev_net_set = set(self.device_mappings.itervalues())
        for dev_name in self.exclude_devices.iterkeys():
            if dev_name not in dev_net_set:
                raise ValueError(_("Device name %(dev_name)s is missing from "
                                   "physical_device_mappings") % {'dev_name':
                                                                  dev_name})


def main():
    common_config.init(sys.argv[1:])

    common_config.setup_logging()
    try:
        config_parser = NetmapNicAgentConfigParser()
        config_parser.parse()
        device_mappings = config_parser.device_mappings
        exclude_devices = config_parser.exclude_devices

    except ValueError as e:
        LOG.error(_("Failed on Agent configuration parse : %s."
                    " Agent terminated!"), e)
        raise SystemExit(1)
    LOG.info(_("Physical Devices mappings: %s"), device_mappings)
    LOG.info(_("Exclude Devices: %s"), exclude_devices)

    polling_interval = cfg.CONF.AGENT.polling_interval
    root_helper = cfg.CONF.AGENT.root_helper
    try:
        agent = NetmapNicSwitchAgent(device_mappings,
                                    exclude_devices,
                                    polling_interval,
                                    root_helper)
    except exc.NetmapNicError:
        LOG.exception(_("Agent Initialization Failed"))
        raise SystemExit(1)
    # Start everything.
    LOG.info(_("Agent initialized successfully, now running... "))
    agent.daemon_loop()


if __name__ == '__main__':
    main()
