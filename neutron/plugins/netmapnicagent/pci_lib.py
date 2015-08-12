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

import re

from neutron.agent.linux import ip_lib
from neutron.openstack.common import log as logging
from neutron.plugins.netmapnicagent.common import exceptions as exc

LOG = logging.getLogger(__name__)


class PciDeviceIPWrapper(ip_lib.IPWrapper):
    """Wrapper class for ip link commands.

    wrapper for getting/setting pci device details using ip link...
    """
    VF_PATTERN = "^vf(\s+)(?P<vf_index>\d+)(\s+)"
    MAC_PATTERN = "MAC(\s+)(?P<mac>[a-fA-F0-9:]+),"
    STATE_PATTERN = "(\s+)link-state(\s+)(?P<state>\w+)"
    RATE_PATTERN = "rate(\s+)(?P<rate>[0-9]+)(\s+)"
    ANY_PATTERN = "(.*),"

    VF_LINE_FORMAT = VF_PATTERN + MAC_PATTERN + "(.*)"
    VF_DETAILS_REG_EX = re.compile(VF_LINE_FORMAT)
    VF_DETAILS_RATE = re.compile("(.*)" + RATE_PATTERN + "(.*)")

    class LinkState:
        ENABLE = "enable"
        DISABLE = "disable"

    def __init__(self, dev_name, root_helper=None):
        super(ip_lib.IPWrapper, self).__init__(root_helper=root_helper)
        self.dev_name = dev_name

    def get_assigned_macs(self, vf_list):
        """Get assigned mac addresses for vf list.

        @param vf_list: list of vf indexes
        @return: list of assigned mac addresses
        """
        try:
            out = self._execute('', "link", ("show", self.dev_name),
                                self.root_helper)
        except Exception as e:
            LOG.exception(_("Failed executing ip command"))
            raise exc.IpCommandError(dev_name=self.dev_name,
                                     reason=str(e))
        vf_lines = self._get_vf_link_show(vf_list, out)
        vf_details_list = []
        if vf_lines:
            for vf_line in vf_lines:
                vf_details = self._parse_vf_link_show(vf_line)
                if vf_details:
                    vf_details_list.append(vf_details)
        return [vf_details.get("MAC") for vf_details in
                vf_details_list]

    def get_vf_state(self, vf_index):
        """Get vf state {True/False}

        @param vf_index: vf index
        @todo: Handle "auto" state
        """
        try:
            out = self._execute('', "link", ("show", self.dev_name),
                                self.root_helper)
        except Exception as e:
            LOG.exception(_("Failed executing ip command"))
            raise exc.IpCommandError(dev_name=self.dev_name,
                                     reason=str(e))
        vf_lines = self._get_vf_link_show([vf_index], out)
        if vf_lines:
            vf_details = self._parse_vf_link_show(vf_lines[0])
            if vf_details:
                state = vf_details.get("link-state",
                                       self.LinkState.DISABLE)
            if state != self.LinkState.DISABLE:
                return True
        return False

    def set_vf_state(self, vf_index, state):
        """sets vf state.

        @param vf_index: vf index
        @param state: required state {True/False}
        """
        status_str = self.LinkState.ENABLE if state else \
            self.LinkState.DISABLE

        try:
            self._execute('', "link", ("set", self.dev_name, "vf",
                                       str(vf_index), "state", status_str),
                          self.root_helper)
        except Exception as e:
            LOG.exception(_("Failed executing ip command"))
            raise exc.IpCommandError(dev_name=self.dev_name,
                                     reason=str(e))

    def get_vf_rate(self, vf_index):
        """Get vf tx rate

        @param vf_index: vf index
        """
        try:
            out = self._execute('', "link", ("show", self.dev_name),
                                self.root_helper)
        except Exception as e:
            LOG.exception(_("Failed executing ip command"))
            raise exc.IpCommandError(dev_name=self.dev_name,
                                     reason=str(e))
        vf_lines = self._get_vf_link_show([vf_index], out)
        if vf_lines:
            vf_details = self._parse_vf_link_show(vf_lines[0])
            if vf_details:
                rate = vf_details.get("rate", None)
            if rate:
                return True
        return False

    def set_vf_rate(self, vf_index, rate):
        """sets vf rate.

        @param vf_index: vf index
        @param rate: tx rate
        """
        
        try:
            self._execute('', "link", ("set", self.dev_name, "vf",
                                       str(vf_index), "rate", rate),
                          self.root_helper)
        except Exception as e:
            LOG.exception(_("Failed executing ip command"))
            raise exc.IpCommandError(dev_name=self.dev_name,
                                     reason=str(e))

    def _get_vf_link_show(self, vf_list, link_show_out):
        """Get link show output for VFs

        get vf link show command output filtered by given vf list
        @param vf_list: list of vf indexes
        @param link_show_out: link show command output
        @return: list of output rows regarding given vf_list
        """
        vf_lines = []
        for line in link_show_out.split("\n"):
            line = line.strip()
            if line.startswith("vf"):
                details = line.split()
                index = int(details[1])
                if index in vf_list:
                    vf_lines.append(line)
        if not vf_lines:
            LOG.warning(_("Cannot find vfs %(vfs)s in device %(dev_name)s"),
                        {'vfs': vf_list, 'dev_name': self.dev_name})
        return vf_lines

    def _parse_vf_link_show(self, vf_line):
        """Parses vf link show command output line.

        @param vf_line: link show vf line
        """
        vf_details = {}
        pattern_match = self.VF_DETAILS_REG_EX.match(vf_line)
        rate_match = self.VF_DETAILS_RATE.match(vf_line)
        if pattern_match:
            vf_details["vf"] = int(pattern_match.group("vf_index"))
            vf_details["MAC"] = pattern_match.group("mac")
            vf_details["link-state"] = "on"
            if rate_match:
                vf_details["rate"] = rate_match.group("rate")
        else:
            LOG.warning(_("failed to parse vf link show line %(line)s: "
                          "for %(device)s"), {'line': vf_line,
                                              'device': self.dev_name})
        return vf_details
