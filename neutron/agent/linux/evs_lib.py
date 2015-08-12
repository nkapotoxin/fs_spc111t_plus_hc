# Copyright 2011 VMware, Inc.
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

import itertools
import operator

from oslo.config import cfg

from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils
from neutron.common import exceptions
from neutron.openstack.common import excutils
from neutron.openstack.common import jsonutils
from neutron.openstack.common import log as logging
from neutron.plugins.common import constants

# Default timeout for ovs-vsctl command
DEFAULT_OVS_VSCTL_TIMEOUT = 10

# Special return value for an invalid OVS ofport
INVALID_OFPORT = '-1'

# default port_type
DEFAULT_SC_TYPE = "default"
TRANS_SC_TYPE = "trans"
NONTRANS_SC_TYPE = "nontrans"

VIRTIO_PORT_TYPE = "virtio"
PHYSICAL_PORT_TYPE = "physical"



OPTS = [
    cfg.IntOpt('ovs_vsctl_timeout',
               default=DEFAULT_OVS_VSCTL_TIMEOUT,
               help=_('Timeout in seconds for ovs-vsctl commands')),
]
cfg.CONF.register_opts(OPTS)

LOG = logging.getLogger(__name__)


class VifPort:
    def __init__(self, port_name, ofport, vif_id, vif_mac, switch_name):
        self.port_name = port_name
        self.ofport = ofport
        self.vif_id = vif_id
        self.vif_mac = vif_mac
        self.switch = switch_name

    def __str__(self):
        return ("iface-id=" + self.vif_id + ", vif_mac=" +
                self.vif_mac + ", port_name=" + self.port_name +
                ", ofport=" + str(self.ofport) + ", bridge_name=" +
                self.switch)


class BaseEVS(object):
    def __init__(self, root_helper):
        self.root_helper = root_helper
        self.vsctl_timeout = cfg.CONF.ovs_vsctl_timeout

    def run_vsctl(self, args, check_error=False):
        full_args = ["ovs-vsctl", "--timeout=%d" % self.vsctl_timeout] + args
        try:
            return utils.execute(full_args, root_helper=self.root_helper)
        except Exception as e:
            with excutils.save_and_reraise_exception() as ctxt:
                LOG.error(_("Unable to execute %(cmd)s. "
                            "Exception: %(exception)s"),
                          {'cmd': full_args, 'exception': e})
                if not check_error:
                    ctxt.reraise = False
                    
    def add_bridge(self, bridge_name, datapath_type = ""):
        if datapath_type:          
            self.run_vsctl(["--", "--may-exist", "add-br", bridge_name, 
                            "--", "set", "bridge", bridge_name, 
                            "datapath_type="+datapath_type])
        else:
            self.run_vsctl(["--", "--may-exist", "add-br", bridge_name, 
                                        "--", "set", "bridge", bridge_name, 
                                        "datapath_type=dpdk"])            
        return EVSBridge(bridge_name, self.root_helper)
    
    def delete_bridge(self, bridge_name):
        self.run_vsctl(["--", "--if-exists", "del-br", bridge_name])

    def bridge_exists(self, bridge_name):
        try:
            self.run_vsctl(['br-exists', bridge_name], check_error=True)
        except RuntimeError as e:
            with excutils.save_and_reraise_exception() as ctxt:
                if 'Exit code: 2\n' in str(e):
                    ctxt.reraise = False
                    return False
        return True

    def get_bridge_name_for_port_name(self, port_name):
        try:
            return self.run_vsctl(['port-to-br', port_name], check_error=True)
        except RuntimeError as e:
            with excutils.save_and_reraise_exception() as ctxt:
                if 'Exit code: 1\n' in str(e):
                    ctxt.reraise = False

    def port_exists(self, port_name):
        return bool(self.get_bridge_name_for_port_name(port_name))


class EVSBridge(BaseEVS):
    def __init__(self, br_name, root_helper):
        super(EVSBridge, self).__init__(root_helper)
        self.br_name = br_name
    def set_controller(self, controller_names):
        vsctl_command = ['--', 'set-controller', self.br_name]
        vsctl_command.extend(controller_names)
        self.run_vsctl(vsctl_command, check_error=True)
    def del_controller(self):
        self.run_vsctl(['--', 'del-controller', self.br_name],
                       check_error=True)
    def get_controller(self):
        res = self.run_vsctl(['--', 'get-controller', self.br_name],
                             check_error=True)
        if res:
            return res.strip().split('\n')
        return res
    def set_secure_mode(self):
        self.run_vsctl(['--', 'set-fail-mode', self.br_name, 'secure'],
                       check_error = True)
    def set_protocols(self, protocols):
        self.run_vsctl(['--', 'set', 'bridge', self.br_name,
                        "protocols=%s" % protocols],
                       check_error = True)
    def create(self, datapath_type):
        self.add_bridge(self.br_name, datapath_type)

    def destroy(self):
        self.delete_bridge(self.br_name)

    def reset_bridge(self):
        self.destroy()
        self.create()

    #add physical port
    def add_port_physical(self, port_name, numa_id = 1):
        self.run_vsctl(["--", "--may-exist", "add-port", self.br_name, port_name, 
                        "--", "set port", port_name,
                        "other_config:port_type=physical",
                        "other_config:numa_id="+numa_id])
        return self.get_port_ofport(port_name)
   
    #add virtual port
    def add_port(self, port_name, port_type = VIRTIO_PORT_TYPE, numa_id = 1):
        if port_type != VIRTIO_PORT_TYPE:
            self.run_vsctl(["--", "--may-exist", "add-port", self.br_name, port_name])
        else:
            self.run_vsctl(["--", "--may-exist", "add-port", self.br_name,port_name,
                            "--", "set","port", port_name,
                            "other_config:port_type="+VIRTIO_PORT_TYPE,
                            "other_config:numa_id="+numa_id])
        return self.get_port_ofport(port_name)

    def delete_port(self, port_name):
        self.run_vsctl(["--", "--if-exists", "del-port", self.br_name,
                        port_name])

    def set_db_attribute(self, table_name, record, column, value):
        args = ["set", table_name, record, "%s=%s" % (column, value)]
        self.run_vsctl(args)

    def clear_db_attribute(self, table_name, record, column):
        args = ["clear", table_name, record, column]
        self.run_vsctl(args)

    def run_ofctl(self, cmd, args, process_input=None):
        full_args = ["ovs-ofctl", cmd, self.br_name] + args
        try:
            return utils.execute(full_args, root_helper=self.root_helper,
                                 process_input=process_input)
        except Exception as e:
            LOG.error(_("Unable to execute %(cmd)s. Exception: %(exception)s"),
                      {'cmd': full_args, 'exception': e})

    def count_flows(self):
        flow_list = self.run_ofctl("dump-flows", []).split("\n")[1:]
        return len(flow_list) - 1

    def remove_all_flows(self):
        self.run_ofctl("del-flows", [])

    def get_port_tag_dict(self):
        """Get a dict of port names and associated vlan tags.

        e.g. the returned dict is of the following form::

            {u'int-ebr-p798de6': [],
             u'qve-76d9e6b6-21': 1,
             u'tapce5318ff-78': 1,
             u'tape1400310-e6': 1}

        The TAG ID is only available in the "Port" table and is not available
        in the "Interface" table queried by the get_vif_port_set() method.

        """
        port_names = self.get_port_name_list()
        args = ['--format=json', '--', '--columns=name,tag', 'list', 'Port']
        result = self.run_vsctl(args, check_error=True)
        port_tag_dict = {}
        if not result:
            return port_tag_dict
        for name, tag in jsonutils.loads(result)['data']:
            if name not in port_names:
                continue
            # 'tag' can be [u'set', []] or an integer
            if isinstance(tag, list):
                tag = tag[1]
            port_tag_dict[name] = tag
        return port_tag_dict

    def get_port_ofport(self, port_name):
        ofport = self.db_get_val("Interface", port_name, "ofport")
        # This can return a non-integer string, like '[]' so ensure a
        # common failure case
        try:
            int(ofport)
            return ofport
        except (ValueError, TypeError):
            return INVALID_OFPORT 

    def do_action_flows(self, action, kwargs_list):
        flow_strs = [_build_flow_expr_str(kw, action) for kw in kwargs_list]
        self.run_ofctl('%s-flows' % action, ['-'], '\n'.join(flow_strs))

    def do_sc_action_flows(self, action, kwargs_list):
        flow_strs = [_build_flow_expr_str(kw, action) for kw in kwargs_list]
        self.run_ofctl('%s-flow' % action, ['-'], '\n'.join(flow_strs))
    
    def add_sc_flow(self, **kwargs):
        self.do_sc_action_flows('add', [kwargs])
    

    def add_flow(self, **kwargs):
        self.do_action_flows('add', [kwargs])

    def mod_flow(self, **kwargs):
        self.do_action_flows('mod', [kwargs])

    def delete_flows(self, **kwargs):
        self.do_action_flows('del', [kwargs])
        
    def dump_flows_for_table(self, table):
        retval = None
        flow_str = "table=%s" % table
        flows = self.run_ofctl("dump-flows", [flow_str])
        if flows:
            retval = '\n'.join(item for item in flows.splitlines()
                               if 'NXST' not in item)
        return retval

    def deferred(self, **kwargs):
        return DeferredEVSBridge(self, **kwargs)

    def add_tunnel_port(self, port_name, remote_ip, local_ip,
                        tunnel_type=constants.TYPE_GRE,
                        vxlan_udp_port=constants.VXLAN_UDP_PORT,
                        dont_fragment=True):
        vsctl_command = ["--", "--may-exist", "add-port", self.br_name,
                         port_name]
        vsctl_command.extend(["--", "set", "Interface", port_name,
                              "type=%s" % tunnel_type])
        if tunnel_type == constants.TYPE_VXLAN:
            # Only set the VXLAN UDP port if it's not the default
            if vxlan_udp_port != constants.VXLAN_UDP_PORT:
                vsctl_command.append("options:dst_port=%s" % vxlan_udp_port)
        vsctl_command.append(("options:df_default=%s" %
                             bool(dont_fragment)).lower())
        vsctl_command.extend(["options:remote_ip=%s" % remote_ip,
                              "options:local_ip=%s" % local_ip,
                              "options:in_key=flow",
                              "options:out_key=flow"])
        self.run_vsctl(vsctl_command)
        ofport = self.get_port_ofport(port_name)
        if (tunnel_type == constants.TYPE_VXLAN and
                ofport == INVALID_OFPORT):
            LOG.error(_('Unable to create VXLAN tunnel port. Please ensure '
                        'that an openvswitch version that supports VXLAN is '
                        'installed.'))
        return ofport
    
    def add_patch_port(self, local_name, remote_name):
        result = self.run_vsctl(["add-port", self.br_name, local_name,
                        "--", "set", "Interface", local_name,
                        "type=patch", "options:peer=%s" % remote_name])
        if not result: 
            br_name = get_bridge_for_iface(self.root_helper,local_name)
            if br_name:
                self.run_vsctl(["--", "--if-exists", "del-port", br_name,local_name])
                
                self.run_vsctl(["add-port", self.br_name, local_name,
                                "--", "set", "Interface", local_name,
                                "type=patch", "options:peer=%s" % remote_name])

        return self.get_port_ofport(local_name)    

    def db_get_val(self, table, record, column, check_error=False):
        output = self.run_vsctl(["get", table, record, column], check_error)
        if output:
            return output.rstrip("\n\r")

    def db_str_to_map(self, full_str):
        list = full_str.strip("{}").split(", ")
        ret = {}
        for e in list:
            if e.find("=") == -1:
                continue
            arr = e.split("=")
            ret[arr[0]] = arr[1].strip("\"")
        return ret
        
    def db_get_map(self, table, record, column, check_error=False):
        output = self.run_vsctl(["get", table, record, column], check_error)
        if output:
            output_str = output.rstrip("\n\r")
            return self.db_str_to_map(output_str)
        return {}        

    #fetch port list of bridge      
    def get_port_name_list(self):
        res = self.run_vsctl(["list-ports", self.br_name], check_error=True)
        if res:
            return res.strip().split("\n")
        return []
    
    #fetch statistics of specified port in bridge
    def get_port_stats(self, port_name):
        return self.db_get_map("Interface", port_name, "statistics")
    
    #fetch statistics of all ports in bridge
    def get_br_ports_stats(self):
        res = self.get_port_name_list()
        ports_stats = {}
        for port_name in res:
            ports_stats[port_name] = self.get_port_stats(port_name)
        return ports_stats
    
    def get_vif_port_set(self, vswitch_prefix):
        ebr_int_port_names = self.get_port_name_list()
        tap_port_names = []
        
        for port_name in ebr_int_port_names:
            if port_name[0:3] == 'qve':
                tap_port_name = port_name.replace('qve','tap')
                tap_port_names.append(tap_port_name) 
        
        edge_ports = set()
        args = ['--format=json', '--', '--columns=name,external_ids,ofport',
                'list', 'Interface']
        result = self.run_vsctl(args, check_error=True)
        if not result:
            return edge_ports
        for row in jsonutils.loads(result)['data']:
            external_ids = dict(row[1][1])
            # Do not consider VIFs which aren't yet ready
            # This can happen when ofport values are either [] or ["set", []]
            # We will therefore consider only integer values for ofport
            ofport = row[2]
            port_name = row[0]
            
            if port_name not in tap_port_names:
                continue
            
            try:
                int_ofport = int(ofport)
            except (ValueError, TypeError):
                LOG.warn(_("Found not yet ready EVS switch port: %s"), row)
            else:
                if int_ofport > 0 :
                    if ("iface-id" in external_ids and
                        "attached-mac" in external_ids):
                        switch = get_bridge_for_iface(self.root_helper, port_name)
                        if switch == self.br_name or switch.startswith(vswitch_prefix):
                            edge_ports.add(external_ids['iface-id'])
                    elif ("xs-vif-uuid" in external_ids and
                          "attached-mac" in external_ids):
                        # if this is a xenserver and iface-id is not
                        # automatically synced to OVS from XAPI, we grab it
                        # from XAPI directly
                        iface_id = self.get_xapi_iface_id(
                            external_ids["xs-vif-uuid"])
                        switch = get_bridge_for_iface(self.root_helper, port_name)
                        if switch == self.br_name or switch.startswith(vswitch_prefix):
                            edge_ports.add(iface_id)
                else:
                    LOG.warn(_("Found failed evs switch port: %s"), row)
        return edge_ports

    def get_port_name_by_id(self, port_id):
        args = ['--format=json', '--', '--columns=name',
                'find', 'Interface',
                'external_ids:iface-id="%s"' % port_id]
        result = self.run_vsctl(args)
        if not result:
            return None
        json_result = jsonutils.loads(result)
        try:
            # Retrieve the indexes of the columns we're looking for
            headings = json_result['headings']
            name_idx = headings.index('name')
            data = json_result['data'][0]
            port_name = data[name_idx]
            if port_name:
                return port_name
            else:
                return None
        except Exception as e:
            LOG.warn(_("Unable to parse interface details. Exception: %s"), e)
            return None
    def get_vif_port_by_id(self, port_id, vswitch_prefix):
        args = ['--format=json', '--', '--columns=external_ids,name,ofport',
                'find', 'Interface',
                'external_ids:iface-id="%s"' % port_id]
        result = self.run_vsctl(args)
        if not result:
            return
        json_result = jsonutils.loads(result)
        try:
            # Retrieve the indexes of the columns we're looking for
            headings = json_result['headings']
            ext_ids_idx = headings.index('external_ids')
            name_idx = headings.index('name')
            ofport_idx = headings.index('ofport')
            # If data attribute is missing or empty the line below will raise
            # an exeception which will be captured in this block.
            # We won't deal with the possibility of ovs-vsctl return multiple
            # rows since the interface identifier is unique
            data = json_result['data'][0]
            port_name = data[name_idx]
            
            switch = get_bridge_for_iface(self.root_helper, port_name)
            # tapXXXXXXXXX-XX plugged in QEPXXXXXXXXX-XX should be felt
            if switch != self.br_name and not switch.startswith(vswitch_prefix):
                LOG.info(_("Port: %(port_name)s is"
                           " not on %(br_name)s and EVS vSwitch"), {'port_name': port_name,
                                                                    'br_name': self.br_name})
                return None
            ofport = data[ofport_idx]
            # ofport must be integer otherwise return None
            if not isinstance(ofport, int) or ofport == -1:
                LOG.warn(_("ofport: %(ofport)s for VIF: %(vif)s is not a "
                           "positive integer"), {'ofport': ofport,
                                                 'vif': port_id})
                return None
            # Find VIF's mac address in external ids
            ext_id_dict = dict((item[0], item[1]) for item in
                               data[ext_ids_idx][1])
            vif_mac = ext_id_dict['attached-mac']
            #assume tapXXXXXXXX-XX plugged in qepXXXXXXXXX-XX is plugged in integ_ebr vSwitch
            return VifPort(port_name, ofport, port_id, vif_mac, switch)
        except Exception as e:
            LOG.warn(_("Unable to parse interface details. Exception: %s"), e)
            return None

    def get_xapi_iface_id(self, xs_vif_uuid):
        args = ["xe", "vif-param-get", "param-name=other-config",
                "param-key=nicira-iface-id", "uuid=%s" % xs_vif_uuid]
        try:
            return utils.execute(args, root_helper=self.root_helper).strip()
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.error(_("Unable to execute %(cmd)s. "
                            "Exception: %(exception)s"),
                          {'cmd': args, 'exception': e})

    # returns a VIF object for each VIF port
    def get_vif_ports(self):
        edge_ports = []
        port_names = self.get_port_name_list()
        for name in port_names:
            external_ids = self.db_get_map("Interface", name, "external_ids",
                                           check_error=True)
            ofport = self.db_get_val("Interface", name, "ofport",
                                     check_error=True)
            if "iface-id" in external_ids and "attached-mac" in external_ids:
                p = VifPort(name, ofport, external_ids["iface-id"],
                            external_ids["attached-mac"], self.br_name)
                edge_ports.append(p)
            elif ("xs-vif-uuid" in external_ids and
                  "attached-mac" in external_ids):
                # if this is a xenserver and iface-id is not automatically
                # synced to OVS from XAPI, we grab it from XAPI directly
                iface_id = self.get_xapi_iface_id(external_ids["xs-vif-uuid"])
                p = VifPort(name, ofport, iface_id,
                            external_ids["attached-mac"], self.br_name)
                edge_ports.append(p)

        return edge_ports
    
    def delete_ports(self, all_ports=False):
        if all_ports:
            port_names = self.get_port_name_list()
        else:
            port_names = (port.port_name for port in self.get_vif_ports())

        for port_name in port_names:
            self.delete_port(port_name)

    def get_local_port_mac(self):
        """Retrieve the mac of the bridge's local port."""
        address = ip_lib.IPDevice(self.br_name, self.root_helper).link.address
        if address:
            return address
        else:
            msg = _('Unable to determine mac address for %s') % self.br_name
            raise Exception(msg)

    #get link state of network card
    def get_eth_link_status(self, port_name):
        res = self.run_vsctl(["list interface",port_name])
        res_map = self.db_str_to_map(res.rstrip("\n\r"))
        return res_map.get("link_state","")
    
    #set sc type
    #sc_type:
    #virtual port: trans/notrans
    def set_port_sc_attribute(self, port_name, sc_type, sf_port_id):
        other_config = self.get_port_other_config(port_name)
        port_type = other_config.get("port_type", PHYSICAL_PORT_TYPE)
        if port_type == PHYSICAL_PORT_TYPE:
            if sc_type != DEFAULT_SC_TYPE:
                LOG.error(_("Can't assign port_type %s with sc_type %s"),port_type, sc_type)
            else:
                self.set_db_attribute("Port", port_name, "other_config:sc_type", sc_type)
        elif port_type == VIRTIO_PORT_TYPE:
            if sc_type == TRANS_SC_TYPE or sc_type == NONTRANS_SC_TYPE:
                self.set_db_attribute("Port", port_name, "other_config:sc_type", sc_type) 
            else:
                LOG.error(_("Can't assign port_type %s with sc_type %s"),port_type, sc_type)
        #set sf_port_id
        self.set_db_attribute("Port", port_name, "other_config:sf_port_id", sf_port_id)

    #set port and cpu connetction
    def set_port_cpu_connection(self, port_name, cpu_id = 1):
        of_port = self.get_port_ofport(port_name)
        if of_port == INVALID_OFPORT:
            LOG.error(_('Unable to find port %s, please check its existence'), port_name)
        else:
            self.run_vsctl(["set port", port_name,
                            "other_config:cpu_id=",cpu_id])

    #set port and numa connection
    def set_port_numa_connection(self, port_name, numa_id = 1):
        of_port = self.get_port_ofport(port_name)
        if of_port == INVALID_OFPORT:
            LOG.error(_("Unable to fine port %s, please check its existence"),port_name)
        else:
            self.run_vsctl(["set port", port_name,
                            "other_config:numa_id=", numa_id])
            
    def get_port_other_config(self, port_name):
        return self.db_get_map("Port", port_name, "other_config")

    def __enter__(self):
        self.create()
        return self

    def __exit__(self, exc_type, exc_value, exc_tb):
        self.destroy()

class DeferredEVSBridge(object):
    '''Deferred EVSBridge.

    This class wraps add_flow, mod_flow and delete_flows calls to an OVSBridge
    and defers their application until apply_flows call in order to perform
    bulk calls. It wraps also ALLOWED_PASSTHROUGHS calls to avoid mixing
    OVSBridge and DeferredOVSBridge uses.
    This class can be used as a context, in such case apply_flows is called on
    __exit__ except if an exception is raised.
    This class is not thread-safe, that's why for every use a new instance
    must be implemented.
    '''
    ALLOWED_PASSTHROUGHS = 'add_port', 'add_tunnel_port', 'delete_port'

    def __init__(self, br, full_ordered=False,
                 order=('add', 'mod', 'del')):
        '''Constructor.

        :param br: wrapped bridge
        :param full_ordered: Optional, disable flow reordering (slower)
        :param order: Optional, define in which order flow are applied
        '''

        self.br = br
        self.full_ordered = full_ordered
        self.order = order
        if not self.full_ordered:
            self.weights = dict((y, x) for x, y in enumerate(self.order))
        self.action_flow_tuples = []

    def __getattr__(self, name):
        if name in self.ALLOWED_PASSTHROUGHS:
            return getattr(self.br, name)
        raise AttributeError(name)

    def add_flow(self, **kwargs):
        self.action_flow_tuples.append(('add', kwargs))

    def do_sc_action_flows(self, action, kwargs_list):
        flow_strs = [_build_flow_expr_str(kw, action) for kw in kwargs_list]
        self.run_ofctl('%s-flow' % action, ['-'], '\n'.join(flow_strs))
    
    def add_sc_flow(self, **kwargs):
        self.do_sc_action_flows('add', [kwargs])


    
    def mod_flow(self, **kwargs):
        self.action_flow_tuples.append(('mod', kwargs))

    def delete_flows(self, **kwargs):
        self.action_flow_tuples.append(('del', kwargs))

    def apply_flows(self):
        action_flow_tuples = self.action_flow_tuples
        self.action_flow_tuples = []
        if not action_flow_tuples:
            return

        if not self.full_ordered:
            action_flow_tuples.sort(key=lambda af: self.weights[af[0]])

        grouped = itertools.groupby(action_flow_tuples,
                                    key=operator.itemgetter(0))
        itemgetter_1 = operator.itemgetter(1)
        for action, action_flow_list in grouped:
            flows = map(itemgetter_1, action_flow_list)
            self.br.do_action_flows(action, flows)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type is None:
            self.apply_flows()
        else:
            LOG.exception(_("OVS flows could not be applied on bridge %s"),
                          self.br.br_name)


def get_bridge_for_iface(root_helper, iface):
    args = ["ovs-vsctl", "--timeout=%d" % cfg.CONF.ovs_vsctl_timeout,
            "iface-to-br", iface]
    try:
        return utils.execute(args, root_helper=root_helper).strip()
    except Exception:
        LOG.exception(_("Interface %s not found."), iface)
        return None


def get_bridges(root_helper):
    args = ["ovs-vsctl", "--timeout=%d" % cfg.CONF.ovs_vsctl_timeout,
            "list-br"]
    try:
        return utils.execute(args, root_helper=root_helper).strip().split("\n")
    except Exception as e:
        with excutils.save_and_reraise_exception():
            LOG.exception(_("Unable to retrieve bridges. Exception: %s"), e)


def get_bridge_external_bridge_id(root_helper, bridge):
    args = ["ovs-vsctl", "--timeout=2", "br-get-external-id",
            bridge, "bridge-id"]
    try:
        return utils.execute(args, root_helper=root_helper).strip()
    except Exception:
        LOG.exception(_("Bridge %s not found."), bridge)
        return None
    


def _build_flow_expr_str(flow_dict, cmd):
    flow_expr_arr = []
    actions = None

    if cmd == 'add':
        flow_expr_arr.append("hard_timeout=%s" %
                             flow_dict.pop('hard_timeout', '0'))
        flow_expr_arr.append("idle_timeout=%s" %
                             flow_dict.pop('idle_timeout', '0'))
        flow_expr_arr.append("priority=%s" %
                             flow_dict.pop('priority', '1'))
    elif 'priority' in flow_dict:
        msg = _("Cannot match priority on flow deletion or modification")
        raise exceptions.InvalidInput(error_message=msg)

    if cmd != 'del':
        if "actions" not in flow_dict:
            msg = _("Must specify one or more actions on flow addition"
                    " or modification")
            raise exceptions.InvalidInput(error_message=msg)
        actions = "actions=%s" % flow_dict.pop('actions')

    for key, value in flow_dict.iteritems():
        if key == 'proto':
            flow_expr_arr.append(value)
        else:
            flow_expr_arr.append("%s=%s" % (key, str(value)))

    if actions:
        flow_expr_arr.append(actions)

    return ','.join(flow_expr_arr)
