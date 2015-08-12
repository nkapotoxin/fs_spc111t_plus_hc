# Copyright 2013 ngfw Networks Inc.
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

from neutron.services.firewall.agents.ngfw import ngfw_template as template
from neutron.services.vpn.device_drivers.template.ngfw import template as vpn_template
from neutron.openstack.common import log as logging
import json
import netaddr
LOG = logging.getLogger(__name__)

NGFW_URL_POLICY_SECURITY='/policy/security-policy'
NGFW_URL_TRAFFIC_POLICY = '/policy/traffic-policy'
NGFW_URL_ADDR_SET = '/object/address'
NGFW_URL_TRAFFIC_POLICY_TIME_RANGE = '/object/time-range'
NGFW_URL_NAT_SERVER = '/policy/nat-policy/nat-server'
NGFW_URL_STATIC_ROUTE = '/network/router/static-route'
NGFW_URL_SAVE_CFG = '/system/save-cfg'
NGFW_URL_AUTH='/'

NGFW_URL_VPN_IKE_PEER = '/network/ipsec-policy'
NGFW_URL_VPN_IKE_PROPOSAL = '/network/ipsec-policy'
NGFW_URL_VPN_IPSEC_PROPOSAL = '/network/ipsec-policy'
NGFW_URL_VPN_IPSEC_POLICY = '/network/ipsec-policy'
NGFW_URL_VPN_IKE_PEER_GET = '/network/ipsec-policy?type=ike-peer&vsys=root'
NGFW_URL_VPN_IKE_PROPOSAL_GET = '/network/ipsec-policy?type=ike-proposal&vsys=root'
NGFW_URL_VPN_IPSEC_PROPOSAL_GET = '/network/ipsec-policy?type=ipsec-proposal&vsys=root'
NGFW_URL_VPN_IPSEC_POLICY_GET = '/network/ipsec-policy?type=ipsec-policy&vsys=root'
NGFW_URL_VPN_IPSEC_ACL = '/object/acl'

NGFW_DEFAULT_HEADER={"SN":"0", 
                     "Cache-Control":"no-cache,no-store", 
                     "Connection":"Keep-Alive", 
                     "API-Version":"1.0", 
                     "Content-Type":"application/x-www-form-urlencoded"}


ROUTER_OBJ_PREFIX = 'r_'
OBJ_PREFIX_LEN = 8
NGFW_MAX_OBJ_CNT = 5
TRUST_ZONE = '_z_trust'
UNTRUST_ZONE = '_z_untrust'
SNAT_RULE = '_snat'
DNAT_RULE = '_dnat'
ROUTER_POLICY = '_p'


def get_router_object_prefix(ri):
    return ROUTER_OBJ_PREFIX + ri.router['id'][:OBJ_PREFIX_LEN]


def get_firewall_object_prefix(ri, fw):
    return get_router_object_prefix(ri) + '_' + fw['id'][:OBJ_PREFIX_LEN]


def get_trusted_zone_name(ri):
    return get_router_object_prefix(ri) + TRUST_ZONE


def get_untrusted_zone_name(ri):
    return get_router_object_prefix(ri) + UNTRUST_ZONE


def get_snat_rule_name(ri):
    return get_router_object_prefix(ri) + SNAT_RULE


def get_dnat_rule_name(ri):
    return get_router_object_prefix(ri) + DNAT_RULE


def get_router_policy_name(ri):
    return get_router_object_prefix(ri) + ROUTER_POLICY


def get_firewall_policy_name(ri, fw, rule):
    return get_firewall_object_prefix(ri, fw) + '_' + rule['id'][:OBJ_PREFIX_LEN]

def get_floatingip_name(floatingip_id):
    return floatingip_id[:OBJ_PREFIX_LEN]


def string_transfer(str):
    str=str.replace(" ","")
    str=str.replace("\n","")
    str=str.replace("\t","")
    return str


def xmldumps(obj):
    config = ""
    if isinstance(obj, dict):
        for key, value in obj.iteritems():
            if isinstance(value, list):
                for v in value:
                    cfg = "<%s>%s</%s>" % (key, v, key)
                    config += cfg
            else:
                cfg = "<%s>%s</%s>" % (key, xmldumps(value), key)
                config += cfg
    else:
        config = obj

    return config


def parse_xml_name(xml_str, key_begin, key_end):
    index = 0
    xml_name_list = []
    if xml_str:
        while True:
            index = xml_str.find(key_begin, index)  
            if index == -1:
                break    
            begin = index + len(key_begin) 
            end = xml_str.find(key_end, begin) 
            if end == -1:
                break
            xml_name_list.append(xml_str[begin:end])   
            index = end
            
    return xml_name_list 

def get_security_policy_zone(src_zone, dest_zone):
    str = ''
    if src_zone:
        str = str + template.CONFIG_POLICY_SECURITY_POLICY_SOURCE_ZONE. \
                             format(zone_name=src_zone)

    if dest_zone:
        str = str + template.CONFIG_POLICY_SECURITY_POLICY_DESTINATION_ZONE. \
                             format(zone_name=dest_zone)

    return str


def get_security_policy_icmp(type):
    str = template.CONFIG_POLICY_SECURITY_POLICY_RULE_SERVICE_ICMP. \
                         format(protocol_type=type)                                       
    return str


def get_security_policy_ip(src_ip, dest_ip):
    str = ''
    if src_ip:
        if '/' not in src_ip:
            src_ip = src_ip + '/32'
        str = str + template.CONFIG_POLICY_SECURITY_POLICY_RULE_SOURCE_IP. \
                             format(ip_address=src_ip) 
    if dest_ip:
        if '/' not in dest_ip:
            dest_ip = dest_ip + '/32'        
        str = str + template.CONFIG_POLICY_SECURITY_POLICY_RULE_DESTINATION_IP. \
                             format(ip_address=dest_ip)                             
                         
    return str
        
def get_security_policy_tcp_or_udp_port(protocol, src_port, dest_port):
    str = ''
    if src_port:
        if ':' in src_port:
            port1=src_port.split(':')[0]
            port2=src_port.split(':')[1]
            if int(port1) > int(port2):
                (port1, port2) = (port2, port1)
        else:
            port1=src_port
            port2=src_port          
        str = str + template.CONFIG_POLICY_SECURITY_POLICY_RULE_SERVICE_SRC_PORT. \
                             format(port1=port1, port2=port2)
    if dest_port:
        if ':' in dest_port:
            port3=dest_port.split(':')[0]
            port4=dest_port.split(':')[1]
            if int(port3) > int(port4):
                (port3, port4) = (port4, port3)              
        else:
            port3=dest_port
            port4=dest_port
        str = str + template.CONFIG_POLICY_SECURITY_POLICY_RULE_SERVICE_DST_PORT. \
                             format(port3=port3, port4=port4)

    str = template.CONFIG_POLICY_SECURITY_POLICY_RULE_SERVICE_TCP_UDP. \
                         format(protocol=protocol, port_list=str)
                             
    str = template.CONFIG_POLICY_SECURITY_POLICY_RULE_SERVICE. \
                         format(rule_service=str)
                         
    return str

def get_security_policy_rule_name(ri, fw, rule, postfix=''):  
    rule_name = get_firewall_policy_name(ri, fw, rule)

    str = template.CONFIG_POLICY_SECURITY_POLICY_RULE. \
                   format(rule_name=rule_name+postfix)
                   
    return str

def get_security_policy_rule(rule_name):
    str = template.CONFIG_POLICY_SECURITY_POLICY_STATIC_RULE.format(rule_name=rule_name)
    return str

def _get_security_policy(rule, str, option='before', target_rule=None):
    if rule.get("mode", None) and rule.get("mode", None).lower() == 'mix' and 'rule_profile' in rule.keys():
        rule_desc = json.loads(rule['rule_profile']).get("security-zone", None)
        if rule_desc:
            src_zone = rule_desc.get("source-zone", None)
            dts_zone = rule_desc.get("destination-zone", None)
            str = str + get_security_policy_zone(src_zone, dts_zone)
    
    str = str + get_security_policy_ip(rule['source_ip_address'], rule['destination_ip_address'])  
    
    if rule['action'].lower() == 'allow':  
        bool_value = 'true'
    else:
        bool_value = 'false'
        
    if target_rule:
        option_cfg = template.CONFIG_POLICY_SECURITY_POLICY_OPTION.format(option_action=option,
                                                                 target_rule_name=target_rule)  
    else:
        option_cfg = ""      
      
    str = template.CONFIG_POLICY_SECURITY_POLICY.format(rule_name_list=str, 
                                                        bool_value=bool_value,
                                                        option_cfg=option_cfg)  
    
    return string_transfer(str)        


def get_security_policy(ri, fw, rule, target_rule=None):
    protocol = rule['protocol'] 
    if protocol is None:
        str = get_security_policy_rule_name(ri, fw, rule)
        result = _get_security_policy(rule, str, 'before', target_rule)
    elif protocol.lower() == 'icmp':
        str = get_security_policy_rule_name(ri, fw, rule)
        str = str + get_security_policy_icmp('icmp')        
        result = _get_security_policy(rule, str, 'before', target_rule)
    else:
        str = get_security_policy_rule_name(ri, fw, rule)
        str = str + get_security_policy_tcp_or_udp_port(protocol, rule['source_port'], rule['destination_port'])
        result = _get_security_policy(rule, str, 'before', target_rule)
    return result

def get_security_policy_body(ri, fw, rule, target_rule=None):
    security_policy = get_security_policy(ri, fw, rule, target_rule)
    before = len('<sec-policy><static-policy>')
    after = len('</static-policy></sec-policy>')
    bodyinfo = security_policy[before:-after]
    return bodyinfo


def get_static_route(static_route):
    '''    
    {"ip_address":"172.28.0.0",
     "mask_length":"24",
     "next_hop_address":"10.9.0.1",
     "outgoing_interface":"eth3",
     "priority":"63",
     "description":"aaaaaaaaaaa"
     }
    '''

    priority = ""
    description = ""
    next_hop_address = ""
    outgoing_interface = ""
    name = ""
    #str_list = []
    
    destination_prefix = static_route["ip_address"] + '/' + static_route["mask_length"]

    if static_route.has_key("name") and static_route["name"]:
        name = static_route["name"]

    if static_route.has_key("priority") and static_route["priority"]:
        priority = static_route["priority"]
        
    if static_route.has_key("description") and static_route["description"]:
        description = static_route["description"]

    if static_route.has_key("next_hop_address") and static_route["next_hop_address"]:
        next_hop_address = static_route["next_hop_address"]
    
    if static_route.has_key("outgoing_interface") and static_route["outgoing_interface"]:
        outgoing_interface = static_route["outgoing_interface"]
        
        

    str = template.CONFIG_STATIC_ROUTE.format(name=name,\
                                              description=description, \
                                              destination_prefix=destination_prefix, \
                                              next_hop_address=next_hop_address, \
                                              outgoing_interface=outgoing_interface, \
                                              priority=priority)    
        
   
    ret = string_transfer(str) 
    return ret

def get_addr_set(address_object):
    str = template.CONFIG_ADDRESS_SET_OBJECT.\
        format(addr_set_object_name=address_object['name'],
               id=address_object['elements']['id'],
               ip=address_object['elements']['address-ipv4'])
    return str

def get_value_from_xml(key, bodyinfo):
    begin_str = '<%s>' % key
    end_str = '</%s>' % key
    begin = bodyinfo.find(begin_str) + len(begin_str)
    end = bodyinfo.find(end_str)
    if begin != -1 and end != -1:
        str_to_return = bodyinfo[begin:end]
        return str_to_return
    return ''

def get_elements_from_xml(bodyinfo):
    index = 0
    elements_list = []
    if bodyinfo:
        while True:
            element = {}
            index = bodyinfo.find('<id>', index)
            if index == -1:
                break
            begin = index + len('<id>')
            end = bodyinfo.find('</id>', begin)
            if end == -1:
                break
            element['id'] = bodyinfo[begin:end]
            index = end + len('</id>')
            if bodyinfo[index:index+len('<address-ipv4>')] == '<address-ipv4>':
                address_ipv4 = get_value_from_xml('address-ipv4', bodyinfo[index:])
                element['address-ipv4'] = address_ipv4
                index = bodyinfo.find('</address-ipv4>', index)
                if index == -1:
                    LOG.error(_('get elements from xml failed'))
                    return None
                index += len('</address-ipv4>')
            elif bodyinfo[index:index+len('<mac-address>')] == '<mac-address>':
                mac_address = get_value_from_xml('mac-address', bodyinfo[index:])
                element['mac-address'] = mac_address
                index = bodyinfo.find('</mac-address>', index)
                if index == -1:
                    LOG.error(_('get elements from xml failed'))
                    return None
                index += len('</mac-address>')
            elif bodyinfo[index:index+len('<start-ipv4>')] == '<start-ipv4>':
                start_ipv4 = get_value_from_xml('start-ipv4', bodyinfo[index:])
                index = bodyinfo.find('<end-ipv4>')
                end_ipv4 = get_value_from_xml('end-ipv4', bodyinfo[index:])
                element['start-ipv4'] = start_ipv4
                element['end-ipv4'] = end_ipv4
                index = bodyinfo.find('</end-ipv4>', index)
                if index == -1:
                    LOG.error(_('get elements from xml failed'))
                    return None
                index += len('</end-ipv4>')
            elif bodyinfo[index:index+len('<addrset-name>')] == '<addrset-name>':
                addrset_name = get_value_from_xml('addrset-name', bodyinfo[index:])
                element['addrset-name'] = addrset_name
                index = bodyinfo.find('</addrset-name>', index)
                if index == -1:
                    LOG.error(_('get elements from xml failed'))
                    return None
                index += len('</addrset-name>')
            elements_list.append(element)
    return elements_list

def analysis_addr_object(bodyinfo):
    addr_object = {}
    name = get_value_from_xml('name', bodyinfo)
    elements_info = get_value_from_xml('elements', bodyinfo)
    elements = get_elements_from_xml(elements_info)
    addr_object['name'] = name
    addr_object['elements'] = elements
    return addr_object

def analysis_addr_group(bodyinfo):
    addr_group = {}
    name = get_value_from_xml('name', bodyinfo)
    elements_info = get_value_from_xml('elements', bodyinfo)
    elements = get_elements_from_xml(elements_info)
    addr_group['name'] = name
    addr_group['elements'] = elements
    return addr_group

def get_security_policy_to_delete(rule_name):
    str = template.CONFIG_POLICY_SECURITY_POLICY_RULE. \
                   format(rule_name=rule_name)
    
    str = template.CONFIG_POLICY_SECURITY_POLICY_TO_DELETE.format(rule_name_list=str)  
    
    return string_transfer(str)   

   
def get_nat_server_static_map(nat_name, floatingIP, fixedIP, no_reverse=False):     
    str = template.CONFIG_POLICY_NAT_SERVER_STATIC_MAP_NAME. \
                   format(nat_name=nat_name)
                   
    str = str + template.CONFIG_POLICY_NAT_SERVER_STATIC_MAP_RULE. \
                   format(floatingIP=floatingIP, fixedIP=fixedIP) 
                   
    if no_reverse:
        str = str + template.CONFIG_POLICY_NAT_SERVER_STATIC_MAP_NOREVERSE         
                   
    str = template.CONFIG_POLICY_NAT_SERVER_STATIC_MAP.format(nat_name_list=str)
                    
    return string_transfer(str)


def get_nat_server_static_map_to_delete(nat_name):
    str = template.CONFIG_POLICY_NAT_SERVER_STATIC_MAP_NAME. \
                   format(nat_name=nat_name)
                   
    str = template.CONFIG_POLICY_NAT_SERVER_STATIC_MAP.format(nat_name_list=str)               
    
    return string_transfer(str)


def get_in_acl_body(name, destination_ip_address, target_rule):
    rule_template = {"name":name, 
                     "source_ip_address":'',
                     "destination_ip_address":destination_ip_address,
                     "mode":"mix",
                     "rule_profile":'{"security-zone":{"source-zone":"untrust", "destination-zone":"trust"}}',
                     "action":"allow"}
    
    str = template.CONFIG_POLICY_SECURITY_POLICY_RULE. \
                   format(rule_name="InFip"+name)   
                   
    bodyinfo = _get_security_policy(rule_template, str, 'after', target_rule)     
    
    return bodyinfo   

def get_out_acl_body(name, source_ip_address, target_rule):
    rule_template = {"name":name, 
                     "source_ip_address":source_ip_address,
                     "destination_ip_address":'',
                     "mode":"mix",
                     "rule_profile":'{"security-zone":{"source-zone":"trust", "destination-zone":"untrust"}}',
                     "action":"allow"}
    
    str = template.CONFIG_POLICY_SECURITY_POLICY_RULE. \
                   format(rule_name="OutFip"+name)   
                   
    bodyinfo = _get_security_policy(rule_template, str, 'after', target_rule)     
    
    return bodyinfo          
    
def get_out_acl_body_to_delete(name):
    str = template.CONFIG_POLICY_SECURITY_POLICY_RULE. \
                   format(rule_name="OutFip"+name)
    
    str = template.CONFIG_POLICY_SECURITY_POLICY_TO_DELETE.format(rule_name_list=str)  
    
    return string_transfer(str)

def get_in_acl_body_to_delete(name):
    str = template.CONFIG_POLICY_SECURITY_POLICY_RULE. \
                   format(rule_name="InFip"+name)
    
    str = template.CONFIG_POLICY_SECURITY_POLICY_TO_DELETE.format(rule_name_list=str)  
    
    return string_transfer(str)


def build_traffic_policy(key, value):
    str = "<%s>" % key + value + "</%s>" % key
    return str

def get_vpn_ike_peer(ike_peer):
    ike_peer_name = ''
    vsys_num = ''
    pre_shared_key = ''
    ike_version = ''
    ike_proposal = ''
    peer_address = ''
    phase1_mode = ''
    vpn_instance = ''
    if ike_peer:
        if ike_peer.has_key("ike_peer_name") and ike_peer["ike_peer_name"]:
            ike_peer_name = ike_peer.get("ike_peer_name")
        if ike_peer.has_key("vsys_num") and ike_peer["vsys_num"]:
            vsys_num = ike_peer.get("vsys_num")
        if ike_peer.has_key("pre_shared_key") and ike_peer["pre_shared_key"]:
            pre_shared_key = ike_peer.get("pre_shared_key")
        if ike_peer.has_key("ike_version") and ike_peer["ike_version"]:
            ike_version = ike_peer.get("ike_version")
        if ike_peer.has_key("ike_proposal") and ike_peer["ike_proposal"]:
            ike_proposal = ike_peer.get("ike_proposal")
        if ike_peer.has_key("peer_address") and ike_peer["peer_address"]:
            peer_address = ike_peer.get("peer_address")
        if ike_peer.has_key("phase1_mode") and ike_peer["phase1_mode"]:
            phase1_mode = ike_peer.get("phase1_mode")
        if ike_peer.has_key("vpn_instance") and ike_peer["vpn_instance"]:
            vpn_instance = ike_peer.get("vpn_instance")
        str = vpn_template.CONFIG_IKE_PEER.format(vpn_instance = vpn_instance,\
                                              ike_peer_name=ike_peer_name,\
                                              vsys_num = vsys_num,\
                                              pre_shared_key = pre_shared_key,\
                                              ike_version = ike_version,\
                                              ike_proposal = ike_proposal,\
                                              peer_address = peer_address,\
                                              phase1_mode = phase1_mode)
        return string_transfer(str)
    return None


def get_vpn_ike_proposal(ike_proposal):
    id = ''
    auth_algorithm = ''
    integrity_algorithm = ''
    encryption_algorithm = ''
    auth_mode = ''
    dh = ''
    lifetime = ''
    if ike_proposal:
        if ike_proposal.has_key("id") and ike_proposal["id"]:
            id = ike_proposal.get("id")
        if ike_proposal.has_key("auth_algorithm") and ike_proposal["auth_algorithm"]:
            auth_algorithm = ike_proposal.get("auth_algorithm")
        if ike_proposal.has_key("integrity_algorithm") and ike_proposal["integrity_algorithm"]:
            integrity_algorithm = ike_proposal.get("integrity_algorithm")
        if ike_proposal.has_key("encryption_algorithm") and ike_proposal["encryption_algorithm"]:
            encryption_algorithm = ike_proposal.get("encryption_algorithm")
        if ike_proposal.has_key("auth_mode") and ike_proposal["auth_mode"]:
            auth_mode = ike_proposal.get("auth_mode")
        if ike_proposal.has_key("dh") and ike_proposal["dh"]:
            dh = ike_proposal.get("dh")
        if ike_proposal.has_key("lifetime") and ike_proposal["lifetime"]:
            lifetime = ike_proposal.get("lifetime")
        str = vpn_template.CONFIG_IKE_PROPOSAL.format(id = id,\
                                              auth_algorithm = auth_algorithm,\
                                              integrity_algorithm = integrity_algorithm,\
                                              encryption_algorithm = encryption_algorithm,\
                                              auth_mode = auth_mode,\
                                              dh = dh,\
                                              lifetime = lifetime)
        return string_transfer(str)
    return None

def get_vpn_ipsec_policy(ipsec_policy):
    alias = ''
    name = ''
    sequence = ''
    scenario = ''
    acl = ''
    ike_peer_name = ''
    ipsec_proposal_name = ''
    pfs = ''
    interface_name = ''
    local_address = ''
    if ipsec_policy:
        if ipsec_policy.has_key("alias") and ipsec_policy["alias"]:
            alias = ipsec_policy.get("alias")
        if ipsec_policy.has_key("name") and ipsec_policy["name"]:
            name = ipsec_policy.get("name")
        if ipsec_policy.has_key("sequence") and ipsec_policy["sequence"]:
            sequence = ipsec_policy.get("sequence")
        if ipsec_policy.has_key("scenario") and ipsec_policy["scenario"]:
            scenario = ipsec_policy.get("scenario")
        if ipsec_policy.has_key("acl") and ipsec_policy["acl"]:
            acl = ipsec_policy.get("acl")
        if ipsec_policy.has_key("ike_peer_name") and ipsec_policy["ike_peer_name"]:
            ike_peer_name = ipsec_policy.get("ike_peer_name")
        if ipsec_policy.has_key("ipsec_proposal_name") and ipsec_policy["ipsec_proposal_name"]:
            ipsec_proposal_name = ipsec_policy.get("ipsec_proposal_name")
        if ipsec_policy.has_key("pfs") and ipsec_policy["pfs"]:
            pfs = ipsec_policy.get("pfs")
        if ipsec_policy.has_key("interface_name") and ipsec_policy["interface_name"]:
            interface_name = ipsec_policy.get('interface_name')
            #TOTO
        if ipsec_policy.has_key("ike_peer_name") and ipsec_policy["ike_peer_name"]:
            local_address = ipsec_policy.get("local_address")

        str = vpn_template.CONFIG_IPSEC_POLICY.format(alias = alias,\
                                              name = name,\
                                              sequence = sequence,\
                                              scenario = scenario,\
                                              acl = acl,\
                                              ike_peer_name = ike_peer_name,\
                                              ipsec_proposal_name = ipsec_proposal_name,\
                                              pfs = pfs,\
                                              interface_name = interface_name,\
                                              local_address = local_address)
        return string_transfer(str)
    return None

def get_index_from_value(type, value, pool):
    entry_cnt = 0
    index = None
    if type == 'range':
        for entry in pool:
            if value >= entry[0] and value <= entry[1]:
                entry_cnt = entry_cnt + value - entry[0]
                index = entry_cnt
                break
            else:
                entry_cnt = entry_cnt + (entry[1] - entry[0]) + 1
    elif type == 'ip_pool':
        for entry in pool:
            if value in netaddr.IPNetwork(entry):
                entry_cnt = entry_cnt + list(netaddr.IPNetwork(entry)).index(netaddr.IPAddress(value))
                index = entry_cnt
                break
            else:
                entry_cnt = entry_cnt + len(netaddr.IPNetwork(entry))
    return index

def get_value_by_index(type, index, pool):
    entry_cnt_last = 0
    entry_cnt = 0
    value = None
    if type == 'range':
        for entry in pool:
            entry_cnt = entry_cnt + (int(entry.split(':')[1]) - int(entry.split(':')[0])) + 1
            if index < entry_cnt:
                value = int(entry.split(':')[0]) + index - entry_cnt_last
                break
            entry_cnt_last = entry_cnt
    elif type == 'ip_pool':
        for entry in pool:
            entry_cnt = entry_cnt + len(netaddr.IPNetwork(entry))
            if index < entry_cnt:
                value = str(list(netaddr.IPNetwork(entry))[index - entry_cnt_last])
                break
            entry_cnt_last = entry_cnt
    return value


def get_vpn_ipsec_proposal(ipsec_proposal):
    ipsec_proposal_name = ''
    transform_protocol = ''
    esp_auth_algorithm = ''
    esp_encryption_algorithm = ''
    ah_auth_algorithm = ''
    encapsulation_mode = ''
    if ipsec_proposal:
        if ipsec_proposal.has_key("ipsec_proposal_name") and ipsec_proposal["ipsec_proposal_name"]:
            ipsec_proposal_name = ipsec_proposal.get("ipsec_proposal_name")
        if ipsec_proposal.has_key("transform_protocol") and ipsec_proposal["transform_protocol"]:
            transform_protocol = ipsec_proposal.get("transform_protocol")
        if ipsec_proposal.has_key("esp_auth_algorithm") and ipsec_proposal["esp_auth_algorithm"]:
            esp_auth_algorithm = ipsec_proposal.get("esp_auth_algorithm")
        if ipsec_proposal.has_key("esp_encryption_algorithm") and ipsec_proposal["esp_encryption_algorithm"]:
            esp_encryption_algorithm = ipsec_proposal.get("esp_encryption_algorithm")
        if ipsec_proposal.has_key("ah_auth_algorithm") and ipsec_proposal["ah_auth_algorithm"]:
            ah_auth_algorithm = ipsec_proposal.get("ah_auth_algorithm")
        if ipsec_proposal.has_key("encapsulation_mode") and ipsec_proposal["encapsulation_mode"]:
            encapsulation_mode = ipsec_proposal.get("encapsulation_mode")

        str = vpn_template.CONFIG_IPSEC_PROPOSAL.format(ipsec_proposal_name = ipsec_proposal_name,\
                                              transform_protocol= transform_protocol,\
                                              esp_auth_algorithm= esp_auth_algorithm,\
                                              esp_encryption_algorithm = esp_encryption_algorithm,\
                                              ah_auth_algorithm = ah_auth_algorithm,\
                                              encapsulation_mode = encapsulation_mode)
        return str
    return None

def get_vpn_ipsec_acl_entries(access_list_entries):
    rule_name = ''
    src_lower_port = ''
    src_upper_port = ''
    des_lower_port = ''
    des_upper_port = ''
    protocol = ''
    destination_ipv4_network = ''
    source_ipv4_network = ''
    if access_list_entries:
        str = ''
        for i in range(len(access_list_entries)):
            access_list_entry = access_list_entries[i]
            if access_list_entry.has_key('rule_name') and access_list_entry['rule_name']:
                rule_name = access_list_entry.get('rule_name')
            if access_list_entry.has_key('src_lower_port') and access_list_entry['src_lower_port']:
                src_lower_port = access_list_entry.get('src_lower_port')
            if access_list_entry.has_key('src_upper_port') and access_list_entry['src_upper_port']:
                src_upper_port = access_list_entry.get('src_upper_port')
            if access_list_entry.has_key('des_lower_port') and access_list_entry['des_lower_port']:
                des_lower_port = access_list_entry.get('des_lower_port')
            if access_list_entry.has_key('des_upper_port') and access_list_entry['des_upper_port']:
                des_upper_port = access_list_entry.get('des_upper_port')
            if access_list_entry.has_key('protocol'):
                protocol = access_list_entry.get('protocol')
            if access_list_entry.has_key('destination_ipv4_network') and access_list_entry['destination_ipv4_network']:
                destination_ipv4_network = access_list_entry.get('destination_ipv4_network')
            if access_list_entry.has_key('source_ipv4_network') and access_list_entry['source_ipv4_network']:
                source_ipv4_network = access_list_entry.get('source_ipv4_network')
            str = str + vpn_template.CONFIG_IPSEC_ACL_LIST_ENTRY.format(rule_name = rule_name,\
                                                  src_lower_port = src_lower_port,\
                                                  src_upper_port = src_upper_port,\
                                                  des_lower_port = des_lower_port,\
                                                  des_upper_port = des_upper_port,\
                                                  protocol = protocol,\
                                                  destination_ipv4_network = destination_ipv4_network,\
                                                  source_ipv4_network = source_ipv4_network)
        return str
    return None



def get_vpn_ipsec_acl_list(ipsec_acl):
    access_control_list_name = ''
    access_list_entries = ''
    access_control_list_oper_data = ''
    access_control_list_type = ''
    if ipsec_acl:
        if ipsec_acl.has_key('access_control_list_name') and ipsec_acl['access_control_list_name']:
            access_control_list_name = ipsec_acl.get('access_control_list_name')
        if ipsec_acl.has_key('vsys') and ipsec_acl['vsys']:
            vsys = ipsec_acl.get('vsys')
        if ipsec_acl.has_key('access_list_entries') and ipsec_acl['access_list_entries']:
            access_list_entries = get_vpn_ipsec_acl_entries(ipsec_acl.get('access_list_entries'))
        if ipsec_acl.has_key('access_control_list_oper_data') and ipsec_acl['access_control_list_oper_data']:
            access_control_list_oper_data = ipsec_acl.get('access_control_list_oper_data')
        if ipsec_acl.has_key('access_control_list_type') and ipsec_acl['access_control_list_type']:
            access_control_list_type = ipsec_acl.get('access_control_list_type')
        str = vpn_template.CONFIG_IPSEC_ACL_LIST_LISTS.format(vsys=vsys,\
                                              access_control_list_name = access_control_list_name,\
                                              access_list_entries = access_list_entries,\
                                              access_control_list_oper_data = access_control_list_oper_data,\
                                              access_control_list_type = access_control_list_type)
        return string_transfer(str)
    return None




def build_auto_save_name(str):
    name = "<name>" + str + "</name>"
    return name
