# Copyright (c) 2014 Brocade Communications Systems, Inc.
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


"""NGFW XML Configuration Command Templates.

Interface Configuration Commands
"""


ICMP_TYPE_NUMBER = 256

CONFIG_POLICY_SECURITY_POLICY = """
    <sec-policy>
        <static-policy>
            <static-rule>
                {rule_name_list}
                <policy-log>true</policy-log>
                <session-log>true</session-log>
                <action>{bool_value}</action>
                {option_cfg}
            </static-rule>
        </static-policy>
    </sec-policy>
"""

CONFIG_POLICY_SECURITY_POLICY_TO_DELETE = """
    <sec-policy>
        <static-policy>
            <static-rule>
                {rule_name_list}
            </static-rule>
        </static-policy>
    </sec-policy>
"""

CONFIG_POLICY_SECURITY_POLICY_RULE = """
    <name>{rule_name}</name>
"""

CONFIG_POLICY_SECURITY_POLICY_STATIC_RULE = """
    <static-rule>
        <name>{rule_name}</name>
    </static-rule>
"""

CONFIG_POLICY_SECURITY_POLICY_SOURCE_ZONE = """
    <source-zone>{zone_name}</source-zone>
"""

CONFIG_POLICY_SECURITY_POLICY_DESTINATION_ZONE = """
    <destination-zone>{zone_name}</destination-zone>
"""

CONFIG_POLICY_SECURITY_POLICY_RULE_SERVICE = """
    <service>
        <service-items>
            {rule_service}
        </service-items>
    </service>
"""

CONFIG_POLICY_SECURITY_POLICY_RULE_SERVICE_TCP_UDP = """
    <{protocol}>
        {port_list}
    </{protocol}>
"""

CONFIG_POLICY_SECURITY_POLICY_RULE_SERVICE_ICMP = """
    <service>
        <service-object>{protocol_type}</service-object>
    </service>
"""

CONFIG_POLICY_SECURITY_POLICY_RULE_SERVICE_SRC_PORT = """
    <source-port>
        <start>{port1}</start>
        <end>{port2}</end>
    </source-port>    
"""

CONFIG_POLICY_SECURITY_POLICY_RULE_SERVICE_DST_PORT = """
    <dest-port>
        <start>{port3}</start>
        <end>{port4}</end>
    </dest-port>    
"""

CONFIG_POLICY_SECURITY_POLICY_RULE_DESTINATION_IP = """
    <destination-ip>
        <address-ipv4>
            <address-prefix-ipv4>{ip_address}</address-prefix-ipv4>
        </address-ipv4>    
    </destination-ip>
"""

CONFIG_POLICY_SECURITY_POLICY_RULE_SOURCE_IP = """
    <source-ip>
        <address-ipv4>
            <address-prefix-ipv4>{ip_address}</address-prefix-ipv4>
        </address-ipv4>
    </source-ip>
"""

CONFIG_POLICY_SECURITY_POLICY_OPTION = """
    <option>{option_action}</option>
    <target-policy>{target_rule_name}</target-policy>
"""

CONFIG_POLICY_NAT_SERVER_STATIC_MAP = """
    <nat-server>
        <server-mapping>
            {nat_name_list}
        </server-mapping>
    </nat-server>    
"""

CONFIG_POLICY_NAT_SERVER_STATIC_MAP_NAME = """
    <name>{nat_name}</name>
"""

CONFIG_POLICY_NAT_SERVER_STATIC_MAP_RULE = """
    <global>
        <start-ip>{floatingIP}</start-ip>
    </global>
    <inside>
        <start-ip>{fixedIP}</start-ip>
    </inside>
"""

CONFIG_POLICY_NAT_SERVER_STATIC_MAP_NOREVERSE = """
    <no-reverse>true</no-reverse>
"""

CONFIG_STATIC_ROUTE = """
<routing>
    <routing-instance>
        <name>{name}</name>
        <routing-protocols>
            <routing-protocol>
                    <static-routes>
                        <v4ur:ipv4>
                            <v4ur:route>
                                <v4ur:description>{description}</v4ur:description>
                                <v4ur:destination-prefix>{destination_prefix}</v4ur:destination-prefix>
                                <v4ur:next-hop-list>
                                    <v4ur:next-hop>
                                        <v4ur:address>{next_hop_address}</v4ur:address>
                                        <v4ur:outgoing-interface>{outgoing_interface}</v4ur:outgoing-interface>
                                        <v4ur:priority>{priority}</v4ur:priority>
                                    </v4ur:next-hop>
                                </v4ur:next-hop-list>
                            </v4ur:route>
                        </v4ur:ipv4>
                    </static-routes>    
            </routing-protocol>
        </routing-protocols>
    </routing-instance>
</routing>
"""


CONFIG_ADDRESS_SET_OBJECT = """
<address-set>
    <addr-object>
        <name>{addr_set_object_name}</name>
        <elements>
            <id>{id}</id>
            <address-ipv4>{ip}</address-ipv4>
        </elements>
    </addr-object>
</address-set>
"""
