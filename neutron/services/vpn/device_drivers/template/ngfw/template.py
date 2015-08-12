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

CONFIG_IPSEC_ACL_LIST_LISTS = """
    <access-lists>
        <access-list>
            <access-control-list-name>{access_control_list_name}</access-control-list-name>
            <access-list-entries>{access_list_entries}</access-list-entries>
            <hw-acl:vsys>{vsys}</hw-acl:vsys>
        </access-list>
    </access-lists>
"""

CONFIG_IPSEC_ACL_LIST_ENTRY = """
    <access-list-entry>
        <rule-name>{rule_name}</rule-name>
        <matches>
            <protocol>{protocol}</protocol>
            <destination-ipv4-network>{destination_ipv4_network}</destination-ipv4-network>
            <source-ipv4-network>{source_ipv4_network}</source-ipv4-network>
        </matches>
        <actions>
          <permit/>
        </actions>
    </access-list-entry>
"""

CONFIG_IKE_PEER = """
    <ike-peer>
        <ike-peer>
            <name>{ike_peer_name}</name>
            <vsys>{vsys_num}</vsys>
            <pre-shared-key>{pre_shared_key}</pre-shared-key>
            <ike-version>{ike_version}</ike-version>
            <ike-proposal>{ike_proposal}</ike-proposal>
            <peer-address>{peer_address}</peer-address>
            <phase1-mode>{phase1_mode}</phase1-mode>
            <vpn-instance>{vpn_instance}</vpn-instance>
        </ike-peer>
    </ike-peer>
"""

CONFIG_IKE_PROPOSAL = """
    <ike-proposal>
        <ike-proposal>
            <id>{id}</id>
            <auth-algorithm>{auth_algorithm}</auth-algorithm>
            <integrity-algorithm>{integrity_algorithm}</integrity-algorithm>
            <encryption-algorithm>{encryption_algorithm}</encryption-algorithm>
            <auth-mode>{auth_mode}</auth-mode>
            <dh>{dh}</dh>
            <lifetime>{lifetime}</lifetime>
        </ike-proposal>
    </ike-proposal>
"""

CONFIG_IPSEC_POLICY = """
    <ipsec-policy>
        <ipsec-policy>
            <alias>{alias}</alias>
            <name>{name}</name>
            <sequence>{sequence}</sequence>
            <scenario>{scenario}</scenario>
            <acl>{acl}</acl>
            <ike-peer-name>{ike_peer_name}</ike-peer-name>
            <ipsec-proposal-name>{ipsec_proposal_name}</ipsec-proposal-name>
            <pfs>{pfs}</pfs>
            <local-information>
                <interface-name>{interface_name}</interface-name>
                <local-address>{local_address}</local-address>
            </local-information>
        </ipsec-policy>
    </ipsec-policy>
"""

CONFIG_IPSEC_PROPOSAL = """
    <ipsec-proposal>
        <ipsec-proposal>
            <name>{ipsec_proposal_name}</name>
            <transform-protocol>{transform_protocol}</transform-protocol>
            <esp-auth-algorithm>{esp_auth_algorithm}</esp-auth-algorithm>
            <esp-encryption-algorithm>{esp_encryption_algorithm}</esp-encryption-algorithm>
            <ah-auth-algorithm>{ah_auth_algorithm}</ah-auth-algorithm>
            <encapsulation-mode>{encapsulation_mode}</encapsulation-mode>
        </ipsec-proposal>
    </ipsec-proposal>
"""
