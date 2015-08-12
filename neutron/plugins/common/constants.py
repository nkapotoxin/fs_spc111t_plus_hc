# Copyright 2012 OpenStack Foundation.
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

# service type constants:
CORE = "CORE"
DUMMY = "DUMMY"
LOADBALANCER = "LOADBALANCER"
FIREWALL = "FIREWALL"
VPN = "VPN"
METERING = "METERING"
L3_ROUTER_NAT = "L3_ROUTER_NAT"
SERVICE_CHAIN = 'SERVICE_CHAIN'


#maps extension alias to service type
EXT_TO_SERVICE_MAPPING = {
    'dummy': DUMMY,
    'lbaas': LOADBALANCER,
    'fwaas': FIREWALL,
    'vpnaas': VPN,
    'metering': METERING,
    'router': L3_ROUTER_NAT,
    'servicechain': SERVICE_CHAIN
}

# TODO(salvatore-orlando): Move these (or derive them) from conf file
ALLOWED_SERVICES = [CORE, DUMMY, LOADBALANCER, FIREWALL, VPN, METERING,
                    L3_ROUTER_NAT]

COMMON_PREFIXES = {
    CORE: "",
    DUMMY: "/dummy_svc",
    LOADBALANCER: "/lb",
    FIREWALL: "/fw",
    VPN: "/vpn",
    METERING: "/metering",
    L3_ROUTER_NAT: "",
}

# Service operation status constants
ACTIVE = "ACTIVE"
DOWN = "DOWN"
INACTIVE = "INACTIVE"
CREATED = "CREATED"
PENDING_CREATE = "PENDING_CREATE"
PENDING_UPDATE = "PENDING_UPDATE"
PENDING_DELETE = "PENDING_DELETE"
INACTIVE = "INACTIVE"
ERROR = "ERROR"

ACTIVE_PENDING_STATUSES = (
    ACTIVE,
    PENDING_CREATE,
    PENDING_UPDATE
)

# FWaaS firewall rule action
FWAAS_ALLOW = "allow"
FWAAS_DENY = "deny"

# FWaaS firewall rule mode
FWAAS_MODE_NORMAL = "normal"
FWAAS_MODE_MIX = "mix"
FWAAS_MODE_PROFILE = "profile"

# L3 Protocol name constants
TCP = "tcp"
UDP = "udp"
ICMP = "icmp"

# Network Type constants
TYPE_FLAT = 'flat'
TYPE_GRE = 'gre'
TYPE_LOCAL = 'local'
TYPE_VXLAN = 'vxlan'
TYPE_VLAN = 'vlan'
TYPE_NONE = 'none'

# Values for network_type
VXLAN_UDP_PORT = 4789
