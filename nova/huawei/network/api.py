# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2011 X.commerce, a business unit of eBay Inc.
# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# Copyright 2013 IBM Corp.
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

from nova.huawei.compute import rpcapi as compute_rpcapi
from nova.network import api as core_api
from nova.huawei.network import rpcapi as network_rpcapi
from nova.openstack.common import log as logging

LOG = logging.getLogger(__name__)


class HuaweiAPI(core_api.API):
    """API for doing networking via the nova-network network manager.

    This is a pluggable module - other implementations do networking via
    other services (such as Neutron).
    """
    _sentinel = object()

    def __init__(self, **kwargs):
        super(HuaweiAPI, self).__init__(**kwargs)
        self.network_rpcapi = network_rpcapi.HuaweiNetworkAPI()
        self.compute_rpcapi = compute_rpcapi.HuaweiComputeAPI()

    @core_api.wrap_check_policy
    def update_interface_address(self, context, instance_uuid, vif_uuid,
                                 network_uuid, address):
        args = {}
        args['instance_uuid'] = instance_uuid
        args['vif_uuid'] = vif_uuid
        args['network_uuid'] = network_uuid
        args['address'] = address
        self.network_rpcapi.update_interface_address(context, **args)

    @core_api.wrap_check_policy
    def update_vif_pg_info(self, context, instance):
        """Inject network info for the instance."""
        self.compute_rpcapi.update_vif_pg_info(context, instance=instance)

    def get_physical_network(self, context, requested_networks):
        network_info = {"network": {}}
        return network_info

    def update_port_profile(self, context, instance, network_info):
        return

    def update_port_info(self, context, instance, requested_networks):
        return

    def deallocate_ports_for_instance(self, context, instance, network_info, requested_networks):
        return

    def check_port_usable(self, context, instance, port_id):
        return