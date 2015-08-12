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
import itertools

import uuid
from oslo.config import cfg
from neutronclient.common import exceptions as neutron_client_exc
from nova.compute import utils as compute_utils
from nova.compute import task_states
from nova import exception
from nova import objects

from nova.i18n import _, _LE, _LW
from nova.network import base_api
from nova.network import model as network_model
from nova.network import neutronv2
from nova.objects import huawei_instance_extra
from nova.huawei import exception as hw_exception

from nova.network.neutronv2 import api as neutronv2_api
from nova.openstack.common import excutils
from nova.openstack.common import log as logging
from nova.openstack.common import jsonutils
from nova.openstack.common import lockutils
from nova.pci import pci_request
from nova.network.neutronv2 import constants
from nova.compute import flavors

LOG = logging.getLogger(__name__)
CONF = cfg.CONF

class API(neutronv2_api.API):
    """Huawei extend API for interacting with the neutron 2.x API."""

    def __init__(self):
        super(API, self).__init__()

    def allocate_port_for_instance(self, context, instance, port_id,
                                   network_id=None, requested_ip=None, pci_list=None):
        """Allocate a port for the instance."""
        if not network_id and not port_id:
            nets = self._get_available_networks(context, context.project_id)
            if len(nets) > 1:
                msg = _("Multiple possible networks found, use a Network "
                        "ID to be more specific.")
                raise exception.NetworkAmbiguous(msg)
        requested_networks = objects.NetworkRequestList(
            objects=[objects.NetworkRequest(network_id=network_id,
                address=requested_ip,
                port_id=port_id,
                pci_request_id=None)])
        return self.allocate_for_instance(context, instance,
            requested_networks=requested_networks, pci_list=pci_list)

    def allocate_for_instance(self, context, instance, **kwargs):
        """Allocate network resources for the instance.

        :param context: The request context.
        :param instance: nova.objects.instance.Instance object.
        :param requested_networks: optional value containing
            network_id, fixed_ip, and port_id
        :param security_groups: security groups to allocate for instance
        :param macs: None or a set of MAC addresses that the instance
            should use. macs is supplied by the hypervisor driver (contrast
            with requested_networks which is user supplied).
            NB: NeutronV2 currently assigns hypervisor supplied MAC addresses
            to arbitrary networks, which requires openflow switches to
            function correctly if more than one network is being used with
            the bare metal hypervisor (which is the only one known to limit
            MAC addresses).
        :param dhcp_options: None or a set of key/value pairs that should
            determine the DHCP BOOTP response, eg. for PXE booting an instance
            configured with the baremetal hypervisor. It is expected that these
            are already formatted for the neutron v2 api.
            See nova/virt/driver.py:dhcp_options_for_instance for an example.
        """
        hypervisor_macs = kwargs.get('macs', None)
        available_macs = None
        if hypervisor_macs is not None:
            # Make a copy we can mutate: records macs that have not been used
            # to create a port on a network. If we find a mac with a
            # pre-allocated port we also remove it from this set.
            available_macs = set(hypervisor_macs)
        neutron = neutronv2.get_client(context)
        LOG.debug('allocate_for_instance()', instance=instance)
        if not instance.project_id:
            msg = _('empty project id for instance %s')
            raise exception.InvalidInput(
                reason=msg % instance.uuid)
        requested_networks = kwargs.get('requested_networks')
        dhcp_opts = kwargs.get('dhcp_options', None)
        ports = {}
        net_ids = []
        ordered_networks = []
        if requested_networks:
            for request in requested_networks:
                if request.port_id:
                    try:
                        port = neutron.show_port(request.port_id)['port']
                    except neutron_client_exc.PortNotFoundClient:
                        raise exception.PortNotFound(port_id=request.port_id)
                    if port['tenant_id'] != instance.project_id:
                        raise exception.PortNotUsable(port_id=request.port_id,
                                                      instance=instance.uuid)
                    if (port.get('device_id') and
                            port.get('device_id') != instance['uuid']):
                        raise exception.PortInUse(port_id=request.port_id)
                    if hypervisor_macs is not None:
                        if port['mac_address'] not in hypervisor_macs:
                            raise exception.PortNotUsable(
                                port_id=request.port_id,
                                instance=instance.uuid)
                        else:
                            # Don't try to use this MAC if we need to create a
                            # port on the fly later. Identical MACs may be
                            # configured by users into multiple ports so we
                            # discard rather than popping.
                            available_macs.discard(port['mac_address'])
                    request.network_id = port['network_id']
                    ports[request.port_id] = port
                if request.network_id:
                    net_ids.append(request.network_id)
                    ordered_networks.append(request)

        nets = self._get_available_networks(context, instance.project_id,
                                            net_ids)
        if not nets:
            LOG.warn(_LW("No network configured!"), instance=instance)
            return network_model.NetworkInfo([])

        # if this function is directly called without a requested_network param
        # or if it is indirectly called through allocate_port_for_instance()
        # with None params=(network_id=None, requested_ip=None, port_id=None,
        # pci_request_id=None):
        if (not requested_networks
            or requested_networks.is_single_unspecified):
            # bug/1267723 - if no network is requested and more
            # than one is available then raise NetworkAmbiguous Exception
            if len(nets) > 1:
                msg = _("Multiple possible networks found, use a Network "
                        "ID to be more specific.")
                raise exception.NetworkAmbiguous(msg)
            ordered_networks.append(
                objects.NetworkRequest(network_id=nets[0]['id']))
            db_req_networks = list()
            db_obj = huawei_instance_extra.HuaweiInstanceExtra(
                instance_uuid=instance.uuid)
            db_instance = db_obj.get_by_instance_uuid(
                context, instance_uuid=instance.uuid)
            if db_instance.request_network:
                db_req_networks = jsonutils.loads(db_instance.request_network)
            db_req_networks.append([nets[0]['id'], None, None])
            db_obj.request_network = jsonutils.dumps(db_req_networks)
            db_obj.create(context)

        # NOTE(): check external net attach permission after the
        #                check for ambiguity, there could be another
        #                available net which is permitted bug/1364344
        self._check_external_network_attach(context, nets)

        security_groups = kwargs.get('security_groups', [])
        security_group_ids = []

        # TODO() Should optimize more to do direct query for security
        # group if len(security_groups) == 1
        if len(security_groups):
            search_opts = {'tenant_id': instance.project_id}
            user_security_groups = neutron.list_security_groups(
                **search_opts).get('security_groups')

        for security_group in security_groups:
            name_match = None
            uuid_match = None
            for user_security_group in user_security_groups:
                if user_security_group['name'] == security_group:
                    if name_match:
                        raise exception.NoUniqueMatch(
                            _("Multiple security groups found matching"
                              " '%s'. Use an ID to be more specific.") %
                            security_group)

                    name_match = user_security_group['id']
                if user_security_group['id'] == security_group:
                    uuid_match = user_security_group['id']

            # If a user names the security group the same as
            # another's security groups uuid, the name takes priority.
            if not name_match and not uuid_match:
                raise exception.SecurityGroupNotFound(
                    security_group_id=security_group)
            elif name_match:
                security_group_ids.append(name_match)
            elif uuid_match:
                security_group_ids.append(uuid_match)

        touched_port_ids = []
        created_port_ids = []
        ports_in_requested_order = []
        nets_in_requested_order = []
        for request in ordered_networks:
            # Network lookup for available network_id
            network = None
            for net in nets:
                if net['id'] == request.network_id:
                    network = net
                    break
            # if network_id did not pass validate_networks() and not available
            # here then skip it safely not continuing with a None Network
            else:
                continue

            nets_in_requested_order.append(network)
            # If security groups are requested on an instance then the
            # network must has a subnet associated with it. Some plugins
            # implement the port-security extension which requires
            # 'port_security_enabled' to be True for security groups.
            # That is why True is returned if 'port_security_enabled'
            # is not found.
            if (security_groups and not (
                    network['subnets']
                    and network.get('port_security_enabled', True))):
                # add for roll back
                self._delete_ports(neutron, instance, created_port_ids)
                raise exception.SecurityGroupCannotBeApplied()
            request.network_id = network['id']
            zone = 'compute:%s' % instance.availability_zone
            port_req_body = {'port': {'device_id': instance.uuid,
                                      'device_owner': zone}}
            try:
                self._populate_neutron_extension_values(context,
                                                        instance,
                                                        request.pci_request_id,
                                                        port_req_body)
                # Requires admin creds to set port bindings
                port_client = (neutron if not
                self._has_port_binding_extension(context) else
                               neutronv2.get_client(context, admin=True))
                if request.port_id:
                    port = ports[request.port_id]
                    port_client.update_port(port['id'], port_req_body)
                    touched_port_ids.append(port['id'])
                    ports_in_requested_order.append(port['id'])
                else:
                    created_port = self._create_port(
                        port_client, instance, request.network_id,
                        port_req_body, request.address,
                        security_group_ids, available_macs, dhcp_opts)
                    created_port_ids.append(created_port)
                    ports_in_requested_order.append(created_port)
            except Exception:
                with excutils.save_and_reraise_exception():
                    for port_id in touched_port_ids:
                        try:
                            port_req_body = {'port': {'device_id': ''}}
                            # Requires admin creds to set port bindings
                            if self._has_port_binding_extension(context):
                                port_req_body['port']['binding:host_id'] = None
                                port_client = neutronv2.get_client(
                                    context, admin=True)
                            else:
                                port_client = neutron
                            port_client.update_port(port_id, port_req_body)
                        except Exception:
                            msg = _LE("Failed to update port %s")
                            LOG.exception(msg, port_id)

                    self._delete_ports(neutron, instance, created_port_ids)

        pci_list = kwargs.get('pci_list', [])
        nw_info = self.get_instance_nw_info(context, instance,
                                            networks=nets_in_requested_order,
                                            port_ids=ports_in_requested_order,
                                            pci_list=pci_list)
        # NOTE(): Only return info about ports we created in this run.
        # In the initial allocation case, this will be everything we created,
        # and in later runs will only be what was created that time. Thus,
        # this only affects the attach case, not the original use for this
        # method.
        return network_model.NetworkInfo([vif for vif in nw_info
                                          if vif['id'] in created_port_ids +
                                             touched_port_ids])

    def get_instance_nw_info(self, context, instance, networks=None,
                             port_ids=None, use_slave=False, pci_list=None):
        """Return network information for specified instance
           and update cache.
        """
        # NOTE(): It would be nice if use_slave had us call
        #                   special APIs that pummeled slaves instead of
        #                   the master. For now we just ignore this arg.
        with lockutils.lock('refresh_cache-%s' % instance['uuid']):
            instance = objects.Instance.get_by_uuid(context,
                instance['uuid'], expected_attrs=['system_metadata'],
                use_slave=use_slave)
            result = self._get_instance_nw_info(context, instance, networks,
                port_ids, pci_list)
            base_api.update_instance_cache_with_nw_info(self, context,
                instance,
                nw_info=result,
                update_cells=False)
        return result

    def _get_instance_nw_info(self, context, instance, networks=None,
                              port_ids=None, pci_list=None):
        # NOTE(): This is an inner method intended to be called
        # by other code that updates instance nwinfo. It *must* be
        # called with the refresh_cache-%(instance_uuid) lock held!
        LOG.debug('get_instance_nw_info()', instance=instance)
        nw_info = self._build_network_info_model(context, instance, networks,
            port_ids, pci_list)
        return network_model.NetworkInfo.hydrate(nw_info)

    def _find_pci_num(self, pcilist):
        free_pci = None
        if pcilist == None or len(pcilist) == 0:
            free_pci = 3

            return free_pci
        pcilist.sort()
        if pcilist[-1] >= 31:
            for i in range(3,31):
                if i not in pcilist:
                    free_pci = i
                    break
        else:
            free_pci = pcilist[-1] + 1

        if not free_pci:
            LOG.error("Cannot find available PCI slot num")
            raise hw_exception.PciSlotNotFree()
        return free_pci

    def _build_network_info_model(self, context, instance, networks=None,
                                  port_ids=None, pci_list=None):
        """Return list of ordered VIFs attached to instance.

        :param context - request context.
        :param instance - instance we are returning network info for.
        :param networks - List of networks being attached to an instance.
                          If value is None this value will be populated
                          from the existing cached value.
        :param port_ids - List of port_ids that are being attached to an
                          instance in order of attachment. If value is None
                          this value will be populated from the existing
                          cached value.
        """

        search_opts = {'tenant_id': instance['project_id'],
                       'device_id': instance['uuid'], }
        client = neutronv2.get_client(context, admin=True)
        data = client.list_ports(**search_opts)

        current_neutron_ports = data.get('ports', [])
        networks, port_ids, iface_slot_map = self._gather_port_ids_and_networks(
            context, instance, networks, port_ids)
        nw_info = network_model.NetworkInfo()

        current_neutron_port_map = {}
        for current_neutron_port in current_neutron_ports:
            current_neutron_port_map[current_neutron_port['id']] = (
                current_neutron_port)

        for port_id in port_ids:
            current_neutron_port = current_neutron_port_map.get(port_id)
            if current_neutron_port:
                vif_active = False
                if (current_neutron_port['admin_state_up'] is False
                    or current_neutron_port['status'] == 'ACTIVE'):
                    vif_active = True

                network_IPs = self._nw_info_get_ips(client,
                    current_neutron_port)
                subnets = self._nw_info_get_subnets(context,
                    current_neutron_port,
                    network_IPs)

                devname = "tap" + current_neutron_port['id']
                devname = devname[:network_model.NIC_NAME_LEN]

                network, ovs_interfaceid = (
                    self._nw_info_build_network(current_neutron_port,
                        networks, subnets))
                if current_neutron_port['id'] in iface_slot_map:
                    free_pci = iface_slot_map[current_neutron_port['id']]
                else:
                    free_pci = self._find_pci_num(pci_list)
                    pci_list.append(free_pci)
                nw_info.append(network_model.VIF(
                    id=current_neutron_port['id'],
                    address=current_neutron_port['mac_address'],
                    network=network,
                    vnic_type=current_neutron_port.get('binding:vnic_type',
                        network_model.VNIC_TYPE_NORMAL),
                    type=current_neutron_port.get('binding:vif_type'),
                    profile=current_neutron_port.get('binding:profile'),
                    details=current_neutron_port.get('binding:vif_details'),
                    ovs_interfaceid=ovs_interfaceid,
                    devname=devname,
                    active=vif_active,
                    pci_slotnum=free_pci))

        return nw_info

    def _gather_port_ids_and_networks(self, context, instance, networks=None,
                                      port_ids=None):
        """Return an instance's complete list of port_ids and networks."""

        if ((networks is None and port_ids is not None) or
                (port_ids is None and networks is not None)):
            message = ("This method needs to be called with either "
                       "networks=None and port_ids=None or port_ids and "
                       " networks as not none.")
            raise exception.NovaException(message=message)

        ifaces = compute_utils.get_nw_info_for_instance(instance)
        # This code path is only done when refreshing the network_cache
        if port_ids is None:
            port_ids = [iface['id'] for iface in ifaces]
            net_ids = [iface['network']['id'] for iface in ifaces]

        if networks is None:
            networks = self._get_available_networks(context,
                                                    instance['project_id'],
                                                    net_ids)
        # an interface was added/removed from instance.
        else:
            # Since networks does not contain the existing networks on the
            # instance we use their values from the cache and add it.
            networks = networks + [
                {'id': iface['network']['id'],
                 'name': iface['network']['label'],
                 'tenant_id': iface['network']['meta']['tenant_id']}
                for iface in ifaces]

            # Include existing interfaces so they are not removed from the db.
            port_ids = [iface['id'] for iface in ifaces] + port_ids

        iface_slot_map = {}
        for iface in ifaces:
            iface_slot_map[iface['id']] = iface['meta'].get('pci_slotnum',
                                                             None)

        return networks, port_ids, iface_slot_map

    def create_pci_requests_for_sriov_ports(self, context, pci_requests,
                                            requested_networks):
        """Check requested networks for any SR-IOV port request.

        Create a PCI request object for each SR-IOV port, and add it to the
        pci_requests object that contains a list of PCI request object.
        """
        if not requested_networks:
            return

        neutron = neutronv2.get_client(context, admin=True)
        for request_net in requested_networks:
            phynet_name = None
            vnic_type = network_model.VNIC_TYPE_NORMAL

            # TODO if the base code changes, should check here
            vnic_type_list = [network_model.VNIC_TYPE_VHOSTUSER,
                              network_model.VNIC_TYPE_NORMAL]

            if request_net.port_id:
                vnic_type, phynet_name = self._get_port_vnic_info(
                    context, neutron, request_net.port_id)
            pci_request_id = None
            if vnic_type not in vnic_type_list:
                request = objects.InstancePCIRequest(
                    count=1,
                    spec=[{pci_request.PCI_NET_TAG: phynet_name}],
                    request_id=str(uuid.uuid4()))
                pci_requests.requests.append(request)
                pci_request_id = request.request_id

            request_net.pci_request_id = pci_request_id

    def get_physical_network(self, context, requested_networks):

        network_info = {"network":{}}
        if not requested_networks:
            return network_info

        vnic_type_list = [network_model.VNIC_TYPE_VHOSTUSER]
        neutron = neutronv2.get_client(context, admin=True)
        for request_net in requested_networks:
            if request_net.port_id:
                vnic_type, phynet_name = self._get_port_vnic_info(
                    context, neutron, request_net.port_id)
                if vnic_type in vnic_type_list and phynet_name:
                    network_info['network'][phynet_name
                    ] = network_info['network'].get(phynet_name, 0) + 1

        LOG.debug("the physical network_info is %s", network_info)
        return network_info

    def get_subnet_by_id(self, context, subnet_id):
        """
        get subnet info by subnet id
        :param context:
        :param subnet_id:
        :return:
        """
        search_opts = {'id': subnet_id}
        data = neutronv2.get_client(context).list_subnets(**search_opts)
        ipam_subnets = data.get('subnets', [])
        result = None

        for subnet in ipam_subnets:
            if subnet_id == subnet['id']:
                result = subnet
                break
        return result

    def migrate_instance_finish(self, context, instance, migration, rt=None):
        """Finish migrating the network of an instance."""
        if not self._has_port_binding_extension(context, refresh_cache=True):
            return

        neutron = neutronv2.get_client(context, admin=True)
        search_opts = {'device_id': instance['uuid'],
                       'tenant_id': instance['project_id']}
        data = neutron.list_ports(**search_opts)
        ports = data['ports']

        vif_profiles = {}
        allocated_pci_devs = []
        if rt:
            network_info = instance['info_cache'].get('network_info')
            task_state = instance['task_state'] if isinstance(
                instance, dict) else instance.task_state
            if task_state == task_states.RESIZE_REVERTING:
                inst_pcis = rt.pci_tracker.allocations[instance['uuid']]
            else:
                inst_pcis = rt.pci_tracker.claims[instance['uuid']]
            for claimed_dev, port in itertools.product(inst_pcis, ports):
                pool = rt.pci_tracker.pci_stats._create_pool_keys_from_dev(
                    claimed_dev)
                if not pool or 'physical_network' not in pool:
                    LOG.warning(_("Cannot get pool for dev: %s or device "
                                  "haven't physical_network"), claimed_dev)
                    continue
                if (pool['physical_network'] == port['binding:profile'].get(
                        'physical_network') and claimed_dev.address not in
                        allocated_pci_devs and port['id'] not in vif_profiles):
                    port['binding:profile']['pci_slot'] = claimed_dev.address
                    allocated_pci_devs.append(claimed_dev.address)
                    port['binding:profile']['pci_vendor_info'] = ':'.join((
                        pool['vendor_id'], pool['product_id']))
                    vif_profiles[port['id']] = port['binding:profile']
            for vif in network_info:
                if vif['id'] in vif_profiles:
                    vif['profile'] = vif_profiles[vif['id']]
        for p in ports:
            port_req_body = {'port': {'binding:host_id':
                                          migration['dest_compute']}}
            if vif_profiles and p['id'] in vif_profiles:
                port_req_body['port'].update(
                    {'binding:profile': vif_profiles[p['id']]})
            try:
                neutron.update_port(p['id'], port_req_body)
            except Exception:
                with excutils.save_and_reraise_exception():
                    msg = _LE("Unable to update host of port %s")
                    LOG.exception(msg, p['id'])

    def update_port_profile(self, context, instance, network_info):
        neutron = neutronv2.get_client(context, admin=True)
        for vif in network_info:
            try:
                neutron.update_port(vif['id'],
                                    {'port': {'binding:profile':
                                              vif['profile']}})
            except Exception:
                with excutils.save_and_reraise_exception():
                    LOG.exception(_LE("Unable to update host of port %s"),
                                  vif['id'])

    def update_port_info(self, context, instance, requested_networks):
        port_req_body = {'port': {}}
        neutron = neutronv2.get_client(context)
        for request in requested_networks:
            # not hostdev network port info
            if not request.pci_request_id:
                continue

            if not request.port_id:
                continue

            self._refresh_neutron_extensions_cache(context)
            if self._has_port_binding_extension(context):
                self._populate_neutron_binding_profile(instance,
                                                       request.pci_request_id,
                                                       port_req_body)

            # Requires admin creds to set port bindings
            port_client = (neutron if not
            self._has_port_binding_extension(context) else
                           neutronv2.get_client(context, admin=True))

            port_client.update_port(request.port_id, port_req_body)

    def get_port_type(self, context, port_id):
         neutron = neutronv2.get_client(context)
         vnic_type, phynet_name = self._get_port_vnic_info(
            context, neutron, port_id)
         return vnic_type
    def _populate_neutron_extension_values(self, context, instance,
                                           pci_request_id, port_req_body):
        """Populate neutron extension values for the instance.

        If the extensions loaded contain QOS_QUEUE then pass the rxtx_factor.
        """
        self._refresh_neutron_extensions_cache(context)
        if constants.QOS_QUEUE in self.extensions:
            flavor = flavors.extract_flavor(instance)
            rxtx_factor = flavor.get('rxtx_factor')
            port_req_body['port']['rxtx_factor'] = rxtx_factor
        if self._has_port_binding_extension(context):
            tmp_host = instance.get('host')
            LOG.info("to create network: orig_host=%s" % tmp_host)
            try:
                if CONF.host_postfix is not None:
                    tmp_host = tmp_host.rstrip(CONF.host_postfix)
            except Exception, e:
                tmp_host = instance.get('host')
            LOG.info("to create network: after_host=%s" % tmp_host)
            port_req_body['port']['binding:host_id'] = tmp_host
            self._populate_neutron_binding_profile(instance,
                                                   pci_request_id,
                                                   port_req_body)

    def deallocate_ports_for_instance(self, context, instance, network_info, requested_networks):
        if network_info is None:
            # not allocated networks
            return

        neutron = neutronv2.get_client(context)
        port_req_body = {'port': {'device_id': ''}}
        # Requires admin creds to set port bindings
        if self._has_port_binding_extension(context):
            port_req_body['port']['binding:host_id'] = None
            port_client = neutronv2.get_client(
                context, admin=True)
        else:
            port_client = neutron

        if requested_networks:
            for req in requested_networks:
                if req.port_id:
                    port_client.update_port(req.port_id, port_req_body)
                elif req.network_id:
                    port_ids = []
                    port_id=dict(network_info[0]).get('id')
                    port_ids.append(port_id)
                    self._delete_ports(neutron, instance, port_ids)

        self.get_instance_nw_info(context, instance, use_slave=True)

    def check_port_usable(self, context, instance, port_id):
        if port_id is None:
            return

        neutron = neutronv2.get_client(context)
        try:
            port = neutron.show_port(port_id)['port']
        except neutron_client_exc.PortNotFoundClient:
            raise exception.PortNotFound(port_id=port_id)
        if port['tenant_id'] != instance.project_id:
            raise exception.PortNotUsable(port_id=port_id,
                                          instance=instance.uuid)
        if port.get('device_id'):
            raise exception.PortInUse(port_id=port_id)