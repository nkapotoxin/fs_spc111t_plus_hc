# Copyright (c) 2013 OpenStack Foundation
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
import abc

from neutron.common import exceptions as exc
from neutron.common import topics
from neutron.openstack.common.gettextutils import _LI
from neutron.openstack.common.gettextutils import _LW
from neutron.openstack.common import log
from neutron.plugins.common import utils as plugin_utils
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers import helpers

LOG = log.getLogger(__name__)

TUNNEL = 'tunnel'


class TunnelTypeDriver(helpers.TypeDriverHelper):
    """Define stable abstract interface for ML2 type drivers.

    tunnel type networks rely on tunnel endpoints. This class defines abstract
    methods to manage these endpoints.
    """

    def __init__(self, model):
        super(TunnelTypeDriver, self).__init__(model)
        self.segmentation_key = iter(self.primary_keys).next()

    @abc.abstractmethod
    def sync_allocations(self):
        """Synchronize type_driver allocation table with configured ranges."""

    @abc.abstractmethod
    def add_endpoint(self, ip):
        """Register the endpoint in the type_driver database.

        param ip: the ip of the endpoint
        """
        pass

    @abc.abstractmethod
    def get_endpoints(self):
        """Get every endpoint managed by the type_driver

        :returns a list of dict [{id:endpoint_id, ip_address:endpoint_ip},..]
        """
        pass

    def _initialize(self, raw_tunnel_ranges):
        self.tunnel_ranges = []
        self._parse_tunnel_ranges(raw_tunnel_ranges, self.tunnel_ranges)
        self.sync_allocations()

    def _parse_tunnel_ranges(self, tunnel_ranges, current_range):
        for entry in tunnel_ranges:
            entry = entry.strip()
            try:
                tun_min, tun_max = entry.split(':')
                tun_min = tun_min.strip()
                tun_max = tun_max.strip()
                tunnel_range = int(tun_min), int(tun_max)
            except ValueError as ex:
                raise exc.NetworkTunnelRangeError(tunnel_range=entry, error=ex)
            plugin_utils.verify_tunnel_range(tunnel_range, self.get_type())
            current_range.append(tunnel_range)
        LOG.info(_LI("%(type)s ID ranges: %(range)s"),
                 {'type': self.get_type(), 'range': current_range})

    def is_partial_segment(self, segment):
        return segment.get(api.SEGMENTATION_ID) is None

    def validate_provider_segment(self, segment):
        physical_network = segment.get(api.PHYSICAL_NETWORK)
        if physical_network:
            msg = _("provider:physical_network specified for %s "
                    "network") % segment.get(api.NETWORK_TYPE)
            raise exc.InvalidInput(error_message=msg)

        for key, value in segment.items():
            if value and key not in [api.NETWORK_TYPE,
                                     api.SEGMENTATION_ID]:
                msg = (_("%(key)s prohibited for %(tunnel)s provider network"),
                       {'key': key, 'tunnel': segment.get(api.NETWORK_TYPE)})
                raise exc.InvalidInput(error_message=msg)

    def reserve_provider_segment(self, session, segment):
        if self.is_partial_segment(segment):
            alloc = self.allocate_partially_specified_segment(session)
            if not alloc:
                raise exc.NoNetworkAvailable()
        else:
            segmentation_id = segment.get(api.SEGMENTATION_ID)
            alloc = self.allocate_fully_specified_segment(
                session, **{self.segmentation_key: segmentation_id})
            if not alloc:
                raise exc.TunnelIdInUse(tunnel_id=segmentation_id)
        return {api.NETWORK_TYPE: self.get_type(),
                api.PHYSICAL_NETWORK: None,
                api.SEGMENTATION_ID: getattr(alloc, self.segmentation_key)}

    def allocate_tenant_segment(self, session):
        alloc = self.allocate_partially_specified_segment(session)
        if not alloc:
            return
        return {api.NETWORK_TYPE: self.get_type(),
                api.PHYSICAL_NETWORK: None,
                api.SEGMENTATION_ID: getattr(alloc, self.segmentation_key)}

    def release_segment(self, session, segment):
        tunnel_id = segment[api.SEGMENTATION_ID]

        inside = any(lo <= tunnel_id <= hi for lo, hi in self.tunnel_ranges)

        info = {'type': self.get_type(), 'id': tunnel_id}
        with session.begin(subtransactions=True):
            query = (session.query(self.model).
                     filter_by(**{self.segmentation_key: tunnel_id}))
            if inside:
                count = query.update({"allocated": False})
                if count:
                    LOG.debug("Releasing %(type)s tunnel %(id)s to pool",
                              info)
            else:
                count = query.delete()
                if count:
                    LOG.debug("Releasing %(type)s tunnel %(id)s outside pool",
                              info)

        if not count:
            LOG.warning(_LW("%(type)s tunnel %(id)s not found"), info)

    def get_allocation(self, session, tunnel_id):
        return (session.query(self.model).
                filter_by(**{self.segmentation_key: tunnel_id}).
                first())


class TunnelRpcCallbackMixin(object):

    def setup_tunnel_callback_mixin(self, notifier, type_manager):
        self._notifier = notifier
        self._type_manager = type_manager

    def tunnel_sync(self, rpc_context, **kwargs):
        """Update new tunnel.

        Updates the database with the tunnel IP. All listening agents will also
        be notified about the new tunnel IP.
        """
        tunnel_ip = kwargs.get('tunnel_ip')
        tunnel_type = kwargs.get('tunnel_type')
        if not tunnel_type:
            msg = _("Network_type value needed by the ML2 plugin")
            raise exc.InvalidInput(error_message=msg)
        driver = self._type_manager.drivers.get(tunnel_type)
        if driver:
            tunnel = driver.obj.add_endpoint(tunnel_ip)
            tunnels = driver.obj.get_endpoints()
            entry = {'tunnels': tunnels}
            # Notify all other listening agents
            self._notifier.tunnel_update(rpc_context, tunnel.ip_address,
                                         tunnel_type)
            # Return the list of tunnels IP's to the agent
            return entry
        else:
            msg = _("network_type value '%s' not supported") % tunnel_type
            raise exc.InvalidInput(error_message=msg)


class TunnelAgentRpcApiMixin(object):

    def _get_tunnel_update_topic(self):
        return topics.get_topic_name(self.topic,
                                     TUNNEL,
                                     topics.UPDATE)

    def tunnel_update(self, context, tunnel_ip, tunnel_type):
        self.fanout_cast(context,
                         self.make_msg('tunnel_update',
                                       tunnel_ip=tunnel_ip,
                                       tunnel_type=tunnel_type),
                         topic=self._get_tunnel_update_topic())
