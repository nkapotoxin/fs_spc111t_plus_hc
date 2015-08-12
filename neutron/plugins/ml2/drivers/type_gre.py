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

from oslo.config import cfg
from oslo.db import exception as db_exc
from six import moves
import sqlalchemy as sa
from sqlalchemy import sql

from neutron.common import exceptions as exc
from neutron.db import api as db_api
from neutron.db import model_base
from neutron.openstack.common.gettextutils import _LE
from neutron.openstack.common import log
from neutron.plugins.common import constants as p_const
from neutron.plugins.ml2.drivers import type_tunnel

LOG = log.getLogger(__name__)

gre_opts = [
    cfg.ListOpt('tunnel_id_ranges',
                default=[],
                help=_("Comma-separated list of <tun_min>:<tun_max> tuples "
                       "enumerating ranges of GRE tunnel IDs that are "
                       "available for tenant network allocation"))
]

cfg.CONF.register_opts(gre_opts, "ml2_type_gre")


class GreAllocation(model_base.BASEV2):

    __tablename__ = 'ml2_gre_allocations'

    gre_id = sa.Column(sa.Integer, nullable=False, primary_key=True,
                       autoincrement=False)
    allocated = sa.Column(sa.Boolean, nullable=False, default=False,
                          server_default=sql.false())


class GreEndpoints(model_base.BASEV2):
    """Represents tunnel endpoint in RPC mode."""
    __tablename__ = 'ml2_gre_endpoints'

    ip_address = sa.Column(sa.String(64), primary_key=True)

    def __repr__(self):
        return "<GreTunnelEndpoint(%s)>" % self.ip_address


class GreTypeDriver(type_tunnel.TunnelTypeDriver):

    def __init__(self):
        super(GreTypeDriver, self).__init__(GreAllocation)

    def get_type(self):
        return p_const.TYPE_GRE

    def initialize(self):
        try:
            self._initialize(cfg.CONF.ml2_type_gre.tunnel_id_ranges)
        except exc.NetworkTunnelRangeError:
            LOG.exception(_("Failed to parse tunnel_id_ranges. "
                            "Service terminated!"))
            raise SystemExit()

    def sync_allocations(self):

        # determine current configured allocatable gres
        gre_ids = set()
        for gre_id_range in self.tunnel_ranges:
            tun_min, tun_max = gre_id_range
            if tun_max + 1 - tun_min > 1000000:
                LOG.error(_LE("Skipping unreasonable gre ID range "
                            "%(tun_min)s:%(tun_max)s"),
                          {'tun_min': tun_min, 'tun_max': tun_max})
            else:
                gre_ids |= set(moves.xrange(tun_min, tun_max + 1))

        session = db_api.get_session()
        with session.begin(subtransactions=True):
            # remove from table unallocated tunnels not currently allocatable
            allocs = (session.query(GreAllocation).all())
            for alloc in allocs:
                try:
                    # see if tunnel is allocatable
                    gre_ids.remove(alloc.gre_id)
                except KeyError:
                    # it's not allocatable, so check if its allocated
                    if not alloc.allocated:
                        # it's not, so remove it from table
                        LOG.debug("Removing tunnel %s from pool", alloc.gre_id)
                        session.delete(alloc)

            # add missing allocatable tunnels to table
            for gre_id in sorted(gre_ids):
                alloc = GreAllocation(gre_id=gre_id)
                session.add(alloc)

    def get_endpoints(self):
        """Get every gre endpoints from database."""

        LOG.debug("get_gre_endpoints() called")
        session = db_api.get_session()

        with session.begin(subtransactions=True):
            gre_endpoints = session.query(GreEndpoints)
            return [{'ip_address': gre_endpoint.ip_address}
                    for gre_endpoint in gre_endpoints]

    def add_endpoint(self, ip):
        LOG.debug("add_gre_endpoint() called for ip %s", ip)
        session = db_api.get_session()
        try:
            gre_endpoint = GreEndpoints(ip_address=ip)
            gre_endpoint.save(session)
        except db_exc.DBDuplicateEntry:
            gre_endpoint = (session.query(GreEndpoints).
                            filter_by(ip_address=ip).one())
            LOG.warning(_("Gre endpoint with ip %s already exists"), ip)
        return gre_endpoint
