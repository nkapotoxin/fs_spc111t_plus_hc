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

from sqlalchemy import or_
from sqlalchemy.orm import exc

from oslo.db import exception as db_exc

from neutron.common import constants as n_const
from neutron.db import api as db_api
from neutron.db import models_v2
from neutron.db import securitygroups_db as sg_db
from neutron.db import trunk_port_db as trunk_port

from neutron.extensions import portbindings
from neutron import manager
from neutron.openstack.common import log
from neutron.openstack.common import uuidutils
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2 import models

LOG = log.getLogger(__name__)

# limit the number of port OR LIKE statements in one query
MAX_PORTS_PER_QUERY = 500

def _make_segment_dict(record):
    """Make a segment dictionary out of a DB record."""
    return {api.ID: record.id,
            api.NETWORK_TYPE: record.network_type,
            api.PHYSICAL_NETWORK: record.physical_network,
            api.SEGMENTATION_ID: record.segmentation_id}


def add_network_segment(session, network_id, segment, is_dynamic=False):
    with session.begin(subtransactions=True):
        record = models.NetworkSegment(
            id=uuidutils.generate_uuid(),
            network_id=network_id,
            network_type=segment.get(api.NETWORK_TYPE),
            physical_network=segment.get(api.PHYSICAL_NETWORK),
            segmentation_id=segment.get(api.SEGMENTATION_ID),
            is_dynamic=is_dynamic
        )
        session.add(record)
        segment[api.ID] = record.id
    LOG.info(_("Added segment %(id)s of type %(network_type)s for network"
               " %(network_id)s"),
             {'id': record.id,
              'network_type': record.network_type,
              'network_id': record.network_id})


def get_network_segments(session, network_id, filter_dynamic=False):
    with session.begin(subtransactions=True):
        query = (session.query(models.NetworkSegment).
                 filter_by(network_id=network_id))
        if filter_dynamic is not None:
            query = query.filter_by(is_dynamic=filter_dynamic)
        records = query.all()

        return [_make_segment_dict(record) for record in records]


def get_segment_by_id(session, segment_id):
    with session.begin(subtransactions=True):
        try:
            record = (session.query(models.NetworkSegment).
                      filter_by(id=segment_id).
                      one())
            return _make_segment_dict(record)
        except exc.NoResultFound:
            return


def get_dynamic_segment(session, network_id, physical_network=None,
                        segmentation_id=None):
        """Return a dynamic segment for the filters provided if one exists."""
        with session.begin(subtransactions=True):
            query = (session.query(models.NetworkSegment).
                     filter_by(network_id=network_id, is_dynamic=True))
            if physical_network:
                query = query.filter_by(physical_network=physical_network)
            if segmentation_id:
                query = query.filter_by(segmentation_id=segmentation_id)
            record = query.first()

        if record:
            return _make_segment_dict(record)
        else:
            LOG.debug("No dynamic segment %s found for "
                      "Network:%(network_id)s, "
                      "Physical network:%(physnet)s, "
                      "segmentation_id:%(segmentation_id)s",
                      {'network_id': network_id,
                       'physnet': physical_network,
                       'segmentation_id': segmentation_id})
            return None


def delete_network_segment(session, segment_id):
    """Release a dynamic segment for the params provided if one exists."""
    with session.begin(subtransactions=True):
        (session.query(models.NetworkSegment).
         filter_by(id=segment_id).delete())


def add_port_binding(session, port_id):
    with session.begin(subtransactions=True):
        record = models.PortBinding(
            port_id=port_id,
            vif_type=portbindings.VIF_TYPE_UNBOUND)
        session.add(record)
        return record


def get_locked_port_and_binding(session, port_id):
    """Get port and port binding records for update within transaction."""

    try:
        # REVISIT(rkukura): We need the Port and PortBinding records
        # to both be added to the session and locked for update. A
        # single joined query should work, but the combination of left
        # outer joins and postgresql doesn't seem to work.
        port = (session.query(models_v2.Port).
                enable_eagerloads(False).
                filter_by(id=port_id).
                with_lockmode('update').
                one())
        binding = (session.query(models.PortBinding).
                   enable_eagerloads(False).
                   filter_by(port_id=port_id).
                   with_lockmode('update').
                   one())
        return port, binding
    except exc.NoResultFound:
        return None, None


def ensure_dvr_port_binding(session, port_id, host, router_id=None):
    record = (session.query(models.DVRPortBinding).
              filter_by(port_id=port_id, host=host).first())
    if record:
        return record

    try:
        with session.begin(subtransactions=True):
            record = models.DVRPortBinding(
                port_id=port_id,
                host=host,
                router_id=router_id,
                vif_type=portbindings.VIF_TYPE_UNBOUND,
                vnic_type=portbindings.VNIC_NORMAL,
                cap_port_filter=False,
                status=n_const.PORT_STATUS_DOWN)
            session.add(record)
            return record
    except db_exc.DBDuplicateEntry:
        LOG.debug("DVR Port %s already bound", port_id)
        return (session.query(models.DVRPortBinding).
                filter_by(port_id=port_id, host=host).one())


def delete_dvr_port_binding(session, port_id, host):
    with session.begin(subtransactions=True):
        (session.query(models.DVRPortBinding).
         filter_by(port_id=port_id, host=host).
         delete(synchronize_session=False))


def delete_dvr_port_binding_if_stale(session, binding):
    if not binding.router_id and binding.status == n_const.PORT_STATUS_DOWN:
        with session.begin(subtransactions=True):
            LOG.debug("DVR: Deleting binding %s", binding)
            session.delete(binding)


def get_port(session, port_id):
    """Get port record for update within transcation."""

    with session.begin(subtransactions=True):
        try:
            record = (session.query(models_v2.Port).
                      filter(models_v2.Port.id.startswith(port_id)).
                      one())
            return record
        except exc.NoResultFound:
            return
        except exc.MultipleResultsFound:
            LOG.error(_("Multiple ports have port_id starting with %s"),
                      port_id)
            return


def get_vlan_mappings(rpc_context, port):
    """Get VLAN mappings for a trunk network."""

    session = rpc_context.session
    remote_nets = {}
    if 'trunkport:type' in port:
        if port['trunkport:type'] != 'trunk':
            return remote_nets
    else:
        return remote_nets

    with session.begin(subtransactions=True):
        try:
            vlan_mappings = (
                session.query(trunk_port.TrunkPort, models_v2.Port,
                              models.NetworkSegment).
                enable_eagerloads(False).
                filter(trunk_port.TrunkPort.parent_id == port['id']).
                filter(trunk_port.TrunkPort.port_id == models_v2.Port.id).
                filter(models.NetworkSegment.network_id ==
                       models_v2.Port.network_id).all())

            if not vlan_mappings:
                return remote_nets

            for mapping in vlan_mappings:
                subport_id = mapping[0].port_id
                vid = mapping[0].vid
                net = mapping[1].network_id
                ntype = mapping[2].network_type
                pnet = mapping[2].physical_network
                seg_id = mapping[2].segmentation_id

                remote_nets[subport_id] = {'net_id': net, 'vid': vid,
                                        'network_type': ntype,
                                        'physical_network': pnet,
                                        'segmentation_id': seg_id}

        except exc.NoResultFound:
            pass

    return remote_nets


def get_port_from_device_mac(device_mac):
    LOG.debug(_("get_port_from_device_mac() called for mac %s"), device_mac)
    session = db_api.get_session()
    qry = session.query(models_v2.Port).filter_by(mac_address=device_mac)
    return qry.first()

def get_ports_and_sgs(port_ids):
    """Get ports from database with security group info."""

    # break large queries into smaller parts
    if len(port_ids) > MAX_PORTS_PER_QUERY:
        LOG.debug("Number of ports %(pcount)s exceeds the maximum per "
                  "query %(maxp)s. Partitioning queries.",
                  {'pcount': len(port_ids), 'maxp': MAX_PORTS_PER_QUERY})
        return (get_ports_and_sgs(port_ids[:MAX_PORTS_PER_QUERY]) +
                get_ports_and_sgs(port_ids[MAX_PORTS_PER_QUERY:]))

    LOG.debug("get_ports_and_sgs() called for port_ids %s", port_ids)
    if not port_ids:
        # if port_ids is empty, avoid querying to DB to ask it for nothing
        return []
    ports_to_sg_ids = get_sg_ids_grouped_by_port(port_ids)
    return [make_port_dict_with_security_groups(port, sec_groups)
            for port, sec_groups in ports_to_sg_ids.iteritems()]

def get_sg_ids_grouped_by_port(port_ids):
    sg_ids_grouped_by_port = {}
    session = db_api.get_session()
    sg_binding_port = sg_db.SecurityGroupPortBinding.port_id

    with session.begin(subtransactions=True):
        # partial UUIDs must be individually matched with startswith.
        # full UUIDs may be matched directly in an IN statement
        partial_uuids = set(port_id for port_id in port_ids
                            if not uuidutils.is_uuid_like(port_id))
        full_uuids = set(port_ids) - partial_uuids
        or_criteria = [models_v2.Port.id.startswith(port_id)
                       for port_id in partial_uuids]
        if full_uuids:
            or_criteria.append(models_v2.Port.id.in_(full_uuids))

        query = session.query(models_v2.Port,
                              sg_db.SecurityGroupPortBinding.security_group_id)
        query = query.outerjoin(sg_db.SecurityGroupPortBinding,
                                models_v2.Port.id == sg_binding_port)
        query = query.filter(or_(*or_criteria))

        for port, sg_id in query:
            if port not in sg_ids_grouped_by_port:
                sg_ids_grouped_by_port[port] = []
            if sg_id:
                sg_ids_grouped_by_port[port].append(sg_id)
    return sg_ids_grouped_by_port
def make_port_dict_with_security_groups(port, sec_groups):
    plugin = manager.NeutronManager.get_plugin()
    port_dict = plugin._make_port_dict(port)
    port_dict['security_groups'] = sec_groups
    port_dict['security_group_rules'] = []
    port_dict['security_group_source_groups'] = []
    port_dict['fixed_ips'] = [ip['ip_address']
                              for ip in port['fixed_ips']]
    return port_dict


def get_port_binding_host(port_id):
    session = db_api.get_session()
    with session.begin(subtransactions=True):
        try:
            query = (session.query(models.PortBinding).
                     filter(models.PortBinding.port_id.startswith(port_id)).
                     one())
        except exc.NoResultFound:
            LOG.debug(_("No binding found for port %(port_id)s"),
                      {'port_id': port_id})
            return
        except exc.MultipleResultsFound:
            LOG.error(_("Multiple ports have port_id starting with %s"),
                      port_id)
            return
    return query.host


def generate_dvr_port_status(session, port_id):
    # an OR'ed value of status assigned to parent port from the
    # dvrportbinding bucket
    query = session.query(models.DVRPortBinding)
    final_status = n_const.PORT_STATUS_BUILD
    for bind in query.filter(models.DVRPortBinding.port_id == port_id):
        if bind.status == n_const.PORT_STATUS_ACTIVE:
            return bind.status
        elif bind.status == n_const.PORT_STATUS_DOWN:
            final_status = bind.status
    return final_status


def get_dvr_port_binding_by_host(session, port_id, host):
    with session.begin(subtransactions=True):
        binding = (session.query(models.DVRPortBinding).
                   filter(models.DVRPortBinding.port_id.startswith(port_id),
                          models.DVRPortBinding.host == host).first())
    if not binding:
        LOG.debug("No binding for DVR port %(port_id)s with host "
                  "%(host)s", {'port_id': port_id, 'host': host})
    return binding


def get_dvr_port_bindings(session, port_id):
    with session.begin(subtransactions=True):
        bindings = (session.query(models.DVRPortBinding).
                    filter(models.DVRPortBinding.port_id.startswith(port_id)).
                    all())
    if not bindings:
        LOG.debug("No bindings for DVR port %s", port_id)
    return bindings
