#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.
import sqlalchemy as sa
from sqlalchemy import orm
from sqlalchemy.orm import exc

from neutron.api.rpc.agentnotifiers import trunkport_rpc_agent_api
from neutron.api.v2 import attributes
from neutron.common import constants as trunk_constants
from neutron.common import exceptions as n_exc
from neutron.db import db_base_plugin_v2
from neutron.db import model_base
from neutron.db import models_v2
from neutron.extensions import trunk_port
from neutron import manager
from neutron.openstack.common import log

DEVICE_OWNER_TRUNK_INTF = trunk_constants.DEVICE_OWNER_TRUNK_INTF

SUPPORT_NETWORK_TYPE = ['vlan']
NETWORK_TYPE = 'provider:network_type'
PHYSICAL_NETWORK = 'provider:physical_network'
SEGMENTATION_ID = 'provider:segmentation_id'


LOG = log.getLogger(__name__)


class TrunkPort(model_base.BASEV2):
    port_id = sa.Column(sa.String(36),
                        sa.ForeignKey('ports.id', ondelete="CASCADE"),
                        primary_key=True)

    trunk_type = sa.Column(sa.String(16))

    parent_id = sa.Column(sa.String(36))

    vid = sa.Column(sa.Integer, nullable=False)

    port = orm.relationship(
        models_v2.Port,
        backref=orm.backref("trunk_type",
                            lazy='joined', uselist=False,
                            cascade='delete'))


class Trunk_port_db_mixin(object):

    @property
    def trunkport_rpc_notifier(self):
        if not hasattr(self, '_trunkport_rpc_notifier'):
            self._trunkport_rpc_notifier = (
                trunkport_rpc_agent_api.TrunkportAgentNotifyAPI())
        return self._trunkport_rpc_notifier

    @property
    def _core_plugin(self):
        return manager.NeutronManager.get_plugin()

    def _trunk_port_model_hook(self, context, original_model, query):
        query = query.outerjoin(TrunkPort,
                                (original_model.id ==
                                 TrunkPort.port_id))
        return query

    def _trunk_port_result_filter_hook(self, query, filters):
        type_values = filters and filters.get(trunk_port.TRUNKPORT_TYPE, [])
        parent_values = filters and filters.get(trunk_port.TRUNKPORT_PARENT, [])
        vid_values = filters and filters.get(trunk_port.TRUNKPORT_VID, [])
        if not type_values and not parent_values and not vid_values:
            return query

        if type_values:
            if len(type_values) == 1:
                query = query.filter(TrunkPort.trunk_type == type_values[0])
            else:
                query = query.filter(TrunkPort.trunk_type.in_(type_values))

        if parent_values:
            if len(parent_values) == 1:
                query = query.filter(TrunkPort.parent_id == parent_values[0])
            else:
                query = query.filter(TrunkPort.parent_id.in_(parent_values))

        if vid_values:
            if len(vid_values) == 1:
                query = query.filter(TrunkPort.vid == vid_values[0])
            else:
                query = query.filter(TrunkPort.vid.in_(vid_values))

        return query

    db_base_plugin_v2.NeutronDbPluginV2.register_model_query_hook(
        models_v2.Port,
        "trunk_port",
        '_trunk_port_model_hook',
        None,
        '_trunk_port_result_filter_hook')


    def _valid_network_info(self, context, network_id):
        """Get network segments for trunk port.

        Do not work while network has no segments, or has multiple segments
        """
        network_info = self._core_plugin.get_network(context, network_id)
        if network_info.get(NETWORK_TYPE, None) not in SUPPORT_NETWORK_TYPE:
            raise trunk_port.NetworkTypeInvalid(type=network_info.get(NETWORK_TYPE))

        return network_info

    def _valid_trunk_port(self, context, port_data):
        """Before create trunk type port valid inputs.

        Attribute 'trunkport:type' must be 'trunk'
        Attribute 'trunkport:parent_id' and 'trunkport:vid' cannot be provided
        Network type must in SUPPORT_NETWORK_TYPE, 'vlan' for now
        """
        trunk_type  = port_data.get(trunk_port.TRUNKPORT_TYPE)
        parent_id  = port_data.get(trunk_port.TRUNKPORT_PARENT)
        vid  = port_data.get(trunk_port.TRUNKPORT_VID)

        if not trunk_type:
            return

        if trunk_type == trunk_port.TRUNK_TYPE_TRUNK:
            if (attributes.is_attr_set(parent_id) or
                    attributes.is_attr_set(vid)):
                raise trunk_port.TrunkPortCannotHasParentVid()

            self._valid_network_info(context, port_data['network_id'])

    def _check_unique_subport_parent(self, context, parent_id, vid):
        """Only one subport per network is allowed under parent port.
        """
        trunk_port_qry = context.session.query(TrunkPort)
        try:
            trunk_port_qry.filter_by(trunk_type=trunk_port.SUBPORT,
                                     parent_id=parent_id,
                                     vid=vid).one()
        except exc.NoResultFound:
            return True
        return False

    def _valid_subport_network(self, context, vid, network_id, parent_port_netid):
        """Valid subport type port.

        Subport vid must be consistent with network segment_id.
        Network type must in SUPPORT_NETWORK_TYPE, 'vlan' for now.
        Parent port and subport has to allocate same physical network.
        """
        if network_id == parent_port_netid:
            msg = (_('Subport cannot allocate the same network %s '
                     'with parent port') % network_id)
            raise n_exc.BadRequest(resource='subport', msg=msg)

        network_info = self._valid_network_info(context, network_id)
        if vid != network_info[SEGMENTATION_ID]:
            raise trunk_port.InvalidTrunkPortVid(vid=vid,
                                                 vlanid=network_info[SEGMENTATION_ID])

        parent_network_info = self._valid_network_info(context,parent_port_netid)

        if network_info[PHYSICAL_NETWORK]!= parent_network_info[PHYSICAL_NETWORK]:
            raise trunk_port.TrunkPortPhysicalNetworksNotMatch()

    def _valid_subport(self, context, port_data):
        """Before create subport type port valid inputs.

        Attribute 'trunkport:type' must be 'subport'.
        Attribute 'trunkport:parent_id' and 'trunkport:vid' must be provided.

        parent port must be existed trunk type port.

        network type must in SUPPORT_NETWORK_TYPE, 'vlan' for now
        """
        trunk_type  = port_data.get(trunk_port.TRUNKPORT_TYPE)
        parent_id  = port_data.get(trunk_port.TRUNKPORT_PARENT)
        vid  = port_data.get(trunk_port.TRUNKPORT_VID)
        network_id = port_data['network_id']

        if not trunk_type:
            return

        if trunk_type == trunk_port.SUBPORT:
            if (not attributes.is_attr_set(parent_id) or
                    not attributes.is_attr_set(vid)):
                raise trunk_port.SubPortRequireParentVid()

            parent_port = self._core_plugin._get_port(context, parent_id)
            if (self.get_port_trunk_type(context, parent_id) !=
                                            trunk_port.TRUNK_TYPE_TRUNK):
                raise trunk_port.ParentPortRequireTrunkType(port_id=parent_id)

            self._valid_subport_network(context, vid, network_id, parent_port['network_id'])

            if not self._check_unique_subport_parent(context, parent_id, vid):
                data = {'network_id': network_id,
                        'parent_id': parent_id}
                msg = (_('Subport associated with network %(network_id)s '
                         'under parent port %(parent_id)s already exist.') % data)
                raise n_exc.BadRequest(resource='subport', msg=msg)


    def _process_copy_parent(self, context, port_data):
        trunk_type  = port_data.get(trunk_port.TRUNKPORT_TYPE)
        parent_id  = port_data.get(trunk_port.TRUNKPORT_PARENT)
        vid  = port_data.get(trunk_port.TRUNKPORT_VID)

        if (not attributes.is_attr_set(trunk_type) and (attributes.
                is_attr_set(parent_id) or attributes.is_attr_set(vid))):
            raise trunk_port.TrunkPortTypeRequired()

        if not attributes.is_attr_set(trunk_type):
            return

        if trunk_type == trunk_port.TRUNK_TYPE_TRUNK :
            return self._valid_trunk_port(context, port_data)
        else:
            self._valid_subport(context, port_data)
            self._subport_copy_parent(context, port_data, parent_id)

    def _subport_copy_parent(self, context, port_data, parent_id):

        if not attributes.is_attr_set(parent_id):
            return

        tp = self._core_plugin._get_port(context, parent_id)
        if tp.port_binding:
            # TODO(Erik.M): Add check that address is free.
            port_data['mac_address'] = tp.mac_address
            port_data['device_owner'] = DEVICE_OWNER_TRUNK_INTF
            port_data['status'] = trunk_constants.PORT_STATUS_ACTIVE

    def _process_port_create_trunk_type(self, context, port, port_data):
        trunk_type_val = port_data.get(trunk_port.TRUNKPORT_TYPE)
        trunk_type_set = attributes.is_attr_set(trunk_type_val)
        parent_id_val = port_data.get(trunk_port.TRUNKPORT_PARENT)
        parent_id_set = attributes.is_attr_set(parent_id_val)
        vid_val = port_data.get(trunk_port.TRUNKPORT_VID)
        vid_set = attributes.is_attr_set(vid_val)
        if not trunk_type_set:
            return
        if not parent_id_set:
            parent_id_val = ''
        if not vid_set:
            vid_val = 0
        with context.session.begin(subtransactions=True):
            tp = TrunkPort(port_id=port['id'],
                           trunk_type=trunk_type_val,
                           parent_id=parent_id_val,
                           vid=vid_val)
            context.session.add(tp)
        self._extend_port_dict_trunk_type(port, tp)


    def get_port_trunk_type(self, context, port_id):
        with context.session.begin(subtransactions=True):
            trunk_port = context.session.query(
                TrunkPort).filter_by(port_id=port_id).first()
            return trunk_port and trunk_port.trunk_type or None

    def _extend_port_dict_trunk_type(self, port_res, tp):
        if tp:
            port_res[trunk_port.TRUNKPORT_TYPE] = tp.trunk_type
            port_res[trunk_port.TRUNKPORT_PARENT] = tp.parent_id
            port_res[trunk_port.TRUNKPORT_VID] = tp.vid
        else:
            # TODO(Erik.M): Check why unit test fails when if cases are removed
            if trunk_port.TRUNKPORT_TYPE in port_res:
                port_res[trunk_port.TRUNKPORT_TYPE] = None
            if trunk_port.TRUNKPORT_PARENT in port_res:
                port_res[trunk_port.TRUNKPORT_PARENT] = None
            if trunk_port.TRUNKPORT_VID in port_res:
                port_res[trunk_port.TRUNKPORT_VID] = None

    def extend_port_dict_trunk_type(self, port_res, port_db):
        if(port_db.trunk_type):
            port_res[trunk_port.TRUNKPORT_TYPE] = (
                port_db.trunk_type.trunk_type)
            port_res[trunk_port.TRUNKPORT_PARENT] = (
                port_db.trunk_type.parent_id)
            port_res[trunk_port.TRUNKPORT_VID] = (
                port_db.trunk_type.vid)
        return(port_res)

    def create_subport(self, context, id, network_id, vid):
        tp = self._core_plugin._get_port(context, id)
        net = self._core_plugin._get_network(context, network_id)

        name = "%s-%s" % (tp['name'], vid)

        port = self._core_plugin.create_port(context, {
            'port':
            {'tenant_id': tp['tenant_id'],
             'network_id': net['id'],
             'fixed_ips': attributes.ATTR_NOT_SPECIFIED,
             'mac_address': tp['mac_address'],
             'admin_state_up': True,
             'device_id': tp['device_id'],
             'device_owner': DEVICE_OWNER_TRUNK_INTF,
             'security_groups': attributes.ATTR_NOT_SPECIFIED,
             'name': name,
             'binding:host_id': tp['port_binding']['host'],
             'binding:profile': tp['port_binding']['profile'],
             'binding:vif_details': tp['port_binding']['vif_details'],
             'binding:vif_type': tp['port_binding']['vif_type'],
             'binding:vnic_type': tp['port_binding']['vnic_type'],
             'trunkport:type': 'subport',
             'trunkport:parent_id': id,
             'trunkport:vid': vid}})

        return port

    def _process_trunk_port_create(self, context, port):
        if trunk_port.TRUNKPORT_PARENT in port:
            self.trunkport_rpc_notifier.trunkports_updated(
                context, [port[trunk_port.TRUNKPORT_PARENT]])

    def _process_trunk_port_status_update(self, context, port):
        with context.session.begin(subtransactions=True):
            subports = context.session.query(
                TrunkPort).filter_by(parent_id=port.id).all()

            if subports:
                status = port.status
                for p in subports:
                    self._core_plugin.update_port_status(context,
                                                         p.port_id,
                                                         status)

    def _process_trunk_port_update(self, context, id, port,
                                   mech_context):
        port2 = mech_context.current
        with context.session.begin(subtransactions=True):
            subports = context.session.query(
                TrunkPort).filter_by(parent_id=id).all()

        if subports:
            LOG.debug(_("process trunk port update port2: %s") % port2)
            for p in subports:
                sp = self._core_plugin._get_port(context, p.port_id)
                LOG.debug(_("subport: %s") % sp)
                self._core_plugin.update_port(
                    context,
                    p.port_id,
                    {'port':
                     {'mac_address': port2['mac_address'],
                      'admin_state_up': port2['admin_state_up'],
                      'device_id': port2['device_id'],
                      'device_owner': DEVICE_OWNER_TRUNK_INTF,
                      'binding:vif_type': port2['binding:vif_type'],
                      'binding:host_id': port2['binding:host_id'],
                      'binding:vif_details': port2[
                          'binding:vif_details'],
                      'trunkport:type': 'subport',
                      'trunkport:parent_id': id,
                      'trunkport:vid': sp.trunk_type.vid}})

    def _process_trunk_port_delete(self, context, port):
        if trunk_port.TRUNKPORT_PARENT in port:
            self.trunkport_rpc_notifier.trunkports_updated(
                context, [port[trunk_port.TRUNKPORT_PARENT]])

        with context.session.begin(subtransactions=True):
            subports = context.session.query(
                TrunkPort).filter_by(parent_id=port['id']).all()
            if subports:
                for p in subports:
                    self._core_plugin._delete_port(context.elevated(),
                                                   p.port_id)


def _extend_port_dict_trunk_type(plugin, port_res, port_db):
    if not isinstance(plugin, Trunk_port_db_mixin):
        return
    plugin.extend_port_dict_trunk_type(port_res, port_db)


# Register dict extend functions for ports
db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
    attributes.PORTS, [_extend_port_dict_trunk_type])
