# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 OpenStack Foundation
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
# @author: Sean M. Collins, sean@coreitpro.com, Comcast #
import re

from neutron.common import constants
from neutron.common import exceptions
from neutron.db import model_base
from neutron.db import models_v2
from neutron.db import db_base_plugin_v2
from neutron.extensions import qos as ext_qos

import sqlalchemy as sa
from sqlalchemy import orm

from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)

class QoSNotFound(exceptions.NotFound):
    message = _("QoS %(qos_id)s could not be found")


class QoSPortMappingNotFound(exceptions.NotFound):
    message = _("QoS mapping for port %(port_id)s"
                " could not be found")


class QoSNetworkMappingNotFound(exceptions.NotFound):
    message = _("QoS mapping for network %(net_id)s"
                " could not be found")


class QoS(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    __tablename__ = 'qoses'
    type = sa.Column(sa.Enum(constants.TYPE_QOS_DSCP,
                             constants.TYPE_QOS_RATELIMIT,
                             constants.TYPE_QOS_ALL, name='qos_types'))
    description = sa.Column(sa.String(255), nullable=False)
    shared = sa.Column(sa.Boolean(), nullable=False)
    policies = orm.relationship('QoSPolicy',
                                cascade='all, delete, delete-orphan')
    ports = orm.relationship('PortQoSMapping',
                             cascade='all, delete, delete-orphan')
    networks = orm.relationship('NetworkQoSMapping',
                                cascade='all, delete, delete-orphan')


class QoSPolicy(model_base.BASEV2, models_v2.HasId):
    __tablename__ = 'qos_policies'
    qos_id = sa.Column(sa.String(36),
                       sa.ForeignKey('qoses.id', ondelete='CASCADE'),
                       nullable=False,
                       primary_key=True)
    key = sa.Column(sa.String(255), nullable=False,
                    primary_key=True)
    value = sa.Column(sa.String(255), nullable=False)


class NetworkQoSMapping(model_base.BASEV2):
    network_id = sa.Column(sa.String(36), sa.ForeignKey('networks.id',
                           ondelete='CASCADE'), nullable=False,
                           primary_key=True)
    qos_id = sa.Column(sa.String(36), sa.ForeignKey('qoses.id',
                       ondelete='CASCADE'), nullable=False, primary_key=True)


class PortQoSMapping(model_base.BASEV2):
    port_id = sa.Column(sa.String(36), sa.ForeignKey('ports.id',
                        ondelete='CASCADE'), nullable=False, primary_key=True)
    qos_id = sa.Column(sa.String(36), sa.ForeignKey('qoses.id',
                       ondelete='CASCADE'), nullable=False, primary_key=True)


class QoSDbMixin(ext_qos.QoSPluginBase):
    
    def _qos_port_model_hook(self, context, original_model, query):
        query = query.outerjoin(PortQoSMapping,
                                (original_model.id ==
                                 PortQoSMapping.port_id))
        return query

    def _qos_port_result_filter_hook(self, query, filters):
        values = filters and filters.get(ext_qos.QOS, [])
        if not values:
            return query
        if len(values) == 1:
            query = query.filter(PortQoSMapping.qos_id == values[0])
        else:
            query = query.filter(PortQoSMapping.qos_id.in_(values))
        return query

    db_base_plugin_v2.NeutronDbPluginV2.register_model_query_hook(
        models_v2.Port,
        "portqosmapping_port",
        '_qos_port_model_hook',
        None,
        '_qos_port_result_filter_hook')
    
    def _get_qos(self, context, id):
        try:
            qos = self._get_by_id(context, QoS, id)
        except orm.exc.NoResultFound:
            raise QoSNotFound(qos_id=id)
        return qos

    def _create_qos_dict(self, qos, fields=None):
        res = {'id': qos['id'],
               'tenant_id': qos['tenant_id'],
               'type': qos['type'],
               'description': qos['description'],
               'shared': qos['shared'],
               'policies': {}}
        for item in qos.policies:
            res['policies'][item['key']] = item['value']
        return self._fields(res, fields)

    def _db_delete(self, context, item):
        with context.session.begin(subtransactions=True):
            context.session.delete(item)

    def create_qos(self, context, qos):
        q = qos['qos']
        self.validate_qos(q)
        tenant_id = self._get_tenant_id_for_create(context, q)

        with context.session.begin(subtransactions=True):
            qos_db_item = QoS(type=q['type'],
                              description=q['description'],
                              tenant_id=tenant_id,
                              shared=q['shared'])
            for k, v in q['policies'].iteritems():
                qos_db_item.policies.append(
                    QoSPolicy(qos_id=qos_db_item.id, key=k, value=v))
            context.session.add(qos_db_item)
        return self._create_qos_dict(qos_db_item)

    def create_qos_for_network(self, context, qos_id, network_id):
        with context.session.begin(subtransactions=True):
            db = NetworkQoSMapping(qos_id=qos_id, network_id=network_id)
            context.session.add(db)
        return db.qos_id

    def create_qos_for_port(self, context, qos_id, port_id):
        with context.session.begin(subtransactions=True):
            db = PortQoSMapping(qos_id=qos_id, port_id=port_id)
            context.session.add(db)
        return db.qos_id

    def delete_qos(self, context, id):
        try:
            self._db_delete(context, self._get_by_id(context, QoS, id))
        except orm.exc.NoResultFound:
            raise QoSNotFound(qos_id=id)

    def delete_qos_for_network(self, context, network_id):
        try:
            self._db_delete(context,
                            self._model_query(context,
                                              NetworkQoSMapping)
                            .filter_by(network_id=network_id).one())
        except orm.exc.NoResultFound:
            raise exceptions.NotFound

    def delete_qos_for_port(self, context, port_id):
        try:
            self._db_delete(context,
                            self._model_query(context, PortQoSMapping)
                            .filter_by(port_id=port_id).one())
        except orm.exc.NoResultFound:
            raise QoSPortMappingNotFound(port_id=port_id)

    def get_mapping_for_network(self, context, network_id):
        try:
            with context.session.begin(subtransactions=True):
                return self._model_query(context, NetworkQoSMapping).filter_by(
                    network_id=network_id).all()
        except orm.exc.NoResultFound:
            raise QoSNetworkMappingNotFound(net_id=network_id)

    def get_mapping_for_port(self, context, port_id):
        try:
            with context.session.begin(subtransactions=True):
                return self._model_query(context, PortQoSMapping).filter_by(
                    port_id=port_id).all()
        except  :
            raise QoSPortMappingNotFound(port_id=port_id)

    def get_qos(self, context, id, fields=None):
        try:
            with context.session.begin(subtransactions=True):
                return self._create_qos_dict(
                    self._get_by_id(context, QoS, id), fields)
        except orm.exc.NoResultFound:
            raise QoSNotFound(qos_id=id)

    def get_qoses(self, context, filters=None, fields=None,
                  sorts=None, limit=None,
                  marker=None, page_reverse=False, default_sg=False):
        marker_obj = self._get_marker_obj(context, 'qos', limit, marker)

        return self._get_collection(context,
                                    QoS,
                                    self._create_qos_dict,
                                    filters=filters, fields=fields,
                                    sorts=sorts,
                                    limit=limit, marker_obj=marker_obj,
                                    page_reverse=page_reverse)

    def update_mapping_for_network(self, context, mapping):
        db = self.get_mapping_for_network(context, mapping.network_id)[0]
        with context.session.begin(subtransactions=True):
            db.update(mapping)

    def update_mapping_for_port(self, context, mapping):
        db = self.get_mapping_for_port(context, mapping.port_id)[0]
        with context.session.begin(subtransactions=True):
            db.update(mapping)

    def update_qos(self, context, id, qos):
        q = qos['qos']
        db = self._get_by_id(context, QoS, id)
        self.validate_qos(q, cur_qos=db)
        with context.session.begin(subtransactions=True):
            if q.get('policies'):
                db.policies = []
                for k, v in q['policies'].iteritems():
                    db.policies.append(
                        QoSPolicy(qos_id=db, key=k, value=v))
                del q['policies']
            db.update(q)
        return self._create_qos_dict(db)

    def validate_qos(self, qos, cur_qos=None):
        qos_type = qos.get('type')
        if cur_qos:
            qos_type = qos.get('type') or cur_qos.type
            if qos.get('policies') == None:
                return

        if 'policies' not in qos:
            raise ext_qos.QoSValidationError()

        try:
            validator = getattr(self, 'validate_policy_' + (qos_type))
        except AttributeError:
            raise Exception(_('No validator found for type: %s') % (qos_type))
        validator(qos['policies'])

    def validate_policy_dscp(self, policy):

        if len(policy.keys()) > 1:
            raise ext_qos.QoSValidationError()

        if constants.TYPE_QOS_DSCP in policy:
            try:
                dscp = int(policy[constants.TYPE_QOS_DSCP])
                if dscp < 0 or dscp > 63:
                    raise ext_qos.QoSValidationError()
            except ValueError:
                raise ext_qos.QoSValidationError()
        else:
            raise ext_qos.QoSValidationError()

    def validate_policy_ratelimit(self, policy):
        RE_TC_RATE = '[1-9][0-9]*((bps){0,1})|([mk]{1}bit)|([mk]{1}bps)'
        RE_TC_LATENCY = '[1-9][0-9]*[mu]{0,1}s(ecs?){0,1}'
        RE_TC_BURST = '[1-9][0-9]*(b{0,1})|([mk]{1}b)|([mk]{1}bit)'

        try:
            for k in policy.keys():
                if k not in [constants.TYPE_QOS_POLICY_TC_RATE,
                             constants.TYPE_QOS_POLICY_TC_BURST,
                             constants.TYPE_QOS_POLICY_TC_LATENCY]:
                    raise ext_qos.QoSValidationError()    
                    
            if not (re.match(RE_TC_RATE,
                             policy[constants.TYPE_QOS_POLICY_TC_RATE]) and
                    re.match(RE_TC_LATENCY,
                             policy[constants.TYPE_QOS_POLICY_TC_LATENCY]) and
                    re.match(RE_TC_BURST,
                             policy[constants.TYPE_QOS_POLICY_TC_BURST])):
                raise ext_qos.QoSValidationError()
            
            RE_EXT = '[0-9]*$'
            if re.match(RE_EXT,policy[constants.TYPE_QOS_POLICY_TC_BURST]):
                policy[constants.TYPE_QOS_POLICY_TC_BURST] += 'Mb'
            if re.match(RE_EXT,policy[constants.TYPE_QOS_POLICY_TC_RATE]):
                policy[constants.TYPE_QOS_POLICY_TC_RATE] += 'Mb'
            
        except KeyError:
            raise ext_qos.QoSValidationError()

    def validate_policy_all(self, policy):
        
        RE_RATE_TC = '[1-9][0-9]*Mbyte/s$'
        RE_BURST_TC = '[1-9][0-9]*Mbyte$'
        
        TEMP_RATE_TC = '[1-9][0-9]*Mbps$'
        TEMP_BURST_TC = '[1-9][0-9]*Mb$'
        
        RE_EXT = '[0-9]*$'
        try:
            if len(policy.keys()) == 0:
                raise ext_qos.QoSValidationError()
            LOG.debug(_('validate_policy_all policy %s'),policy)
            for k in policy.keys():
                if k not in [constants.TYPE_QOS_DSCP,
                             constants.TYPE_QOS_POLICY_TC_RX_RATE,
                             constants.TYPE_QOS_POLICY_TC_RX_BURST,
                             constants.TYPE_QOS_POLICY_TC_TX_RATE,
                             constants.TYPE_QOS_POLICY_TC_TX_BURST]:
                    raise ext_qos.QoSValidationError() 
                    
            if policy.get(constants.TYPE_QOS_DSCP):
                try:
                    dscp = int(policy[constants.TYPE_QOS_DSCP])
                    if dscp < 0 or dscp > 63:
                        raise ext_qos.QoSValidationError()
                except ValueError:
                    raise ext_qos.QoSValidationError()

            if policy.get(constants.TYPE_QOS_POLICY_TC_RX_RATE) or \
                       policy.get(constants.TYPE_QOS_POLICY_TC_RX_BURST):
                if re.match(RE_EXT,policy.get(constants.TYPE_QOS_POLICY_TC_RX_BURST)):
                    policy[constants.TYPE_QOS_POLICY_TC_RX_BURST] += 'Mbyte'
                if re.match(RE_EXT,policy.get(constants.TYPE_QOS_POLICY_TC_RX_RATE)):
                    policy[constants.TYPE_QOS_POLICY_TC_RX_RATE] += 'Mbyte/s'
                    
                if re.match(TEMP_BURST_TC,policy.get(constants.TYPE_QOS_POLICY_TC_RX_BURST)):
                    policy[constants.TYPE_QOS_POLICY_TC_RX_BURST] = policy[constants.TYPE_QOS_POLICY_TC_RX_BURST][:-2]
                    policy[constants.TYPE_QOS_POLICY_TC_RX_BURST] += 'Mbyte'
                if re.match(TEMP_RATE_TC,policy.get(constants.TYPE_QOS_POLICY_TC_RX_RATE)):
                    policy[constants.TYPE_QOS_POLICY_TC_RX_RATE] = policy[constants.TYPE_QOS_POLICY_TC_RX_RATE][:-4]
                    policy[constants.TYPE_QOS_POLICY_TC_RX_RATE] += 'Mbyte/s'

                if not(re.match(RE_RATE_TC,
                            policy[constants.TYPE_QOS_POLICY_TC_RX_RATE]) and
                    re.match(RE_BURST_TC,
                            policy[constants.TYPE_QOS_POLICY_TC_RX_BURST])):
                    raise ext_qos.QoSValidationError()
                
                var_rx_rate = policy[constants.TYPE_QOS_POLICY_TC_RX_RATE]
                var_rx_rate = var_rx_rate[:-7]
                var_rx_burst = policy[constants.TYPE_QOS_POLICY_TC_RX_BURST]
                var_rx_burst = var_rx_burst[:-5]
                if int(var_rx_rate) <= 10 or int(var_rx_burst) <= 1:
                    raise ext_qos.QoSLimitedError()
                    
            if policy.get(constants.TYPE_QOS_POLICY_TC_TX_RATE) or \
                       policy.get(constants.TYPE_QOS_POLICY_TC_TX_BURST):
                
                if re.match(RE_EXT,policy.get(constants.TYPE_QOS_POLICY_TC_TX_RATE)):
                    policy[constants.TYPE_QOS_POLICY_TC_TX_RATE] += 'Mbyte/s'
                if re.match(RE_EXT,policy.get(constants.TYPE_QOS_POLICY_TC_TX_BURST)):
                    policy[constants.TYPE_QOS_POLICY_TC_TX_BURST] += 'Mbyte'
                    
                if re.match(TEMP_BURST_TC,policy.get(constants.TYPE_QOS_POLICY_TC_TX_BURST)):
                    policy[constants.TYPE_QOS_POLICY_TC_TX_BURST] = policy[constants.TYPE_QOS_POLICY_TC_TX_BURST][:-2]
                    policy[constants.TYPE_QOS_POLICY_TC_TX_BURST] += 'Mbyte'
                if re.match(TEMP_RATE_TC,policy.get(constants.TYPE_QOS_POLICY_TC_TX_RATE)):
                    policy[constants.TYPE_QOS_POLICY_TC_TX_RATE] = policy[constants.TYPE_QOS_POLICY_TC_TX_RATE][:-4]
                    policy[constants.TYPE_QOS_POLICY_TC_TX_RATE] += 'Mbyte/s'
                    
                if not(re.match(RE_RATE_TC,
                            policy[constants.TYPE_QOS_POLICY_TC_TX_RATE]) and
                    re.match(RE_BURST_TC,
                            policy[constants.TYPE_QOS_POLICY_TC_TX_BURST])):
                    raise ext_qos.QoSValidationError()
                
                var_tx_rate = policy[constants.TYPE_QOS_POLICY_TC_TX_RATE]
                var_tx_rate = var_tx_rate[:-7]
                var_tx_burst = policy[constants.TYPE_QOS_POLICY_TC_TX_BURST]
                var_tx_burst = var_tx_burst[:-5]
                if int(var_tx_rate) <= 10 or int(var_tx_burst) <= 1:
                    raise ext_qos.QoSLimitedError()  
                
        except KeyError:
            raise ext_qos.QoSValidationError()

def get_policies_by_port(session, port_id):

    result = {}
    with session.begin(subtransactions=True):
        records = (session.query(PortQoSMapping).
                   filter_by(port_id=port_id).all())
    if records:
        qos_id = records[0].get('qos_id')
        if qos_id:
            results = session.query(QoS).filter_by(id=qos_id)
            for policy in results.one().policies:
                result[policy['key']] = policy['value']

    return result