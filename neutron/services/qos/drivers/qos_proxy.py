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

import traceback
from oslo.config import cfg
from neutronclient.common import exceptions
from neutron import context as n_context
from neutron.common import constants
from neutron.services.qos.drivers import qos_base
from neutron.openstack.common import log as logging
from neutron.plugins.l2_proxy.agent import neutron_proxy_context
from neutron.plugins.l2_proxy.agent import clients

LOG = logging.getLogger(__name__)

class QosProxyDriver(qos_base.QoSDriver):
    def __init__(self, ports_mapping = {}):

        self.client = clients.CascadeNeutronClient(clients.CASCADED)
        #{cascading_port_id:cascaded_port_id}
        self.ports_mapping = ports_mapping
        #{cascaded_qos_id:cascaded_qos_detail}
        self.cascaded_qoses = {}
        #{cascading_qos_id:cascaded_qos_id}
        self.qoses_mapping = {}
        self._sync_qos_mapping()

    def _sync_qos_mapping(self):
        qoses_mapping = {}
        qoses_ret = self.client('list_qoses')
        qoses = qoses_ret.get('qoses')
        if qoses_ret and qoses and len(qoses):
            for qos in qoses:
                qos_id = qos.get('id')
                description = qos.get('description')
                if description:
                    try:
                        #qos@xxxxxx
                        qoses_mapping[description[4:]] = qos_id
                        self.cascaded_qoses[qos_id] = qos
                    except:
                        LOG.warn("Qos(%s) description is invalid in cascaded." % qos_id)

        LOG.info("_sync_qos_mapping in qos_proxy:[qoses_mapping]%s" % qoses_mapping)
        self.qoses_mapping = qoses_mapping

    def _add_qos_mapping(self, key, value):
        self.qoses_mapping[key] = value

    def _remove_qos_mapping(self, key):
        self.qoses_mapping.pop(key)

    def _check_polices(self, csg_polices, csd_polices):
        for key, value in csd_polices.items():
            if csg_polices.has_key(key) and csg_polices[key] == value:
                continue
            else:
                return False
        return True

    def create_qos_for_port(self, policy, port_id, **kwargs):
        #"tx_burstsize": "3Mb", "tx_averateLimit": "30Mbps", "rx_burstsize": "3Mb", "rx_averateLimit": "30Mbps", "dscp": "21"

        LOG.info("create_qos_for_port in qos_proxy:%s, %s, %s" % (port_id, policy, kwargs.get('qos', '')))
        try:
            qos = kwargs.get('qos', {})
            qos_id = qos.get('id')
            tenant_id = qos.get('tenant_id', '')
            shared = qos.get('shared')
            type = qos.get('type')
            if not qos_id or not port_id:
                return

            qos_body = {'qos': {'policies': {},
                                'tenant_id': tenant_id,
                                'shared': shared,
                                'type': type}}

            if self.ports_mapping:
                cascaded_port = self.ports_mapping.get(port_id)
                if not cascaded_port:
                    return
                else:
                    cascaded_port_id = cascaded_port['id']

            dscp = policy.get(constants.TYPE_QOS_DSCP)
            tx_rate = policy.get(constants.TYPE_QOS_POLICY_TC_TX_RATE)
            tx_burst = policy.get(constants.TYPE_QOS_POLICY_TC_TX_BURST)
            rx_rate = policy.get(constants.TYPE_QOS_POLICY_TC_RX_RATE)
            rx_burst = policy.get(constants.TYPE_QOS_POLICY_TC_RX_BURST)

            if dscp:
                qos_body['qos']['policies']['dscp'] = dscp
            if tx_rate:
                qos_body['qos']['policies']['tx_averateLimit'] = tx_rate
            if tx_burst:
                qos_body['qos']['policies']['tx_burstsize'] = tx_burst
            if rx_rate:
                qos_body['qos']['policies']['rx_averateLimit'] = rx_rate
            if rx_burst:
                qos_body['qos']['policies']['rx_burstsize'] = rx_burst

            if not self.qoses_mapping.get(qos_id):
                qos_body['qos']['description'] = 'qos@'+qos_id
                qos_ret = self.client('create_qos', qos_body)
                if qos_ret and qos_ret.get('qos'):
                    cascaded_qos = qos_ret.get('qos')
                    self._add_qos_mapping(qos_id, cascaded_qos['id'])
                    self.cascaded_qoses[cascaded_qos['id']] = cascaded_qos
                else:
                    LOG.error("Create QoS(%s) failed." % qos_id)
                    return
            elif self.qoses_mapping[qos_id] in self.cascaded_qoses:
                csd_qos = self.cascaded_qoses[self.qoses_mapping[qos_id]]
                need_update = not self._check_polices(qos_body['qos']['policies'], csd_qos.get('policies'))
                need_update |= (qos_body['qos']['shared'] != csd_qos.get('shared'))
                #remove read-only attribute
                qos_body['qos'].pop('tenant_id', None)
                qos_body['qos'].pop('type', None)
                if need_update:
                    qos_ret = self.client('update_qos', csd_qos['id'], qos_body)
                    if not qos_ret or not qos_ret.get('qos'):
                        LOG.error("Update QoS(%s) failed." % csd_qos['id'])
                        return
                    self.cascaded_qoses[self.qoses_mapping[qos_id]] = qos_ret.get('qos')
            else:
                LOG.error("qoses_mapping and cascaded_qoses are not synchronous. Details: %s, %s" %
                          (self.qoses_mapping[qos_id], self.cascaded_qoses))
                return

            req_props = {'qos': self.qoses_mapping.get(qos_id)}
            port_ret = self.client('update_port', cascaded_port_id, {'port': req_props})
            if not port_ret or not port_ret.get('port'):
                LOG.debug("Update port(%s) failed." % ('port@'+port_id))

        except:
            LOG.error("create_qos_for_port occur exception(%s)." % traceback.format_exc())

    def delete_qos_for_port(self, qos_id, port_id, **kwargs):

        LOG.info("delete_qos_for_port in qos_proxy:%s, %s" % (port_id, qos_id))

        try:

            if self.ports_mapping:
                cascaded_port = self.ports_mapping.get(port_id)
                if cascaded_port:
                    req_props = {'qos': ''}
                    self.client('update_port', cascaded_port['id'], {'port': req_props})
                else:
                    return
            else:
                search_opts = {'name': 'port@'+port_id}
                ports_ret = self.client('list_ports', **search_opts)
                if ports_ret and ports_ret.get('ports') and len(ports_ret.get('ports', [])):
                    cascaded_port = ports_ret.get('ports')[0]
                    cascaded_port_id = cascaded_port['id']
                    req_props = {'qos': ''}
                    self.client('update_port', cascaded_port_id, {'port': req_props})
                else:
                    LOG.debug("Can not find port name(%s)." % ('port@'+port_id))
                    return

            if qos_id:
                cascaded_qos_id = self.qoses_mapping.get(qos_id)
                if cascaded_qos_id:
                    search_opts = {'qos': cascaded_qos_id}
                    try:
                        ports_ret = self.client('list_ports', **search_opts)
                        if not ports_ret or not ports_ret.get('ports') or not len(ports_ret.get('ports', [])):
                            #delete qos if not port in used.
                            self.client('delete_qos', cascaded_qos_id)
                            self.cascaded_qoses.pop(cascaded_qos_id)
                            self._remove_qos_mapping(qos_id)
                    except exceptions.NotFound:
                        pass
                    except:
                        LOG.error('Delete qos(%s) failed.' % qos_id)
        except:
            LOG.debug("delete_qos_for_port occur exception(%s)." % traceback.format_exc())

    def port_qos_updated(self, policy, port_id, **kwargs):
        self.create_qos_for_port(policy, port_id, **kwargs)

    def delete_qos_for_network(self, network_id):
        pass

    def network_qos_updated(self, policy, network_id):
        pass