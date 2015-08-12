import sqlalchemy as sa
from sqlalchemy.orm import exc
from sqlalchemy import orm

from neutron.db import model_base
from neutron.db import models_v2
from neutron.openstack.common import uuidutils
from neutron.plugins.common import constants
from neutron.db.models_v2 import model_base
from neutron.common import exceptions as q_exc
from neutron.openstack.common import log as logging
from neutron.api.v2 import attributes
from neutron.extensions import loadbalancer
from neutron.db import db_base_plugin_v2
from neutron.db.loadbalancer import loadbalancer_db

from neutron import manager
import netaddr
from netaddr import IPAddress

LOG = logging.getLogger(__name__)

class Listener(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant,
             models_v2.HasStatusDescription):
    """Represents a v2 neutron loadbalancer vip_listener."""

    vip_id = sa.Column(sa.String(36),
                       sa.ForeignKey('vips.id', 
                                     ondelete='CASCADE'))
    protocol_port = sa.Column(sa.Integer, nullable=False)
    protocol = sa.Column(sa.Enum("HTTP", "HTTPS", "TCP", name="lb_protocols"),
                         nullable=False)
    
    
class LoadBalancer_db_mixin(loadbalancer_db.LoadBalancerPluginDb):
    @property
    def _core_plugin(self):
        return manager.NeutronManager.get_plugin()
        
    
    ########################################################
    # LISTENER DB access
    def _make_listener_dict(self, listener, fields=None):
        res = {'id': listener['id'],
               'vip_id': listener['vip_id'],
               'protocol_port': listener['protocol_port'],
               'protocol': listener['protocol'],
               'status': listener['status'],
               'status_description': listener['status_description']}

        return self._fields(res, fields)
    
    def create_vip_listener(self, context, listener, vip_id):
        l = listener['listener']

        with context.session.begin(subtransactions=True):
            vip = self._get_resource(context, loadbalancer_db.Vip, vip_id)
            if vip:
                if vip['protocol'] != l['protocol']:
                    raise loadbalancer.ListenerProtocolMismatch(
                        listener_proto=l['protocol'],
                        vip_proto=vip['protocol'])
                elif vip['protocol_port'] == l['protocol_port']:
                    raise loadbalancer.VipProtocolPortInUse(
                        protocol_port=l['protocol_port'])
                else:
                    for port in vip['extra_listeners']:
                        if port['protocol_port'] == l['protocol_port']:
                            raise loadbalancer.ListenerProtocolPortInUse(
                                protocol_port=l['protocol_port'])
                    listener_db = Listener(id=uuidutils.generate_uuid(),
                                           vip_id = vip_id,
                                           tenant_id = l['tenant_id'],
                                           protocol_port=l['protocol_port'],
                                           protocol=l['protocol'],
                                           status=constants.PENDING_CREATE)
                    context.session.add(listener_db)

        return self._make_listener_dict(listener_db)
    
    def delete_vip_listener(self, context, id, vip_id=None):
        with context.session.begin(subtransactions=True):
            vip = self._get_resource(context, loadbalancer_db.Vip, vip_id)
            listener_db = self._get_resource(context, Listener, id)
            if listener_db['vip_id'] != vip['id']:
                raise loadbalancer.ListenerNotInVip(
                        listener_id=id,
                        vip_id=vip['id'])
            context.session.delete(listener_db)        

    def get_vip_listener(self, context, id, vip_id=None, fields=None):
        vip = self._get_resource(context, loadbalancer_db.Vip, vip_id)
        try:
            listener = self._get_by_id(context, Listener, id)
        except exc.NoResultFound:
            raise loadbalancer.ListenerNotFound(listener_id=id)
        if vip_id != listener['vip_id']:
            raise loadbalancer.ListenerNotInVip(
                        listener_id=id,
                        vip_id=vip_id)
        return self._make_listener_dict(listener, fields)
    
    def get_vip_listeners(self,context, vip_id=None, 
             filters=None, fields=None):
        vip = self._get_resource(context, loadbalancer_db.Vip, vip_id)
        #add the elememt of 'vip_id' to the filters dict
        filters['vip_id'] = [vip['id']]
        return self._get_collection(context, Listener, 
                                    self._make_listener_dict,
                                    filters=filters, fields=fields) 

