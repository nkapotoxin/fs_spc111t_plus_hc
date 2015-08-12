import netaddr
from oslo.config import cfg
from neutron import manager
from neutron.common import rpc as q_rpc
from neutron.db import api as qdbapi
from neutron.db import common_db_mixin as db_base_plugin_v2

from neutron.db.servicechain import servicechain_db
from neutron.db.servicechain import servicechain_pool as sc_pool
from neutron.db import model_base
from neutron.openstack.common import log
from neutron.common import rpc as n_rpc

from neutron.plugins.common import constants
from neutron.services.servicechain import constants as sc_const
from neutron.services.servicechain import rpc as sc_rpc
from neutron.db import agents_db
from neutron.openstack.common import loopingcall
from neutron.common import topics


LOG = log.getLogger(__name__)


class ServiceChainPluginRpcCallbacks(n_rpc.RpcCallback, sc_rpc.ServiceChainRpcCallbackMixin):

    def __init__(self, plugin):
        super(ServiceChainPluginRpcCallbacks, self).__init__()
        self.plugin = plugin

    
class ServiceChainNotifierApi(n_rpc.RpcProxy,
                              sc_rpc.ServiceChainNotifierRpcApiMixin):
    
    BASE_RPC_API_VERSION = '1.0'

    def __init__(self, topic):
        super(ServiceChainNotifierApi, self).__init__(
            topic=topic, default_version=self.BASE_RPC_API_VERSION)

        
    
class ServiceChainPlugin(servicechain_db.ServiceChainDbMixin,
                   db_base_plugin_v2.CommonDbMixin):
    
    supported_extension_aliases = ['service-chain']

    def __init__(self):
        self.setup_sc_pool()
        self.setup_rpc()
        upate_chain_status = loopingcall.FixedIntervalLoopingCall(
                self._upate_chain_status_task, session=qdbapi.get_session())
        upate_chain_status.start(interval=10)        

            
    def setup_sc_pool(self):
        try:
            sc_sf_pools = []
            for sc_pool_str in cfg.CONF.SERVICECHAIN.servicechain_pool.split(','):
                sc_range = sc_pool_str.split(':')
                if len(sc_range) == 3:
                    pool = {'sf_sc_identifier':sc_range[0],'sf_port_id_begin':sc_range[1],
                            'sf_port_id_end':sc_range[2]}
                    sc_sf_pools.append(pool)
            if len(sc_sf_pools) > 0:
                sc_pool.init_servicechain_pool(sc_sf_pools)
        except Exception,ex:
            LOG.error(_('init_servicechain_pool error: %s'),ex)


    def setup_rpc(self):  
            
        self.notifier = ServiceChainNotifierApi(sc_const.SERVICECHAIN_AGENT_TOPIC)
        self.topic = sc_const.SERVICECHAIN_TOPIC       
        self.endpoints = [ServiceChainPluginRpcCallbacks(self)]
        self.conn = n_rpc.create_connection(new=True)
        self.conn.create_consumer(
            self.topic, self.endpoints, fanout=False)
        self.conn.consume_in_threads()
      

    def get_plugin_name(self):
        return constants.SERVICE_CHAIN
    
    def get_plugin_type(self):
        return constants.SERVICE_CHAIN

    def get_plugin_description(self):
        return 'Service Chain plugin'

    def get_service_traffic_classifier(self, context, service_traffic_classifier_id,fields=None):
        LOG.debug(_("Getting Service Traffic Classifier id %s "),service_traffic_classifier_id)
        session = context.session
        with session.begin(subtransactions=True):
            result = super(ServiceChainPlugin,
                           self).get_service_traffic_classifier(context, service_traffic_classifier_id,fields)
            return self._fields(result, fields)


    def get_service_traffic_classifiers(self, context,filters=None, fields=None,
                                sorts=None, limit=None, marker=None, page_reverse=False):
        LOG.debug(_("Getting All Service Traffic Classifier List"))
        session = context.session
        with session.begin(subtransactions=True):
            classifiers = super(ServiceChainPlugin, self).get_service_traffic_classifiers(context, filters, fields, sorts,
                                            limit, marker, page_reverse)
            return [self._fields(classifier, fields) for classifier in classifiers]
      
    def create_service_traffic_classifier(self, context, service_traffic_classifier):
        LOG.debug(_("Creating service traffic classifier %s"), service_traffic_classifier)
        result = super(ServiceChainPlugin, self).create_service_traffic_classifier(context, service_traffic_classifier)
        classifier_id = result['id']
        LOG.debug(_("Create service instance success, classifier_id:" + classifier_id))
        return result

    
    def update_service_traffic_classifier(self, context, service_traffic_classifier_id,
                                 service_traffic_classifier):
        LOG.debug(_("Updating service traffic classifier %s"), service_traffic_classifier)
        result = super(ServiceChainPlugin, self).update_service_traffic_classifier(context, service_traffic_classifier_id,
                                                                                   service_traffic_classifier)
        LOG.debug(_("update service instance success"))
        return result

    
    def delete_service_traffic_classifier(self, context, service_traffic_classifier_id):
        LOG.debug(_("Deleting service traffic classifier %s"), service_traffic_classifier_id)
        result = super(ServiceChainPlugin, self).delete_service_traffic_classifier(context, service_traffic_classifier_id)
        LOG.debug(_("Delete service instance success, classifier_id:" + service_traffic_classifier_id))

    
    def create_service_function_instance(self, context, service_function_instance):
        LOG.debug(_("Creating service instance %s"), service_function_instance)
        result = super(ServiceChainPlugin, self).create_service_function_instance(context, service_function_instance)
        serviceinstance_id = result['id']
        LOG.debug(_("Create service instance success, serviceinstance_id:" + serviceinstance_id))
        return result

    def get_service_function_instance(self, context, service_function_instance_id,fields=None):
        LOG.debug(_("Getting Service Function Instance id %s "),service_function_instance_id)
        session = context.session
        with session.begin(subtransactions=True):
            result = super(ServiceChainPlugin,
                           self).get_service_function_instance(context, service_function_instance_id,fields)
            return self._fields(result, fields)


    def get_service_function_instances(self, context,filters=None, fields=None,
                                sorts=None, limit=None, marker=None, page_reverse=False):
        LOG.debug(_("Getting All Service Function Instance List"))
        session = context.session
        with session.begin(subtransactions=True):
            serviceinstances = super(ServiceChainPlugin, self).get_service_function_instances(context, filters, fields, sorts,
                                            limit, marker, page_reverse)
            return [self._fields(instance, fields) for instance in serviceinstances]

    def update_service_function_instance(self, context, service_function_instance_id,
                                                                    service_function_instance):
        LOG.debug(_("updating Service Function Instance %s, with %s"), service_function_instance_id,
                    service_function_instance)
        result = super(ServiceChainPlugin, self).update_service_function_instance(context,
                                                                                  service_function_instance_id,
                                                                                  service_function_instance)
        serviceinstance_id = result['id']
        LOG.debug(_("Update service instance success, serviceinstance_id:" + serviceinstance_id))
        return result

    
    def delete_service_function_instance(self, context, service_function_instance_id):
        LOG.debug(_("Deleting service instance %s"), service_function_instance_id)
        super(ServiceChainPlugin, self).delete_service_function_instance(context, service_function_instance_id)
        LOG.debug(_("Delete service instance success, serviceinstance_id:" + service_function_instance_id))
                
    
    def create_service_function_group(self, context, service_function_group):
        LOG.debug(_("Creating service_function_group %s"), service_function_group)
        result = super(ServiceChainPlugin, self).create_service_function_group(context, service_function_group)
        service_function_group_id = result['id']
        LOG.debug(_("Create service_function_group success, service_function_group:" + service_function_group_id))
        return result

    
    def update_service_function_group(self, context, service_function_group_id,
                                 service_function_group):
        LOG.debug(_("Updating service_function_group %s"), service_function_group_id)
        result = super(ServiceChainPlugin, self).update_service_function_group(context, \
                                                service_function_group_id, service_function_group)
        LOG.debug(_("Updating service_function_group success"))
        return result

    
    def delete_service_function_group(self, context, service_function_group_id):
        LOG.debug(_("Deleting service_function_group %s"), service_function_group_id)
        super(ServiceChainPlugin, self).delete_service_function_group(context, service_function_group_id)
        LOG.debug(_("Delete service_function_group success"))
        
    def get_service_function_group(self, context, service_function_group_id, fields=None):
        LOG.debug(_("Getting service_function_group id %s"),service_function_group_id)
        session = context.session
        with session.begin(subtransactions=True):
            result = super(ServiceChainPlugin,\
                           self).get_service_function_group(context, service_function_group_id,fields)
            return self._fields(result, fields)


    def get_service_function_groups(self, context,filters=None, fields=None,
                                sorts=None, limit=None, marker=None, page_reverse=False):
        session = context.session
        with session.begin(subtransactions=True):
            service_function_groups = super(ServiceChainPlugin,
                         self).get_service_function_groups(context, filters, fields, sorts,
                                            limit, marker, page_reverse)
            return [self._fields(group, fields) for group in service_function_groups]        
                                  
    
    def create_service_chain(self, context, service_chain):
        LOG.debug(_("Creating service_chain %s"), service_chain)
        result = super(ServiceChainPlugin, self).create_service_chain(context, service_chain)
        service_chain_id = result['id']
        LOG.debug(_("Create service_chain success, service_chain_id:" + service_chain_id))
        return result

    
    def update_service_chain(self, context, service_chain_id,
                                 service_chain):
        LOG.debug(_("Updating service_chain %s"), service_chain_id)
        result = super(ServiceChainPlugin, self).update_service_chain(context, \
                                                service_chain_id, service_chain)
        LOG.debug(_("Updating service_chain success"))
        return result

    
    def delete_service_chain(self, context, service_chain_id):
        LOG.debug(_("Deleting service_chain %s"), service_chain_id)
        super(ServiceChainPlugin, self).delete_service_chain(context, service_chain_id)
        LOG.debug(_("Delete service_chain success"))
        
    def get_service_chain(self, context, service_service_chain_id,fields=None):
        LOG.debug(_("Getting service_chain id %s"),service_service_chain_id)
        session = context.session
        with session.begin(subtransactions=True):
            result = super(ServiceChainPlugin,\
                           self).get_service_chain(context, service_service_chain_id,fields)
            return self._fields(result, fields)


    def get_service_chains(self, context,filters=None, fields=None,
                                sorts=None, limit=None, marker=None, page_reverse=False):
        session = context.session
        with session.begin(subtransactions=True):
            service_chains = super(ServiceChainPlugin,
                         self).get_service_chains(context, filters, fields, sorts,
                                            limit, marker, page_reverse)
            return [self._fields(chain, fields) for chain in service_chains]        
                