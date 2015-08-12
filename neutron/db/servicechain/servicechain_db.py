

import copy
import time
import sys
reload(sys)
sys.setdefaultencoding("utf-8")

from eventlet import greenthread
from sqlalchemy.orm import exc
from sqlalchemy.sql import expression as expr
from neutron.api.v2 import attributes
from neutron.common import exceptions as q_exc
from neutron.db import db_base_plugin_v2 as base_db
from neutron.db import db_base_plugin_v2 as new_base_db
from neutron.db.servicechain import models_sc
from neutron.extensions import servicechain as schain
from neutron.extensions import servicechain as sc_exc
from neutron.extensions.servicechain import ServiceChainPluginBase
from neutron.openstack.common import log as logging
from neutron.openstack.common import jsonutils
from neutron import manager
from neutron.services.servicechain import constants as sc_const
from neutron.extensions import portbindings
from neutron.openstack.common import uuidutils
from neutron.db import api as qdbapi
from neutron.db import common_db_mixin as base_db_new

from neutron.db.servicechain import servicechain_pool as sc_pool
from neutron.common import constants


LOG = logging.getLogger(__name__)



class ServiceChainDbMixin(ServiceChainPluginBase,
                     base_db.NeutronDbPluginV2):


    def _thread_add_sf_port(self, context, instance_ctx):
        pass

    def _validate_instance_or_classifier_name(self, context, idf, new_name, old_name = None):
        if not old_name or new_name != old_name:
            if idf == schain.INSTANCE:
                getname = context.session.query(models_sc.ServiceFunctionInstance).filter_by(
                        name=new_name).first()
            else:
                getname = context.session.query(models_sc.ServiceTrafficClassifier).filter_by(
                        name=new_name).first()
            if getname:
                LOG.error(_('_checkout %s_name failed: name of %s '
                        'is used by other %s'),idf, new_name,idf)
                if idf == schain.INSTANCE:
                    raise sc_exc.ServiceFunctionInstanceNameExist(name=new_name)
                else:
                    raise sc_exc.ServiceTrafficClassifierNameExist(name=new_name)

    def _check_classification_type(self,cltype):
        if cltype == 'SCH' :
            LOG.debug(_('the classification type %s is not support now'),cltype)
            raise schain.ServiceClassifierTypeNotSupport(type=cltype)
        elif cltype != 'dl_src' and cltype != '5tuple':
            LOG.debug(_('the classification type %s is error'),cltype)
            raise schain.ServiceClassifierTypeError(type=cltype)
        else:
            return cltype

    def _get_by_name(self, context, model, name):
        query = self._model_query(context, model)
        return query.filter(model.name == name).one()

    def _get_tenant_id_for_create(self, context, resource):
        if context.is_admin and 'tenant_id' in resource:
            tenant_id = resource['tenant_id']
        elif ('tenant_id' in resource and
              resource['tenant_id'] != context.tenant_id):
            reason = _('Cannot create resource for another tenant')
            raise q_exc.AdminRequired(reason=reason)
        else:
            tenant_id = context.tenant_id
        return tenant_id

    def set_dict_info(self, context, port, inst_cxt, flag, dflag = 'add'):
        uvp_id = {}
        port_info = {}
        uvp_port_info = {}
        uvp_type = {}
        host_info = {}
        mac_info = {}
        mac = None
        uvp_type['sc_type'] = inst_cxt['classification_type']
        uvp_port_info.update(uvp_type)
        host_info['host_id'] = inst_cxt['host_id']
        uvp_port_info.update(host_info)
        port_info['port_id'] = port
        uvp_port_info.update(port_info)

        if dflag != 'del':
            try:
                core_plugin = manager.NeutronManager.get_plugin()
                port_vm = core_plugin.get_port(context, port)
                if port_vm:
                    mac =  port_vm['mac_address']
            except exc.NoResultFound:
                LOG.debug(_("instance set dict info get_port cannot find"))
                raise schain.ScPortNotFound(id=port)
            if mac:
                mac_info['dst_mac'] = mac
                uvp_port_info.update(mac_info)
            else:
                mac_info['dst_mac'] = '00:00:00:00:00:00'
                uvp_port_info.update(mac_info)

        if flag == 'user':
            uvp_id['sf_port_id'] = inst_cxt['user_side_sf_port_id']
            uvp_port_info.update(uvp_id)

            if inst_cxt.get('user_side_action',None):
                uvp_port_info.update(jsonutils.loads(inst_cxt['user_side_action']))

        else:
            uvp_id['sf_port_id'] = inst_cxt['network_side_sf_port_id']
            uvp_port_info.update(uvp_id)

            if inst_cxt.get('network_side_action',None):
                uvp_port_info.update(jsonutils.loads(inst_cxt['network_side_action']))
        return uvp_port_info

    def _instance_or_classifier_set_info(self, context, inst_cxt, flag, port_list = {}):
        """set port info to uvp"""
        uvp_port_info = {}
        #for instance create
        if flag == schain.INSTANCE:
            if inst_cxt['user_side_port'] != inst_cxt['network_side_port']:
                uvp_port_info = self.set_dict_info(context, inst_cxt['network_side_port'], inst_cxt, 'network')
                self.notifier.set_port_type(context, uvp_port_info)

            uvp_port_info = self.set_dict_info(context, inst_cxt['user_side_port'], inst_cxt, 'user')
            LOG.debug(_("Create instance and now set port info %s"),uvp_port_info)
            self.notifier.set_port_type(context, uvp_port_info)
        #for classifier update port
        elif len(port_list):

            for key,value in port_list.iteritems():
                if key == 'port_id':
                    try:
                        core_plugin = manager.NeutronManager.get_plugin()
                        port_vm = core_plugin.get_port(context, value)
                        if port_vm:
                            mac =  port_vm['mac_address']
                    except exc.NoResultFound:
                        LOG.debug(_("classifier update dict info get_port cannot find"))
                        raise schain.ScPortNotFound(id=value)

                    if mac:
                        uvp_port_info.update({'dst_mac':mac})
                    else:
                        uvp_port_info.update({'dst_mac':'00:00:00:00:00:00'})

            uvp_port_info.update(port_list)
            uvp_port_info.update({'sc_type':inst_cxt['classification_type']})
            LOG.debug(_("update classifier port and now set port info %s"),uvp_port_info)
            self.notifier.set_port_type(context, uvp_port_info)
        #for classifier create port
        else:
            for port in jsonutils.loads(inst_cxt['ports']):

                try:
                    core_plugin = manager.NeutronManager.get_plugin()
                    port_vm = core_plugin.get_port(context, port)
                    if port_vm:
                        mac =  port_vm['mac_address']
                except exc.NoResultFound:
                    LOG.debug(_("classifier set info  get_port cannot find"))
                    raise schain.ScPortNotFound(id=port)

                if mac:
                    uvp_port_info.update({'dst_mac':mac})
                else:
                    uvp_port_info.update({'dst_mac':'00:00:00:00:00:00'})

                sf_port_id = jsonutils.loads(inst_cxt['list_ports'])[port]
                host_id = jsonutils.loads(inst_cxt['list_hosts'])[port]
                uvp_port_info.update({'port_id':port,'sc_type':inst_cxt['classification_type'],
                                            'sf_port_id':sf_port_id,'host_id':host_id})
                LOG.debug(_("create classifier and now set port info %s"),uvp_port_info)
                self.notifier.set_port_type(context, uvp_port_info)

    def _instance_or_classifier_del_info(self, context, inst_cxt, flag, port_list = {}):
        uvp_port_info = {}
        if flag == schain.INSTANCE:
            if inst_cxt['user_side_port'] == inst_cxt['network_side_port']:
                uvp_port_info.update(self.set_dict_info(context, inst_cxt['user_side_port'], inst_cxt, 'user', 'del'))
                LOG.debug(_("delete service instance and now clear user and network sdie port info %s"),uvp_port_info)
                self.notifier.clear_port_type(context, uvp_port_info)
            else:
                #clear all port one by one
                uvp_port_info = self.set_dict_info(context, inst_cxt['user_side_port'], inst_cxt,'user', 'del')
                LOG.debug(_("delete service instance and now clear user side port info %s"),uvp_port_info)
                self.notifier.clear_port_type(context, uvp_port_info)

                uvp_port_info = self.set_dict_info(context, inst_cxt['network_side_port'], inst_cxt,'network', 'del')
                LOG.debug(_("delete service instance and now clear network side port info %s"),uvp_port_info)
                self.notifier.clear_port_type(context, uvp_port_info)

        elif len(port_list):
            uvp_port_info.update(port_list)
            uvp_port_info.update({'sc_type':inst_cxt['classification_type']})
            LOG.debug(_("decrease service classifier port and now clear port info %s"),uvp_port_info)
            self.notifier.clear_port_type(context, uvp_port_info)

        else:
            for port in jsonutils.loads(inst_cxt['ports']):
                sf_port_id = jsonutils.loads(inst_cxt['list_ports'])[port]
                host_id = jsonutils.loads(inst_cxt['list_hosts'])[port]
                uvp_port_info.update({'port_id':port,'sc_type':inst_cxt['classification_type'],
                                            'sf_port_id':sf_port_id,'host_id':host_id})
                LOG.debug(_("delete service classifier port and now clear port info %s"),uvp_port_info)
                self.notifier.clear_port_type(context, uvp_port_info)

    def _check_vm_port(self, context, port, device_id):
        try:
            core_plugin = manager.NeutronManager.get_plugin()
            port_vm = core_plugin.get_port(context, port)
            if port_vm and port_vm['device_id'] != device_id:
                LOG.error(_('port %s does not belong to device %s or the device %s is not exist'),
                              port, device_id, device_id)
                raise schain.DevicePortNotFound(port_id=port, device=device_id)
            elif port_vm and port_vm['binding:vnic_type'] != 'vhostuser':
                LOG.error(_('instance port %s is not a vhostuser type port'),port)
                raise schain.ScPortTypeInvalidate(port_id=port)
        except exc.NoResultFound:
                raise schain.ScPortNotFound(id=port)

    def _check_sc_port(self, context, port, uuid = None):
        if uuid:
            nw_sc_port = context.session.query(models_sc.ServiceChainAllocation).filter_by(
                        port_id=port,sf_sc_id=uuid).first()
            if nw_sc_port:
                LOG.debug(_("the port %s is used by sc_sf_id %s"),port,uuid)
                return

        sc_port = context.session.query(models_sc.ServiceChainAllocation).filter_by(
                port_id=port).first()
        if sc_port:
            LOG.error(_('_check_not_sc_port failed: port_id of %s '
                            'is used by source context'), port)
            raise schain.PortInUse(port=port,id=sc_port['sf_sc_id'])

    def _check_device_is_instance(self, context, dev_id):
        instance = context.session.query(models_sc.ServiceFunctionInstance).filter_by(
                        device_id=dev_id).first()
        if instance:
            LOG.error(_('_check_not_sc_port failed: port_id of %s '
                            'is used by source context'), dev_id)
            raise schain.DeviceInUse(device=dev_id)

    def _check_port(self, context, port, device_id):
        self._check_vm_port(context, port, device_id);
        self._check_sc_port(context, port);

    def _validate_instance_context_port(self, context, instance_context, instance_device_id):
        user_side_port = instance_context['user_side_port']
        network_side_port = instance_context['network_side_port']
        ports = set()
        ports.add(user_side_port)
        ports.add(network_side_port)
        for port in ports:
            self._check_port(context, port, instance_device_id)

    def _validate_classifier_port(self, context, port, flag):
        classifier_port = port
        core_plugin = manager.NeutronManager.get_plugin()
        port_vm = core_plugin.get_port(context, classifier_port)
        if flag:
            #classifier port  must belong a vm
            if port_vm and port_vm['device_id'] and port_vm['binding:vnic_type'] == 'vhostuser':
                return port_vm['id']
            elif port_vm and not port_vm['device_id']:
                LOG.error(_('classifier port %s is not belong to a vm'),port)
                raise  schain.ScPortNotVm(port_id=port)
            elif port_vm and port_vm['binding:vnic_type'] != 'vhostuser':
                LOG.error(_('classifier port %s is not a vhostuser type port'),port)
                raise schain.ScPortTypeInvalidate(port_id=port)
            else:
                LOG.error(_("can not find port %s in port table"),port)
                raise schain.ScPortNotFound(id=port)
        else:
            if port_vm:
                return port_vm["binding:host_id"]
            else:
                LOG.error(_("can not find port %s in port table"),port)
                raise schain.ScPortNotFound(id=port)

    def _get_service_traffic_classifier(self, context, classifier_id):
        try:
            return self._get_by_id(context, models_sc.ServiceTrafficClassifier, classifier_id)
        except exc.NoResultFound:
            raise schain.ServiceTrafficClassifierNotFound(id=classifier_id)

    def _get_service_function_instance(self, context, func_instance_id):
        try:
            return self._get_by_id(context, models_sc.ServiceFunctionInstance, func_instance_id)
        except exc.NoResultFound:
            raise schain.ServiceFunctionInstanceNotFound(id=func_instance_id)

    def _delete_service_function_instance(self,context,vm_port_id,instance_id):
        other_ctx = context.session.query(models_sc.ServiceFuntionInstanceContext).filter(
            expr.and_(expr.or_(models_sc.ServiceFuntionInstanceContext.user_side_port == vm_port_id,
                     models_sc.ServiceFuntionInstanceContext.network_side_port == vm_port_id),
                     models_sc.ServiceFuntionInstanceContext.service_function_instance_id != instance_id)).first()
        if not other_ctx:
            sc_pool._recycle_sf_or_port(context, vm_port_id, instance_id, schain.INSTANCE)

    def _make_traffic_classifier_dict(self, traffic_classifier, fields=None):
        """ make traffic classifier dict """
        list_chains = []
        if traffic_classifier['service_chain_id']:
            for tclassifier in traffic_classifier['service_chain_id']:
                chain_id = tclassifier['service_chain_id']
                list_chains.append(chain_id)

        res = {'id':traffic_classifier['id'],
               'tenant_id':traffic_classifier['tenant_id'],
               'name':traffic_classifier['name'],
               'ports':jsonutils.loads(traffic_classifier['ports']),
               'description':traffic_classifier['description'],
               'classification_type':traffic_classifier['classification_type'],
               'service_chain_id':list_chains
              }
        return self._fields(res, fields)

    def _make_function_instance_dict(self, function_instance, fields=None):
        """ to be done """
        instance_ctx = function_instance['context']
        ctx = {'user_side_port':instance_ctx['user_side_port'],
               'user_side_action':jsonutils.loads(instance_ctx['user_side_action']),
               'network_side_port':instance_ctx['network_side_port'],
               'network_side_action':jsonutils.loads(instance_ctx['network_side_action']),
               'classification_type':instance_ctx['classification_type']}

        if function_instance.get('group_id',None):
            group_uuid =  function_instance['group_id']['group_id']
        else:
            group_uuid = None

        res = {'id':function_instance['id'],
               'tenant_id':function_instance['tenant_id'],
               'name':function_instance['name'],
               'admin_state':function_instance['admin_state'],
               'fault_policy':function_instance['fault_policy'],
               'context':ctx,
               'device_id':function_instance['device_id'],
               'type':function_instance['type'],
               'group_id':group_uuid,
               'description':function_instance['description']
               }

        return self._fields(res, fields)

    def create_service_traffic_classifier(self, context, service_traffic_classifier):
        LOG.debug(_("Create service traffic classifier %s"), service_traffic_classifier)
        st_classifier = service_traffic_classifier['service_traffic_classifier']
        name = st_classifier['name']
        tenant_id = self._get_tenant_id_for_create(context, st_classifier)
        session = context.session

        with session.begin(subtransactions=True):
            #validate name is ok
            self._validate_instance_or_classifier_name(context, schain.CLASSIFIER, name)

            #the classifier port should not bigger than 64
            if len(st_classifier['ports']) > 64:
                LOG.debug(_("the classifier port number is more than the most number 64"))
                raise schain.ServiceTrafficClassifierPortToLager(name=name)

            #check port is ok
            cls_port = set()
            for port_id in st_classifier['ports']:
                #check port is in used
                self._check_sc_port(context, port_id)
                #check port is vm port
                port = self._validate_classifier_port(context, port_id, 1)
                cls_port.add(port)

            uuid = uuidutils.generate_uuid()

            list_ports = {}
            list_hosts = {}
            for port_id in st_classifier['ports']:
                sf_port_dict = sc_pool._allocation_sf_port_id(context, port_id, uuid, schain.CLASSIFIER)
                host_id = self._validate_classifier_port(context, port_id, 0)
                list_hosts[port_id] = host_id
                list_ports[port_id] = sf_port_dict['sf_port_id']
                if not self.host_agents(context, constants.AGENT_TYPE_SERVICECHAIN, host_id):
                    raise schain.ScAgentNotFount(id=host_id)                
                
            #add content
            args = {'id':uuid,
                    'name':name,'tenant_id':tenant_id,
                    'description':st_classifier['description'],
                    'ports':jsonutils.dumps(cls_port),
                    'list_ports':jsonutils.dumps(list_ports),
                    'list_hosts':jsonutils.dumps(list_hosts),
                    'classification_type':st_classifier['classification_type']
                    }

            new_classifier = models_sc.ServiceTrafficClassifier(**args)
            session.add(new_classifier)
            #set port info to uvp
            self._instance_or_classifier_set_info(context, new_classifier, schain.CLASSIFIER)

            return self._make_traffic_classifier_dict(new_classifier)

    
    def update_service_traffic_classifier(self, context, service_traffic_classifier_id, service_traffic_classifier):
        LOG.debug(_("update service traffic classifier %s with info %s"),service_traffic_classifier_id,service_traffic_classifier)
        new_st_classifier = service_traffic_classifier['service_traffic_classifier']
        session = context.session
        with session.begin(subtransactions=True):
            old_st_classifier = self._get_service_traffic_classifier(context,service_traffic_classifier_id)

            if new_st_classifier.get('name',None):
                self._validate_instance_or_classifier_name(context, schain.CLASSIFIER, new_st_classifier['name'],
                                                           old_st_classifier['name'])

            if new_st_classifier.get('classification_type',None):
                self._check_classification_type(new_st_classifier['classification_type'])

            port_add_list = []
            port_del_list = []

            if new_st_classifier.get('ports',None):
                #get all port in new classifier
                new_port_list = set()
                for port in new_st_classifier['ports']:
                    #we need to validate port is ok and is be used by other classifier
                    port_id = self._validate_classifier_port(context, port, 1)
                    self._check_sc_port(context, port, old_st_classifier['id'])
                    new_port_list.add(port_id)
                #get all port in old classifier
                old_port_list = set()
                for port in jsonutils.loads(old_st_classifier['ports']):
                    old_port_list.add(port)

                #check add or del port
                port_add_list = new_port_list - old_port_list
                port_del_list = old_port_list - new_port_list

                list_ports = jsonutils.loads(old_st_classifier['list_ports'])
                list_hosts = jsonutils.loads(old_st_classifier['list_hosts'])
                #when add port you must allocation sf_port_id for the port
                if port_add_list:
                    for port_id in port_add_list:
                        host_id = self._validate_classifier_port(context, port, 0)
                        sf_port_dict = sc_pool._allocation_sf_port_id(context, port_id, old_st_classifier['id'], schain.CLASSIFIER)
                        list_ports.update({port_id:sf_port_dict['sf_port_id']})
                        list_hosts.update({port_id:host_id})
                        #we should set port info when add
                        self._instance_or_classifier_set_info(context, old_st_classifier, schain.CLASSIFIER, \
                                                              {'port_id':port_id,'sf_port_id':sf_port_dict['sf_port_id'],'host_id':host_id})

                #when del port you must recycle sf_port_id for the port
                if port_del_list :
                    for port_id in port_del_list:
                        sc_pool._recycle_sf_or_port(context, port_id, old_st_classifier['id'], schain.CLASSIFIER)
                        pop_sf_port_id = list_ports.pop(port_id)
                        pop_host_id = list_hosts.pop(port_id)
                        #we should del port info when delete
                        self._instance_or_classifier_del_info(context, old_st_classifier, schain.CLASSIFIER,\
                                                              {'port_id':port_id,'sf_port_id':pop_sf_port_id,'host_id':pop_host_id})
                #update list_ports for add/del
                old_st_classifier['ports'] = jsonutils.dumps(new_st_classifier['ports'])
                new_st_classifier.pop("ports")
                old_st_classifier['list_ports'] = jsonutils.dumps(list_ports)
                old_st_classifier['list_hosts'] = jsonutils.dumps(list_hosts)

            old_st_classifier.update(new_st_classifier)

            new_classifier = self._get_service_traffic_classifier(context, service_traffic_classifier_id)
            #if new classifier in chain should update port flow
            if  len(new_classifier['service_chain_id']):
                    if port_del_list :
                        self._treat_update_classifier_action(context, new_classifier, port_del_list)
                    if port_add_list:
                        self._treat_update_classifier_action(context, new_classifier)

            return self._make_traffic_classifier_dict(new_classifier)

    
    def delete_service_traffic_classifier(self, context, service_traffic_classifier_id):
        session = context.session
        with session.begin(subtransactions=True):
            st_classifier = self._get_service_traffic_classifier(context,service_traffic_classifier_id)
            #if classifier is used,so can not be delete
            if st_classifier['service_chain_id']:
                LOG.debug(_("the classifier is used by chains %s"),st_classifier['service_chain_id'])
                raise schain.ServiceClassifierInUse(id=service_traffic_classifier_id)

            for vm_port_id in jsonutils.loads(st_classifier['ports']):
                sc_pool._recycle_sf_or_port(context, vm_port_id, service_traffic_classifier_id, schain.CLASSIFIER)
            #delete classifier uvp cfg
            self._instance_or_classifier_del_info(context, st_classifier, schain.CLASSIFIER)
            #delete db info
            session.delete(st_classifier)

    def get_service_traffic_classifier(self, context, service_traffic_classifier_id,
                              fields=None):
        st_classifier = self._get_service_traffic_classifier(context, service_traffic_classifier_id)
        return self._make_traffic_classifier_dict(st_classifier)
    
    def get_service_traffic_classifiers(self, context, filters=None, fields=None,
                               sorts=None, limit=None, marker=None,
                               page_reverse=False):
        marker_obj = self._get_marker_obj(context, 'service_traffic_classifier', limit, marker)
        return self._get_collection(context, models_sc.ServiceTrafficClassifier,
                                    self._make_traffic_classifier_dict,
                                    filters=filters, fields=fields,
                                    sorts=sorts,
                                    limit=limit,
                                    marker_obj=marker_obj,
                                    page_reverse=page_reverse)

    
    def get_service_traffic_classifier_count(self, context, uuid, filters=None):
        pass


    def host_agents(self, context, agent_type, host_uuid):
        core_plugin = manager.NeutronManager.get_plugin()        
        return  core_plugin.get_agents_db(
                context,filters={'agent_type': [agent_type],
                'host': [host_uuid]})    
    
    def create_service_function_instance(self, context, service_function_instance):
        """create service function instance"""
        LOG.debug(_("Create Service function Instance %s"),service_function_instance)

        function_instance = service_function_instance['service_function_instance']
        instance_context = function_instance['context']
        device_id = function_instance['device_id']
        tenant_id = self._get_tenant_id_for_create(context, function_instance)
        session = context.session
        with session.begin(subtransactions=True):
            #create service function instance
            # check name exist
            self._validate_instance_or_classifier_name(context, schain.INSTANCE, function_instance['name'])
            #vlaidate device is in use
            self._check_device_is_instance(context,device_id)
            #validate instance port
            self._validate_instance_context_port(context, instance_context, device_id)

            if function_instance.get('fault_policy',None):
                policy = function_instance['fault_policy']
            else:
                policy = None
            #save instance to db
            id = uuidutils.generate_uuid()

            args = {'id':id,
                    'device_id': device_id,
                    'name': function_instance['name'],
                    'description': function_instance['description'],
                    'fault_policy': policy,
                    'type': function_instance['type'],
                    'tenant_id': tenant_id,
                    'admin_state': function_instance['admin_state']}
            new_instance = models_sc.ServiceFunctionInstance(**args)
            session.add(new_instance)
            #save instance context with sf_port_id to db
            user_action = {}
            network_action = {}

            if instance_context.get('user_side_port',None):
                user_side_port = instance_context['user_side_port']
            else:
                raise schain.ServiceFunctionPortIsNull()

            if instance_context.get('network_side_port',None):
                network_side_port = instance_context['network_side_port']
            else:
                raise schain.ServiceFunctionPortIsNull()

            if instance_context.get('user_side_action',None):
                user_action.update(instance_context['user_side_action'])

            if instance_context.get('network_side_action',None):
                network_action.update(instance_context['network_side_action'])

            if instance_context.get('classification_type',None):
                clf_type = self._check_classification_type(instance_context['classification_type'])
            else:
                raise schain.ServiceClassifierTypeIsNull()

            argvs = {'service_function_instance_id':new_instance['id'],
                     'user_side_port': user_side_port,
                     'user_side_action': jsonutils.dumps(user_action),
                     'network_side_port':network_side_port,
                     'network_side_action':jsonutils.dumps(network_action),
                     'classification_type': clf_type}
            # vas has one or two port
            core_plugin = manager.NeutronManager.get_plugin()
            if user_side_port != network_side_port:
                port_set = set()
                port_set.add(user_side_port)
                port_set.add(network_side_port)
                list_ports = {}
                for port_id in port_set:
                    sf_port_dict = sc_pool._allocation_sf_port_id(context, port_id, new_instance['id'],schain.INSTANCE)
                    list_ports.update({port_id:sf_port_dict['sf_port_id']})
                    port_vm = core_plugin.get_port(context, port_id)
                argvs['user_side_sf_port_id'] = list_ports[user_side_port]
                argvs['network_side_sf_port_id'] = list_ports[network_side_port]
                argvs['host_id'] = port_vm["binding:host_id"]
            else:
                sf_port_dict = sc_pool._allocation_sf_port_id(context, user_side_port, new_instance['id'],schain.INSTANCE)
                port_vm = core_plugin.get_port(context, user_side_port)
                argvs['user_side_sf_port_id'] = sf_port_dict['sf_port_id']
                argvs['network_side_sf_port_id'] = sf_port_dict['sf_port_id']
                argvs['host_id'] = port_vm["binding:host_id"]
                #set port info to

            if not self.host_agents(context, constants.AGENT_TYPE_SERVICECHAIN, argvs['host_id']):
                raise schain.ScAgentNotFount(id=argvs['host_id'])
            new_instance_context = models_sc.ServiceFuntionInstanceContext(**argvs)
            session.add(new_instance_context)
            #set port info to uvp
            self._instance_or_classifier_set_info(context, new_instance_context, schain.INSTANCE)

            return self._make_function_instance_dict(new_instance)

    def update_service_function_instance(self, context, service_function_instance_id,
                                                                service_function_instance):
        #get new instance
        LOG.debug(_("update service function instance %s with info %s"),service_function_instance_id,\
                  service_function_instance)
        flag = 0
        active_flag = 0
        action_flag = 0
        new_function_instance = service_function_instance['service_function_instance']
        session = context.session
        with session.begin(subtransactions=True):
            #get service funtion instance by id
            old_function_instance = self._get_service_function_instance(context,service_function_instance_id)

            if new_function_instance.get('context',None):
                new_instance_context = new_function_instance['context']
                old_instance_context = old_function_instance['context']

                old_user_port = old_instance_context['user_side_port']
                old_network_port = old_instance_context['network_side_port']
                old_cls_type = old_instance_context['classification_type']

                if new_instance_context.get('user_side_port',None):
                    user_port = new_instance_context['user_side_port']
                else:
                    user_port = None
                if new_instance_context.get('network_side_port',None):
                    network_port = new_instance_context['network_side_port']
                else:
                    network_port = None

                if new_instance_context.has_key('user_side_action'):
                    user_action = new_instance_context['user_side_action']
                else:
                    user_action = None
                if new_instance_context.has_key('network_side_action'):
                    network_action = new_instance_context['network_side_action']
                else:
                    network_action = None
                if new_instance_context.has_key('classification_type'):
                    clf_type = self._check_classification_type(new_instance_context['classification_type'])
                else:
                    clf_type = None

                inst_context = {}

                if user_port and old_user_port != user_port  or \
                                network_port and old_network_port != network_port:
                    LOG.debug(_("user side port or network side port can not be update"))
                    raise schain.ServiceInstancePortChange()

                if user_action != None and len(user_action) >= 0:
                    inst_context['user_side_action'] = jsonutils.dumps(user_action)
                    action_flag = 1

                if network_action != None and len(network_action) >=0 :
                    inst_context['network_side_action'] = jsonutils.dumps(network_action)
                    action_flag = 1

                if clf_type and clf_type != old_cls_type:
                    inst_context['classification_type'] = clf_type
                    flag = 1

                if old_function_instance['admin_state']  != 'error':
                    old_instance_context.update(inst_context)
                else:
                    LOG.debug(_("Service Instance %s is error and can not update context"),old_function_instance['name'])
                    raise schain.ServiceInstanceIsError(name=old_function_instance['name'])
            #if context exist,after update del it for update instance
            if new_function_instance.has_key('context'):
                new_function_instance.pop('context')

            #check name changed
            if new_function_instance.get('name', None) :
                self._validate_instance_or_classifier_name(context, schain.INSTANCE, new_function_instance['name'],
                                                           old_function_instance['name'])
            #brance instance state is error
            if  old_function_instance['admin_state']  != 'error':
                LOG.debug(_("update service funtion instance go to admin_state normal way"))
                #check instance in the group
                if old_function_instance['group_id']:
                    #if instance in group and change instance type will be not allow
                    if new_function_instance.get('type',None) and old_function_instance['type'] != new_function_instance['type']:
                            LOG.debug(_("the instance is in group %s ,so attr type can not be changed " ),old_function_instance['group_id'])
                            raise schain.ServiceFunctionInstanceInGroup(id=service_function_instance_id,
                                                                        group=old_function_instance['group_id']['group_id'])
                    group_uuid = old_function_instance['group_id']['group_id']
                    group_qry = session.query(models_sc.ServiceFunctionPath).with_lockmode('update')
                    chain = group_qry.filter_by(service_function_group_id=group_uuid).first()

                    if chain:
                        instances_to_leave = {}
                        group_db = session.query(models_sc.ServiceFunctionGroup).filter_by(id=group_uuid).first()
                        if group_db.get('members', None):
                            for instance in group_db['members']:

                                weight = instance.get('weight', None)
                                inst_dict = {'weight': weight,
                                            'instance_id': instance['instance_id']}

                                func_instance = session.query(models_sc.ServiceFunctionInstance).filter_by(id\
                                                                                =instance['instance_id']).first()
                                instances_to_leave[instance['instance_id']] = inst_dict
                        #
                        if new_function_instance.get('admin_state',None) and \
                                        old_function_instance['admin_state'] != new_function_instance['admin_state']:

                            instband = session.query(models_sc.ServiceFunctionGroupBindInstance).\
                                                filter_by(instance_id=service_function_instance_id).first()
                            #before set flows we must update function instance
                            old_function_instance.update(new_function_instance)
                            active_flag = 1
                            function_port_list = {}

                            if new_function_instance['admin_state'] == 'active':
                                LOG.debug(_("update the instance %s state to active and update port flows"),service_function_instance_id)
                                instances_to_add = {}

                                function_port_list[service_function_instance_id] = 'active'
                                self._treat_update_group_action(context,group_db, None, instances_to_leave, [], function_port_list)

                            elif new_function_instance['admin_state'] == 'inactive':
                                LOG.debug(_("update the instance %s state to inactive and update port flows"),service_function_instance_id)
                                function_port_id = set()
                                function_port_id.add(service_function_instance_id)
                                function_port_list[service_function_instance_id] = 'inactive'
                                self._treat_update_group_action(context,group_db, None, instances_to_leave, [], function_port_list)

                            else:
                                function_port_list[service_function_instance_id] = 'error'
                                LOG.debug(_("update the instance %s state to error and update port flows"),service_function_instance_id)
                                if new_function_instance.get('fault_policy',None):
                                    if new_function_instance['fault_policy'] == 'None' :
                                        new_function_instance.pop('fault_policy')
                                        if old_function_instance['fault_policy'] in ['bypass','drop']:
                                            self._treat_update_group_action(context,group_db, None, instances_to_leave, [], function_port_list)
                                    else:
                                        self._treat_update_group_action(context,group_db, None, instances_to_leave, [], function_port_list)
                                else:
                                    if old_function_instance['fault_policy'] in ['bypass','drop']:
                                        self._treat_update_group_action(context, group_db, None, instances_to_leave, [], function_port_list)
                        else:
                            if action_flag == 1:
                                old_function_instance.update(new_function_instance)
                                active_flag = 1
                                self._treat_update_group_action(context, group_db, None, instances_to_leave, [], [])

                    # weather group in chain or not you should update
                    if active_flag == 0:
                        LOG.debug(_("the instance %s state is none or not change,so just update"),service_function_instance_id)
                        old_function_instance.update(new_function_instance)
                # instance not in a  group
                else:
                    LOG.debug(_("the instance %s is not in any group,so just update"),service_function_instance_id)
                    old_function_instance.update(new_function_instance)
                #if clf_type changed,should change configure
                if flag == 1:
                    LOG.debug(_("set port config in ovs db for instance %s"),old_function_instance['name'])
                    self._instance_or_classifier_set_info(context, old_instance_context, schain.INSTANCE)

            #brance instance admin_state is not error
            else:
                if new_function_instance.get('type',None) \
                        and old_function_instance['type'] != new_function_instance['type']:
                    LOG.debug(_("the instance %s admin_state is error, so attr type can not be changed "),old_function_instance['name'])
                    raise schain.ServiceInstanceIsError(name=old_function_instance['name'])

                if new_function_instance.get('fault_policy',None) and \
                                old_function_instance['fault_policy'] != new_function_instance['fault_policy']:
                    LOG.debug(_("the instance %s admin_state is error, so attr fault_policy can not be changed "),old_function_instance['name'])
                    raise schain.ServiceInstanceIsError(name=old_function_instance['name'])

                if new_function_instance.get('admin_state',None) and new_function_instance['admin_state'] == 'active':
                    LOG.debug(_("update service funtion instance to admin_state error way"))
                    if old_function_instance['group_id']:
                        group_uuid = old_function_instance['group_id']['group_id']
                        group_qry = session.query(models_sc.ServiceFunctionPath).with_lockmode('update')
                        chain = group_qry.filter_by(service_function_group_id=group_uuid).first()
                        if chain:
                            instances_to_leave = {}
                            function_port_list = {}
                            group_db = session.query(models_sc.ServiceFunctionGroup).filter_by(id=group_uuid).first()
                            if group_db.get('members', None):
                                for instance in group_db['members']:
                                    weight = instance.get('weight', None)
                                    inst_dict = {'weight': weight,
                                                 'instance_id': instance['instance_id']}
                                    func_instance = session.query(models_sc.ServiceFunctionInstance).filter_by(id \
                                                                                                        =instance['instance_id']).first()
                                    if func_instance['admin_state'] == 'active':
                                        instances_to_leave[instance['instance_id']] = inst_dict

                                instband = session.query(models_sc.ServiceFunctionGroupBindInstance). \
                                                    filter_by(instance_id=service_function_instance_id).first()

                                old_function_instance.update(new_function_instance)
                                active_flag = 1

                                LOG.debug(_("update the instance %s state error to active and update port flows"),service_function_instance_id)
                                instances_to_add = {}

                                instances_to_add.update({service_function_instance_id:{'weight':instband['weight'],
                                                                                       'instance_id':service_function_instance_id}})
                                instances_to_leave.update({service_function_instance_id:{'weight':instband['weight'],
                                                                                         'instance_id':service_function_instance_id}})
                                function_port_list[service_function_instance_id] = 'active'
                                self._treat_update_group_action(context,group_db, instances_to_add,instances_to_leave, [], function_port_list)

                elif  new_function_instance.get('admin_state',None) and new_function_instance['admin_state'] == 'inactive':
                    LOG.debug(_("the instance %s admin_state is error, so attr admin_state can not be changed to inactive"),old_function_instance['name'])
                    raise schain.ServiceInstanceIsError(name=old_function_instance['name'])

                if active_flag == 0:
                    old_function_instance.update(new_function_instance)

            #get new instance by id
            db_function_instance = self._get_service_function_instance(context, service_function_instance_id)
            return self._make_function_instance_dict(db_function_instance)

    
    def delete_service_function_instance(self, context, service_function_instance_id):
         session = context.session
         with session.begin(subtransactions=True):
             #get service funtion instance
             function_instance_db = self._get_service_function_instance(context, service_function_instance_id)
             #validate instance is in use
             if function_instance_db['group_id'] :
                 LOG.debug(_("the instance %s has added to the group %s,cann't be delete"),service_function_instance_id,
                           function_instance_db['group_id'])
                 raise schain.ServiceFunctionInstanceInuse(id = service_function_instance_id,
                                                           group = function_instance_db['group_id']['group_id'])
             else:
                instance_ctx = function_instance_db['context']
                if instance_ctx['user_side_port'] == instance_ctx['network_side_port']:
                    self._delete_service_function_instance(context, instance_ctx['user_side_port'], function_instance_db['id'])
                else:
                    recycle_ports = set()
                    recycle_ports.add(instance_ctx['user_side_port'])
                    recycle_ports.add(instance_ctx['network_side_port'])
                    for port_id in recycle_ports:
                        self._delete_service_function_instance(context, port_id,function_instance_db['id'])
                #delete uvp config
                LOG.debug(_("Delete port config in ovs db for instance %s"),function_instance_db['name'])
                self._instance_or_classifier_del_info(context, instance_ctx, schain.INSTANCE)
                #delete servicechain db
                session.delete(function_instance_db)

    def get_service_function_instance(self, context,
                                      service_function_instance_id, fields=None):

        function_instance = self._get_service_function_instance(context,service_function_instance_id)
        return self._make_function_instance_dict(function_instance, fields)

    
    def get_service_function_instances(self, context, filters=None, fields=None,
                                        sorts=None, limit=None, marker=None,
                                        page_reverse=False):
        marker_obj = self._get_marker_obj(context, 'service_function_instance', limit, marker)
        return self._get_collection(context, models_sc.ServiceFunctionInstance,
                                    self._make_function_instance_dict,
                                    filters=filters, fields=fields,
                                    sorts=sorts,
                                    limit=limit,
                                    marker_obj=marker_obj,
                                    page_reverse=page_reverse)

    def get_service_function_instance_count(self, context, filters=None):
        pass
                
                
                
    def _get_serviceinstance_by_id(self, context, instance_id):
        try:
            serviceinstance = self._get_by_id(context, models_sc.ServiceFunctionInstance, instance_id)
        except exc.NoResultFound:
            LOG.error(_('service instance %(id)s could not be found'),
                      {'id': instance_id})
            raise sc_exc.ServiceInstanceNotFound(id=instance_id)
        return serviceinstance

    def  _validate_instance_inuse(self, db_instance, group_id):
        if db_instance['group_id']:
            if db_instance['group_id']['group_id'] != group_id:
                LOG.error(_('Service instance %s is in use by group %s'),
                          db_instance['id'],
                          db_instance['group_id']['group_id'])
                raise sc_exc.ServiceInstanceInUse(id=db_instance['id'])

    
    #for all groups: one name just for one group
    def _validate_group_name(self, context, new_name, old_name = None):       
        if not old_name or new_name != old_name:
            group_name = context.session.query(models_sc.ServiceFunctionGroup).filter_by(
                    name=new_name).first()
            if group_name:
                LOG.error(_('_checkout group_name failed: name of %s '
                        'is used by other group'), new_name)
                raise sc_exc.GroupNameInUse(name=new_name)         
    
    #check the instance's type is equal to the group's type     
    def _validate_group_instance_type(self, instance_type, group_type):
        if instance_type != group_type:
            LOG.error(_('_checkout type failed: instancetype of %s '
                    'is not equal to the grouptype %s' ), instance_type, group_type)            
            raise sc_exc.GroupInstanceTypeNotEqual(instance_type = instance_type,
                                                   group_type = group_type)  
    
    def _create_group_id(self, context, group_uuid):
        return sc_pool._allocation_sf_port_id(context, '', group_uuid, 'service_function_group')
    
    def _make_serviceinstancegroup_dict(self, serviceinstancegroup, fields=None,
                           process_extensions=True):
        res = {'id': serviceinstancegroup['id'],
               'tenant_id': serviceinstancegroup['tenant_id'],
               'members': [{'instance_id': instance['instance_id'],
                            'weight': instance['weight']}
                            for instance in serviceinstancegroup['members']],               
               'name': serviceinstancegroup['name'],
               'description': serviceinstancegroup['description'],
               'type': serviceinstancegroup['type'],
               'method': jsonutils.loads(serviceinstancegroup['method']),
               'service_chain_id':[binding['service_chain_id'] 
                            for binding in serviceinstancegroup['service_chain_id']]
               }

        if process_extensions:
            self._apply_dict_extend_functions(
                'service_function_groups', res, serviceinstancegroup)
        return self._fields(res, fields)

    def  _get_serviceinstancegroup_by_id(self, context, group_id):
        try:
            serviceinstancegroup = self._get_by_id(context, models_sc.ServiceFunctionGroup, group_id)
        except exc.NoResultFound:
            LOG.error(_('service_function_group %(id)s could not be found'),
                      {'id': group_id})
            raise sc_exc.ServiceInstanceGroupNotFound(id=group_id)
        return serviceinstancegroup   

    def _validate_group_inuse(self, context, db_group):
        group_in_chain = context.session.query(models_sc.ServiceFunctionPath).filter_by(
                service_function_group_id=db_group['id']).first()                
        if group_in_chain:
            raise sc_exc.ServiceGroupInUse(id=db_group['id'])                         


    def _treat_update_classifier_action(self, context, db_clasfsifier, port_to_delete = []):

        LOG.debug("_treat_update_classifier_action, port_to_delete=%s,db_clasfsifier=%s" %(port_to_delete,db_clasfsifier))   
 
        if port_to_delete:
            self._delete_port_flows(context, port_to_delete)             
                        
        for ClassifierBindChain in db_clasfsifier['service_chain_id']:
                         
            port_flows_back_list = []
            
            service_chain_uuid = ClassifierBindChain['service_chain_id']
            chain_db = context.session.query(models_sc.ServiceChain).filter_by(id=\
                           service_chain_uuid).first()              
                          
            service_function_path = []
            for function_path in chain_db['service_function_path']:
                service_function_path.append(function_path['service_function_group_id'])    
                    
            functionpath_new_all = self._check_functionpath(context, service_function_path)
            
            traffic_classifier = []
            traffic_classifier.append(db_clasfsifier['id'])  
            
            if functionpath_new_all:  
                group_first = []
                group_first.append(functionpath_new_all[0])    
                port_flows_back_list = self._create_classifier_flows(context, chain_db, traffic_classifier, 
                                              group_first)                  
            else:
                port_flows_back_list = self._create_classifier_flows(context, chain_db, traffic_classifier, None)                 
 
                
            if port_flows_back_list:        
                port_flows_back = []
                for flow in port_flows_back_list:
                    port_flows_back.append(self._make_portflow_dict(flow))           
                greenthread.spawn(self._thread_add_port_flows, context, port_flows_back)              
        
        
    def _treat_update_group_action(self, context, db_group, instances_to_add, error_or_active_instance,\
                                   instances_to_delete = [], update_instance = {}):

        LOG.debug("instances_to_add=%s, error_or_active_instance=%s,instances_to_delete=%s, update_instance=%s" \
                  %(instances_to_add, error_or_active_instance,instances_to_delete,update_instance))             

        #all of the chain
        if instances_to_delete:
            self._delete_instance_flows(context, instances_to_delete)
                
        for ServiceFunctionPath in db_group['service_chain_id']:
            port_flows_back_list = []
            
            service_chain_uuid = ServiceFunctionPath['service_chain_id']
            chain_db = context.session.query(models_sc.ServiceChain).filter_by(id=\
                           service_chain_uuid).first()          
            
            before_group = None
            after_group = None
                 
            if update_instance and update_instance.values()[0] == 'inactive':
                db_groupbinding = context.session.query(models_sc.ServiceFunctionGroupBindInstance).\
                                            filter_by(group_id=db_group['id']).all()                                           
                instance_all = 0
                instance_inactive = 0                                                      
                for ServiceFunctionGroupBindInstance in db_groupbinding: 
                    instance_db = context.session.query(models_sc.ServiceFunctionInstance).filter_by(
                                  id=ServiceFunctionGroupBindInstance['instance_id']).first()  
                    instance_all = instance_all + 1
                    if instance_db.get('admin_state') == 'inactive':
                        instance_inactive = instance_inactive + 1

                LOG.debug("_treat_update_group_action, instance_inactive= %s, instance_all=%s" %\
                      (instance_inactive,instance_all))                        
                
                if instance_all == instance_inactive and instance_all != 0 :
                    raise sc_exc.ShouldNotUpdateGroupOneInstance(id=db_group['id'])

                
                instance_id = update_instance.keys()[0]
                
                instance_db = context.session.query(models_sc.ServiceFunctionInstance).filter_by(
                                                    id=instance_id).first() 
                if chain_db.get('direction',None) == 'U2N':  
                    in_port = instance_db['context']['network_side_port']       
                else:
                    in_port = instance_db['context']['user_side_port']

                flow = context.session.query(models_sc.PortFlow).\
                                              filter_by(in_port_uuid=in_port,
                                                        service_chain_id=chain_db['id']).first()
                flow.update({'instance_state': 'inactive'})                 

            service_function_path = []
            for function_path in chain_db['service_function_path']:
                service_function_path.append(function_path['service_function_group_id'])    
                     
            functionpath_new_all = self._check_functionpath(context, service_function_path, db_group['id'])
            local_group_index = functionpath_new_all.index(db_group['id'])   
            
            traffic_classifier = []   
            for classifier in chain_db['traffic_classifier']:
                traffic_classifier.append(classifier['service_traffic_classifier_id'])  
            
            LOG.debug("_treat_update_group_action, service_chain_uuid= %s, functionpath_new_all=%s" %\
                      (service_chain_uuid,functionpath_new_all))                       

            if error_or_active_instance:
                if local_group_index == 0:
                    group_first = []
                    group_first.append(db_group['id'])    
                    port_flows_back_list_classifier = self._create_classifier_flows\
                                                      (context, chain_db, traffic_classifier, group_first, [], update_instance)
                    functionpath = []
                    functionpath.append(db_group['id'])
                    if db_group['id'] != functionpath_new_all[-1]:
                        after_group = functionpath_new_all[local_group_index + 1]
                        functionpath.append(after_group)                  
                        port_flows_back_list_function_path= self._create_function_path_flows\
                                                            (context, chain_db, functionpath, True, [], update_instance)
                    else:
                        port_flows_back_list_function_path = self._create_function_path_flows\
                                                            (context, chain_db, functionpath, False, [], update_instance)
                    port_flows_back_list = port_flows_back_list_classifier + port_flows_back_list_function_path                      
                else:
                    functionpath = []
                    before_group = functionpath_new_all[local_group_index - 1]
                    functionpath.append(before_group)
                    functionpath.append(db_group['id'])     
                    if db_group['id'] != functionpath_new_all[-1]:
                        after_group = functionpath_new_all[local_group_index + 1]
                        functionpath.append(after_group)                  
                        port_flows_back_list = self._create_function_path_flows(context, chain_db, functionpath, True, [], update_instance)
                    else:
                        port_flows_back_list = self._create_function_path_flows(context, chain_db, functionpath, False, [], update_instance)
            elif not error_or_active_instance:
                if local_group_index == 0:
                    group_first = []
                    if len(functionpath_new_all) != 1:
                        group_first.append(functionpath_new_all[local_group_index + 1])      
                    port_flows_back_list = self._create_classifier_flows(context, chain_db, traffic_classifier, group_first)
                else:
                    functionpath = []
                    before_group = functionpath_new_all[local_group_index - 1]
                    functionpath.append(before_group) 
                    if db_group['id'] != functionpath_new_all[-1]:
                        after_group = functionpath_new_all[local_group_index + 1]
                        functionpath.append(after_group)                  
                        port_flows_back_list = self._create_function_path_flows(context, chain_db, functionpath, True)
                    else:
                        port_flows_back_list = self._create_function_path_flows(context, chain_db, functionpath, False)      
   
            if port_flows_back_list:        
                port_flows_back = []
                for flow in port_flows_back_list:
                    port_flows_back.append(self._make_portflow_dict(flow))                  
                greenthread.spawn(self._thread_add_port_flows, context, port_flows_back)   

 
    def _validate_chain_name(self, context, new_name, old_name = None):
        if not old_name or new_name != old_name:
            chain_name = context.session.query(models_sc.ServiceChain).filter_by(
                    name=new_name).first()
            if chain_name:
                LOG.error(_('_checkout chain_name failed: name of %s '
                        'is used by other chain'), new_name)
                raise sc_exc.ChainNameInUse(name=new_name) 
        
    def _validate_traffic_classifier(self, context, traffic_classifier):
        for classifier_id in traffic_classifier:
            try:
                self._get_by_id(context, models_sc.ServiceTrafficClassifier, classifier_id)
            except exc.NoResultFound:
                LOG.error(_('_checkout traffic_classifier failed: %s'
                        'does not exit'), classifier_id)
                raise sc_exc.Classifier_If_Exit(classifier_id=classifier_id)  
                              
    
    def _validate_service_function_path(self, context, service_function_path): 
        if len(service_function_path) > 8:
            raise sc_exc.Group_in_Chain_Max_Length(length=len(service_function_path)) 
                
        for group_uuid in service_function_path:
            db_groupbinding = context.session.query(models_sc.ServiceFunctionGroupBindInstance).\
                                            filter_by(group_id=group_uuid).all()

            db_group = context.session.query(models_sc.ServiceFunctionGroup).\
                                            filter_by(id=group_uuid).all()                                                                
            if not db_group:
                raise sc_exc.Group_in_Chain_If_Exit(group_uuid=group_uuid) 
                
            instance_all = 0
            instance_inactive = 0    
                                                                  
            for ServiceFunctionGroupBindInstance in db_groupbinding: 
                
                instance_db = context.session.query(models_sc.ServiceFunctionInstance).filter_by(
                              id=ServiceFunctionGroupBindInstance['instance_id']).first()  
                instance_all = instance_all + 1
                if instance_db.get('admin_state') == 'inactive':
                    instance_inactive = instance_inactive + 1
            
            if instance_all == instance_inactive and instance_all != 0 :
                raise sc_exc.OneGroupAllInstanceAreInactive()

    def _validate_destination_mac(self, context, destination_context, sc_db = None):
        if destination_context.get('destination_flag') == 'chain':
            port = manager.NeutronManager.get_plugin().get_ports(context,\
                    filters={'mac_address': [destination_context['destination_mac']]})
            if not port:
                raise sc_exc.Destination_mac_not_Exit(destination_mac=destination_context['destination_mac'])  
        else:
            if sc_db != None:
                old_destination_context = jsonutils.loads(sc_db['destination_context'])
                destination_flag = old_destination_context.get('destination_flag')  
                if destination_flag == 'chain':          
                    port = manager.NeutronManager.get_plugin().get_ports(context,\
                            filters={'mac_address': [destination_context['destination_mac']]})
                    if not port:
                        raise sc_exc.Destination_mac_not_Exit(destination_mac=destination_context['destination_mac'])
                else:
                    raise sc_exc.Destination_mac_not_Exit(destination_mac=destination_context['destination_mac'])
                                        
         

    def _create_chain_id(self, context, chain_uuid):
        return sc_pool._allocation_sf_port_id(context, '', chain_uuid,'service_chain')


    def _create_sc_bind_classifier(self, context, classifiers, chain_id):
        for classifier in classifiers:
            binding = models_sc.ServiceTrafficClassifierBindChain(service_chain_id=chain_id,
                                                   service_traffic_classifier_id=classifier)
            context.session.add(binding)  

    def _create_sc_bind_FunctionPath(self, context, service_function_path, chain_id):
        i = 1
        for group_uuid in service_function_path:            
            binding = models_sc.ServiceFunctionPath(service_chain_id=chain_id,
                                                   service_function_group_id=group_uuid,
                                                   hop_index=i)
            context.session.add(binding)
            i = i + 1

    def _make_servicechain_dict(self, servicechain, fields=None,
                           process_extensions=True):
        service_function_path_list = []
        traffic_classifier_list = []
        
        for group_uuid in servicechain['service_function_path']:
            service_function_path_list.append(group_uuid['service_function_group_id'])

        for traffic_classifier in servicechain['traffic_classifier']:
            traffic_classifier_list.append(traffic_classifier['service_traffic_classifier_id'])
                
        res = {'id': servicechain['id'],
               'name': servicechain['name'],       
               'direction': servicechain['direction'],        
               'chain_id': servicechain['chain_id'],
               'description': servicechain['description'],              
               'traffic_classifier': traffic_classifier_list,
               'catenated_chain': servicechain['catenated_chain'],
               'service_function_path': service_function_path_list,              
               'destination_context': jsonutils.loads(servicechain['destination_context']),
               'status': servicechain['status']
               }
        if process_extensions:
            self._apply_dict_extend_functions(
                'service_chains', res, servicechain)
        return self._fields(res, fields)
    
    def _get_servicechain_by_id(self, context, chain_id):
        try:
            servicechain = self._get_by_id(context, models_sc.ServiceChain, chain_id)
        except exc.NoResultFound:
            LOG.error(_('service chain %(id)s could not be found'),
                      {'id': chain_id})
            raise sc_exc.ServiceChainNotFound(id=chain_id)
        return servicechain
    
    #This function we will create the classifier or group next hop's information
    #information: {group_uuid1:{'group_id':xx, 'sf_port_list':[sf_port_id1:{sf_port_weight:xx, 
    #information: pair_sf_port_id1:xx, dl_dst:xx, fault_policy:xx},...]},group_uuid2:{...},...} 
    #information: the key is the first group, it's value is his next group
    #for classifier: the first_setp is True, we will create the first not empty group's information 
    #for classifier: we will append the same group to service_function_path(only the first group), because we 
    #for classifier: create the information from the second group, after this we will pop this group;  
    #update_instance: {instance_id: admin_state}, when instance change his admin_state, to _create_group_port_flow,
    #we check his admin_state, we find it does not equal to the current admin_state of the instance, so we store it;     
    def _create_group_port_flow(self, context, service_chain, service_function_path, first_setp = False, update_instance = {}): 
                
        sf_port_dict = {}
        if first_setp:
            service_function_path.append(service_function_path[0])
                  
        for group_uuid in service_function_path[1:]:  
            sf_port_dict[group_uuid]={}
            
            group_db = context.session.query(models_sc.ServiceFunctionGroup).filter_by(id=group_uuid).first()              
            db_groupbinding = context.session.query(models_sc.ServiceFunctionGroupBindInstance).\
                                            filter_by(group_id=group_uuid).all()             
            
            if service_chain.get('direction',None) == 'U2N':
                hash_policy = jsonutils.loads(group_db['method'])['uplink']
            elif service_chain.get('direction',None) == 'N2U':
                hash_policy = jsonutils.loads(group_db['method'])['uplink']

            sf_port_list = []                    
            for GroupBindInstance in db_groupbinding:               
                sf_port = {}                            
                instance_db = self._get_service_function_instance(context,GroupBindInstance['instance_id']) 
                
                state = 'active'   
                
                if instance_db['admin_state'] == 'inactive':
                    state = 'inactive'
                        
                if service_chain.get('direction',None) == 'U2N':      
                    sf_port_id = instance_db['context']['user_side_sf_port_id']
                    sf_port_uuid = instance_db['context']['user_side_port']
                    pair_sf_port_id = instance_db['context']['network_side_sf_port_id'] 
                    sf_port_uuid_pair =  instance_db['context']['network_side_port']
                elif service_chain.get('direction',None) == 'N2U':
                    sf_port_id = instance_db['context']['network_side_sf_port_id']
                    sf_port_uuid = instance_db['context']['network_side_port']
                    pair_sf_port_id = instance_db['context']['user_side_sf_port_id']   
                    sf_port_uuid_pair =  instance_db['context']['user_side_port']                 
                
                type = instance_db['context']['classification_type']    
                sf_port_weight = GroupBindInstance['weight']
                
                
                if instance_db['admin_state'] == 'error':                   
                    fault_policy = instance_db['fault_policy']
                else:
                    fault_policy = 'default' 
                
                udmac = None
                ndmac = None
                                    
                if instance_db.get('context',None).get('user_side_action',None):
                    user_side_action = jsonutils.loads(instance_db['context']['user_side_action'])
                    if user_side_action.get('dmac',None):
                        udmac = user_side_action.get('dmac',None)
      
                if instance_db.get('context',None).get('network_side_action',None):
                    network_side_action = jsonutils.loads(instance_db['context']['network_side_action'])       
                    if network_side_action.get('dmac',None):
                        ndmac = network_side_action.get('dmac',None)                 

                port_details = manager.NeutronManager.get_plugin().get_port(context, sf_port_uuid)               
                dl_dst = port_details['mac_address']  
                
                port_details_pair = manager.NeutronManager.get_plugin().get_port(context, sf_port_uuid_pair)               
                dl_dst_pair = port_details_pair['mac_address']     
                                          
                sf_port[sf_port_id] = {'sf_port_weight': sf_port_weight,
                                       'dl_dst': dl_dst,
                                       'pair_sf_port_id': pair_sf_port_id,
                                       'dl_dst_pair': dl_dst_pair,
                                       'fault_policy': fault_policy,                        
                                       'udmac': udmac,
                                       'ndmac': ndmac,
                                       'state': state       
                                       }
                sf_port_list.append(sf_port)
            sf_port_dict[group_uuid]['sf_port_list'] = sf_port_list
            sf_port_dict[group_uuid]['group_id'] = group_db['group_id']
            sf_port_dict[group_uuid]['hash_policy'] = hash_policy
            
        if first_setp:
            service_function_path.pop()            
            
        return sf_port_dict         

    def _delete_instance_flows(self, context, instance_to_delete_list = []):
        for instance in instance_to_delete_list:        
            instance_db = context.session.query(models_sc.ServiceFunctionInstance).filter_by(
                          id=instance).first()
            #this way can't deal with N2U chain?
            port_flows = context.session.query(models_sc.PortFlow).\
                   filter(expr.or_(models_sc.PortFlow.in_port_uuid==instance_db['context']['network_side_port'], \
                                   models_sc.PortFlow.in_port_uuid==instance_db['context']['user_side_port'])).all()
            LOG.debug("_delete_instance_flows,port_flows=%s" %(port_flows)) 
                                               
            port_flows_user=context.session.query(models_sc.PortFlow).\
                            filter_by(in_port_uuid=instance_db['context']['user_side_port']).all()
            port_flows_net=context.session.query(models_sc.PortFlow).\
                            filter_by(in_port_uuid=instance_db['context']['network_side_port']).all()
                                                                                                                                                                                                                                                             
            for port_flow in port_flows_user:  
                make_port_flow= self._make_portflow_dict(port_flow)
                LOG.debug("_delete_instance_flows,port_flows_user make_port_flow=%s" %(make_port_flow))
                self.notifier.delete_port_flows(context, make_port_flow)                  
                context.session.delete(port_flow)   
                
            for port_flow in port_flows_net:  
                make_port_flow= self._make_portflow_dict(port_flow)
                LOG.debug("_delete_instance_flows, port_flows_net make_port_flow=%s" %(make_port_flow))
                self.notifier.delete_port_flows(context, make_port_flow)                    
                context.session.delete(port_flow)                               
                              

    #the flows of classifier to group:
    #if the classifier's port has been Incorporated into the more than one chain,
    #we should delete all of the flows of chain, group and port flows
    def _delete_port_flows(self, context, port_to_delete_list = []):
        for port_uuid in port_to_delete_list:       
            port_flows_to_delete_db = context.session.query(models_sc.PortFlow).\
                    filter_by(in_port_uuid=port_uuid).all() 
            for port_flow_to_delete in port_flows_to_delete_db:
                make_port_flow= self._make_portflow_dict(port_flow_to_delete)
                self.notifier.delete_port_flows(context, make_port_flow)   
                context.session.delete(port_flow_to_delete)                   
        

    #classifiers->groups->END
    #if groups has no error or active's instance, the flows are classifier to END, the group_first is None
    #if groups has error or active's instance, the flows are classifiers->group_first 
    #every in_port_uuid just has one 'port_flow', the others should be deleted, so we will delete it then create it  
    #if destination_flag not equal to chain, we will not Issued the flows   
    def _create_classifier_flows(self, context, service_chain, classifiers, group_first, 
                                 instance_to_delete_list = [], update_instance = {}):      
        port_flows_back_list = []         
        sf_port_dict = None         
        if group_first:                
            sf_port_dict = self._create_group_port_flow(context, service_chain, group_first, True, update_instance) 
            
        if service_chain['direction'] == "U2N":
            chain_direction = 1
        elif service_chain['direction'] == "N2U":
            chain_direction = 0

        for classifier in classifiers:     
            classifier_db = context.session.query(models_sc.ServiceTrafficClassifier).filter_by(
                              id=classifier).first() 
            LOG.debug("_create_classifier_flows, classifier_db:%s" %classifier_db)                              
            for classifier_port_uuid in jsonutils.loads(classifier_db['list_ports']).keys():
                PortFlow_db = context.session.query(models_sc.PortFlow).\
                                               filter_by(in_port_uuid=classifier_port_uuid,
                                               service_chain_id=service_chain['id']).first()
                                                         
                history_portlist = {}
                old_port_list = {}
                history_portlist['old_port_list'] = old_port_list                                                                      

                if PortFlow_db: 
                    #the group_id is from 0 to 127
                    if PortFlow_db.get('group_id',None) or PortFlow_db.get('group_id',None) == 0:
                        history_portlist['group_id'] = PortFlow_db['group_id']
                    db_sf_port_list =  jsonutils.loads(PortFlow_db['sf_port_list'])
                    if db_sf_port_list:
                        for db_sf_port in db_sf_port_list:
                            old_port_list[int(db_sf_port.keys()[0])] = int(db_sf_port[db_sf_port.keys()[0]]['pair_sf_port_id'])
                    context.session.delete(PortFlow_db) 
                else:
                    history_portlist['group_id'] = -1
                
                if sf_port_dict:    
                    new_db_sf_port_list = sf_port_dict[group_first[0]]['sf_port_list']
                    if new_db_sf_port_list:
                        for new_db_sf_port in new_db_sf_port_list:
                            if old_port_list.has_key(new_db_sf_port.keys()[0]):
                                old_port_list.pop(int(new_db_sf_port.keys()[0])) 
                                
                LOG.debug("_create_classifier_flows, history_portlist:%s" %history_portlist)  
                    
                in_port_pair = {}
                in_port_pair ['pair_port_uuid'] = classifier_port_uuid
                in_port_pair ['pair_in_port'] = jsonutils.loads(classifier_db['list_ports'])[classifier_port_uuid]
                in_port_pair ['fault_policy'] = 'default'
                            
                port_details = manager.NeutronManager.get_plugin().get_port(context, classifier_port_uuid)         
                host_id = port_details['binding:host_id']
                outer_dl_src = port_details['mac_address'] 
              
                if group_first:                          
                    args = {
                            'chain_id': service_chain['chain_id'],
                            'host_id': host_id,
                            'in_port':  jsonutils.loads(classifier_db['list_ports'])[classifier_port_uuid],
                            'in_port_uuid': classifier_port_uuid,
                            'outer_dl_src':  outer_dl_src,
                            'group_id':  sf_port_dict[group_first[0]]['group_id'],                      
                            'sf_port_list':  jsonutils.dumps(sf_port_dict[group_first[0]]['sf_port_list']), 
                            'breakout_dl_src':  None,
                            'breakout_dl_dst': None,
                            'service_chain_id':service_chain['id'],
                            'status': service_chain['status'],
                            'hash_policy': sf_port_dict[group_first[0]]['hash_policy'],
                            'chain_direction': chain_direction,
                            'in_port_pair': jsonutils.dumps(in_port_pair),
                            'instance_state': None,
                            'history_portlist': jsonutils.dumps(history_portlist)                                  
                            }
                else:
                    destination_context = jsonutils.loads(service_chain['destination_context'])
                    if destination_context['destination_flag'] == 'chain':
                        breakout_dl_dst = destination_context['destination_mac']  
                    else:
                        breakout_dl_dst = "00:00:00:00:00:00"
                                                        
                    args = {
                            'chain_id': service_chain['chain_id'],
                            'host_id': host_id,
                            'in_port':  jsonutils.loads(classifier_db['list_ports'])[classifier_port_uuid],
                            'in_port_uuid': classifier_port_uuid,
                            'outer_dl_src': outer_dl_src,
                            'group_id':  None,                      
                            'sf_port_list':  [], 
                            'breakout_dl_src':  outer_dl_src,
                            'breakout_dl_dst': breakout_dl_dst,
                            'service_chain_id':service_chain['id'],
                            'status': service_chain['status'],
                            'hash_policy': None,
                            'chain_direction': chain_direction,
                            'in_port_pair': jsonutils.dumps(in_port_pair),
                            'instance_state': None,
                            'history_portlist': jsonutils.dumps(history_portlist)                                  
                            }                                                 
                port_flow = models_sc.PortFlow(**args)
                context.session.add(port_flow)
                
                port_flows_back_list.append(port_flow)
        
        LOG.debug("_create_classifier_flows, port_flows_back_list:%s" %port_flows_back_list) 
        return port_flows_back_list
    


    #service_function_path: it has groups who has error or active instances in group 
    #update_group if False or length(service_function_path)>1,for the last group we will Issued the flows from last group to END
    #the before group's sf_port_list is the after group's information, every instance in before group will Issued the flows 
    #if the instance admin_state is inactive, we will not Issued the flows                         
    def _create_function_path_flows(self, context, db_servicechain, service_function_path, update_group = False,
                                    instance_to_delete_list = [], update_instance = {}):             
        port_flows_back_list = []
                     
        sf_port_dict = self._create_group_port_flow(context, db_servicechain, service_function_path, False, update_instance) 
        LOG.debug("_create_function_path_flows, sf_port_dict:%s" %sf_port_dict)
        
        if db_servicechain['direction'] == "U2N":
            chain_direction = 1
        elif db_servicechain['direction'] == "N2U":
            chain_direction = 0  
            
        for instance in instance_to_delete_list:        
            instance_db = context.session.query(models_sc.ServiceFunctionInstance).filter_by(
                          id=instance).first() 
            port_flows_net = context.session.query(models_sc.PortFlow).\
                    filter_by(in_port_uuid=instance_db['context']['network_side_port'],
                              service_chain_id=db_servicechain['id']).first()  
            if port_flows_net:
                context.session.delete(port_flows_net)   
            port_flows_user = context.session.query(models_sc.PortFlow).\
                    filter_by(in_port_uuid=instance_db['context']['user_side_port'],
                              service_chain_id=db_servicechain['id']).first()
            if port_flows_user:
                context.session.delete(port_flows_user)                        
                    
        for i in range(len(service_function_path)):             
            group_uuid = service_function_path[i]

            db_groupbinding = context.session.query(models_sc.ServiceFunctionGroupBindInstance).\
                                            filter_by(group_id=group_uuid).all()                        
            
            if group_uuid != service_function_path[-1] or update_group == False or len(service_function_path) == 1:
                for GroupBindInstance in db_groupbinding:                                                  
                    instance_db = context.session.query(models_sc.ServiceFunctionInstance).filter_by(
                                                        id=GroupBindInstance['instance_id']).first() 
                    LOG.debug("_create_classifier_flows, instance_db=%s" %instance_db) 
                    PortFlow_db = None
                    port_flows_net = context.session.query(models_sc.PortFlow).\
                            filter_by(in_port_uuid=instance_db['context']['network_side_port'],
                                      service_chain_id=db_servicechain['id']).first()   
                    if port_flows_net:
                        PortFlow_db = port_flows_net
    
                    port_flows_user = context.session.query(models_sc.PortFlow).\
                            filter_by(in_port_uuid=instance_db['context']['user_side_port'],
                                      service_chain_id=db_servicechain['id']).first()                                     
                    if port_flows_user:
                        PortFlow_db = port_flows_user
                    
                    history_portlist = {} 
                    old_port_list = {}
                    history_portlist['group_id'] = -1
                    history_portlist['old_port_list'] = old_port_list   
    
                    if PortFlow_db: 
                        LOG.debug("_create_classifier_flows, PortFlow_db=%s,group_id:%s" %(PortFlow_db,PortFlow_db['group_id'])) 
                        if PortFlow_db.get('group_id',None) or PortFlow_db.get('group_id',None) == 0:
                            history_portlist['group_id'] = PortFlow_db['group_id']
                        db_sf_port_list =  jsonutils.loads(PortFlow_db['sf_port_list'])
                        if db_sf_port_list:
                            for db_sf_port in db_sf_port_list:
                                old_port_list[int(db_sf_port.keys()[0])] = int(db_sf_port[db_sf_port.keys()[0]]['pair_sf_port_id'])     
                                                            
                        context.session.delete(PortFlow_db)  
                           
    
                    state = 'active'
                    if instance_db['admin_state'] == 'inactive':
                        state = 'inactive'
    
                    if db_servicechain.get('direction',None) == 'U2N':  
                        in_port = instance_db['context']['network_side_sf_port_id']    
                        in_port_uuid = instance_db['context']['network_side_port']
                        pair_port_uuid = instance_db['context']['user_side_port']  
                        pair_in_port = instance_db['context']['user_side_sf_port_id']   
                    else:
                        in_port = instance_db['context']['user_side_sf_port_id']    
                        in_port_uuid = instance_db['context']['user_side_port']
                        pair_port_uuid = instance_db['context']['network_side_port']   
                        pair_in_port = instance_db['context']['network_side_sf_port_id']
    
                    if instance_db['admin_state'] == 'error':                   
                        fault_policy = instance_db['fault_policy']
                    else:
                        fault_policy = 'default'
    
                    udmac = None
                    ndmac = None             
                    
                    if instance_db.get('context',None).get('user_side_action',None):
                        user_side_action = jsonutils.loads(instance_db['context']['user_side_action'])
                        if user_side_action.get('dmac',None):
                            udmac = user_side_action.get('dmac',None)
                        
                    if instance_db.get('context',None).get('network_side_action',None):
                        network_side_action = jsonutils.loads(instance_db['context']['network_side_action'])      
                        if network_side_action.get('dmac',None):
                            ndmac = network_side_action.get('dmac',None)    
                            
                    port_details_pair = manager.NeutronManager.get_plugin().get_port(context, pair_port_uuid)                                                  
                        
                    in_port_pair = {}
                    in_port_pair['pair_port_uuid'] = pair_port_uuid
                    in_port_pair['pair_in_port'] = pair_in_port
                    in_port_pair['fault_policy'] = fault_policy
                    in_port_pair['pair_outer_dl_src'] = port_details_pair['mac_address']  
                    in_port_pair['udmac'] = udmac
                    in_port_pair['ndmac'] = ndmac   
    
                    port_details = manager.NeutronManager.get_plugin().get_port(context, in_port_uuid)         
                    host_id = port_details['binding:host_id']
                    outer_dl_src = port_details['mac_address']                                                               


                    if group_uuid != service_function_path[-1]:
                        if sf_port_dict:    
                            new_db_sf_port_list = sf_port_dict[service_function_path[i+1]]['sf_port_list']
                            if new_db_sf_port_list:
                                for new_db_sf_port in new_db_sf_port_list:
                                    if old_port_list.has_key(new_db_sf_port.keys()[0]):
                                        old_port_list.pop(int(new_db_sf_port.keys()[0]))     
                        LOG.debug("_create_function_path_flows, group_uuid:%s,service_function_path:%s" \
                                  %(history_portlist,service_function_path))
                        LOG.debug("_create_function_path_flows, history_portlist:%s" %history_portlist)  
        
                        args = {
                                'chain_id': db_servicechain['chain_id'],
                                'host_id': host_id,
                                'in_port':  in_port,
                                'in_port_uuid': in_port_uuid,
                                'outer_dl_src':  outer_dl_src,
                                'group_id':  sf_port_dict[service_function_path[i+1]]['group_id'],                      
                                'sf_port_list':  jsonutils.dumps(sf_port_dict[service_function_path[i+1]]['sf_port_list']), 
                                'breakout_dl_src':  None,
                                'breakout_dl_dst': None,
                                'service_chain_id':db_servicechain['id'],
                                'status': db_servicechain['status'],  
                                'hash_policy': sf_port_dict[service_function_path[i+1]]['hash_policy'],
                                'chain_direction': chain_direction,
                                'in_port_pair': jsonutils.dumps(in_port_pair),       
                                'instance_state': state,
                                'history_portlist': jsonutils.dumps(history_portlist)    
                                } 
                        port_flow = models_sc.PortFlow(**args)
                        context.session.add(port_flow) 
                        port_flows_back_list.append(port_flow)                      
                    else:
                        LOG.debug("_create_function_path_flows, group_uuid:%s,service_function_path:%s,update_group:%s" \
                                  %(history_portlist,service_function_path,update_group))                
                        if update_group == False or len(service_function_path) == 1:
                            breakout_dl_src = port_details['mac_address'] 
                            destination_context = jsonutils.loads(db_servicechain['destination_context'])
                            if destination_context['destination_flag'] == 'chain':
                                breakout_dl_dst = destination_context['destination_mac']  
                            else:
                                breakout_dl_dst = "00:00:00:00:00:00"
        
                            args = {
                                    'chain_id': db_servicechain['chain_id'],
                                    'host_id': host_id,
                                    'in_port':  in_port,
                                    'in_port_uuid': in_port_uuid,
                                    'outer_dl_src':  outer_dl_src,
                                    'group_id':  None,                      
                                    'sf_port_list':  [], 
                                    'breakout_dl_src':  breakout_dl_src,
                                    'breakout_dl_dst': breakout_dl_dst,
                                    'service_chain_id':db_servicechain['id'],
                                    'status': db_servicechain['status'],  
                                    'hash_policy': None,
                                    'chain_direction': chain_direction,
                                    'in_port_pair': jsonutils.dumps(in_port_pair),
                                    'instance_state': state,
                                    'history_portlist': jsonutils.dumps(history_portlist)
                                    }   
                               
                            port_flow = models_sc.PortFlow(**args)
                            context.session.add(port_flow) 
                            port_flows_back_list.append(port_flow)             
 
        return port_flows_back_list 
        

    def _delete_servicechain_record(self, context, chain_id):
        session = context.session
        try:
            servicechain = self._get_by_id(context, models_sc.ServiceChain, chain_id)
            session.delete(servicechain)
        except exc.NoResultFound:
            LOG.error(_('service chain %(id)s could not be found'),
                      {'id': chain_id})
            raise sc_exc.ServiceChainNotFound(id=chain_id)

    #in port_flows: if there are more than one items which in_port=flow['in_port'] and group_id=flow['group_id']
    #we think that one group has been insert into more than two chain,
    #on the service_chain_agent we should not delete the 'SF_GROUP' and 'SF_PORT' table until all of this chain 
    #been deleted 
    def _delete_portflows_one_chain(self, context, service_chain_id):
        port_flows = context.session.query(models_sc.PortFlow).filter_by(service_chain_id=service_chain_id).all()
        for flow in port_flows:
            group_inport_flows_count = int(context.session.query(models_sc.PortFlow).\
                    filter_by(in_port=flow['in_port'], group_id=flow['group_id']).count())
            himeself_count = int(context.session.query(models_sc.PortFlow).\
                    filter_by(in_port=flow['in_port']).count())            
            dict_flow = self._make_count_portflow_dict(flow, None, True, group_inport_flows_count, himeself_count)
            self.notifier.delete_port_flows(context, dict_flow)                     
        LOG.debug("_delete_portflows_one_chain, port_flows=:%s" %port_flows)

    #here we will select the group who has error or active instance 
    #when we update one group, the update_group_uuid is not None, even if the group is empty we will set the
    #group into function_path, because we will get his before or after group     
    def _check_functionpath(self, context, functionpath, update_group_uuid = None): 
        new_functionpath = []
        for group_uuid in functionpath:
            GroupBindInstance = context.session.query(models_sc.ServiceFunctionGroupBindInstance).\
                                filter_by(group_id=group_uuid).first()
            if GroupBindInstance:
                if GroupBindInstance.get('instance_id',None):
                    new_functionpath.append(group_uuid)             
            elif group_uuid == update_group_uuid and update_group_uuid:
                new_functionpath.append(update_group_uuid)  
        return new_functionpath
    
    
    def _make_portflow_dict(self, port_flow, fields=None,
                           process_extensions=True):

        if port_flow['sf_port_list']:
            sf_port_list = jsonutils.loads(port_flow['sf_port_list'])
        else:
            sf_port_list = []
            
        res = {
            'chain_id': port_flow['chain_id'],
            'host_id': port_flow['host_id'],
            'in_port': port_flow['in_port'],
            'in_port_uuid': port_flow['in_port_uuid'],
            'outer_dl_src': port_flow['outer_dl_src'],
            'group_id': port_flow['group_id'],                      
            'sf_port_list': sf_port_list,
            'hash_policy': port_flow['hash_policy'],
            'breakout_dl_src':  port_flow['breakout_dl_src'],
            'breakout_dl_dst': port_flow['breakout_dl_dst'],
            'service_chain_id': port_flow['service_chain_id'],
            'status': port_flow['status'],
            'chain_direction': port_flow['chain_direction'],
            'in_port_pair': jsonutils.loads(port_flow['in_port_pair']),
            'instance_state': port_flow['instance_state'],
            'history_portlist': jsonutils.loads(port_flow['history_portlist'])
            }            

        
        if process_extensions:
            self._apply_dict_extend_functions(
                'port_flow', res, port_flow)
        return self._fields(res, fields)

    #if the group in more than one chain, when we delete one chain we should not delete the group or sf_port flows
    def _make_count_portflow_dict(self, port_flow, fields=None,
                           process_extensions=True, group_inport_flows_count = 0, himeself_count = 0):
        if port_flow['sf_port_list']:
            sf_port_list = jsonutils.loads(port_flow['sf_port_list'])
        else:
            sf_port_list = []

        res = {
            'chain_id': port_flow['chain_id'],
            'host_id': port_flow['host_id'],
            'in_port': port_flow['in_port'],
            'in_port_uuid': port_flow['in_port_uuid'],
            'outer_dl_src': port_flow['outer_dl_src'],
            'group_id': port_flow['group_id'],                      
            'sf_port_list': sf_port_list,
            'hash_policy': port_flow['hash_policy'],
            'breakout_dl_src':  port_flow['breakout_dl_src'],
            'breakout_dl_dst': port_flow['breakout_dl_dst'],
            'service_chain_id': port_flow['service_chain_id'],
            'status': port_flow['status'],
            'chain_direction': port_flow['chain_direction'],           
            'group_count': group_inport_flows_count,
            'in_port_pair': jsonutils.loads(port_flow['in_port_pair']),
            'instance_state': port_flow['instance_state'],
            'himeself_count': himeself_count,
            'history_portlist': jsonutils.loads(port_flow['history_portlist'])
            }            
        
        if process_extensions:
            self._apply_dict_extend_functions(
                'port_flow', res, port_flow)
        return self._fields(res, fields)    
           

    def _get_port_flows(self, context, chain_id):
        port_flows_back = []
        with context.session.begin(subtransactions=True):
            query = context.session.query(models_sc.PortFlow)

            port_flows = query.filter_by(service_chain_id=chain_id).all()
            for flow in port_flows:
                port_flows_back.append(self._make_portflow_dict(flow))
            return port_flows_back 

        
    def _thread_add_port_flows(self,context,flows_list):
        for port_flow in flows_list:
            self.notifier.add_port_flows(context, port_flow)               


    def deal_with_update_classifier(self, context, db_classifier_list, update_classifier, db_servicechain):
        add_classifier = []
        delete_classifier = []
        
        for classifier_id in update_classifier:
            add_classifier.append(classifier_id)
        
        for classifier_id in db_classifier_list:
            if classifier_id in add_classifier:
                index_pop = add_classifier.index(classifier_id)
                add_classifier.pop(index_pop)
            else:  
                delete_classifier.append(classifier_id)

        LOG.debug("deal_with_update_classifier,add_classifier=%s,delete_classifier=%s" \
                                                    %(add_classifier,delete_classifier))
        LOG.debug("deal_with_update_classifier,chain_uuid=%s" %db_servicechain['id'])
                        
        for classifier_id in delete_classifier:
            db_classifier = self._get_by_id(context, models_sc.ServiceTrafficClassifier, classifier_id) 
            LOG.debug("deal_with_update_classifier,db_classifier=%s" %db_classifier)             
            list_ports = jsonutils.loads(db_classifier.get('list_ports',None))
            for port_id in list_ports.keys():                         
                port_flows_to_delete_db = context.session.query(models_sc.PortFlow).\
                        filter_by(in_port_uuid=port_id,service_chain_id=db_servicechain['id']).first()
                LOG.debug("deal_with_update_classifier,port_flows_to_delete_db=%s" %port_flows_to_delete_db)     
                if port_flows_to_delete_db:
                    make_port_flow= self._make_portflow_dict(port_flows_to_delete_db)
                    self.notifier.delete_port_flows(context, make_port_flow)   
                    context.session.delete(port_flows_to_delete_db)  
            db_classifier_to_delete = context.session.query(models_sc.ServiceTrafficClassifierBindChain).\
                                      filter_by(service_traffic_classifier_id=classifier_id).first()      
            context.session.delete(db_classifier_to_delete)                    
                

        if add_classifier:
            LOG.debug("deal_with_update_classifier,add_classifier=%s" %add_classifier)
            self._create_sc_bind_classifier(context, add_classifier, db_servicechain['id'])
                        
            service_function_paths = db_servicechain['service_function_path'] 
            service_function_path = []   
            for group_binding in service_function_paths:
                service_function_path.append(group_binding['service_function_group_id'])   
                                              
            functionpath = self._check_functionpath(context, service_function_path)
            if functionpath:
                group_first = []
                group_first.append(functionpath[0])
                port_flows_back_list = self._create_classifier_flows(context, db_servicechain, add_classifier, group_first)
            else:
                port_flows_back_list = self._create_classifier_flows(context, db_servicechain, add_classifier, None)  
                
            if port_flows_back_list:        
                port_flows_back = []
                for flow in port_flows_back_list:
                    port_flows_back.append(self._make_portflow_dict(flow))                  
                greenthread.spawn(self._thread_add_port_flows, context, port_flows_back)                                    
                       
                        

    #we choose the easiest way to realize the function
    #if we don't change traffic_classifier, service_function_path or destination_context we just update the 'chain_db'
    #otherwise, we will delete the ClassifierBindChain_db or ServiceFunctionPath, then create it  
    #we delete all the port_flows of one chain, then create it 
    def _update_create_service_chain(self, context, service_chain, db_servicechain):
        with context.session.begin(subtransactions=True):
                        
            if not service_chain.get('traffic_classifier', None) and \
                                    not service_chain.get('service_function_path', None)\
                                    and not service_chain.get('destination_context', None):
                LOG.debug("_update_create_service_chain,only_update_db=%s" %service_chain)                
                db_servicechain.update(service_chain)    
                return 
            
            if service_chain.get('traffic_classifier', None) and \
                                 not service_chain.get('service_function_path', None)\
                                 and not service_chain.get('destination_context', None):
                LOG.debug("_update_create_service_chain,only_update_classifier=%s" %service_chain['traffic_classifier']) 
                db_classifier_list = []
                for classifier in db_servicechain.get('traffic_classifier',None):         
                    db_classifier_list.append(classifier['service_traffic_classifier_id']) 
                update_classifier = service_chain.get('traffic_classifier', None)
                self.deal_with_update_classifier(context, db_classifier_list, \
                                                 update_classifier, db_servicechain)                  
                return


            self._delete_portflows_one_chain(context,db_servicechain['id'])
            
            one_chain_all_PortFlow_db = context.session.query(models_sc.PortFlow).\
                                filter_by(service_chain_id=db_servicechain['id']).all()
                                                                
            for chain_PortFlow_db in one_chain_all_PortFlow_db:
                LOG.debug("_update_create_service_chain,_delete_portflows_one_chain=%s" %chain_PortFlow_db)
                context.session.delete(chain_PortFlow_db)
                                
                                                                             
            if service_chain.get('traffic_classifier', None):
                LOG.debug("update_chain_traffic_classifier=%s" %service_chain['traffic_classifier'])
                result = context.session.query(models_sc.ServiceTrafficClassifierBindChain).\
                                    filter_by(service_chain_id=db_servicechain['id']).all()
                for chain_ServiceTrafficClassifierBindChain_db in result:
                    context.session.delete(chain_ServiceTrafficClassifierBindChain_db) 
                                    
                traffic_classifier = service_chain.get('traffic_classifier') 
                service_chain.pop('traffic_classifier')                                
                self._create_sc_bind_classifier(context, traffic_classifier, db_servicechain['id']) 
            else:
                LOG.debug("db_traffic_classifier=%s" %db_servicechain['traffic_classifier'])
                traffic_classifier_paths = db_servicechain['traffic_classifier'] 
                traffic_classifier = []   
                for classifier_binding in traffic_classifier_paths:
                    traffic_classifier.append(classifier_binding['service_traffic_classifier_id'])                           


            if service_chain.get('service_function_path', None):
                LOG.debug("update_chain_service_function_path=%s" %service_chain['service_function_path'])
                result = context.session.query(models_sc.ServiceFunctionPath).\
                                    filter_by(service_chain_id=db_servicechain['id']).all()
                for chain_ServiceFunctionPath_db in result:
                    context.session.delete(chain_ServiceFunctionPath_db)                      
                
                service_function_path = service_chain.get('service_function_path')     
                service_chain.pop('service_function_path')                   
                self._create_sc_bind_FunctionPath(context, service_function_path, db_servicechain['id'])
            else:         
                LOG.debug("db_service_function_path=%s" %db_servicechain['service_function_path'])      
                service_function_paths = db_servicechain['service_function_path'] 
                service_function_path = []   
                for group_binding in service_function_paths:
                    service_function_path.append(group_binding['service_function_group_id'])                                 


            if service_chain.get('destination_context', None):
                LOG.debug("update_chain_destination_context=%s" %service_chain['destination_context'])
                destination_context = service_chain['destination_context']
                if destination_context.get('destination_flag',None):
                    destination_flag = destination_context['destination_flag']
                else:
                    destination_flag = jsonutils.loads(db_servicechain['destination_context'])['destination_flag']

                db_update_destination={'destination_flag':destination_flag}   
                                    
                if destination_context.get('destination_mac',None):
                    destination_mac = destination_context['destination_mac']
                    
                    db_update_destination={'destination_flag':destination_flag,
                                           'destination_mac':destination_mac}                    
     
                db_servicechain.update({'destination_context': jsonutils.dumps(db_update_destination)})
                service_chain.pop('destination_context')    
                                                                                              

            functionpath = self._check_functionpath(context, service_function_path)
            if functionpath:
                group_first = []
                group_first.append(functionpath[0])
                self._create_classifier_flows(context, db_servicechain, traffic_classifier, group_first)
            else:
                self._create_classifier_flows(context, db_servicechain, traffic_classifier, None)            
            if functionpath:
                self._create_function_path_flows(context, db_servicechain, functionpath)
                        
            db_servicechain.update(service_chain)  
            
            time.sleep(2)
            port_flows_back_list = self._get_port_flows(context, db_servicechain['id'])                  
            greenthread.spawn(self._thread_add_port_flows, context, port_flows_back_list)             
            
                                      

    def create_service_function_group(self, context, service_function_group):
        group = service_function_group['service_function_group']
        LOG.debug("create_service_function_group:%s" %group)
        
        session = context.session
        with session.begin(subtransactions=True):
            self._validate_group_name(context, group.get('name', None))
            
            tenant_id = self._get_tenant_id_for_create(context, group)
            generate_group_id = uuidutils.generate_uuid()
            group_id = self._create_group_id(context, generate_group_id)
            
            args = {'id': generate_group_id,
                    'tenant_id': tenant_id,
                    'name': group['name'],                    
                    'description':group['description'],       
                    'type': group['type'],                                  
                    'method': jsonutils.dumps(group['method']),
                    'group_id': group_id['sf_port_id']}
            new_group = models_sc.ServiceFunctionGroup(**args)
            session.add(new_group)
            
            #the max instances in one group is 64
            if len(group['members']) > 64:
                raise sc_exc.TooManyGroupMembers(lenth=len(group['members']))               
            
            for instance in group['members']:                
                weight = instance.get('weight', None)
                db_instance = self._get_serviceinstance_by_id(context, instance.get('instance_id', None))
                self._validate_instance_inuse(db_instance, new_group['id'])
                self._validate_group_instance_type(db_instance['type'], group['type'])            
                binding = models_sc.ServiceFunctionGroupBindInstance(instance_id=instance['instance_id'],
                                                                     group_id=new_group['id'],
                                                                     weight=weight)
                session.add(binding)
            
        return self._make_serviceinstancegroup_dict(new_group, process_extensions=False)


    
    def update_service_function_group(self, context, service_function_group_id,
                                 service_function_group):      
        group = service_function_group['service_function_group']
        LOG.debug("update_service_function_group:%s" %group)
        session = context.session
        
        with session.begin(subtransactions=True):
            db_serviceinstancegroup = self._get_serviceinstancegroup_by_id(context, service_function_group_id)
            if group.get('name', None):
                self._validate_group_name(context, group['name'], db_serviceinstancegroup['name'])
            
            #instance_map:all of the group's members:{instance_id:{'weight':xx,'instance_id':xx,'admin_state':xx},..}
            #error_or_active_instance:the instance's admin_state is error or active in instance_map 
            #instances_to_add:new instances, the type just like instance_map and it should be active or error
            #instances_to_delete:the instance to become inactive or scale in the instance:[instance_id1,instance_id2]
            instance_map = {}   
            error_or_active_instance = {}
            instances_to_add = {}
            instances_to_delete = []
        
            #when we update the group, we find the group has instance and you want to change his type, it is wrong
            #if group['members'] is [] that's mean you will clear empty the group so you can update the type
            if group.get('members', None) != []:    
                if db_serviceinstancegroup.get('members', None) != []:
                    if group.get('type', None):
                        raise sc_exc.GroupCanNotUpdateType(id = service_function_group_id)  

            #when the group Incorporated into the chain we should not update the method
            if db_serviceinstancegroup['service_chain_id']: 
                if group.get('method', None):
                    raise sc_exc.GroupCanNotUpdateMethod(id = service_function_group_id)
                
            if group.get('method', None):      
                method = group.get('method', None)  
                db_serviceinstancegroup.update({"method":jsonutils.dumps(method)})
                group.pop("method")              

            #if: if you add instances to members
            #elif: if you set the members [], we will remove all the instances
            #else: we will just update the db of group                     
            if group.get('members', None):
                if len(group['members']) > 64:
                    raise sc_exc.TooManyGroupMembers(lenth=len(group['members']))                    
                
                for instance in group['members']:  
                    db_instance = self._get_serviceinstance_by_id(context, instance['instance_id'])
                                      
                    weight = instance.get('weight', None)
                    inst_dict = {'weight': weight, 
                                 'instance_id': instance['instance_id']}
                    instance_map[instance['instance_id']] = inst_dict
                    
                    self._validate_instance_inuse(db_instance, db_serviceinstancegroup['id'])
                    self._validate_group_instance_type(db_instance['type'], db_serviceinstancegroup['type'])    
                
                group.pop("members")

                db_groupbinding = session.query(models_sc.ServiceFunctionGroupBindInstance).\
                                                filter_by(group_id=service_function_group_id).all()                

                for db_bind in db_groupbinding:
                    if db_bind['instance_id'] in instance_map.keys():
                        LOG.debug("update instance %s in group:%s" %(db_bind['instance_id'], db_serviceinstancegroup['id']))

                        error_or_active_instance[db_bind['instance_id']] = instance_map[db_bind['instance_id']]
                           
                        db_bind.update(instance_map[db_bind['instance_id']]) 
                        instance_map.pop(db_bind['instance_id'])
                        
                    else:
                        LOG.debug("delete instance in group:%s" %db_bind['instance_id'])
                        instances_to_delete.append(db_bind['instance_id'])
                        session.delete(db_bind)

                instances_to_add = instance_map
                for add_inst_id_key in instance_map.keys():
                    binding = models_sc.ServiceFunctionGroupBindInstance(
                                                        instance_id = instance_map[add_inst_id_key]['instance_id'],
                                                        group_id = service_function_group_id,
                                                        weight = instance_map[add_inst_id_key]['weight'])
                    session.add(binding)
                    error_or_active_instance[add_inst_id_key] = instance_map[add_inst_id_key]
                                            
            elif group.get('members', None) == []: 
                for db_group_instance in db_serviceinstancegroup.get('members', None):
                    instances_to_delete.append(db_group_instance['instance_id'])
                for db_bind in db_serviceinstancegroup['members']:
                    session.delete(db_bind)

            #if the group has already belong to the chains, we will change himself or his before or after group           
            if db_serviceinstancegroup['service_chain_id']:                    
                self._treat_update_group_action(context, db_serviceinstancegroup, \
                                                instances_to_add, error_or_active_instance, instances_to_delete)

            db_serviceinstancegroup.update(group)
            db_serviceinstancegroup = self._get_serviceinstancegroup_by_id(context, service_function_group_id)
            
            return self._make_serviceinstancegroup_dict(db_serviceinstancegroup, process_extensions=False)

    
    def delete_service_function_group(self, context, service_function_group_id):     
        session = context.session
        with session.begin(subtransactions=True):
            db_serviceinstancegroup = self._get_serviceinstancegroup_by_id(context, service_function_group_id)
            
            self._validate_group_inuse(context, db_serviceinstancegroup)        

            sc_pool._recycle_sf_or_port(context, None, service_function_group_id, schain.GROUP)            
            session.delete(db_serviceinstancegroup)

    
    def get_service_function_group(self, context, service_function_group_id,
                              fields=None):    
        group = self._get_serviceinstancegroup_by_id(context, service_function_group_id)
        return self._make_serviceinstancegroup_dict(group, fields)

    
    def get_service_function_groups(self, context, filters=None, fields=None,
                               sorts=None, limit=None, marker=None,
                               page_reverse=False):       
        marker_obj = self._get_marker_obj(context, 'service_function_group', limit, marker)
        return self._get_collection(context, models_sc.ServiceFunctionGroup,
                                    self._make_serviceinstancegroup_dict,
                                    filters=filters, fields=fields,
                                    sorts=sorts,
                                    limit=limit,
                                    marker_obj=marker_obj,
                                    page_reverse=page_reverse)  

    
                
    def create_service_chain(self, context, service_chain):
        sc = service_chain['service_chain']
        LOG.debug("create_service_chain:%s" %sc)
        
        self._validate_chain_name(context, sc.get('name',None))
        self._validate_traffic_classifier(context, sc.get('traffic_classifier',None))  
        self._validate_service_function_path(context, sc.get('service_function_path',None))
        if not sc['destination_context'].get('destination_flag', None):
            raise sc_exc.Destination_Flag_Error(destination_context=sc.get('destination_context',None)) 
        if sc.get('destination_context',None): 
            self._validate_destination_mac(context, sc.get('destination_context'))            
            

        with context.session.begin(subtransactions=True):
            
            tenant_id = self._get_tenant_id_for_create(context, sc)
            generate_chain_id = uuidutils.generate_uuid()
            chain_id = self._create_chain_id(context, generate_chain_id)

            sc_arg = {'id': generate_chain_id,                  
                    'name': sc['name'], 
                    'direction': sc['direction'],
                    'chain_id': chain_id['sf_port_id'], 
                    'description': sc['description'],
                    'tenant_id':tenant_id,
                    'catenated_chain': sc['catenated_chain'], 
                    'destination_context': jsonutils.dumps(sc['destination_context']),
                    'status': sc_const.STATUS_BUILDING}           
            new_sc = models_sc.ServiceChain(**sc_arg)
            context.session.add(new_sc)
            
            self._create_sc_bind_classifier(context, sc.get('traffic_classifier'), new_sc['id'])
            self._create_sc_bind_FunctionPath(context, sc.get('service_function_path'), new_sc['id'])
            
             
            functionpath = self._check_functionpath(context, sc.get('service_function_path'))
            if functionpath:
                group_first = []
                group_first.append(functionpath[0])
                self._create_classifier_flows(context, new_sc, sc.get('traffic_classifier'), group_first)
            else:
                self._create_classifier_flows(context, new_sc, sc.get('traffic_classifier'), None)            
            if functionpath:
                self._create_function_path_flows(context, new_sc, functionpath)
        
        port_flows_back_list = self._get_port_flows(context, generate_chain_id)                  
        greenthread.spawn(self._thread_add_port_flows, context, port_flows_back_list)  
                    
        return self._make_servicechain_dict(self._get_servicechain_by_id(context, new_sc['id']))

    
    def update_service_chain(self, context, service_chain_id,
                                 service_chain):    
        new_sc = service_chain['service_chain']
        db_servicechain = self._get_servicechain_by_id(context, service_chain_id)  

        LOG.debug("update_service_chain, new_sc:%s" %new_sc)
        LOG.debug("update_service_chain, old_sc:%s" %db_servicechain)            
        
         
        if new_sc.get('name',None):
            self._validate_chain_name(context, new_sc.get('name'), db_servicechain['name'])
        if new_sc.get('traffic_classifier',None):    
            self._validate_traffic_classifier(context, new_sc.get('traffic_classifier')) 
        if new_sc.get('service_function_path',None):     
            self._validate_service_function_path(context, new_sc.get('service_function_path'))
        if new_sc.has_key('destination_context') and not new_sc.get('destination_context',None):   
            raise sc_exc.Destination_Flag_Error(destination_context=new_sc.get('destination_context',None)) 
        if new_sc.get('destination_context'): 
            if new_sc.get('destination_context').get('destination_mac'):
                self._validate_destination_mac(context, new_sc.get('destination_context'), db_servicechain)                   

        with context.session.begin(subtransactions=True):   
            new_sc['status'] = sc_const.STATUS_BUILDING
            service_chain_db = self._get_servicechain_by_id(context, service_chain_id)
            self._update_create_service_chain(context, new_sc, service_chain_db)
             
            db_servicechain = self._get_servicechain_by_id(context, service_chain_id)          
                                        
        return self._make_servicechain_dict(db_servicechain, process_extensions=False)


    def delete_service_chain(self, context, service_chain_id):
        session = context.session
        with session.begin(subtransactions=True):
            service_chain = self._get_servicechain_by_id(context, service_chain_id)                            
            self._delete_portflows_one_chain(context, service_chain_id)    

            groups_info ={}
            for group_chain_bingd_db in service_chain['service_function_path']:
                group_db = context.session.query(models_sc.ServiceFunctionGroup).filter_by(id=\
                               group_chain_bingd_db['service_function_group_id']).first()  
                groups_info[group_db['id']] = group_db['group_id']                 
             
            sc_pool._recycle_sf_or_port(context, None, service_chain_id, schain.CHAIN)
            
            session.delete(service_chain)  
    
    def get_service_chain(self, context, service_chain_id,
                              fields=None):      
        chain = self._get_servicechain_by_id(context, service_chain_id)
        return self._make_servicechain_dict(chain, fields) 

    
    def get_service_chains(self, context, filters=None, fields=None,
                               sorts=None, limit=None, marker=None,
                               page_reverse=False):       
        marker_obj = self._get_marker_obj(context, 'service_chain', limit, marker)
        return self._get_collection(context, models_sc.ServiceChain,
                                    self._make_servicechain_dict,
                                    filters=filters, fields=fields,
                                    sorts=sorts,
                                    limit=limit,
                                    marker_obj=marker_obj,
                                    page_reverse=page_reverse)

    
    #every 10s the server will call _upate_chain_status_task to check port_flows' status
    #For one Chain, if all of the port_flows of one chain are active then the chain should be set active
    #otherwise, exceed one port_flow of a chain is not active, the chain should be set error  
    #we should choose all of the inactive port_flows, so we could make sure which chains are inactive or set inactive    
    def _upate_chain_status_task(self, **kwargs):
        try:
            session = qdbapi.get_session()
            active_status = {'status':sc_const.STATUS_ACTIVE}
 
            if session.query(models_sc.PortFlow).all() == []:
                return                          
                 
            with session.begin(subtransactions=True):
                db_not_active_servicechains = session.query(models_sc.ServiceChain).\
                                        filter(expr.not_(models_sc.ServiceChain.status==sc_const.STATUS_ACTIVE)).all()
                for servicechain in db_not_active_servicechains:
                    not_active_portflow = session.query(models_sc.PortFlow).\
                                        filter(expr.and_(models_sc.PortFlow.service_chain_id==servicechain.id,
                                               expr.or_(models_sc.PortFlow.status==sc_const.STATUS_BUILDING, 
                                               models_sc.PortFlow.status==sc_const.STATUS_ERROR))).all()
                    if not len(not_active_portflow):
                        servicechain.update(active_status)           
            
            with session.begin(subtransactions=True):
                error_chains_list = []
                db_error_portflows = session.query(models_sc.PortFlow).filter_by(status=sc_const.STATUS_ERROR).all()
                if db_error_portflows:
                    LOG.debug(_("_upate_chain_status_task db_error_portflows= %s"), db_error_portflows)           
                    for error_portflow in db_error_portflows:
                        if error_portflow['service_chain_id'] not in error_chains_list:
                            error_chains_list.append(error_portflow['service_chain_id'])
                        
                    error_chains_list_new_set = set(error_chains_list)
                                        
                    if not error_chains_list_new_set:
                        return
                    else:
                        err_status = {'status':sc_const.STATUS_ERROR}
                        for chain_id in error_chains_list_new_set:
                            db_sc = session.query(models_sc.ServiceChain).filter_by(id=chain_id).first()
                            db_sc.update(err_status)                     
                                                     
        except Exception as e:
            LOG.error(_("_upate_chain_status_task failed, except by %s"), e)     
            

def _make_portflow_dict(port_flow):
        
    if port_flow['sf_port_list']:
        sf_port_list = jsonutils.loads(port_flow['sf_port_list'])
    else:
        sf_port_list = []
        
    res = {
        'chain_id': port_flow['chain_id'],
        'host_id': port_flow['host_id'],
        'in_port': port_flow['in_port'],
        'in_port_uuid': port_flow['in_port_uuid'],
        'outer_dl_src': port_flow['outer_dl_src'],
        'group_id': port_flow['group_id'],                      
        'sf_port_list': sf_port_list,
        'hash_policy': port_flow['hash_policy'],
        'breakout_dl_src':  port_flow['breakout_dl_src'],
        'breakout_dl_dst': port_flow['breakout_dl_dst'],
        'service_chain_id': port_flow['service_chain_id'],
        'status': port_flow['status'],
        'chain_direction': port_flow['chain_direction'],
        'in_port_pair': jsonutils.loads(port_flow['in_port_pair']),
        'instance_state': port_flow['instance_state'],
        'history_portlist': jsonutils.loads(port_flow['history_portlist'])
        }  
    return res

            
    
#we will according to the host, chain_id, ports_id_status from servicechain_agent to set the port_flows status   
#ports_id_status is just like: {port_id1:status, port_id2:status,...}              
def update_portflows_status(context, host, chain_id, ports_id_status):
    try: 
        LOG.debug(_("update_portflows_status, host=%s, chain_id=%s, ports_id_status=%s") \
                  %(host, chain_id, ports_id_status))
        with context.session.begin(subtransactions=True):

            for port_info in ports_id_status:
                port_flow = context.session.query(models_sc.PortFlow).filter_by(host_id=host, \
                                  chain_id=port_info[1], in_port_uuid=port_info[0]).first()
                port_flow_status = {'status':port_info[2]}
                port_flow.update(port_flow_status)                    
        
    except Exception as e:
        LOG.error(_("update_portflows_status failed, except by %s"), e)   


#we will according to the host, port_id from servicechain_agent to get port_flow to return back 
def get_portflows_by_host_portid(context, host, port_id):
    try:
        LOG.debug(_("get_portflows_by_host, host=%s, port_id=%s") %(host, port_id))
        port_all_chains_flows_list = [] 
        port_all_chains_flows = context.session.query(models_sc.PortFlow).filter_by(host_id=host, in_port_uuid=port_id).all()
        if port_all_chains_flows:
            for port_one_chain_flow in port_all_chains_flows:
    
                LOG.debug(_("get_portflows_by_host, port_one_chain_flow=%s") %port_one_chain_flow)
                port_all_chains_flows_list.append(_make_portflow_dict(port_one_chain_flow)) 
            return port_all_chains_flows_list
        else:
            return None 
    except Exception as e:
      
        LOG.error(_("get_portflows_by_host failed, except by %s"), e)         
        
def get_instance_classifier_by_host_portid(context, host, port_id):
    try:
        
        LOG.debug(_("get_instance_classifier_by_host_portid, host=%s, port_id=%s") %(host, port_id)) 

        instance_port_info = False 
        classifier_back_info = None 
        back_info = {}  
        instance_port_info = context.session.query(models_sc.ServiceFuntionInstanceContext).\
               filter(expr.or_(models_sc.ServiceFuntionInstanceContext.user_side_port==port_id, \
                               models_sc.ServiceFuntionInstanceContext.network_side_port==port_id)).first()

        if instance_port_info:
            back_info['instance'] = instance_port_info
            return back_info                               

        classifiers_port_info = context.session.query(models_sc.ServiceTrafficClassifier).all()
        for ports_info in classifiers_port_info:
            for port in jsonutils.loads(ports_info['ports']):
                if port_id == port:
                    classifier_back_info = ports_info
                    break

        if classifier_back_info:
            back_info['classifiers'] = classifier_back_info
            return back_info 

        return False 
    except Exception as e:
        LOG.error(_("get_portflows_by_host failed, except by %s"), e)         
              

