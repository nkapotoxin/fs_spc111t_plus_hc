
import abc
import netaddr
import re

from oslo.config import cfg

from neutron.api import extensions
from neutron.api.v2 import attributes as attr
from neutron.api.v2 import base
from neutron import manager
from neutron.plugins.common import constants
from neutron import quota
from neutron.openstack.common import log as logging
from neutron.common import exceptions as nexc
from neutron.openstack.common import uuidutils


LOG = logging.getLogger(__name__)

SERVICE_TRAFFIC_CLASSIFIERS = 'service_traffic_classifiers'
SERVICE_FUNCTION_INSTANCES = 'service_function_instances'
SERVICE_FUNCTION_GROUPS = 'service_function_groups'
SERVICE_CHAINS = 'service_chains'

CLASSIFIER = 'service_traffic_classifier'
INSTANCE = 'service_function_instance'
GROUP = 'service_function_group'
CHAIN = 'service_chain'


class ServiceFunctionInstanceNameExist(nexc.InUse):
    message = _("Service Function Instance named %(name)s has exist,you should use other name")

class ServiceInstancePortChange(nexc.BadRequest):
    message = _("Service Function Instance context user or network side port cannot be update")

class ScPortTypeInvalidate(nexc.InUse):
    message = _("Service Traffic Classifier or Instance use port %(port_id)s is not a vhostuser port")

class ScPortNotVm(nexc.NotFound):
    message = _("Service Traffic Classifier or Instance use port %(port_id)s is not belong to a vm")

class ServiceFunctionInstanceInuse(nexc.InUse):
    message = _("Service Function Instance %(id)s is added to group %(group)s")

class ServiceFunctionInstanceInGroup(nexc.InUse):
    message = _("Service Function Instance %(id)s is added to group %(group)s so cannot change type")

class ServiceTrafficClassifierNameExist(nexc.InUse):
    message = _("Service Traffic Classifier %(name)s has exist")

class ServiceClassifierTypeNotSupport(nexc.InUse):
    message = _("Service Traffic Classifier type %(type)s is not support now")

class ServiceClassifierTypeError(nexc.InUse):
    message = _("Service Traffic Classifier type %(type)s is error")

class ServiceClassifierTypeIsNull(nexc.InUse):
    message = _("Classification type is required")

class ServiceFunctionPortIsNull(nexc.PortNotFound):
    message = _("Service Function Instance user/network side port is required")

class ServiceInstanceIsError(nexc.InUse):
    message = _("Service Function Instance  %(name)s state is error and context/type/"
                "state/fault_policy can not be updated")

class PortInUse(nexc.InUse):
    message = _("port %(port)s is used by other Instance or Classifier %(id)s")

class ScAgentNotFount(nexc.NotFound):
    message =_("There is no service_chain_agent in host %(id)s, we can not create classifier or instance")
    
class DeviceInUse(nexc.InUse):
    message = _("The device %(device)s is used by other instance")

class ScPortNotFound(nexc.NotFound):
    message =_("The port %(id)s is not found or not belong to a vm")

class DevicePortNotFound(nexc.NotFound):
    message =_("The port %(port_id)s does not belong to the device %(device)s or "
               "the device %(device)s is not exist")

class ServiceInstanceInUse(nexc.InUse):
    message = _("Service Function Instance %(id)s is in use")

class ServiceClassifierInUse(nexc.InUse):
    message = _("Service Traffic classifier %(id)s is in use")
    
class GroupNameInUse(nexc.InUse):
    message = _("name %(name)s is used by other Group")
    
class ServiceInstanceNotFound(nexc.NotFound):
    message = _("Service Instance %(id)s could not be found")

class ServiceGroupInUse(nexc.InUse):
    message = _("Service Group %(id)s is in use")
    
class GroupInstanceTypeNotEqual(nexc.InUse):
    message = _("Instancetype of %(instance_type)s is not equal to the grouptype %(group_type)s") 
    
class ServiceInstanceGroupNotFound(nexc.NotFound):
    message = _("service_function_group %(id)s could not be found") 

class ShouldNotUpdateGroupOneInstance(nexc.InUse):
    message = _("you should not make the group %(id)s with all instance inactives")
    
class ChainNameInUse(nexc.InUse):
    message = _("name %(name)s is used by other chain")
    
class Classifier_If_Exit(nexc.NotFound):
    message = _("classifier %(classifier_id)s does not exist")

class Group_in_Chain_If_Exit(nexc.NotFound):
    message = _("group %(group_uuid)s does not exist")

class Group_in_Chain_Max_Length(nexc.InUse):
    message = _("the max groups in one chain is 8, but you input %(length)s groups")

class Destination_Flag_Error(nexc.InUse):
    message = _("destination_context %(destination_context)s can not be "
                "None and flag must in ['packet','chain','default']")

class Destination_mac_not_Exit(nexc.NotFound):
    message = _("destination_mac %(destination_mac)s does not exit or you flag is not chain")
    
class ServiceChainNotFound(nexc.NotFound):
    message = _("Service Chain %(id)s could not be found")

class ServiceTrafficClassifierNotFound(nexc.NotFound):
    message = _("ServiceTrafficClassifier %(id)s could not be found")

class ServiceFunctionInstanceNotFound(nexc.NotFound):
    message = _("ServiceFunctionInstance %(id)s could not be found")

class ServiceFunctionGroupNotFound(nexc.NotFound):
    message = _("ServiceFunctionGroup %(func_group_id)s could not be found")


class ServiceTypeNotFound(nexc.NotFound):
    message = _("ServiceType %(service_type_id) could not be found")


class ServiceTypeNotSupported(nexc.BadRequest):
    message = _("ServiceType %(service_type_id) not supported")

class GroupCanNotUpdateType(nexc.BadRequest):
    message = _("Group %(id)s Has members, should not to update Type")
    
class GroupCanNotUpdateMethod(nexc.BadRequest):
    message = _("Group %(id)s Incorporated into the chain, should not to update method")
        
    
class TooManyGroupMembers(nexc.BadRequest):
    message = _("You intput %(lenth)s, The Max members is 64 in One Group")    
    
    
class OneGroupAllInstanceAreInactive(nexc.InUse):
    message = _("You should not create a group with all inacitve instances or \
                add one group with all inactive instances to chain")      
    
def _validate_instance_ctx(instance_ctx, valid_values=None):
    expected_keys = ['user_side_port', 'network_side_port',
                      'classification_type','user_side_action',
                     'network_side_action' ]

    action_choose=["vlan", "dmac"]

    type_choose = ['dl_src','5tuple']

    for port_key in instance_ctx:
        if port_key not in expected_keys:
            msg = (_("'%(data)s' is not in %(valid_values)s") %
                   {'data': port_key, 'valid_values': expected_keys})
            LOG.debug(msg)
            return msg

    for port_key in ['user_side_port', 'network_side_port']:
        if instance_ctx.has_key(port_key) and \
                not uuidutils.is_uuid_like(instance_ctx[port_key]):
            msg = _("'%s' is not a valid UUID") % port_key
            LOG.debug(msg)
            return msg
    for port_key in ['user_side_action', 'network_side_action']:
        if instance_ctx.has_key(port_key) :
            if not isinstance(instance_ctx[port_key], dict):
                msg = _("'%s' is not a  dictionary") % (instance_ctx[port_key])
                LOG.debug(msg)
                return msg
            else :
                for key in instance_ctx[port_key]:
                    if key not in action_choose:
                        msg = (_("'%(data)s' is not in %(valid_values)s") %
                                {'data': key, 'valid_values': action_choose})
                        LOG.debug(msg)
                        return msg
                    elif key == 'dmac':
                        msg = attr._validate_mac_address(instance_ctx[port_key][key])
                        if msg:
                            msg = _("'%s' is not a valid MAC address") % instance_ctx[port_key][key]
                            LOG.debug(msg)
                            return msg
                    elif key == 'vlan':
                        try:
                            if  int(instance_ctx[port_key][key]) < 0 or int(instance_ctx[port_key][key]) > 4095:
                                msg = (_("vlan tag '%(data)s' is not a valid num in %(valid_values)s") %
                                        {'data': instance_ctx[port_key][key], 'valid_values': '[0-4095]'})
                                LOG.debug(msg)
                                return msg
                        except:
                                msg = (_("vlan tag should be number") )
                                LOG.debug(msg)
                                return msg
    for port_key in ['classification_type']:
        if instance_ctx.has_key(port_key) and instance_ctx[port_key] not in type_choose:
            msg = (_("classification type '%(data)s' is not a valid type ,it should in %(valid_values)s") %
                                {'data': instance_ctx[port_key], 'valid_values': type_choose})
            LOG.debug(msg)
            return msg


def _validate_uuid_list_sc(data, valid_values=None):
    if not isinstance(data, list):
        msg = _("'%s' is not a list") % data
        LOG.debug(msg)
        return msg
        
    if not data:
        msg = _("'%s' can not be empty") % data
        LOG.debug(msg)
        return msg

    ins_set = set()
    for ins_uuid in data:       
        if ins_uuid in ins_set:
            msg = _("'%s' has duplicate key ins_uuid") % ins_uuid
            return msg
       
        ins_set.add(ins_uuid)
    
    
def _validate_instance_members(data, valid_values=None):
    if not isinstance(data, list):
        msg = _("'%s' is not a list") % data
        LOG.debug(msg)
        return msg
    
    instance_set = set()
    expected_keys = ['instance_id', 'weight']
    
    for instance in data:  
        for port_key in instance:
            if port_key not in expected_keys:
                msg = (_("'%(data)s' is not in %(valid_values)s") %
                       {'data': port_key, 'valid_values': expected_keys})
                LOG.debug(msg)
                return msg        
        
        if not isinstance(instance, dict):
            msg = _("'%s' is not a dict") % instance
            LOG.debug(msg)
            return msg
        
        if not instance.has_key('instance_id'):
            msg = _("'%s' must has key instance_id") % instance
            LOG.debug(msg)
            return msg
        else:
            if not uuidutils.is_uuid_like(instance['instance_id']):
                msg = _("'%s' is not a valid UUID") % instance['instance_id']
                LOG.debug(msg)
                return msg            

        if not instance.has_key('weight'):
            msg = _("you must input weight and his value")
            LOG.debug(msg)
            return msg             
        else:
            msg = attr._validate_non_negative(instance['weight'])
            if msg:
                msg = _("the value of weight must be int")
                LOG.debug(msg)
                return msg

            weight = int(instance['weight'])
            if weight <= 0:
                msg = _("the value of weight must be int and big than 0")
                LOG.debug(msg)
                return msg                            
              
                   
        if instance['instance_id'] in instance_set:
            msg = _("'%s' has duplicate key instance_id") % instance
            return msg
        
        instance_set.add(instance['instance_id'])
        
def _validate_destination(instance_ctx, valid_values=None):
    expected_keys = ['destination_flag', 'destination_mac']

    if not isinstance(instance_ctx, dict):
        msg = _("'%s' is not a dict") % instance_ctx
        LOG.debug(msg)
        return msg

    for port_key in instance_ctx:
        if port_key not in expected_keys:
            msg = (_("'%(data)s' is not in %(valid_values)s") %
                   {'data': port_key, 'valid_values': expected_keys})
            LOG.debug(msg)
            return msg
        
    if instance_ctx.has_key('destination_flag'):
        msg = attr._validate_values(instance_ctx['destination_flag'], ['packet', 'chain', 'default'])
        if msg:
            msg = _("'%s' must be 'packet', 'chain' or 'default'") % instance_ctx['destination_flag']
            LOG.debug(msg)
            return msg    
        
        if instance_ctx['destination_flag'] == 'chain':
            if not instance_ctx.has_key('destination_mac'):
                msg = _("'%s' must has key destination_mac") % instance_ctx
                LOG.debug(msg)
                return msg 
        else:
            if instance_ctx.has_key('destination_mac'):
                msg = _("'%s', if destination_flag != chain, you should not input destination_mac") % instance_ctx
                LOG.debug(msg)
                return msg            
                           
                
    
    if instance_ctx.has_key('destination_mac'):
        msg = attr._validate_mac_address(instance_ctx['destination_mac'])
        if msg:
            msg = _("'%s' is not a valid MAC address") % instance_ctx['destination_mac']
            LOG.debug(msg)
            return msg         
                  



def _validate_method_dict(data, valid_values=None):
    if not isinstance(data, dict):
        msg = _("'%s' is not a dict") % data
        LOG.debug(msg)
        return msg
        
    if not data.has_key('uplink'):
        msg = _("'%s' must has key uplink") % data
        LOG.debug(msg)
        return msg    
    
    if not data.has_key('downlink'):
        msg = _("'%s' must has key downlink") % data
        LOG.debug(msg)
        return msg 

    msg = attr._validate_string(data['uplink'])
    if msg:
        msg = _("'uplink' should be string")
        LOG.debug(msg)
        return msg    
    
    msg = attr._validate_string(data['downlink'])
    if msg:
        msg = _("'downlink' should be string")
        LOG.debug(msg)
        return msg

    if data['uplink'] == 'LBM_SIP':
        if data['downlink'] != 'LBM_DIP':
            msg = _("when uplink=LBM_SIP, downlink must be LBM_DIP")
            LOG.debug(msg)
            return msg    

    if data['downlink'] == 'LBM_SIP':
        if data['uplink'] != 'LBM_DIP':
            msg = _("when downlink=LBM_SIP, uplink must be LBM_DIP")
            LOG.debug(msg)
            return msg   

    if data['downlink'] == 'LBM_DIP':
        if data['uplink'] != 'LBM_SIP':
            msg = _("when downlink=LBM_DIP, uplink must be LBM_SIP")
            LOG.debug(msg)
            return msg    

    if data['uplink'] == 'LBM_DIP':
        if data['downlink'] != 'LBM_SIP':
            msg = _("when uplink=LBM_DIP, downlink must be LBM_SIP")
            LOG.debug(msg)
            return msg        

    if data['downlink'] == 'LBM_5TUPLE':
        if data['uplink'] != 'LBM_5TUPLE':
            msg = _("when downlink=LBM_5TUPLE, uplink must be LBM_5TUPLE")
            LOG.debug(msg)
            return msg 

def _validate_type(data, valid_values=None):
    msg = attr._validate_string(data)
    if msg:
        msg = _("type should be string")
        LOG.debug(msg)
        return msg   
    
    if data.strip() == '':
        msg = _("type can not be empty")
        LOG.debug(msg)
        return msg           
                                     
        

attr.validators['type:instance_ctx'] = (
    _validate_instance_ctx)
attr.validators['type:inst_members'] = (
    _validate_instance_members)
attr.validators['type:uuid_list_sc'] = (
    _validate_uuid_list_sc)
attr.validators['type:destination'] = (
    _validate_destination)
attr.validators['type:method_dict'] = (
    _validate_method_dict)
attr.validators['type:type_check'] = (
    _validate_type)



RESOURCE_ATTRIBUTE_MAP = {
    SERVICE_TRAFFIC_CLASSIFIERS: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None}, 'is_visible': True,
               'primary_key': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True, 'is_visible': True},               
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None},
                 'is_visible': True,'required': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'ports': {'allow_post': True, 'allow_put': True,
                  'validate': {'type:uuid_list_sc': None},
                  'is_visible': True,
                  'required': True},                        
        'classification_type': {'allow_post': True, 'allow_put': True,
                  'validate': {'type:values':['dl_src']},
                  'required': True,'is_visible': True},
        'service_chain_id': {'allow_post': False, 'allow_put': False,
                 'is_visible': True},
    },
    SERVICE_FUNCTION_INSTANCES: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None}, 'is_visible': True,
               'primary_key': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True, 'is_visible': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None},
                 'is_visible': True,'required': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'device_id': {'allow_post': True, 'allow_put': False,
                        'validate': {'type:uuid': None},
                        'required':True, 'is_visible': True},
        'context': {'allow_post': True, 'allow_put': True,
                  'validate': {'type:instance_ctx': None},
                  'default': None, 'is_visible': True,
                  'required': True},
        'type': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:type_check': None},
                 'required': True, 'is_visible': True},
        'fault_policy': {'allow_post': True, 'allow_put': True,
               'validate': {'type:values': ['drop','bypass','none']},
               'is_visible': True,'default':'none'},
        'admin_state': {'allow_post': True, 'allow_put': True,
               'validate': {'type:values':['active','inactive','error','none']},
               'is_visible': True,'default': 'active'},
        'group_id': {'allow_post': False, 'allow_put': False,
                         'validate': {'type:uuid': None},
                         'default': None, 'is_visible': True},                       
    },
    SERVICE_FUNCTION_GROUPS: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None}, 'is_visible': True,
               'primary_key': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
               'is_visible': True},
        'members': {'allow_post': True, 'allow_put': True,
                  'validate': {'type:inst_members': None},
                  'default': [], 'is_visible': True,
                  'required': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None},
                 'is_visible': True,'required': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'type': {'allow_post': True, 'allow_put': True,
                         'validate': {'type:type_check': None},
                         'required': True, 'is_visible': True},
        'method': {'allow_post': True, 'allow_put': True,
                   'validate': {'type:method_dict': None}, 'is_visible': True,
                   'default': None},
        'service_chain_id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None}, 'is_visible': True},
    },
    SERVICE_CHAINS: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None}, 'is_visible': True,
               'primary_key': True},
        'direction': {'allow_post': True, 'allow_put': False,
                 'validate': {'type:values':['U2N','N2U']},
                 'required': True, 'is_visible': True},
        'chain_id': {'allow_post': False, 'allow_put': False,
                    'validate': {'type:int': None},
                    'is_visible': True},        
        'tenant_id': {'allow_post': True, 'allow_put': False,
                   'is_visible': True},                
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None},
                 'is_visible': True,'required': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'traffic_classifier': {'allow_post': True, 'allow_put': True,
                  'validate': {'type:uuid_list_sc': None},
                  'default': [], 'is_visible': True,
                  'required': True},
        'catenated_chain': {'allow_post': True, 'allow_put': True,
               'validate': {'type:uuid_or_none': None}, 'is_visible': True,
               'default': None},
        'service_function_path': {'allow_post': True, 'allow_put': True,
               'validate': {'type:uuid_list_sc': None}, 'is_visible': True,
               'required': True, 'default': []},
        'destination_context': {'allow_post': True, 'allow_put': True,
               'validate': {'type:destination': None}, 'is_visible': True},
        'status': {'allow_post': False, 'allow_put': False,
               'validate': {'type:string': None}, 'is_visible': True},
    },
}

servicechain_pool_opts = [
    cfg.StrOpt('servicechain_pool',
               default='service_function_instance:0:16383,service_function_group:0:127,'
                       'service_traffic_classifier:20000:24999,service_chain:1:10000',
               help=_('default of servicechain_pool for servicechain'))
]

cfg.CONF.register_opts(servicechain_pool_opts, 'SERVICECHAIN')

class Servicechain(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "service-chain"

    @classmethod
    def get_alias(cls):
        return "service-chain"

    @classmethod
    def get_description(cls):
        return ("The service chain extension.")

    @classmethod
    def get_namespace(cls):
        #TODO
        return "http://docs.openstack.org/ext/neutron/xxx/api/v1.0"

    @classmethod
    def get_updated(cls):
        return "2014-03-06T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        my_plurals = [(key, key[:-1]) for key in RESOURCE_ATTRIBUTE_MAP.keys()]
        attr.PLURALS.update(dict(my_plurals))
        exts = []
        plugin = manager.NeutronManager.get_service_plugins()[
            constants.SERVICE_CHAIN]
        
        for resource_name in ['service_traffic_classifier', 'service_function_instance', 'service_function_group', 'service_chain']:
            collection_name = resource_name + "s"
            params = RESOURCE_ATTRIBUTE_MAP.get(collection_name, dict())

            member_actions = {}
            
            quota.QUOTAS.register_resource_by_name(resource_name)

            controller = base.create_resource(
                collection_name, resource_name, plugin, params,
                allow_bulk=True,
                member_actions=member_actions,
                allow_pagination=cfg.CONF.allow_pagination,
                allow_sorting=cfg.CONF.allow_sorting)

            ex = extensions.ResourceExtension(collection_name,
                                              controller,
                                              member_actions=member_actions,
                                              attr_map=params)
            exts.append(ex)

        return exts

    def update_attributes_map(self, attributes):
        super(Servicechain, self).update_attributes_map(
            attributes, extension_attrs_map=RESOURCE_ATTRIBUTE_MAP)

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        else:
            return {}


class ServiceChainPluginBase(object):
    __metaclass__ = abc.ABCMeta

    #@abc.abstractmethod    
    def get_service_traffic_classifier(self, context, service_traffic_classifier_id,
                              fields=None):
        pass

    #@abc.abstractmethod    
    def get_service_traffic_classifiers(self, context, filters=None, fields=None,
                               sorts=None, limit=None, marker=None,
                               page_reverse=False):
        pass

    #@abc.abstractmethod    
    def create_service_traffic_classifier(self, context, service_traffic_classifier):
        pass

    #@abc.abstractmethod    
    def update_service_traffic_classifier(self, context, service_traffic_classifier_id,
                                 service_traffic_classifier):
        pass

    #@abc.abstractmethod    
    def delete_service_traffic_classifier(self, context, service_traffic_classifier_id):
        pass

    #@abc.abstractmethod    
    def get_service_function_instance(self, context, service_function_instance_id,fields=None):
        pass

    #@abc.abstractmethod   
    def get_service_function_instances(self, context, filters=None, fields=None,
                               sorts=None, limit=None, marker=None,
                               page_reverse=False):
        pass

    #@abc.abstractmethod    
    def create_service_function_instance(self, context, service_function_instance):
        pass

    #@abc.abstractmethod    
    def update_service_function_instance(self, context, service_function_instance_id,
                                 service_function_instance):
        pass

    #@abc.abstractmethod    
    def delete_service_function_instance(self, context, service_function_instance_id):
        pass

    #@abc.abstractmethod   
    def get_service_function_group(self, context, service_function_group_id,
                              fields=None):
        pass

    #@abc.abstractmethod   
    def get_service_function_groups(self, context, filters=None, fields=None,
                               sorts=None, limit=None, marker=None,
                               page_reverse=False):
        pass

    #@abc.abstractmethod    
    def create_service_function_group(self, context, service_function_group):
        pass

    #@abc.abstractmethod    
    def update_service_function_group(self, context, service_function_group_id,
                                 service_function_group):
        pass

    #@abc.abstractmethod    
    def delete_service_function_group(self, context, service_function_group_id):
        pass

    #@abc.abstractmethod    
    def get_service_chain(self, context, service_chain_id,
                              fields=None):
        pass

    #@abc.abstractmethod    
    def get_service_chains(self, context, filters=None, fields=None,
                               sorts=None, limit=None, marker=None,
                               page_reverse=False):
        pass

    #@abc.abstractmethod   
    def create_service_chain(self, context, service_chain):
        pass

    #@abc.abstractmethod   
    def update_service_chain(self, context, service_chain_id,
                                 service_chain):
        pass

    #@abc.abstractmethod    
    def delete_service_chain(self, context, service_chain_id):
        pass
