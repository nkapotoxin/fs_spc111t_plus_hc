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


import sqlalchemy as sa
from sqlalchemy import orm
from sqlalchemy.orm import exc

from neutron.db import common_db_mixin
from neutron.db import model_base
from neutron.db import models_v2
from neutron.extensions import servicechain as schain
from neutron.openstack.common import uuidutils
from neutron.openstack.common import jsonutils
from neutron.plugins.common import constants

class PortFlow(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """service chain flows for recover"""
    __tablename__ = "port_flows"
    host_id = sa.Column(sa.String(255), nullable=False)
    chain_id = sa.Column(sa.Integer,nullable=False)
    in_port = sa.Column(sa.Integer)
    in_port_uuid = sa.Column(sa.String(64))
    outer_dl_src = sa.Column(sa.String(64))
    group_id = sa.Column(sa.Integer)
    sf_port_list = sa.Column(sa.String(30000))
    fault_policy = sa.Column(sa.String(64))
    breakout_dl_src = sa.Column(sa.String(64))
    breakout_dl_dst = sa.Column(sa.String(64))
    service_chain_id = sa.Column(sa.String(255),sa.ForeignKey('service_chains.id',
                                                      ondelete='CASCADE'))
    status = sa.Column(sa.String(16))
    hash_policy = sa.Column(sa.String(64))
    chain_direction = sa.Column(sa.String(16))
    in_port_pair = sa.Column(sa.String(600))
    instance_state = sa.Column(sa.String(16))
    history_portlist = sa.Column(sa.String(200))

class ServiceChainAvailabilityRange(model_base.BASEV2):
    """availability range for sc_id/sf_port_id/st_classifier_id"""
    
    __tablename__ = "service_chain_availability_ranges"
    allocation_pool_id = sa.Column(sa.String(36),
                                   sa.ForeignKey('service_chain_pools.id',
                                                 ondelete="CASCADE"),
                                   nullable=False,
                                   primary_key=True)
    sf_sc_identifier = sa.Column(sa.String(36),nullable=False)
    sf_port_id_begin = sa.Column(sa.Integer, nullable=False,primary_key=True)
    sf_port_id_end = sa.Column(sa.Integer, nullable=False,primary_key=True)
    
    def __repr__(self):
        return "%s - %s" % (self.sf_port_id_begin, self.sf_port_id_end)

class ServiceChainPool(model_base.BASEV2, models_v2.HasId):
    """all allocation for sc_id/sf_port_id/st_classifier_id"""
    
    __tablename__ = "service_chain_pools"
    sf_sc_identifier = sa.Column(sa.String(36))
    sf_port_id_begin = sa.Column(sa.Integer, nullable=False)
    sf_port_id_end = sa.Column(sa.Integer, nullable=False)
    available_ranges = orm.relationship(ServiceChainAvailabilityRange,
                                        backref='servicechainpool',
                                        lazy="joined",
                                        cascade='all,delete')
    def __repr__(self):
        return "%s - %s" % (self.sf_port_id_begin, self.sf_port_id_end)

class ServiceChainAllocation(model_base.BASEV2):
    """allocationed sc_id/sf_port_id/st_classifier_id"""

    __tablename__ = "service_chain_allocations"
    port_id = sa.Column(sa.String(36))
    sf_sc_id = sa.Column(sa.String(36), nullable=False, primary_key=True)
    sf_sc_identifier = sa.Column(sa.String(36), nullable=False, primary_key=True)
    sf_port_id = sa.Column(sa.Integer, nullable=False, primary_key=True)
    allocation_pool_id = sa.Column(sa.String(36),
                                    sa.ForeignKey('service_chain_pools.id',
                                                  ondelete="CASCADE"),
                                    nullable=False)

class ServiceFuntionInstanceContext(model_base.BASEV2):
    """Service instances context"""

    __tablename__ = 'service_instance_contexts'
    service_function_instance_id = sa.Column(sa.String(36),
                                   sa.ForeignKey('service_function_instances.id',
                                             ondelete='CASCADE'),
                                   primary_key=True)
    host_id = sa.Column(sa.String(255),nullable=False)
    user_side_port = sa.Column(sa.String(64), nullable=False)
    user_side_action = sa.Column(sa.String(128))
    user_side_sf_port_id = sa.Column(sa.Integer)
    network_side_port = sa.Column(sa.String(64),nullable=False)
    network_side_action = sa.Column(sa.String(128))
    network_side_sf_port_id = sa.Column(sa.Integer)
    classification_type = sa.Column(sa.String(64))
    
class ServiceFunctionPath(model_base.BASEV2):
    """ ServiceChain service function path """

    __tablename__ = 'service_function_paths'
    service_chain_id = sa.Column(sa.String(36),
                                 sa.ForeignKey('service_chains.id', ondelete='CASCADE'),
                                 primary_key=True)
    service_function_group_id = sa.Column(sa.String(255),
                                          sa.ForeignKey('service_function_groups.id', ondelete='CASCADE'),
                                          primary_key=True)
    hop_index = sa.Column(sa.Integer, nullable=False)  
    
    
class ServiceTrafficClassifierBindChain(model_base.BASEV2):
    """Service Traffic Classifier bind with Chain"""
    __tablename__='service_traffic_classifier_bind_chains'
    service_chain_id = sa.Column(sa.String(255),
                                 sa.ForeignKey('service_chains.id', ondelete='CASCADE'),
                                 primary_key=True) 
    service_traffic_classifier_id = sa.Column(sa.String(255),
                                 sa.ForeignKey('service_traffic_classifiers.id', ondelete='CASCADE'),
                                 primary_key=True)
    
class ServiceTrafficClassifier(model_base.BASEV2, models_v2.HasId,
                           models_v2.HasTenant):
    """Service traffic classifier"""
    __tablename__ = 'service_traffic_classifiers'
    name = sa.Column(sa.String(50), nullable=False)

    description = sa.Column(sa.String(255))
    ports = sa.Column(sa.String(2560), nullable=False)
    list_hosts = sa.Column(sa.String(5120))
    list_ports = sa.Column(sa.String(2608))
    classification_type = sa.Column(sa.String(36))
    service_chain_id = orm.relationship('ServiceTrafficClassifierBindChain',
                                      backref='ServiceTrafficClassifier',
                                      cascade='all, delete, delete-orphan')

class ServiceChain(model_base.BASEV2, models_v2.HasId,
                       models_v2.HasTenant):
    """ Service Chain """

    __tablename__ = 'service_chains'
    name = sa.Column(sa.String(64))
    direction = sa.Column(sa.String(16))
    chain_id = sa.Column(sa.Integer)
    description = sa.Column(sa.String(255))
    traffic_classifier = orm.relationship(
                        ServiceTrafficClassifierBindChain,
                        backref='ServiceChain', 
                        cascade='all, delete, delete-orphan')
    catenated_chain = sa.Column(sa.String(64))
    service_function_path = orm.relationship(
                        ServiceFunctionPath,
                        backref='ServiceChain',
                        order_by="ServiceFunctionPath.hop_index",
                        cascade='all, delete, delete-orphan')
    destination_context = sa.Column(sa.String(255))
    status = sa.Column(sa.String(32))
    service_flows = orm.relationship(PortFlow,
                                     backref='ServiceChain',
                                     lazy='joined',
                                     order_by='PortFlow.chain_id',
                                     cascade='delete')  
      
class ServiceFunctionGroupBindInstance(model_base.BASEV2):
    '''Service function Group Bind Instance '''

    __tablename__ = 'service_function_group_binding_instances'
    instance_id = sa.Column(sa.String(255),
                            sa.ForeignKey('service_function_instances.id'),
                            nullable=False,
                            primary_key=True)
    group_id = sa.Column(sa.String(255),
                         sa.ForeignKey('service_function_groups.id', ondelete='CASCADE'),
                         nullable=False,
                         primary_key=True)
    weight = sa.Column(sa.Integer, nullable=False)
    

class ServiceFunctionInstance(model_base.BASEV2, models_v2.HasId,
                           models_v2.HasTenant):
    """Service Function Instance db"""

    __tablename__ = 'service_function_instances'
    name = sa.Column(sa.String(64))
    device_id = sa.Column(sa.String(256))
    description = sa.Column(sa.String(1024))
    type = sa.Column(sa.String(64))
    context = orm.relationship(ServiceFuntionInstanceContext,
                               backref='ServiceFunctionInstance',
                               lazy='joined',
                               uselist=False,
                               cascade='delete')
    admin_state = sa.Column(sa.String(16))
    fault_policy = sa.Column(sa.String(16))
    group_id = orm.relationship(ServiceFunctionGroupBindInstance,
                               backref='ServiceFunctionInstance',
                               lazy='joined',
                               uselist=False,
                               cascade='delete')
     
class ServiceFunctionGroup(model_base.BASEV2, models_v2.HasId,
                           models_v2.HasTenant):
    """Service function group"""

    __tablename__ = 'service_function_groups'
    name = sa.Column(sa.String(64))
    description = sa.Column(sa.String(1024))
    members = orm.relationship(ServiceFunctionGroupBindInstance,
                             backref="ServiceFunctionGroup",
                             cascade='all, delete, delete-orphan')
    type = sa.Column(sa.String(36))
    method = sa.Column(sa.String(64))
    group_id = sa.Column(sa.Integer)
    
    service_chain_id = orm.relationship('ServiceFunctionPath',
                                      backref='ServiceFunctionGroup',
                                      cascade='all, delete, delete-orphan')
