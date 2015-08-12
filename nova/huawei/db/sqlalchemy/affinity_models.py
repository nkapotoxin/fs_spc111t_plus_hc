# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2011 X.commerce, a business unit of eBay Inc.
# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# Copyright 2011 Piston Cloud Computing, Inc.
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
"""
SQLAlchemy models for nova data.
"""

from sqlalchemy import Column, Index, Integer, String, schema
from sqlalchemy.dialects.mysql import MEDIUMTEXT
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import ForeignKey, Text
from sqlalchemy.orm import relationship
from oslo.config import cfg

from nova.db.sqlalchemy import models as core_models

CONF = cfg.CONF
BASE = declarative_base()


def MediumText():
    return Text().with_variant(MEDIUMTEXT(), 'mysql')


class AffinityGroupVM(BASE, core_models.NovaBase):
    """Represents a host that is member of an aggregate."""
    __tablename__ = 'affinitygroup_vms'
    __table_args__ = (schema.UniqueConstraint(
        "vm", "affinitygroup_id", "deleted",
        name="uniq_affinitygroup_vms0vm0affinitygroup_id0deleted"
    ),
    )
    id = Column(Integer, primary_key=True, autoincrement=True)
    vm = Column(String(255))
    affinitygroup_id = Column(Integer, ForeignKey('affinitygroups.id'),
                               nullable=False)


class AffinityGroupMetadata(BASE, core_models.NovaBase):
    """Represents a metadata key/value pair for an aggregate."""
    __tablename__ = 'affinitygroup_metadata'
    __table_args__ = (
        schema.UniqueConstraint("affinitygroup_id", "key", "deleted",
                                name="uniq_affinitygroup_metadata0affinitygroup_id0key0deleted"
        ),
        Index('affinitygroup_metadata_key_idx', 'key'),
    )
    id = Column(Integer, primary_key=True)
    key = Column(String(255), nullable=False)
    value = Column(String(255), nullable=False)
    affinitygroup_id = Column(Integer, ForeignKey('affinitygroups.id'), nullable=False)


class AffinityGroup(BASE, core_models.NovaBase):
    """Represents a cluster of hosts that exists in this zone."""
    __tablename__ = 'affinitygroups'
    __table_args__ = ()
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255))
    description = Column(String(255))
    type = Column(String(255))
    _vms = relationship(AffinityGroupVM,
                          primaryjoin='and_('
                                      'AffinityGroup.id == AffinityGroupVM.affinitygroup_id,'
                                      'AffinityGroupVM.deleted == 0,'
                                      'AffinityGroup.deleted == 0)')

    _metadata = relationship(AffinityGroupMetadata,
                             primaryjoin='and_('
                                         'AffinityGroup.id == AffinityGroupMetadata.affinitygroup_id,'
                                         'AffinityGroupMetadata.deleted == 0,'
                                         'AffinityGroup.deleted == 0)')

    def _extra_keys(self):
        return ['vms', 'metadetails', 'availability_zone']

    @property
    def vms(self):
        return [v.vm for v in self._vms]

    @property
    def metadetails(self):
        return dict([(m.key, m.value) for m in self._metadata])

    @property
    def availability_zone(self):
        if 'availability_zone' not in self.metadetails:
            return None
        return self.metadetails['availability_zone']


class VolumeConnection(BASE, core_models.NovaBase):
    """Represents a host that is member of an aggregate."""
    __tablename__ = 'volume_connections'
    __table_args__ = (
        Index('volume_connections_volume_id_idx', 'volume_id'),
        Index('volume_connections_instance_uuid_idx', 'instance_uuid'),
        Index('volume_connections_host_idx', 'host')
    )
    id = Column(Integer, primary_key=True, autoincrement=True)
    instance_uuid = Column(String(36))
    volume_id = Column(String(36))
    host = Column(String(255))


class IronicVolume(BASE, core_models.NovaBase):
    """store ironic connector for cinder-volume."""
    __tablename__ = 'huawei_ironic_volume'
    __table_args__ = ()
    id = Column(Integer, primary_key=True, autoincrement=True)
    node_uuid = Column(String(36))
    connector = Column(Text)
