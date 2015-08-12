# Copyright 2012 OpenStack Foundation
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

from migrate.changeset import UniqueConstraint
from sqlalchemy import Column
from sqlalchemy import DateTime
from sqlalchemy import ForeignKey
from sqlalchemy import Index
from sqlalchemy import Integer
from sqlalchemy import MetaData
from sqlalchemy import String
from sqlalchemy import Table

from nova.huawei.db.sqlalchemy import affinity_db_api as db
from nova.huawei.db.sqlalchemy import affinity_utils

def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    affinitygroup = Table('affinitygroups', meta,
                   Column('created_at', DateTime),
                   Column('updated_at', DateTime),
                   Column('deleted_at', DateTime),
                   Column('deleted', Integer),
                   Column('id', Integer, primary_key=True, nullable=False),
                   Column('name', String(length=255)),
                   Column('description', String(length=255)),
                   Column('type', String(length=255)),
                   mysql_engine='InnoDB',
                   mysql_charset='utf8',
                   )
    affinitygroup_metadata = Table('affinitygroup_metadata', meta,
                          Column('created_at', DateTime),
                          Column('updated_at', DateTime),
                          Column('deleted_at', DateTime),
                          Column('deleted', Integer),
                          Column('id', Integer, primary_key=True, nullable=False),
                          Column('key', String(length=255)),
                          Column('value', String(length=255)),
                          Column('affinitygroup_id', Integer, ForeignKey('affinitygroups.id'),
                                 nullable=False),
                          UniqueConstraint("affinitygroup_id", "key", "deleted",
                                           name="uniq_affinitygroup_metadata0affinitygroup_id0key0deleted"
                          ),
                          mysql_engine='InnoDB',
                          mysql_charset='utf8',
                          )
    affinitygroup_vm = Table('affinitygroup_vms', meta,
                                   Column('created_at', DateTime),
                                   Column('updated_at', DateTime),
                                   Column('deleted_at', DateTime),
                                   Column('deleted', Integer),
                                   Column('id', Integer, primary_key=True, nullable=False),
                                   Column('vm', String(length=255)),
                                   Column('affinitygroup_id', Integer, ForeignKey('affinitygroups.id'),
                                          nullable=False),
                                   UniqueConstraint("vm", "affinitygroup_id", "deleted",
                                                    name="uniq_affinitygroup_vms0vm0affinitygroup_id0deleted"
                                   ),
                                   mysql_engine='InnoDB',
                                   mysql_charset='utf8',
                                   )
    tables = [affinitygroup, affinitygroup_metadata, affinitygroup_vm]

    # create all of the tables
    for table in tables:
        table.create()
        affinity_utils.create_shadow_table(migrate_engine, table=table)


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine
    table_names = ['affinitygroups', 'affinitygroup_vms',
                   'affinitygroup_metadata']
    for name in table_names:
        table = Table(name, meta, autoload=True)
        table.drop()
        table = Table(db._SHADOW_TABLE_PREFIX + name, meta, autoload=True)
        table.drop()
