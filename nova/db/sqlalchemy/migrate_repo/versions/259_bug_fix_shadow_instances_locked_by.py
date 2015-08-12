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

from nova.openstack.common import log as logging
from sqlalchemy import Column
from sqlalchemy import Enum
from sqlalchemy import MetaData
from sqlalchemy import Table

LOG = logging.getLogger()


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    shadow_table = Table('shadow_instances', meta, autoload=True)
    locked_by_column = getattr(shadow_table.c, 'locked_by')
    if str(locked_by_column.type).__contains__("SHADOW_INSTANCES0LOCKED_BY"):
        LOG.info("the shadow instance table need to convert.")
        shadow_table.drop()
        table = Table('instances', meta, autoload=True)
        columns = []
        for column in table.columns:
            if column.name == 'locked_by':
                enum = Enum('owner', 'admin',
                            name='instances0locked_by'.upper())
                column_copy = Column(column.name, enum)
            else:
                column_copy = column.copy()
            columns.append(column_copy)
        shadow_table_name = 'shadow_instances'
        shadow_table = Table(shadow_table_name, meta, *columns,
                             mysql_engine='InnoDB', extend_existing=True)
        shadow_table.create(checkfirst=True)
    else:
        LOG.info("the shadow instance table don't need to convert.")


def downgrade(migrate_engine):
    pass