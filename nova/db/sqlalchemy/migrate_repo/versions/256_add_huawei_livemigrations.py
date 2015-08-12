# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

from sqlalchemy import Column, DateTime, Integer, MetaData, String, Table
from sqlalchemy import Text, Boolean
from nova.db.sqlalchemy import types

from nova.openstack.common import log as logging

LOG = logging.getLogger(__name__)


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    columns = [
        (('created_at', DateTime), {}),
        (('updated_at', DateTime), {}),
        (('deleted_at', DateTime), {}),
        (('deleted', Integer), {}),
        (('id', Integer), dict(primary_key=True, nullable=False)),
        (('instance_uuid', String(length=36)), dict(nullable=False)),
        (('source_host', String(length=255)), dict(nullable=True)),
        (('dest_host', String(length=255)), dict(nullable=True)),
        (('dest_addr', String(length=255)), dict(nullable=True)),
        (('block_migration', Boolean), dict(nullable=True, default=False)),
        (('migrate_data', Text), dict(nullable=True)),
        ]

    for prefix in ('', 'shadow_'):
        basename = prefix + 'huawei_live_migrations'
        if migrate_engine.has_table(basename):
            continue
        _columns = tuple([Column(*args, **kwargs)
                          for args, kwargs in columns])
        table = Table(basename, meta, *_columns, mysql_engine='InnoDB',
                      mysql_charset='utf8')
        table.create()

def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    for prefix in ('', 'shadow_'):
        table_name = prefix + 'huawei_live_migrations'
        if migrate_engine.has_table(table_name):
            instance_extra = Table(table_name, meta, autoload=True)
            instance_extra.drop()