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

from sqlalchemy import Column
from sqlalchemy import DateTime
from sqlalchemy import Integer
from sqlalchemy import MetaData
from sqlalchemy import String
from sqlalchemy import Table
from sqlalchemy import Text


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    columns = [
        (('created_at', DateTime), {}),
        (('updated_at', DateTime), {}),
        (('deleted_at', DateTime), {}),
        (('deleted', Integer), {}),
        (('id', Integer), dict(primary_key=True, nullable=False)),
        (('node_uuid', String(length=36)), dict(nullable=False)),
        (('connector', Text), dict(nullable=True)),
        ]

    for prefix in ('', 'shadow_'):
        basename = prefix + 'huawei_ironic_volume'
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
        table_name = prefix + 'huawei_ironic_volume'
        if migrate_engine.has_table(table_name):
            instance_extra = Table(table_name, meta, autoload=True)
            instance_extra.drop()
