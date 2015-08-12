# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2014 OpenStack Foundation
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
#

"""Update QoS db models

Revision ID: 42f49dd148cd
Revises: 2a8482e506b4
Create Date: 2014-04-21 11:24:31.297532

"""

# revision identifiers, used by Alembic.
revision = '1f9ab3900dd5'
down_revision = '16c8803e1cf'

# Change to ['*'] if this migration applies to all plugins

migration_for_plugins = [
    '*',
]

from neutron.common import constants
from neutron.db import migration

from alembic import op
import sqlalchemy as sa

def upgrade(active_plugins=None, options=None):
    if migration.schema_has_table('qoses'):
        op.add_column('qoses', sa.Column('shared', sa.Boolean(),
                                              server_default=sa.sql.false(),
                                              nullable=True))

def downgrade(active_plugins=None, options=None):
    op.drop_column('qoses', 'shared')