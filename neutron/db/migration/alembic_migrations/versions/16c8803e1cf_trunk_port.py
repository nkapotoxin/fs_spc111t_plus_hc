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

"""trunk_port

Revision ID: 16c8803e1cf
Revises: 544673ac99ab
Create Date: 2014-09-01 18:06:15.722787

"""

# revision identifiers, used by Alembic.
revision = '16c8803e1cf'
down_revision = '42f49dd148cd'

from alembic import op
import sqlalchemy as sa


def upgrade(active_plugins=None, options=None):
    op.create_table(
        'trunkports',
        sa.Column('port_id', sa.String(length=36), nullable=False),
        sa.Column('trunk_type', sa.String(length=16), nullable=True),
        sa.Column('parent_id', sa.String(length=36), nullable=True),
        sa.Column('vid', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['port_id'], ['ports.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('port_id'))
    
    if op.get_bind().dialect.name == 'mysql':
        op.execute("ALTER TABLE %s ENGINE=InnoDB" % 'trunkports')


def downgrade(active_plugins=None, options=None):
    op.drop_table('trunkports')
