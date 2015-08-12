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

"""Added listener table

Revision ID: 4e0b972181bd
Revises: juno
Create Date: 2014-11-13 00:44:15.436971

"""

# revision identifiers, used by Alembic.
revision = '4e0b972181bd'
down_revision = 'juno'

from alembic import op
import sqlalchemy as sa



def upgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.create_table('listeners',
    sa.Column('tenant_id', sa.String(length=255), nullable=True),
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('status_description', sa.String(length=255), nullable=True),
    sa.Column('vip_id', sa.String(length=36), nullable=True),
    sa.Column('protocol_port', sa.Integer(), nullable=False),
    sa.Column('protocol', sa.Enum('HTTP', 'HTTPS', 'TCP', name='protocols'), nullable=False),
    sa.ForeignKeyConstraint(['vip_id'], ['vips.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    )
    if op.get_bind().dialect.name == 'mysql':
        op.execute("ALTER TABLE %s ENGINE=InnoDB" % 'listeners')
    ### end Alembic commands ###


def downgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('listeners')
    sa.Enum('HTTP', 'HTTPS', 'TCP',
             name='protocols').drop(op.get_bind(),checkfirst=False)
    ### end Alembic commands ###