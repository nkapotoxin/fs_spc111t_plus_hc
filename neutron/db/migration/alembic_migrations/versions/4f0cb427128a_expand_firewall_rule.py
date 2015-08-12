# Copyright 2015 OpenStack Foundation
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

"""expand firewall rule

Revision ID: 4f0cb427128a
Revises: 1f9ab3900dd5
Create Date: 2015-04-16 18:06:16.810951

"""

# revision identifiers, used by Alembic.
revision = '4f0cb427128a'
down_revision = '1f9ab3900dd5'

from alembic import op
import sqlalchemy as sa
from neutron.db import migration

SQL_STATEMENT = (
    "update firewall_rules set mode='normal'"
)
SQL_STATEMENT_2 = (
    "insert into firewall_router_associations "
    "select "
    "f.id as fw_id, r.id as router_id "
    "from firewalls f, routers r "
    "where "
    "f.tenant_id=r.tenant_id"
)

def upgrade():
    if migration.schema_has_table('firewall_rules'):
        op.add_column('firewall_rules', sa.Column('mode', sa.String(length=12),
                                              nullable=True))
        op.add_column('firewall_rules', sa.Column('rule_profile', sa.String(length=1024),
                                              nullable=True))
        op.create_table('firewall_router_associations',
        sa.Column('fw_id', sa.String(length=36), nullable=False),
        sa.Column('router_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['fw_id'], ['firewalls.id'],
            ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['router_id'], ['routers.id'],
            ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('fw_id', 'router_id'),
        )

        op.execute(SQL_STATEMENT)
        op.execute(SQL_STATEMENT_2)

def downgrade():
    op.drop_column('firewall_rules', 'mode')
    op.drop_column('firewall_rules', 'rule_profile')
    op.drop_table('firewall_router_associations')