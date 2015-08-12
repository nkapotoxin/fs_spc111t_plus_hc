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

"""update_vpnservice_des_length

Revision ID: 2aa179c7fd81
Revises: 4f0cb427128a
Create Date: 2015-05-18 23:11:26.095560

"""

# revision identifiers, used by Alembic.
revision = '2aa179c7fd81'
down_revision = '4f0cb427128a'

from neutron.db import migration
import sqlalchemy as sa

LEN=4*1024


def upgrade():
    migration.alter_column_if_exists(
        'vpnservices', 'description',
        type_=sa.String(LEN),
        nullable=True)

def downgrade():
     migration.alter_column_if_exists(
        'vpnservices', 'description',
        type_=sa.String(255),
        nullable=True)