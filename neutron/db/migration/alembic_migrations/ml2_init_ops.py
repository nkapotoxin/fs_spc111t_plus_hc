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

# Initial operations for ML2 plugin and drivers


from alembic import op
import sqlalchemy as sa


def create_cisco_ml2_credentials():
    op.create_table(
        'cisco_ml2_credentials',
        sa.Column('credential_id', sa.String(length=255), nullable=True),
        sa.Column('tenant_id', sa.String(length=255), nullable=False),
        sa.Column('credential_name', sa.String(length=255), nullable=False),
        sa.Column('user_name', sa.String(length=255), nullable=True),
        sa.Column('password', sa.String(length=255), nullable=True),
        sa.PrimaryKeyConstraint('tenant_id', 'credential_name'),
    )


def upgrade():
    op.create_table(
        'ml2_vlan_allocations',
        sa.Column('physical_network', sa.String(length=64), nullable=False),
        sa.Column('vlan_id', sa.Integer(), autoincrement=False,
                  nullable=False),
        sa.Column('allocated', sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint('physical_network', 'vlan_id'))

    op.create_table(
        'ml2_vxlan_endpoints',
        sa.Column('ip_address', sa.String(length=64), nullable=False),
        sa.Column('udp_port', sa.Integer(), autoincrement=False,
                  nullable=False),
        sa.PrimaryKeyConstraint('ip_address', 'udp_port'))

    op.create_table(
        'ml2_gre_endpoints',
        sa.Column('ip_address', sa.String(length=64), nullable=False),
        sa.PrimaryKeyConstraint('ip_address'))

    op.create_table(
        'ml2_vxlan_allocations',
        sa.Column('vxlan_vni', sa.Integer(), autoincrement=False,
                  nullable=False),
        sa.Column('allocated', sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint('vxlan_vni'))

    op.create_table(
        'ml2_gre_allocations',
        sa.Column('gre_id', sa.Integer(), autoincrement=False,
                  nullable=False),
        sa.Column('allocated', sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint('gre_id'))

    op.create_table(
        'ml2_flat_allocations',
        sa.Column('physical_network', sa.String(length=64), nullable=False),
        sa.PrimaryKeyConstraint('physical_network'))

    op.create_table(
        'ml2_network_segments',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('network_id', sa.String(length=36), nullable=False),
        sa.Column('network_type', sa.String(length=32), nullable=False),
        sa.Column('physical_network', sa.String(length=64), nullable=True),
        sa.Column('segmentation_id', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['network_id'], ['networks.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'))

    op.create_table(
        'ml2_port_bindings',
        sa.Column('port_id', sa.String(length=36), nullable=False),
        sa.Column('host', sa.String(length=255), nullable=False),
        sa.Column('vif_type', sa.String(length=64), nullable=False),
        sa.Column('cap_port_filter', sa.Boolean(), nullable=False),
        sa.Column('driver', sa.String(length=64), nullable=True),
        sa.Column('segment', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['port_id'], ['ports.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['segment'], ['ml2_network_segments.id'],
                                ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('port_id'))

    op.create_table(
        'cisco_ml2_nexusport_bindings',
        sa.Column('binding_id', sa.Integer(), nullable=False),
        sa.Column('port_id', sa.String(length=255), nullable=True),
        sa.Column('vlan_id', sa.Integer(), autoincrement=False,
                  nullable=False),
        sa.Column('switch_ip', sa.String(length=255), nullable=True),
        sa.Column('instance_id', sa.String(length=255), nullable=True),
        sa.PrimaryKeyConstraint('binding_id'),
    )

    create_cisco_ml2_credentials()

    op.create_table(
        'arista_provisioned_nets',
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('network_id', sa.String(length=36), nullable=True),
        sa.Column('segmentation_id', sa.Integer(),
                  autoincrement=False, nullable=True),
        sa.PrimaryKeyConstraint('id'))

    op.create_table(
        'arista_provisioned_vms',
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('vm_id', sa.String(length=255), nullable=True),
        sa.Column('host_id', sa.String(length=255), nullable=True),
        sa.Column('port_id', sa.String(length=36), nullable=True),
        sa.Column('network_id', sa.String(length=36), nullable=True),
        sa.PrimaryKeyConstraint('id'))

    op.create_table(
        'arista_provisioned_tenants',
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.PrimaryKeyConstraint('id'))


def downgrade():
    op.drop_table('arista_provisioned_tenants')
    op.drop_table('arista_provisioned_vms')
    op.drop_table('arista_provisioned_nets')
    op.drop_table('cisco_ml2_credentials')
    op.drop_table('cisco_ml2_nexusport_bindings')
    op.drop_table('ml2_port_bindings')
    op.drop_table('ml2_network_segments')
    op.drop_table('ml2_flat_allocations')
    op.drop_table('ml2_gre_allocations')
    op.drop_table('ml2_vxlan_allocations')
    op.drop_table('ml2_gre_endpoints')
    op.drop_table('ml2_vxlan_endpoints')
    op.drop_table('ml2_vlan_allocations')
