# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2011 X.commerce, a business unit of eBay Inc.
# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# All Rights Reserved.
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

"""Defines interface for DB access.

The underlying driver is loaded as a :class:`LazyPluggable`.

Functions in this module are imported into the nova.db namespace. Call these
functions from nova.db namespace, not the nova.db.api namespace.

All functions in this module return objects that implement a dictionary-like
interface. Currently, many of these objects are sqlalchemy objects that
implement a dictionary interface. However, a future goal is to have all of
these objects be simple dictionaries.


**Related Flags**

:db_backend:  string to lookup in the list of LazyPluggable backends.
              `sqlalchemy` is the only supported backend right now.

:connection:  string specifying the sqlalchemy connection to use, like:
              `sqlite:///var/lib/nova/nova.sqlite`.

:enable_new_services:  when adding a new service to the database, is it in the
                       pool of available hardware (Default: True)

"""

from oslo.config import cfg
from oslo.db import concurrency

from nova import exception
from nova.openstack.common import log as logging


db_opts = [
    cfg.BoolOpt('enable_new_services',
                default=True,
                help='Services to be added to the available pool on create'),
    cfg.StrOpt('instance_name_template',
               default='instance-%08x',
               help='Template string to be used to generate instance names'),
    cfg.StrOpt('snapshot_name_template',
               default='snapshot-%s',
               help='Template string to be used to generate snapshot names'),
    ]

CONF = cfg.CONF
CONF.register_opts(db_opts)

_BACKEND_MAPPING = {'sqlalchemy': 'nova.huawei.db.sqlalchemy.affinity_db_api'}


IMPL = concurrency.TpoolDbapiWrapper(CONF, backend_mapping=_BACKEND_MAPPING)
LOG = logging.getLogger(__name__)


class NoMoreNetworks(exception.NovaException):
    """No more available networks."""
    pass


class NoMoreTargets(exception.NovaException):
    """No more available targets."""
    pass


###################


def constraint(**conditions):
    """Return a constraint object suitable for use with some updates."""
    return IMPL.constraint(**conditions)


def equal_any(*values):
    """Return an equality condition object suitable for use in a constraint.

    Equal_any conditions require that a model object's attribute equal any
    one of the given values.
    """
    return IMPL.equal_any(*values)


def not_equal(*values):
    """Return an inequality condition object suitable for use in a constraint.

    Not_equal conditions require that a model object's attribute differs from
    all of the given values.
    """
    return IMPL.not_equal(*values)


###################


def affinitygroup_create(context, values, metadata=None):
    """Create a new affinity group with metadata."""
    return IMPL.affinitygroup_create(context, values, metadata)


def affinitygroup_get(context, affinitygroup_id):
    """Get a specific affinity group by id."""
    return IMPL.affinitygroup_get(context, affinitygroup_id)


def affinitygroup_get_by_vm(context, vm, key=None):
    """Get a list of aggregates that host belongs to."""
    return IMPL.affinitygroup_get_by_vm(context, vm, key)


def affinitygroup_metadata_get_by_vm(context, vm, key=None):
    """Get metadata for all aggregates that host belongs to.

    Returns a dictionary where each value is a set, this is to cover the case
    where there two aggregates have different values for the same key.
    Optional key filter
    """
    return IMPL.affinitygroup_metadata_get_by_vm(context, vm, key)


def affinitygroup_metadata_get_by_metadata_key(context,
                                               affinitygroup_id, key):
    """Get metadata for an aggregate by metadata key."""
    return IMPL.affinitygroup_metadata_get_by_metadata_key(context,
                                                           affinitygroup_id, key)


def affinitygroup_vm_get_by_metadata_key(context, key):
    """Get vms with a specific metadata key metadata for all affinitygroups.

    Returns a dictionary where each key is a hostname and each value is a set
    of the key values
    return value:  {machine: set( az1, az2 )}
    """
    return IMPL.affinitygroup_vm_get_by_metadata_key(context, key)


def affinitygroup_update(context, affinitygroup_id, values):
    """Update the attributes of an aggregates.

    If values contains a metadata key, it updates the aggregate metadata too.
    """
    return IMPL.affinitygroup_update(context, affinitygroup_id, values)


def affinitygroup_delete(context, affinitygroup_id):
    """Delete an aggregate."""
    return IMPL.affinitygroup_delete(context, affinitygroup_id)


def affinitygroup_get_all(context):
    """Get all aggregates."""
    return IMPL.affinitygroup_get_all(context)


def affinitygroup_metadata_add(context, affinitygroup_id, metadata,
                               set_delete=False):
    """Add/update metadata. If set_delete=True, it adds only."""
    IMPL.affinitygroup_metadata_add(context, affinitygroup_id, metadata,
                                set_delete)


def affinitygroup_metadata_get(context, affinitygroup_id):
    """Get metadata for the specified aggregate."""
    return IMPL.affinitygroup_metadata_get(context, affinitygroup_id)


def affinitygroup_metadata_delete(context, affinitygroup_id, key):
    """Delete the given metadata key."""
    IMPL.affinitygroup_metadata_delete(context, affinitygroup_id, key)


def affinitygroup_vm_add(context, affinitygroup_id, vm):
    """Add vm to the affinity group."""
    IMPL.affinitygroup_vm_add(context, affinitygroup_id, vm)


def affinitygroup_vm_delete(context, affinitygroup_id, vm):
    """Delete the given vm from the affinity group."""
    IMPL.affinitygroup_vm_delete(context, affinitygroup_id, vm)


def affinitygroup_vms_add(context, affinitygroup_id, vms):
    """Add vms to the affinity group."""
    IMPL.affinitygroup_vm_add(context, affinitygroup_id, vms)


def affinitygroup_vms_delete(context, affinitygroup_id, vms):
    """Delete the given vms from the affinity group."""
    IMPL.affinitygroup_vm_delete(context, affinitygroup_id, vms)


def affinitygroup_vm_get_all(context, affinitygroup_id):
    """Get vms for the specified affinity group."""
    return IMPL.affinitygroup_vm_get_all(context, affinitygroup_id)


def virtual_interface_update(context, vif_id, values):
    """Update virtual interface in the database."""
    return IMPL.virtual_interface_update(context, vif_id, values)


####################
def volume_connection_set(context, volume_id, instance_uuid, host):
    """Init a connection to cinder."""
    return IMPL.volume_connection_set(
        context, volume_id, instance_uuid, host)


def volume_connection_unset(context, volume_id, instance_uuid, host):
    """Terminate a connection to cinder."""
    return IMPL.volume_connection_unset(
        context, volume_id, instance_uuid, host)


def volume_connection_get_num(context, volume_id, host):
    """Get connection number for a given volume."""
    return IMPL.volume_connection_get_num(context, volume_id, host)


def ironic_connector_get(context, node_uuid):
    """Get ironic connector from instance_uuid."""
    return IMPL.ironic_connector_get(context, node_uuid)


def ironic_connector_create(context, values):
    """create a new ironic_volume """
    return IMPL.ironic_connector_create(context, values)


def ironic_connector_delete(context, node_uuid):
    """create a new ironic_volume """
    return IMPL.ironic_connector_delete(context, node_uuid)
