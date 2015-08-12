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

"""Implementation of SQLAlchemy backend."""

import collections
import functools
import sys
import threading
import time

from oslo.config import cfg
from oslo.db import exception as db_exc
from oslo.db.sqlalchemy import session as db_session
from sqlalchemy import or_
from sqlalchemy.orm import contains_eager
from sqlalchemy.orm import joinedload

import nova.context
from nova.huawei.db.sqlalchemy import affinity_models as models
from nova.db.sqlalchemy import models as core_models
from nova.huawei import exception as huawei_exception
from nova.openstack.common import excutils
from nova.openstack.common.gettextutils import _
from nova.openstack.common import log as logging

db_opts = [
    cfg.StrOpt('osapi_compute_unique_server_name_scope',
               default='',
               help='When set, compute API will consider duplicate hostnames '
                    'invalid within the specified scope, regardless of case. '
                    'Should be empty, "project" or "global".'),
]

CONF = cfg.CONF
CONF.register_opts(db_opts)
CONF.import_opt('compute_topic', 'nova.compute.rpcapi')

LOG = logging.getLogger(__name__)

_ENGINE_FACADE = None
_LOCK = threading.Lock()


def _create_facade_lazily():
    global _LOCK, _ENGINE_FACADE
    if _ENGINE_FACADE is None:
        with _LOCK:
            if _ENGINE_FACADE is None:
                _ENGINE_FACADE = db_session.EngineFacade.from_config(CONF)
    return _ENGINE_FACADE


def get_engine(use_slave=False):
    facade = _create_facade_lazily()
    return facade.get_engine(use_slave=use_slave)


def get_session(use_slave=False, **kwargs):
    facade = _create_facade_lazily()
    return facade.get_session(use_slave=use_slave, **kwargs)


_SHADOW_TABLE_PREFIX = 'shadow_'
_DEFAULT_QUOTA_NAME = 'default'
PER_PROJECT_QUOTAS = ['fixed_ips', 'floating_ips', 'networks']


def get_backend():
    """The backend is this module itself."""
    return sys.modules[__name__]


def require_admin_context(f):
    """Decorator to require admin request context.

    The first argument to the wrapped function must be the context.

    """

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        nova.context.require_admin_context(args[0])
        return f(*args, **kwargs)
    return wrapper


def require_context(f):
    """Decorator to require *any* user or admin context.

    This does no authorization for user or project access matching, see
    :py:func:`nova.context.authorize_project_context` and
    :py:func:`nova.context.authorize_user_context`.

    The first argument to the wrapped function must be the context.

    """

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        nova.context.require_context(args[0])
        return f(*args, **kwargs)
    return wrapper


def require_affinitygroup_exists(f):
    """Decorator to require the specified affinitygroup to exist.

    Requires the wrapped function to use context and affinitygroup_id as
    their first two arguments.
    """

    @functools.wraps(f)
    def wrapper(context, affinitygroup_id, *args, **kwargs):
        affinitygroup_get(context, affinitygroup_id)
        return f(context, affinitygroup_id, *args, **kwargs)
    return wrapper


def _retry_on_deadlock(f):
    """Decorator to retry a DB API call if Deadlock was received."""
    @functools.wraps(f)
    def wrapped(*args, **kwargs):
        while True:
            try:
                return f(*args, **kwargs)
            except db_exc.DBDeadlock:
                LOG.warn(_("Deadlock detected when running "
                           "'%(func_name)s': Retrying..."),
                           dict(func_name=f.__name__))
                # Retry!
                time.sleep(0.5)
                continue
    functools.update_wrapper(wrapped, f)
    return wrapped


def model_query(context, model, *args, **kwargs):
    """Query helper that accounts for context's `read_deleted` field.

    :param context: context to query under
    :param session: if present, the session to use
    :param read_deleted: if present, overrides context's read_deleted field.
    :param project_only: if present and context is user-type, then restrict
            query to match the context's project_id. If set to 'allow_none',
            restriction includes project_id = None.
    :param base_model: Where model_query is passed a "model" parameter which is
            not a subclass of NovaBase, we should pass an extra base_model
            parameter that is a subclass of NovaBase and corresponds to the
            model parameter.
    """
    session = kwargs.get('session') or get_session()
    read_deleted = kwargs.get('read_deleted') or context.read_deleted
    project_only = kwargs.get('project_only', False)

    def issubclassof_nova_base(obj):
        return isinstance(obj, type) and issubclass(obj, core_models.NovaBase)

    base_model = model
    if not issubclassof_nova_base(base_model):
        base_model = kwargs.get('base_model', None)
        if not issubclassof_nova_base(base_model):
            raise Exception(_("model or base_model parameter should be "
                              "subclass of NovaBase"))

    query = session.query(model, *args)

    default_deleted_value = base_model.__mapper__.c.deleted.default.arg
    if read_deleted == 'no':
        query = query.filter(base_model.deleted == default_deleted_value)
    elif read_deleted == 'yes':
        pass  # omit the filter to include deleted and active
    elif read_deleted == 'only':
        query = query.filter(base_model.deleted != default_deleted_value)
    else:
        raise Exception(_("Unrecognized read_deleted value '%s'")
                            % read_deleted)

    if nova.context.is_user_context(context) and project_only:
        if project_only == 'allow_none':
            query = query.\
                filter(or_(base_model.project_id == context.project_id,
                           base_model.project_id == None))
        else:
            query = query.filter_by(project_id=context.project_id)

    return query


def exact_filter(query, model, filters, legal_keys):
    """Applies exact match filtering to a query.

    Returns the updated query.  Modifies filters argument to remove
    filters consumed.

    :param query: query to apply filters to
    :param model: model object the query applies to, for IN-style
                  filtering
    :param filters: dictionary of filters; values that are lists,
                    tuples, sets, or frozensets cause an 'IN' test to
                    be performed, while exact matching ('==' operator)
                    is used for other values
    :param legal_keys: list of keys to apply exact filtering to
    """

    filter_dict = {}

    # Walk through all the keys
    for key in legal_keys:
        # Skip ones we're not filtering on
        if key not in filters:
            continue

        # OK, filtering on this key; what value do we search for?
        value = filters.pop(key)

        if key == 'metadata' or key == 'system_metadata':
            column_attr = getattr(model, key)
            if isinstance(value, list):
                for item in value:
                    for k, v in item.iteritems():
                        query = query.filter(column_attr.any(key=k))
                        query = query.filter(column_attr.any(value=v))

            else:
                for k, v in value.iteritems():
                    query = query.filter(column_attr.any(key=k))
                    query = query.filter(column_attr.any(value=v))
        elif isinstance(value, (list, tuple, set, frozenset)):
            # Looking for values in a list; apply to query directly
            column_attr = getattr(model, key)
            query = query.filter(column_attr.in_(value))
        else:
            # OK, simple exact match; save for later
            filter_dict[key] = value

    # Apply simple exact matches
    if filter_dict:
        query = query.filter_by(**filter_dict)

    return query

###################


def constraint(**conditions):
    return Constraint(conditions)


def equal_any(*values):
    return EqualityCondition(values)


def not_equal(*values):
    return InequalityCondition(values)


class Constraint(object):

    def __init__(self, conditions):
        self.conditions = conditions

    def apply(self, model, query):
        for key, condition in self.conditions.iteritems():
            for clause in condition.clauses(getattr(model, key)):
                query = query.filter(clause)
        return query


class EqualityCondition(object):

    def __init__(self, values):
        self.values = values

    def clauses(self, field):
        return or_([field == value for value in self.values])


class InequalityCondition(object):

    def __init__(self, values):
        self.values = values

    def clauses(self, field):
        return [field != value for value in self.values]

####################


def _affinitygroup_get_query(context, model_class, id_field=None,
                             id=None, session=None, read_deleted=None):
    columns_to_join = {models.AffinityGroup: ['_vms', '_metadata']}

    query = model_query(context, model_class, session=session,
                        read_deleted=read_deleted)

    for c in columns_to_join.get(model_class, []):
        query = query.options(joinedload(c))

    if id and id_field:
        query = query.filter(id_field == id)

    return query


def affinitygroup_create(context, values, metadata=None):
    session = get_session()
    query = _affinitygroup_get_query(context,
                                 models.AffinityGroup,
                                 models.AffinityGroup.name,
                                 values['name'],
                                 session=session,
                                 read_deleted='no')
    affinitygroup = query.first()
    if not affinitygroup:
        affinitygroup = models.AffinityGroup()
        affinitygroup.update(values)
        affinitygroup.save(session=session)
        # We don't want these to be lazy loaded later.  We know there is
        # nothing here since we just created this aggregate.
        affinitygroup._vms = []
        affinitygroup._metadata = []
    else:
        raise huawei_exception.\
            AffinityGroupNameExists(affinitygroup_name=values['name'])
    if metadata:
        affinitygroup_metadata_add(context, affinitygroup.id, metadata)
    return affinitygroup_get(context, affinitygroup.id)


def affinitygroup_get(context, affinitygroup_id):
    query = _affinitygroup_get_query(context,
                                 models.AffinityGroup,
                                 models.AffinityGroup.id,
                                 affinitygroup_id)
    affinitygroup = query.first()

    if not affinitygroup:
        raise huawei_exception.\
            AffinityGroupNotFound(affinitygroup_id=affinitygroup_id)

    return affinitygroup


def affinitygroup_get_by_vm(context, vm, key=None):
    """Return rows that match vm  and metadata key (optional).

    :param vm matches vm, and is required.
    :param key Matches metadata key, if not None.
    """
    query = model_query(context, models.AffinityGroup)
    query = query.options(joinedload('_vms'))
    query = query.options(joinedload('_metadata'))
    query = query.join('_vms')
    query = query.filter(models.AffinityGroupVM.vm == vm)

    affinitygroup = query.first()

    if not affinitygroup:
        raise huawei_exception.AffinityGroupNotFound(affinitygroup_id=None)

    if key:
        query = query.join("_metadata").filter(
            models.AffinityGroupMetadata.key == key)
    return query.first()


def affinitygroup_metadata_get_by_vm(context, vm, key=None):
    query = model_query(context, models.AffinityGroup)
    query = query.join("_vms")
    query = query.join("_metadata")
    query = query.filter(models.AffinityGroupVM.vm == vm)
    query = query.options(contains_eager("_metadata"))

    if key:
        query = query.filter(models.AffinityGroupMetadata.key == key)
    rows = query.all()

    metadata = collections.defaultdict(set)
    for aff in rows:
        for kv in aff._metadata:
            metadata[kv['key']].add(kv['value'])
    return dict(metadata)


def affinitygroup_metadata_get_by_metadata_key(context,
                                               affinitygroup_id, key):
    query = model_query(context, models.AffinityGroup)
    query = query.join("_metadata")
    query = query.filter(models.AffinityGroup.id == affinitygroup_id)
    query = query.options(contains_eager("_metadata"))
    query = query.filter(models.AffinityGroupMetadata.key == key)
    rows = query.all()

    metadata = collections.defaultdict(set)
    for aff in rows:
        for kv in aff._metadata:
            metadata[kv['key']].add(kv['value'])
    return dict(metadata)


def affinitygroup_vm_get_by_metadata_key(context, key):
    query = model_query(context, models.AffinityGroup)
    query = query.join("_metadata")
    query = query.filter(models.AffinityGroupMetadata.key == key)
    query = query.options(contains_eager("_metadata"))
    query = query.options(joinedload("_vms"))
    rows = query.all()

    metadata = collections.defaultdict(set)
    for aff in rows:
        for affvm in aff._vms:
            metadata[affvm.vm].add(aff._metadata[0]['value'])
    return dict(metadata)


def affinitygroup_update(context, affinitygroup_id, values):
    session = get_session()
    affinitygroup = (_affinitygroup_get_query(context,
                                      models.AffinityGroup,
                                      models.AffinityGroup.id,
                                      affinitygroup_id,
                                      session=session).first())

    set_delete = False
    if affinitygroup:
        if "availability_zone" in values:
            values.pop('availability_zone')
        if 'metadata' in values:
            metadata = values.get('metadata')
            if "availability_zone" in metadata:
                metadata.pop('availability_zone')
                values['metadata'] = metadata
        metadata = values.get('metadata')
        if metadata is not None:
            affinitygroup_metadata_add(context,
                                       affinitygroup_id,
                                   values.pop('metadata'),
                                   set_delete=set_delete)

        affinitygroup.update(values)
        affinitygroup.save(session=session)
        values['metadata'] = metadata
        return affinitygroup_get(context, affinitygroup.id)
    else:
        raise huawei_exception.\
            AffinityGroupNotFound(affinitygroup_id=affinitygroup_id)


def affinitygroup_delete(context, affinitygroup_id):
    session = get_session()
    with session.begin():
        count = _affinitygroup_get_query(context,
                                     models.AffinityGroup,
                                     models.AffinityGroup.id,
                                     affinitygroup_id,
                                     session=session).soft_delete()
        if count == 0:
            raise huawei_exception.\
                AffinityGroupNotFound(affinitygroup_id=affinitygroup_id)

        #Delete Metadata
        model_query(context,
                    models.AffinityGroupMetadata, session=session). \
            filter_by(affinitygroup_id=affinitygroup_id). \
            soft_delete()


def affinitygroup_get_all(context):
    return _affinitygroup_get_query(context, models.AffinityGroup).all()


def _affinitygroup_metadata_get_query(context, affinitygroup_id,
                                      session=None, read_deleted="yes"):
    return model_query(context,
                       models.AffinityGroupMetadata,
                       read_deleted=read_deleted,
                       session=session). \
        filter_by(affinitygroup_id=affinitygroup_id)


@require_affinitygroup_exists
def affinitygroup_metadata_get(context, affinitygroup_id):
    rows = model_query(context,
                       models.AffinityGroupMetadata). \
        filter_by(affinitygroup_id=affinitygroup_id).all()

    return dict([(r['key'], r['value']) for r in rows])


@require_affinitygroup_exists
def affinitygroup_metadata_delete(context, affinitygroup_id, key):
    count = _affinitygroup_get_query(context,
                                 models.AffinityGroupMetadata,
                                 models.AffinityGroupMetadata.affinitygroup_id,
                                 affinitygroup_id). \
        filter_by(key=key). \
        soft_delete()
    if count == 0:
        raise huawei_exception.\
            AffinityGroupMetadataNotFound(affinitygroup_id=affinitygroup_id,
                                                  metadata_key=key)


@require_affinitygroup_exists
def affinitygroup_metadata_add(context, affinitygroup_id, metadata,
                               set_delete=False, max_retries=10):
    all_keys = metadata.keys()
    for attempt in xrange(max_retries):
        try:
            session = get_session()
            with session.begin():
                query = _affinitygroup_metadata_get_query(context, affinitygroup_id,
                                                      read_deleted='no',
                                                      session=session)
                if set_delete:
                    query.filter(~models.AffinityGroupMetadata.key.in_(all_keys)). \
                        soft_delete(synchronize_session=False)

                query = \
                    query.filter(models.AffinityGroupMetadata.key.in_(all_keys))
                already_existing_keys = set()
                for meta_ref in query.all():
                    key = meta_ref.key
                    meta_ref.update({"value": metadata[key]})
                    already_existing_keys.add(key)

                for key, value in metadata.iteritems():
                    if key in already_existing_keys:
                        continue
                    meta_ref = models.AffinityGroupMetadata()
                    meta_ref.update({"key": key,
                                     "value": value,
                                     "affinitygroup_id": affinitygroup_id})
                    session.add(meta_ref)

            return metadata
        except db_exc.DBDuplicateEntry:
            # a concurrent transaction has been committed,
            # try again unless this was the last attempt
            with excutils.save_and_reraise_exception() as ctxt:
                if attempt < max_retries - 1:
                    ctxt.reraise = False
                else:
                    msg = _("Add metadata failed for affinitygroup %(id)s after "
                            "%(retries)s retries") % {"id": affinitygroup_id,
                                                      "retries": max_retries}
                    LOG.warn(msg)


@require_affinitygroup_exists
def affinitygroup_vm_get_all(context, affinitygroup_id):
    rows = model_query(context,
                       models.AffinityGroupVM). \
        filter_by(affinitygroup_id=affinitygroup_id).all()

    return [r.vm for r in rows]


@require_affinitygroup_exists
def affinitygroup_vm_delete(context, affinitygroup_id, vm):
    count = _affinitygroup_get_query(context,
                                 models.AffinityGroupVM,
                                 models.AffinityGroupVM.affinitygroup_id,
                                 affinitygroup_id). \
        filter_by(vm=vm). \
        soft_delete()
    if count == 0:
        raise huawei_exception.\
            AffinityGroupVMNotFound(affinitygroup_id=affinitygroup_id,
                                                vm=vm)


@require_affinitygroup_exists
def affinitygroup_vm_add(context, affinitygroup_id, vm):
    vm_ref = models.AffinityGroupVM()
    vm_ref.update({"vm": vm, "affinitygroup_id": affinitygroup_id})
    try:
        vm_ref.save()
    except db_exc.DBDuplicateEntry:
        raise huawei_exception.AffinityGroupVMExists(
            vm=vm, affinitygroup_id=affinitygroup_id)
    return vm_ref


@require_affinitygroup_exists
def affinitygroup_vms_delete(context, affinitygroup_id, vms):
    vms_filter = or_([models.AffinityGroupVM.vm == vm_id for vm_id in vms])
    count = _affinitygroup_get_query(context,
                                     models.AffinityGroupVM,
                                     models.AffinityGroupVM.affinitygroup_id,
                                     affinitygroup_id).\
        filter_by(vms_filter).\
        soft_delete()
    if count == 0:
        raise huawei_exception.AffinityGroupVMNotFound(
            affinitygroup_id=affinitygroup_id, vm=vms)


@require_affinitygroup_exists
def affinitygroup_vms_add(context, affinitygroup_id, vms):
    try:
        for vm in vms:
            vm_ref = models.AffinityGroupVM()
            vm_ref.update({"vm": vm, "affinitygroup_id": affinitygroup_id})
            vm_ref.save()
    except db_exc.DBDuplicateEntry:
        raise huawei_exception.AffinityGroupVMExists(
            vm=vms, affinitygroup_id=affinitygroup_id)


@require_context
def virtual_interface_update(context, vif_id, values):
    """Update virtual interface record in the database.

    :param values: = dict containing column values
    """
    session = get_session()
    with session.begin():
        vif_ref = _virtual_interface_query(context).filter_by(id=vif_id).first()
        vif_ref.update(values)
        vif_ref.save(session=session)
        return vif_ref


def _virtual_interface_query(context, session=None):
    return model_query(context, core_models.VirtualInterface, session=session,
                       read_deleted="no")


################
def _volume_connection_get_query(context, session=None,
                                 columns_to_join=None, use_slave=False,
                                 read_deleted="no"):
    if columns_to_join is None:
        columns_to_join = []

    query = model_query(context, models.VolumeConnection, session=session,
                        use_slave=use_slave, read_deleted=read_deleted)

    return query


@require_context
def volume_connection_set(context, volume_id, instance_uuid, host,
                          session=None):
    connection_info_ref = _volume_connection_get_query(context).filter_by(
        instance_uuid=instance_uuid, volume_id=volume_id, host=host).\
        first()
    if not connection_info_ref:
        # create
        connection_info_ref = models.VolumeConnection()
        connection_info_ref.host = host
        connection_info_ref.instance_uuid = instance_uuid
        connection_info_ref.volume_id = volume_id
        connection_info_ref.save()
    return connection_info_ref


@require_context
def volume_connection_unset(context, volume_id, instance_uuid,
                            host, session=None):
    _volume_connection_get_query(context).filter_by(
        instance_uuid=instance_uuid, volume_id=volume_id, host=host).\
        soft_delete()


@require_context
@_retry_on_deadlock
def volume_connection_get_num(context, volume_id, host):
    connection_info_refs = _volume_connection_get_query(context).filter_by(
        volume_id=volume_id, host=host).all()
    return len(connection_info_refs) if connection_info_refs else 0


#add for ironic volume

@require_context
def ironic_connector_get(context, node_uuid, session=None):
    if not session:
        session = get_session()

    result = model_query(context, models.IronicVolume, session=session).\
        filter_by(node_uuid=node_uuid).first()

    return result

@require_context
def ironic_connector_create(context, values):
    ironicVolume = models.IronicVolume()
    ironicVolume.update(values)
    ironicVolume.save()

    return ironicVolume

@require_context
def ironic_connector_delete(context, node_uuid):
    session = get_session()
    with session.begin():
        result = model_query(context, models.IronicVolume, session=session).\
                 filter_by(node_uuid=node_uuid).\
                 soft_delete(synchronize_session=False)

        if not result:
            raise huawei_exception.ComputeHostNotFound(node_uuid=node_uuid)