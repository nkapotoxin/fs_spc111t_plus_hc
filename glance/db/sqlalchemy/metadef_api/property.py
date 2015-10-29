# Copyright (c) 2014 Hewlett-Packard Development Company, L.P.
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


from oslo.db import exception as db_exc
from sqlalchemy import func
import sqlalchemy.orm as sa_orm

from glance.common import exception as exc
from glance.db.sqlalchemy.metadef_api import namespace as namespace_api
from glance.db.sqlalchemy.metadef_api import utils as metadef_utils
from glance.db.sqlalchemy import models_metadef as models
from glance import i18n
import glance.openstack.common.log as os_logging

LOG = os_logging.getLogger(__name__)
_LW = i18n._LW


def _get(context, property_id, session):

    try:
        query = session.query(models.MetadefProperty)\
            .filter_by(id=property_id)
        property_rec = query.one()

    except sa_orm.exc.NoResultFound:
        LOG.warn(_LW("Metadata definition property not found for id=%s",
                     property_id))
        raise exc.MetadefRecordNotFound(
            record_type='property', id=property_id)

    return property_rec


def _get_by_name(context, namespace_name, name, session):
    """get a property; raise if ns not found/visible or property not found"""

    namespace = namespace_api.get(context, namespace_name, session)
    try:
        query = session.query(models.MetadefProperty)\
            .filter_by(name=name, namespace_id=namespace['id'])
        property_rec = query.one()

    except sa_orm.exc.NoResultFound:
        msg = ("The metadata definition property with name=%(name)s"
               " was not found in namespace=%(namespace_name)s."
               % {'name': name, 'namespace_name': namespace_name})
        LOG.debug(msg)
        raise exc.MetadefPropertyNotFound(property_name=name,
                                          namespace_name=namespace_name)

    return property_rec


def get(context, namespace_name, name, session):
    """get a property; raise if ns not found/visible or property not found"""

    property_rec = _get_by_name(context, namespace_name, name, session)
    return property_rec.as_dict()


def get_all(context, namespace_name, session):
    namespace = namespace_api.get(context, namespace_name, session)
    query = session.query(models.MetadefProperty)\
        .filter_by(namespace_id=namespace['id'])
    properties = query.all()

    properties_list = []
    for prop in properties:
        properties_list.append(prop.as_dict())
    return properties_list


def create(context, namespace_name, values, session):
    namespace = namespace_api.get(context, namespace_name, session)
    values.update({'namespace_id': namespace['id']})

    property_rec = models.MetadefProperty()
    metadef_utils.drop_protected_attrs(models.MetadefProperty, values)
    property_rec.update(values.copy())

    try:
        property_rec.save(session=session)
    except db_exc.DBDuplicateEntry:
        msg = ("Can not create metadata definition property. A property"
               " with name=%(name)s already exists in"
               " namespace=%(namespace_name)s."
               % {'name': property_rec.name,
                  'namespace_name': namespace_name})
        LOG.debug(msg)
        raise exc.MetadefDuplicateProperty(
            property_name=property_rec.name,
            namespace_name=namespace_name)

    return property_rec.as_dict()


def update(context, namespace_name, property_id, values, session):
    """Update a property, raise if ns not found/visible or duplicate result"""

    namespace_api.get(context, namespace_name, session)
    property_rec = _get(context, property_id, session)
    metadef_utils.drop_protected_attrs(models.MetadefProperty, values)
    # values['updated_at'] = timeutils.utcnow() - done by TS mixin
    try:
        property_rec.update(values.copy())
        property_rec.save(session=session)
    except db_exc.DBDuplicateEntry:
        msg = ("Invalid update. It would result in a duplicate"
               " metadata definition property with the same name=%(name)s"
               " in namespace=%(namespace_name)s."
               % {'name': property_rec.name,
                  'namespace_name': namespace_name})
        LOG.debug(msg)
        emsg = (_("Invalid update. It would result in a duplicate"
                  " metadata definition property with the same name=%(name)s"
                  " in namespace=%(namespace_name)s.")
                % {'name': property_rec.name,
                   'namespace_name': namespace_name})
        raise exc.MetadefDuplicateProperty(emsg)

    return property_rec.as_dict()


def delete(context, namespace_name, property_name, session):
    property_rec = _get_by_name(
        context, namespace_name, property_name, session)
    if property_rec:
        session.delete(property_rec)
        session.flush()

    return property_rec.as_dict()


def delete_namespace_content(context, namespace_id, session):
    """Use this def only if the ns for the id has been verified as visible"""

    count = 0
    query = session.query(models.MetadefProperty)\
        .filter_by(namespace_id=namespace_id)
    count = query.delete(synchronize_session='fetch')
    return count


def delete_by_namespace_name(context, namespace_name, session):
    namespace = namespace_api.get(context, namespace_name, session)
    return delete_namespace_content(context, namespace['id'], session)


def count(context, namespace_name, session):
    """Get the count of properties for a namespace, raise if ns not found"""

    namespace = namespace_api.get(context, namespace_name, session)

    query = session.query(func.count(models.MetadefProperty.id))\
        .filter_by(namespace_id=namespace['id'])
    return query.scalar()
