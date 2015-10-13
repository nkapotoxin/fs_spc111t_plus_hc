# Copyright 2012 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from keystone.common import sql
from keystone.common import utils
from keystone import config
from keystone import exception
from keystone.i18n import _
from keystone import identity

from keystone.openstack.common import timeutils
from FSComponentUtil import crypt

import log as operationlog
operationlog.init('keystone-api')


# Import assignment sql to ensure that the models defined in there are
# available for the reference from User and Group to Domain.id.
from keystone.assignment.backends import sql as assignment_sql  # noqa


CONF = config.CONF


class User(sql.ModelBase, sql.DictBase):
    __tablename__ = 'user'
    attributes = ['id', 'name', 'domain_id', 'password', 'enabled',
                  'default_project_id','wrong_times','last_error_time']
    id = sql.Column(sql.String(64), primary_key=True)
    name = sql.Column(sql.String(255), nullable=False)
    domain_id = sql.Column(sql.String(64), sql.ForeignKey('domain.id'),
                           nullable=False)
    password = sql.Column(sql.String(128))
    enabled = sql.Column(sql.Boolean)
    extra = sql.Column(sql.JsonBlob())
    default_project_id = sql.Column(sql.String(64))
    wrong_times = sql.Column(sql.String(64))
    last_error_time = sql.Column(sql.String(64))
    # Unique constraint across two columns to create the separation
    # rather than just only 'name' being unique
    __table_args__ = (sql.UniqueConstraint('domain_id', 'name'), {})

    def to_dict(self, include_extra_dict=False):
        d = super(User, self).to_dict(include_extra_dict=include_extra_dict)
        if 'default_project_id' in d and d['default_project_id'] is None:
            del d['default_project_id']
        return d


class Group(sql.ModelBase, sql.DictBase):
    __tablename__ = 'group'
    attributes = ['id', 'name', 'domain_id', 'description']
    id = sql.Column(sql.String(64), primary_key=True)
    name = sql.Column(sql.String(64), nullable=False)
    domain_id = sql.Column(sql.String(64), sql.ForeignKey('domain.id'),
                           nullable=False)
    description = sql.Column(sql.Text())
    extra = sql.Column(sql.JsonBlob())
    # Unique constraint across two columns to create the separation
    # rather than just only 'name' being unique
    __table_args__ = (sql.UniqueConstraint('domain_id', 'name'), {})


class UserGroupMembership(sql.ModelBase, sql.DictBase):
    """Group membership join table."""
    __tablename__ = 'user_group_membership'
    user_id = sql.Column(sql.String(64),
                         sql.ForeignKey('user.id'),
                         primary_key=True)
    group_id = sql.Column(sql.String(64),
                          sql.ForeignKey('group.id'),
                          primary_key=True)


class Identity(identity.Driver):
    # NOTE(henry-nash): Override the __init__() method so as to take a
    # config parameter to enable sql to be used as a domain-specific driver.
    def __init__(self, conf=None):
        super(Identity, self).__init__()

    def default_assignment_driver(self):
        return "keystone.assignment.backends.sql.Assignment"

    @property
    def is_sql(self):
        return True

    def _check_password(self, password, user_ref):
        """Check the specified password against the data store.

        This is modeled on ldap/core.py.  The idea is to make it easier to
        subclass Identity so that you can still use it to store all the data,
        but use some other means to check the password.
        Note that we'll pass in the entire user_ref in case the subclass
        needs things like user_ref.get('name')
        For further justification, please see the follow up suggestion at
        https://blueprints.launchpad.net/keystone/+spec/sql-identiy-pam

        """
        return utils.check_password(password, user_ref.password)

    # Identity interface
    def authenticate(self, user_id, password):
        session = sql.get_session()
        user_ref = None
        try:
            user_ref = self._get_user(session, user_id)
        except exception.UserNotFound:
            raise AssertionError(_('Invalid user / password'))
        if not self._check_password(password, user_ref):
            raise AssertionError(_('Invalid user / password'))
        return identity.filter_user(user_ref.to_dict())

    # user crud

    @sql.handle_conflicts(conflict_type='user')
    def create_user(self, user_id, user):
        user = utils.hash_user_password(user)
        session = sql.get_session()
        try:
            user['email'] = crypt.encrypt(user['email'])
        except:
            pass
        with session.begin():
            user_ref = User.from_dict(user)
            session.add(user_ref)
        operationlog.info("User: %s, created at %s"%(user.get('name',None),timeutils.utcnow()),  extra={"type":"operate"})
        user_dict = user_ref.to_dict()
        try:
            user_dict['email'] = crypt.decrypt(user_dict['email'])
        except:
            pass
        return identity.filter_user(user_dict)

    @sql.truncated
    def list_users(self, hints):
        session = sql.get_session()
        query = session.query(User)
        user_refs = sql.filter_limit_query(User, query, hints)
        user_ref = [identity.filter_user(x.to_dict()) for x in user_refs]
        user_list = []
        for item in user_ref:
            try:
                item['email'] = crypt.decrypt(item['email'])
            except:
                pass
            user_list.append(item)
        return user_list

    def _get_user(self, session, user_id):
        user_ref = session.query(User).get(user_id)
        if not user_ref:
            raise exception.UserNotFound(user_id=user_id)
        user_dict = user_ref.to_dict()
        try:
            user_dict['email'] = crypt.decrypt(user_dict['email'])
        except:
            pass
        new_user = User.from_dict(user_dict)
        for attr in User.attributes:
            if attr != 'id':
                setattr(user_ref, attr, getattr(new_user, attr))
        user_ref.extra = new_user.extra
        return user_ref

    def get_user(self, user_id):
        session = sql.get_session()
        return identity.filter_user(self._get_user(session, user_id).to_dict())

    def get_user_by_name(self, user_name, domain_id):
        session = sql.get_session()
        query = session.query(User)
        query = query.filter_by(name=user_name)
        query = query.filter_by(domain_id=domain_id)
        try:
            user_ref = query.one()
        except sql.NotFound:
            raise exception.UserNotFound(user_id=user_name)
        user_dict = user_ref.to_dict()
        try:
            user_dict['email'] = crypt.decrypt(user_dict['email'])
        except:
            pass
        return identity.filter_user(user_dict)

    @sql.handle_conflicts(conflict_type='user')
    def update_user(self, user_id, user):
        session = sql.get_session()

        with session.begin():
            user_ref = self._get_user(session, user_id)
            old_user_dict = user_ref.to_dict()
            user = utils.hash_user_password(user)
            for k in user:
                old_user_dict[k] = user[k]
            try:
                old_user_dict['email'] = crypt.encrypt(old_user_dict['email'])
            except:
                pass
            new_user = User.from_dict(old_user_dict)
            for attr in User.attributes:
                if attr != 'id':
                    setattr(user_ref, attr, getattr(new_user, attr))
            user_ref.extra = new_user.extra
        if 'password' in user:
            operationlog.info("User: %s, changed password at: %s"%(user_id,timeutils.utcnow()),extra={"type":"operate"})
        user_dict = user_ref.to_dict(include_extra_dict=True)
        try:
            user_dict['email'] = crypt.decrypt(user_dict['email'])
        except:
            pass
        return identity.filter_user(user_dict)

    def add_user_to_group(self, user_id, group_id):
        session = sql.get_session()
        self.get_group(group_id)
        self.get_user(user_id)
        query = session.query(UserGroupMembership)
        query = query.filter_by(user_id=user_id)
        query = query.filter_by(group_id=group_id)
        rv = query.first()
        if rv:
            return

        with session.begin():
            session.add(UserGroupMembership(user_id=user_id,
                                            group_id=group_id))

    def check_user_in_group(self, user_id, group_id):
        session = sql.get_session()
        self.get_group(group_id)
        self.get_user(user_id)
        query = session.query(UserGroupMembership)
        query = query.filter_by(user_id=user_id)
        query = query.filter_by(group_id=group_id)
        if not query.first():
            raise exception.NotFound(_("User '%(user_id)s' not found in"
                                       " group '%(group_id)s'") %
                                     {'user_id': user_id,
                                      'group_id': group_id})

    def remove_user_from_group(self, user_id, group_id):
        session = sql.get_session()
        # We don't check if user or group are still valid and let the remove
        # be tried anyway - in case this is some kind of clean-up operation
        query = session.query(UserGroupMembership)
        query = query.filter_by(user_id=user_id)
        query = query.filter_by(group_id=group_id)
        membership_ref = query.first()
        if membership_ref is None:
            # Check if the group and user exist to return descriptive
            # exceptions.
            self.get_group(group_id)
            self.get_user(user_id)
            raise exception.NotFound(_("User '%(user_id)s' not found in"
                                       " group '%(group_id)s'") %
                                     {'user_id': user_id,
                                      'group_id': group_id})
        with session.begin():
            session.delete(membership_ref)

    def list_groups_for_user(self, user_id, hints):
        # TODO(henry-nash) We could implement full filtering here by enhancing
        # the join below.  However, since it is likely to be a fairly rare
        # occurrence to filter on more than the user_id already being used
        # here, this is left as future enhancement and until then we leave
        # it for the controller to do for us.
        session = sql.get_session()
        self.get_user(user_id)
        query = session.query(Group).join(UserGroupMembership)
        query = query.filter(UserGroupMembership.user_id == user_id)
        return [g.to_dict() for g in query]

    def list_users_in_group(self, group_id, hints):
        # TODO(henry-nash) We could implement full filtering here by enhancing
        # the join below.  However, since it is likely to be a fairly rare
        # occurrence to filter on more than the group_id already being used
        # here, this is left as future enhancement and until then we leave
        # it for the controller to do for us.
        session = sql.get_session()
        self.get_group(group_id)
        query = session.query(User).join(UserGroupMembership)
        query = query.filter(UserGroupMembership.group_id == group_id)

        user_ref = [identity.filter_user(u.to_dict()) for u in query]
        user_list = []
        for item in user_ref:
            try:
                item['email'] = crypt.decrypt(item['email'])
            except:
                pass
            user_list.append(item)
        return user_list

    def delete_user(self, user_id):
        session = sql.get_session()

        with session.begin():
            ref = self._get_user(session, user_id)

            q = session.query(UserGroupMembership)
            q = q.filter_by(user_id=user_id)
            q.delete(False)

            session.delete(ref)

    # group crud

    @sql.handle_conflicts(conflict_type='group')
    def create_group(self, group_id, group):
        session = sql.get_session()
        with session.begin():
            ref = Group.from_dict(group)
            session.add(ref)
        return ref.to_dict()

    @sql.truncated
    def list_groups(self, hints):
        session = sql.get_session()
        query = session.query(Group)
        refs = sql.filter_limit_query(Group, query, hints)
        return [ref.to_dict() for ref in refs]

    def _get_group(self, session, group_id):
        ref = session.query(Group).get(group_id)
        if not ref:
            raise exception.GroupNotFound(group_id=group_id)
        return ref

    def get_group(self, group_id):
        session = sql.get_session()
        return self._get_group(session, group_id).to_dict()

    @sql.handle_conflicts(conflict_type='group')
    def update_group(self, group_id, group):
        session = sql.get_session()

        with session.begin():
            ref = self._get_group(session, group_id)
            old_dict = ref.to_dict()
            for k in group:
                old_dict[k] = group[k]
            new_group = Group.from_dict(old_dict)
            for attr in Group.attributes:
                if attr != 'id':
                    setattr(ref, attr, getattr(new_group, attr))
            ref.extra = new_group.extra
        return ref.to_dict()

    def delete_group(self, group_id):
        session = sql.get_session()

        with session.begin():
            ref = self._get_group(session, group_id)

            q = session.query(UserGroupMembership)
            q = q.filter_by(group_id=group_id)
            q.delete(False)

            session.delete(ref)
