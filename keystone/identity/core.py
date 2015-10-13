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

"""Main entry point into the Identity service."""

import abc
import functools
import os
import uuid

from oslo.config import cfg
import six

from keystone import clean
from keystone.common import dependency
from keystone.common import driver_hints
from keystone.common import manager
from keystone import config
from keystone import exception
from keystone.i18n import _
from keystone.identity.mapping_backends import mapping
from keystone import notifications
from keystone.openstack.common import importutils
from keystone.openstack.common import log
from keystone import HWExtend


CONF = config.CONF

LOG = log.getLogger(__name__)


DOMAIN_CONF_FHEAD = 'keystone.'
DOMAIN_CONF_FTAIL = '.conf'


def filter_user(user_ref):
    """Filter out private items in a user dict.

    'password', 'tenants' and 'groups' are never returned.

    :returns: user_ref

    """
    if user_ref:
        user_ref = user_ref.copy()
        user_ref.pop('password', None)
        user_ref.pop('tenants', None)
        user_ref.pop('groups', None)
        user_ref.pop('domains', None)
        try:
            user_ref['extra'].pop('password', None)
            user_ref['extra'].pop('tenants', None)
        except KeyError:
            pass
    return user_ref


class DomainConfigs(dict):
    """Discover, store and provide access to domain specific configs.

    The setup_domain_drivers() call will be made via the wrapper from
    the first call to any driver function handled by this manager. This
    setup call it will scan the domain config directory for files of the form

    keystone.<domain_name>.conf

    For each file, the domain_name will be turned into a domain_id and then
    this class will:

    - Create a new config structure, adding in the specific additional options
      defined in this config file
    - Initialise a new instance of the required driver with this new config.

    """
    configured = False
    driver = None
    _any_sql = False

    def _load_driver(self, domain_config, assignment_api):
        domain_config_driver = (
            importutils.import_object(
                domain_config['cfg'].identity.driver, domain_config['cfg']))
        domain_config_driver.assignment_api = assignment_api
        return domain_config_driver

    def _load_config(self, assignment_api, file_list, domain_name):

        def assert_no_more_than_one_sql_driver(new_config, config_file):
            """Ensure there is more than one sql driver.

            Check to see if the addition of the driver in this new config
            would cause there to now be more than one sql driver.

            """
            if (new_config['driver'].is_sql and
                    (self.driver.is_sql or self._any_sql)):
                # The addition of this driver would cause us to have more than
                # one sql driver, so raise an exception.
                raise exception.MultipleSQLDriversInConfig(
                    config_file=config_file)
            self._any_sql = new_config['driver'].is_sql

        try:
            domain_ref = assignment_api.get_domain_by_name(domain_name)
        except exception.DomainNotFound:
            LOG.warning(
                _('Invalid domain name (%s) found in config file name'),
                domain_name)
            return

        # Create a new entry in the domain config dict, which contains
        # a new instance of both the conf environment and driver using
        # options defined in this set of config files.  Later, when we
        # service calls via this Manager, we'll index via this domain
        # config dict to make sure we call the right driver
        domain_config = {}
        domain_config['cfg'] = cfg.ConfigOpts()
        config.configure(conf=domain_config['cfg'])
        domain_config['cfg'](args=[], project='keystone',
                             default_config_files=file_list)
        domain_config['driver'] = self._load_driver(
            domain_config, assignment_api)
        assert_no_more_than_one_sql_driver(domain_config, file_list)
        self[domain_ref['id']] = domain_config

    def setup_domain_drivers(self, standard_driver, assignment_api):
        # This is called by the api call wrapper
        self.configured = True
        self.driver = standard_driver

        conf_dir = CONF.identity.domain_config_dir
        if not os.path.exists(conf_dir):
            LOG.warning(_('Unable to locate domain config directory: %s'),
                        conf_dir)
            return

        for r, d, f in os.walk(conf_dir):
            for fname in f:
                if (fname.startswith(DOMAIN_CONF_FHEAD) and
                        fname.endswith(DOMAIN_CONF_FTAIL)):
                    if fname.count('.') >= 2:
                        self._load_config(assignment_api,
                                          [os.path.join(r, fname)],
                                          fname[len(DOMAIN_CONF_FHEAD):
                                                -len(DOMAIN_CONF_FTAIL)])
                    else:
                        LOG.debug(('Ignoring file (%s) while scanning domain '
                                   'config directory'),
                                  fname)

    def get_domain_driver(self, domain_id):
        if domain_id in self:
            return self[domain_id]['driver']

    def get_domain_conf(self, domain_id):
        if domain_id in self:
            return self[domain_id]['cfg']

    def reload_domain_driver(self, assignment_api, domain_id):
        # Only used to support unit tests that want to set
        # new config values.  This should only be called once
        # the domains have been configured, since it relies on
        # the fact that the configuration files have already been
        # read.
        if self.configured:
            if domain_id in self:
                self[domain_id]['driver'] = (
                    self._load_driver(self[domain_id], assignment_api))
            else:
                # The standard driver
                self.driver = self.driver()
                self.driver.assignment_api = assignment_api


def domains_configured(f):
    """Wraps API calls to lazy load domain configs after init.

    This is required since the assignment manager needs to be initialized
    before this manager, and yet this manager's init wants to be
    able to make assignment calls (to build the domain configs).  So
    instead, we check if the domains have been initialized on entry
    to each call, and if requires load them,

    """
    @functools.wraps(f)
    def wrapper(self, *args, **kwargs):
        if (not self.domain_configs.configured and
                CONF.identity.domain_specific_drivers_enabled):
            self.domain_configs.setup_domain_drivers(
                self.driver, self.assignment_api)
        return f(self, *args, **kwargs)
    return wrapper


def exception_translated(exception_type):
    """Wraps API calls to map to correct exception."""

    def _exception_translated(f):
        @functools.wraps(f)
        def wrapper(self, *args, **kwargs):
            try:
                return f(self, *args, **kwargs)
            except exception.PublicIDNotFound as e:
                if exception_type == 'user':
                    raise exception.UserNotFound(user_id=e.message)
                elif exception_type == 'group':
                    raise exception.GroupNotFound(group_id=e.message)
                elif exception_type == 'assertion':
                    raise AssertionError(_('Invalid user / password'))
                else:
                    raise
        return wrapper
    return _exception_translated


@dependency.provider('identity_api')
@dependency.optional('revoke_api')
@dependency.requires('assignment_api', 'credential_api', 'id_mapping_api')
class Manager(manager.Manager):
    """Default pivot point for the Identity backend.

    See :mod:`keystone.common.manager.Manager` for more details on how this
    dynamically calls the backend.

    This class also handles the support of domain specific backends, by using
    the DomainConfigs class. The setup call for DomainConfigs is called
    from with the @domains_configured wrapper in a lazy loading fashion
    to get around the fact that we can't satisfy the assignment api it needs
    from within our __init__() function since the assignment driver is not
    itself yet initialized.

    Each of the identity calls are pre-processed here to choose, based on
    domain, which of the drivers should be called. The non-domain-specific
    driver is still in place, and is used if there is no specific driver for
    the domain in question (or we are not using multiple domain drivers).

    Starting with Juno, in order to be able to obtain the domain from
    just an ID being presented as part of an API call, a public ID to domain
    and local ID mapping is maintained.  This mapping also allows for the local
    ID of drivers that do not provide simple UUIDs (such as LDAP) to be
    referenced via a public facing ID.  The mapping itself is automatically
    generated as entities are accessed via the driver.

    This mapping is only used when:
    - the entity is being handled by anything other than the default driver, or
    - the entity is being handled by the default LDAP driver and backward
    compatible IDs are not required.

    This means that in the standard case of a single SQL backend or the default
    settings of a single LDAP backend (since backward compatible IDs is set to
    True by default), no mapping is used. An alternative approach would be to
    always use the mapping table, but in the cases where we don't need it to
    make the public and local IDs the same. It is felt that not using the
    mapping by default is a more prudent way to introduce this functionality.

    """
    _USER = 'user'
    _USER_PASSWORD = 'user_password'
    _USER_REMOVED_FROM_GROUP = 'user_removed_from_group'
    _GROUP = 'group'

    def __init__(self):
        super(Manager, self).__init__(CONF.identity.driver)
        self.domain_configs = DomainConfigs()

    # Domain ID normalization methods

    def _set_domain_id_and_mapping(self, ref, domain_id, driver,
                                   entity_type):
        """Patch the domain_id/public_id into the resulting entity(ies).

        :param ref: the entity or list of entities to post process
        :param domain_id: the domain scope used for the call
        :param driver: the driver used to execute the call
        :param entity_type: whether this is a user or group

        :returns: post processed entity or list or entities

        Called to post-process the entity being returned, using a mapping
        to substitute a public facing ID as necessary. This method must
        take into account:

        - If the driver is not domain aware, then we must set the domain
          attribute of all entities irrespective of mapping.
        - If the driver does not support UUIDs, then we always want to provide
          a mapping, except for the special case of this being the default
          driver and backward_compatible_ids is set to True. This is to ensure
          that entity IDs do not change for an existing LDAP installation (only
          single domain/driver LDAP configurations were previously supported).
        - If the driver does support UUIDs, then we always create a mapping
          entry, but use the local UUID as the public ID.  The exception to
        - this is that if we just have single driver (i.e. not using specific
          multi-domain configs), then we don't both with the mapping at all.

        """
        conf = CONF.identity

        if not self._needs_post_processing(driver):
            # a classic case would be when running with a single SQL driver
            return ref

        LOG.debug('ID Mapping - Domain ID: %(domain)s, '
                  'Default Driver: %(driver)s, '
                  'Domains: %(aware)s, UUIDs: %(generate)s, '
                  'Compatible IDs: %(compat)s',
                  {'domain': domain_id,
                   'driver': (driver == self.driver),
                   'aware': driver.is_domain_aware(),
                   'generate': driver.generates_uuids(),
                   'compat': CONF.identity_mapping.backward_compatible_ids})

        if isinstance(ref, dict):
            return self._set_domain_id_and_mapping_for_single_ref(
                ref, domain_id, driver, entity_type, conf)
        elif isinstance(ref, list):
            return [self._set_domain_id_and_mapping(
                    x, domain_id, driver, entity_type) for x in ref]
        else:
            raise ValueError(_('Expected dict or list: %s') % type(ref))

    def _needs_post_processing(self, driver):
        """Returns whether entity from driver needs domain added or mapping."""
        return (driver is not self.driver or not driver.generates_uuids() or
                not driver.is_domain_aware())

    def _set_domain_id_and_mapping_for_single_ref(self, ref, domain_id,
                                                  driver, entity_type, conf):
        LOG.debug('Local ID: %s', ref['id'])
        ref = ref.copy()

        self._insert_domain_id_if_needed(ref, driver, domain_id, conf)

        if self._is_mapping_needed(driver):
            local_entity = {'domain_id': ref['domain_id'],
                            'local_id': ref['id'],
                            'entity_type': entity_type}
            public_id = self.id_mapping_api.get_public_id(local_entity)
            if public_id:
                ref['id'] = public_id
                LOG.debug('Found existing mapping to public ID: %s',
                          ref['id'])
            else:
                # Need to create a mapping. If the driver generates UUIDs
                # then pass the local UUID in as the public ID to use.
                if driver.generates_uuids():
                    public_id = ref['id']
                ref['id'] = self.id_mapping_api.create_id_mapping(
                    local_entity, public_id)
                LOG.debug('Created new mapping to public ID: %s',
                          ref['id'])
        return ref

    def _insert_domain_id_if_needed(self, ref, driver, domain_id, conf):
        """Inserts the domain ID into the ref, if required.

        If the driver can't handle domains, then we need to insert the
        domain_id into the entity being returned.  If the domain_id is
        None that means we are running in a single backend mode, so to
        remain backwardly compatible, we put in the default domain ID.
        """
        if not driver.is_domain_aware():
            if domain_id is None:
                domain_id = conf.default_domain_id
            ref['domain_id'] = domain_id

    def _is_mapping_needed(self, driver):
        """Returns whether mapping is needed.

        There are two situations where we must use the mapping:
        - this isn't the default driver (i.e. multiple backends), or
        - we have a single backend that doesn't use UUIDs
        The exception to the above is that we must honor backward
        compatibility if this is the default driver (e.g. to support
        current LDAP)
        """
        is_not_default_driver = driver is not self.driver
        return (is_not_default_driver or (
            not driver.generates_uuids() and
            not CONF.identity_mapping.backward_compatible_ids))

    def _clear_domain_id_if_domain_unaware(self, driver, ref):
        """Clear domain_id details if driver is not domain aware."""
        if not driver.is_domain_aware() and 'domain_id' in ref:
            ref = ref.copy()
            ref.pop('domain_id')
        return ref

    def _select_identity_driver(self, domain_id):
        """Choose a backend driver for the given domain_id.

        :param domain_id: The domain_id for which we want to find a driver.  If
                          the domain_id is specified as None, then this means
                          we need a driver that handles multiple domains.

        :returns: chosen backend driver

        If there is a specific driver defined for this domain then choose it.
        If the domain is None, or there no specific backend for the given
        domain is found, then we chose the default driver.

        """
        if domain_id is None:
            driver = self.driver
        else:
            driver = (self.domain_configs.get_domain_driver(domain_id) or
                      self.driver)

        # If the driver is not domain aware (e.g. LDAP) then check to
        # ensure we are not mapping multiple domains onto it - the only way
        # that would happen is that the default driver is LDAP and the
        # domain is anything other than None or the default domain.
        if (not driver.is_domain_aware() and driver == self.driver and
            domain_id != CONF.identity.default_domain_id and
                domain_id is not None):
                    LOG.warning('Found multiple domains being mapped to a '
                                'driver that does not support that (e.g. '
                                'LDAP) - Domain ID: %(domain)s, '
                                'Default Driver: %(driver)s',
                                {'domain': domain_id,
                                 'driver': (driver == self.driver)})
                    raise exception.DomainNotFound(domain_id=domain_id)
        return driver

    def _get_domain_driver_and_entity_id(self, public_id):
        """Look up details using the public ID.

        :param public_id: the ID provided in the call

        :returns: domain_id, which can be None to indicate that the driver
                  in question supports multiple domains
                  driver selected based on this domain
                  entity_id which will is understood by the driver.

        Use the mapping table to look up the domain, driver and local entity
        that is represented by the provided public ID.  Handle the situations
        were we do not use the mapping (e.g. single driver that understands
        UUIDs etc.)

        """
        conf = CONF.identity
        # First, since we don't know anything about the entity yet, we must
        # assume it needs mapping, so long as we are using domain specific
        # drivers.
        if conf.domain_specific_drivers_enabled:
            local_id_ref = self.id_mapping_api.get_id_mapping(public_id)
            if local_id_ref:
                return (
                    local_id_ref['domain_id'],
                    self._select_identity_driver(local_id_ref['domain_id']),
                    local_id_ref['local_id'])

        # So either we are using multiple drivers but the public ID is invalid
        # (and hence was not found in the mapping table), or the public ID is
        # being handled by the default driver.  Either way, the only place left
        # to look is in that standard driver. However, we don't yet know if
        # this driver also needs mapping (e.g. LDAP in non backward
        # compatibility mode).
        driver = self.driver
        if driver.generates_uuids():
            if driver.is_domain_aware:
                # No mapping required, and the driver can handle the domain
                # information itself.  The classic case of this is the
                # current SQL driver.
                return (None, driver, public_id)
            else:
                # Although we don't have any drivers of this type, i.e. that
                # understand UUIDs but not domains, conceptually you could.
                return (conf.default_domain_id, driver, public_id)

        # So the only place left to find the ID is in the default driver which
        # we now know doesn't generate UUIDs
        if not CONF.identity_mapping.backward_compatible_ids:
            # We are not running in backward compatibility mode, so we
            # must use a mapping.
            local_id_ref = self.id_mapping_api.get_id_mapping(public_id)
            if local_id_ref:
                return (
                    local_id_ref['domain_id'],
                    driver,
                    local_id_ref['local_id'])
            else:
                raise exception.PublicIDNotFound(id=public_id)

        # If we reach here, this means that the default driver
        # requires no mapping - but also doesn't understand domains
        # (e.g. the classic single LDAP driver situation). Hence we pass
        # back the public_ID unmodified and use the default domain (to
        # keep backwards compatibility with existing installations).
        #
        # It is still possible that the public ID is just invalid in
        # which case we leave this to the caller to check.
        return (conf.default_domain_id, driver, public_id)

    def _assert_user_and_group_in_same_backend(
            self, user_entity_id, user_driver, group_entity_id, group_driver):
        """Ensures that user and group IDs are backed by the same backend.

        Raise a CrossBackendNotAllowed exception if they are not from the same
        backend, otherwise return None.

        """
        if user_driver is not group_driver:
            # Determine first if either IDs don't exist by calling
            # the driver.get methods (which will raise a NotFound
            # exception).
            user_driver.get_user(user_entity_id)
            group_driver.get_group(group_entity_id)
            # If we get here, then someone is attempting to create a cross
            # backend membership, which is not allowed.
            raise exception.CrossBackendNotAllowed(group_id=group_entity_id,
                                                   user_id=user_entity_id)

    def _mark_domain_id_filter_satisfied(self, hints):
        if hints:
            for filter in hints.filters:
                if (filter['name'] == 'domain_id' and
                        filter['comparator'] == 'equals'):
                    hints.filters.remove(filter)

    def _ensure_domain_id_in_hints(self, hints, domain_id):
        if (domain_id is not None and
                not hints.get_exact_filter_by_name('domain_id')):
            hints.add_filter('domain_id', domain_id)

    # The actual driver calls - these are pre/post processed here as
    # part of the Manager layer to make sure we:
    #
    # - select the right driver for this domain
    # - clear/set domain_ids for drivers that do not support domains
    # - create any ID mapping that might be required

    @notifications.emit_event('authenticate')
    @domains_configured
    @exception_translated('assertion')
    def authenticate(self, context, user_id, password):
        domain_id, driver, entity_id = (
            self._get_domain_driver_and_entity_id(user_id))
        ref = driver.authenticate(entity_id, password)
        return self._set_domain_id_and_mapping(
            ref, domain_id, driver, mapping.EntityType.USER)

    @notifications.created(_USER, result_id_arg_attr='id')
    @domains_configured
    @exception_translated('user')
    @HWExtend.checkOnCreate
    def create_user(self, user_ref):
        user = user_ref.copy()
        user['name'] = clean.user_name(user['name'])
        user.setdefault('enabled', True)
        user['enabled'] = clean.user_enabled(user['enabled'])
        domain_id = user['domain_id']
        self.assignment_api.get_domain(domain_id)

        # For creating a user, the domain is in the object itself
        domain_id = user_ref['domain_id']
        driver = self._select_identity_driver(domain_id)
        user = self._clear_domain_id_if_domain_unaware(driver, user)
        # Generate a local ID - in the future this might become a function of
        # the underlying driver so that it could conform to rules set down by
        # that particular driver type.
        user['id'] = uuid.uuid4().hex
        ref = driver.create_user(user['id'], user)
        return self._set_domain_id_and_mapping(
            ref, domain_id, driver, mapping.EntityType.USER)

    @domains_configured
    @exception_translated('user')
    def get_user(self, user_id):
        domain_id, driver, entity_id = (
            self._get_domain_driver_and_entity_id(user_id))
        ref = driver.get_user(entity_id)
        return self._set_domain_id_and_mapping(
            ref, domain_id, driver, mapping.EntityType.USER)

    def assert_user_enabled(self, user_id, user=None):
        """Assert the user and the user's domain are enabled.

        :raise AssertionError if the user or the user's domain is disabled.
        """
        if user is None:
            user = self.get_user(user_id)
        self.assignment_api.assert_domain_enabled(user['domain_id'])
        if not user.get('enabled', True):
            raise AssertionError(_('User is disabled: %s') % user_id)

    @domains_configured
    @exception_translated('user')
    def get_user_by_name(self, user_name, domain_id):
        driver = self._select_identity_driver(domain_id)
        ref = driver.get_user_by_name(user_name, domain_id)
        return self._set_domain_id_and_mapping(
            ref, domain_id, driver, mapping.EntityType.USER)

    @manager.response_truncated
    @domains_configured
    @exception_translated('user')
    def list_users(self, domain_scope=None, hints=None):
        driver = self._select_identity_driver(domain_scope)
        hints = hints or driver_hints.Hints()
        if driver.is_domain_aware():
            # Force the domain_scope into the hint to ensure that we only get
            # back domains for that scope.
            self._ensure_domain_id_in_hints(hints, domain_scope)
        else:
            # We are effectively satisfying any domain_id filter by the above
            # driver selection, so remove any such filter.
            self._mark_domain_id_filter_satisfied(hints)
        ref_list = driver.list_users(hints)
        return self._set_domain_id_and_mapping(
            ref_list, domain_scope, driver, mapping.EntityType.USER)

    @notifications.updated(_USER)
    @domains_configured
    @exception_translated('user')
    @HWExtend.checkOnUpdate
    def update_user(self, user_id, user_ref):
        old_user_ref = self.get_user(user_id)
        user = user_ref.copy()
        if 'name' in user:
            user['name'] = clean.user_name(user['name'])
        if 'enabled' in user:
            user['enabled'] = clean.user_enabled(user['enabled'])
        if 'domain_id' in user:
            self.assignment_api.get_domain(user['domain_id'])
        if 'id' in user:
            if user_id != user['id']:
                raise exception.ValidationError(_('Cannot change user ID'))
            # Since any ID in the user dict is now irrelevant, remove its so as
            # the driver layer won't be confused by the fact the this is the
            # public ID not the local ID
            user.pop('id')

        domain_id, driver, entity_id = (
            self._get_domain_driver_and_entity_id(user_id))
        user = self._clear_domain_id_if_domain_unaware(driver, user)
        ref = driver.update_user(entity_id, user)

        enabled_change = ((user.get('enabled') is False) and
                          user['enabled'] != old_user_ref.get('enabled'))
        if enabled_change or user.get('password') is not None:
            self.emit_invalidate_user_token_persistence(user_id)

        return self._set_domain_id_and_mapping(
            ref, domain_id, driver, mapping.EntityType.USER)

    @notifications.deleted(_USER)
    @domains_configured
    @exception_translated('user')
    def delete_user(self, user_id):
        domain_id, driver, entity_id = (
            self._get_domain_driver_and_entity_id(user_id))
        driver.delete_user(entity_id)
        self.assignment_api.delete_user(user_id)
        self.credential_api.delete_credentials_for_user(user_id)
        self.id_mapping_api.delete_id_mapping(user_id)

    @notifications.created(_GROUP, result_id_arg_attr='id')
    @domains_configured
    @exception_translated('group')
    def create_group(self, group_ref):
        group = group_ref.copy()
        group.setdefault('description', '')
        domain_id = group['domain_id']
        self.assignment_api.get_domain(domain_id)

        # For creating a group, the domain is in the object itself
        domain_id = group_ref['domain_id']
        driver = self._select_identity_driver(domain_id)
        group = self._clear_domain_id_if_domain_unaware(driver, group)
        # Generate a local ID - in the future this might become a function of
        # the underlying driver so that it could conform to rules set down by
        # that particular driver type.
        group['id'] = uuid.uuid4().hex
        ref = driver.create_group(group['id'], group)
        return self._set_domain_id_and_mapping(
            ref, domain_id, driver, mapping.EntityType.GROUP)

    @domains_configured
    @exception_translated('group')
    def get_group(self, group_id):
        domain_id, driver, entity_id = (
            self._get_domain_driver_and_entity_id(group_id))
        ref = driver.get_group(entity_id)
        return self._set_domain_id_and_mapping(
            ref, domain_id, driver, mapping.EntityType.GROUP)

    @notifications.updated(_GROUP)
    @domains_configured
    @exception_translated('group')
    def update_group(self, group_id, group):
        if 'domain_id' in group:
            self.assignment_api.get_domain(group['domain_id'])
        domain_id, driver, entity_id = (
            self._get_domain_driver_and_entity_id(group_id))
        group = self._clear_domain_id_if_domain_unaware(driver, group)
        ref = driver.update_group(entity_id, group)
        return self._set_domain_id_and_mapping(
            ref, domain_id, driver, mapping.EntityType.GROUP)

    @notifications.deleted(_GROUP)
    @domains_configured
    @exception_translated('group')
    def delete_group(self, group_id):
        domain_id, driver, entity_id = (
            self._get_domain_driver_and_entity_id(group_id))
        user_ids = (u['id'] for u in self.list_users_in_group(group_id))
        driver.delete_group(entity_id)
        self.id_mapping_api.delete_id_mapping(group_id)
        self.assignment_api.delete_group(group_id)
        for uid in user_ids:
            self.emit_invalidate_user_token_persistence(uid)

    @domains_configured
    @exception_translated('group')
    def add_user_to_group(self, user_id, group_id):
        @exception_translated('user')
        def get_entity_info_for_user(public_id):
            return self._get_domain_driver_and_entity_id(public_id)

        _domain_id, group_driver, group_entity_id = (
            self._get_domain_driver_and_entity_id(group_id))
        # Get the same info for the user_id, taking care to map any
        # exceptions correctly
        _domain_id, user_driver, user_entity_id = (
            get_entity_info_for_user(user_id))

        self._assert_user_and_group_in_same_backend(
            user_entity_id, user_driver, group_entity_id, group_driver)

        group_driver.add_user_to_group(user_entity_id, group_entity_id)

    @domains_configured
    @exception_translated('group')
    def remove_user_from_group(self, user_id, group_id):
        @exception_translated('user')
        def get_entity_info_for_user(public_id):
            return self._get_domain_driver_and_entity_id(public_id)

        _domain_id, group_driver, group_entity_id = (
            self._get_domain_driver_and_entity_id(group_id))
        # Get the same info for the user_id, taking care to map any
        # exceptions correctly
        _domain_id, user_driver, user_entity_id = (
            get_entity_info_for_user(user_id))

        self._assert_user_and_group_in_same_backend(
            user_entity_id, user_driver, group_entity_id, group_driver)

        group_driver.remove_user_from_group(user_entity_id, group_entity_id)
        self.emit_invalidate_user_token_persistence(user_id)

    @notifications.internal(notifications.INVALIDATE_USER_TOKEN_PERSISTENCE)
    def emit_invalidate_user_token_persistence(self, user_id):
        """Emit a notification to the callback system to revoke user tokens.

        This method and associated callback listener removes the need for
        making a direct call to another manager to delete and revoke tokens.

        :param user_id: user identifier
        :type user_id: string
        """
        pass

    @manager.response_truncated
    @domains_configured
    @exception_translated('user')
    def list_groups_for_user(self, user_id, hints=None):
        domain_id, driver, entity_id = (
            self._get_domain_driver_and_entity_id(user_id))
        hints = hints or driver_hints.Hints()
        if not driver.is_domain_aware():
            # We are effectively satisfying any domain_id filter by the above
            # driver selection, so remove any such filter
            self._mark_domain_id_filter_satisfied(hints)
        ref_list = driver.list_groups_for_user(entity_id, hints)
        return self._set_domain_id_and_mapping(
            ref_list, domain_id, driver, mapping.EntityType.GROUP)

    @manager.response_truncated
    @domains_configured
    @exception_translated('group')
    def list_groups(self, domain_scope=None, hints=None):
        driver = self._select_identity_driver(domain_scope)
        hints = hints or driver_hints.Hints()
        if driver.is_domain_aware():
            # Force the domain_scope into the hint to ensure that we only get
            # back domains for that scope.
            self._ensure_domain_id_in_hints(hints, domain_scope)
        else:
            # We are effectively satisfying any domain_id filter by the above
            # driver selection, so remove any such filter.
            self._mark_domain_id_filter_satisfied(hints)
        ref_list = driver.list_groups(hints)
        return self._set_domain_id_and_mapping(
            ref_list, domain_scope, driver, mapping.EntityType.GROUP)

    @manager.response_truncated
    @domains_configured
    @exception_translated('group')
    def list_users_in_group(self, group_id, hints=None):
        domain_id, driver, entity_id = (
            self._get_domain_driver_and_entity_id(group_id))
        hints = hints or driver_hints.Hints()
        if not driver.is_domain_aware():
            # We are effectively satisfying any domain_id filter by the above
            # driver selection, so remove any such filter
            self._mark_domain_id_filter_satisfied(hints)
        ref_list = driver.list_users_in_group(entity_id, hints)
        return self._set_domain_id_and_mapping(
            ref_list, domain_id, driver, mapping.EntityType.USER)

    @domains_configured
    @exception_translated('group')
    def check_user_in_group(self, user_id, group_id):
        @exception_translated('user')
        def get_entity_info_for_user(public_id):
            return self._get_domain_driver_and_entity_id(public_id)

        _domain_id, group_driver, group_entity_id = (
            self._get_domain_driver_and_entity_id(group_id))
        # Get the same info for the user_id, taking care to map any
        # exceptions correctly
        _domain_id, user_driver, user_entity_id = (
            get_entity_info_for_user(user_id))

        self._assert_user_and_group_in_same_backend(
            user_entity_id, user_driver, group_entity_id, group_driver)

        return group_driver.check_user_in_group(user_entity_id,
                                                group_entity_id)

    @domains_configured
    def change_password(self, context, user_id, original_password,
                        new_password):

        # authenticate() will raise an AssertionError if authentication fails
        self.authenticate(context, user_id, original_password)

        update_dict = {'password': new_password}
        self.update_user(user_id, update_dict)


@six.add_metaclass(abc.ABCMeta)
class Driver(object):
    """Interface description for an Identity driver."""

    def _get_list_limit(self):
        return CONF.identity.list_limit or CONF.list_limit

    def is_domain_aware(self):
        """Indicates if Driver supports domains."""
        return True

    @property
    def is_sql(self):
        """Indicates if this Driver uses SQL."""
        return False

    @property
    def multiple_domains_supported(self):
        return (self.is_domain_aware() or
                CONF.identity.domain_specific_drivers_enabled)

    def generates_uuids(self):
        """Indicates if Driver generates UUIDs as the local entity ID."""
        return True

    @abc.abstractmethod
    def authenticate(self, user_id, password):
        """Authenticate a given user and password.
        :returns: user_ref
        :raises: AssertionError
        """
        raise exception.NotImplemented()  # pragma: no cover

    # user crud

    @abc.abstractmethod
    def create_user(self, user_id, user):
        """Creates a new user.

        :raises: keystone.exception.Conflict

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_users(self, hints):
        """List users in the system.

        :param hints: filter hints which the driver should
                      implement if at all possible.

        :returns: a list of user_refs or an empty list.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_users_in_group(self, group_id, hints):
        """List users in a group.

        :param group_id: the group in question
        :param hints: filter hints which the driver should
                      implement if at all possible.

        :returns: a list of user_refs or an empty list.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_user(self, user_id):
        """Get a user by ID.

        :returns: user_ref
        :raises: keystone.exception.UserNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def update_user(self, user_id, user):
        """Updates an existing user.

        :raises: keystone.exception.UserNotFound,
                 keystone.exception.Conflict

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def add_user_to_group(self, user_id, group_id):
        """Adds a user to a group.

        :raises: keystone.exception.UserNotFound,
                 keystone.exception.GroupNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def check_user_in_group(self, user_id, group_id):
        """Checks if a user is a member of a group.

        :raises: keystone.exception.UserNotFound,
                 keystone.exception.GroupNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def remove_user_from_group(self, user_id, group_id):
        """Removes a user from a group.

        :raises: keystone.exception.NotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_user(self, user_id):
        """Deletes an existing user.

        :raises: keystone.exception.UserNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_user_by_name(self, user_name, domain_id):
        """Get a user by name.

        :returns: user_ref
        :raises: keystone.exception.UserNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

    # group crud

    @abc.abstractmethod
    def create_group(self, group_id, group):
        """Creates a new group.

        :raises: keystone.exception.Conflict

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_groups(self, hints):
        """List groups in the system.

        :param hints: filter hints which the driver should
                      implement if at all possible.

        :returns: a list of group_refs or an empty list.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_groups_for_user(self, user_id, hints):
        """List groups a user is in

        :param user_id: the user in question
        :param hints: filter hints which the driver should
                      implement if at all possible.

        :returns: a list of group_refs or an empty list.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_group(self, group_id):
        """Get a group by ID.

        :returns: group_ref
        :raises: keystone.exception.GroupNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def update_group(self, group_id, group):
        """Updates an existing group.

        :raises: keystone.exceptionGroupNotFound,
                 keystone.exception.Conflict

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_group(self, group_id):
        """Deletes an existing group.

        :raises: keystone.exception.GroupNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

    # end of identity


@dependency.provider('id_mapping_api')
class MappingManager(manager.Manager):
    """Default pivot point for the ID Mapping backend."""

    def __init__(self):
        super(MappingManager, self).__init__(CONF.identity_mapping.driver)


@six.add_metaclass(abc.ABCMeta)
class MappingDriver(object):
    """Interface description for an ID Mapping driver."""

    @abc.abstractmethod
    def get_public_id(self, local_entity):
        """Returns the public ID for the given local entity.

        :param dict local_entity: Containing the entity domain, local ID and
                                  type ('user' or 'group').
        :returns: public ID, or None if no mapping is found.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_id_mapping(self, public_id):
        """Returns the local mapping.

        :param public_id: The public ID for the mapping required.
        :returns dict: Containing the entity domain, local ID and type. If no
                       mapping is found, it returns None.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def create_id_mapping(self, local_entity, public_id=None):
        """Create and store a mapping to a public_id.

        :param dict local_entity: Containing the entity domain, local ID and
                                  type ('user' or 'group').
        :param public_id: If specified, this will be the public ID.  If this
                          is not specified, a public ID will be generated.
        :returns: public ID

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_id_mapping(self, public_id):
        """Deletes an entry for the given public_id.

        :param public_id: The public ID for the mapping to be deleted.

        The method is silent if no mapping is found.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def purge_mappings(self, purge_filter):
        """Purge selected identity mappings.

        :param dict purge_filter: Containing the attributes of the filter that
                                  defines which entries to purge. An empty
                                  filter means purge all mappings.

        """
        raise exception.NotImplemented()  # pragma: no cover
