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

"""Token provider interface."""

import abc
import base64
import datetime
import sys
import uuid

from keystoneclient.common import cms
from oslo.utils import timeutils
import six

from keystone.common import cache
from keystone.common import dependency
from keystone.common import manager
from keystone import config
from keystone import exception
from keystone.i18n import _
from keystone.models import token_model
from keystone import notifications
from keystone.openstack.common import log
from keystone.openstack.common import versionutils
from keystone.token import persistence


CONF = config.CONF
LOG = log.getLogger(__name__)
SHOULD_CACHE = cache.should_cache_fn('token')

# NOTE(morganfainberg): This is for compatibility in case someone was relying
# on the old location of the UnsupportedTokenVersionException for their code.
UnsupportedTokenVersionException = exception.UnsupportedTokenVersionException

# NOTE(blk-u): The config options are not available at import time.
EXPIRATION_TIME = lambda: CONF.token.cache_time

# supported token versions
V2 = token_model.V2
V3 = token_model.V3
VERSIONS = token_model.VERSIONS

# default token providers
PKI_PROVIDER = 'keystone.token.providers.pki.Provider'
PKIZ_PROVIDER = 'keystone.token.providers.pkiz.Provider'
UUID_PROVIDER = 'keystone.token.providers.uuid.Provider'

_FORMAT_TO_PROVIDER = {
    'PKI': PKI_PROVIDER,
    # should not support new options, but PKIZ keeps the option consistent
    'PKIZ': PKIZ_PROVIDER,
    'UUID': UUID_PROVIDER
}


def default_expire_time():
    """Determine when a fresh token should expire.

    Expiration time varies based on configuration (see ``[token] expiration``).

    :returns: a naive UTC datetime.datetime object

    """
    expire_delta = datetime.timedelta(seconds=CONF.token.expiration)
    return timeutils.utcnow() + expire_delta


def audit_info(parent_audit_id):
    """Build the audit data for a token.

    If ``parent_audit_id`` is None, the list will be one element in length
    containing a newly generated audit_id.

    If ``parent_audit_id`` is supplied, the list will be two elements in length
    containing a newly generated audit_id and the ``parent_audit_id``. The
    ``parent_audit_id`` will always be element index 1 in the resulting
    list.

    :param parent_audit_id: the audit of the original token in the chain
    :type parent_audit_id: str
    :returns: Keystone token audit data
    """
    audit_id = base64.urlsafe_b64encode(uuid.uuid4().bytes)[:-2]
    if parent_audit_id is not None:
        return [audit_id, parent_audit_id]
    return [audit_id]


@dependency.optional('revoke_api')
@dependency.provider('token_provider_api')
class Manager(manager.Manager):
    """Default pivot point for the token provider backend.

    See :mod:`keystone.common.manager.Manager` for more details on how this
    dynamically calls the backend.

    """

    V2 = V2
    V3 = V3
    VERSIONS = VERSIONS
    INVALIDATE_PROJECT_TOKEN_PERSISTENCE = 'invalidate_project_tokens'
    INVALIDATE_USER_TOKEN_PERSISTENCE = 'invalidate_user_tokens'
    _persistence_manager = None

    @classmethod
    def get_token_provider(cls):
        """Return package path to the configured token provider.

        The value should come from ``keystone.conf`` ``[token] provider``,
        however this method ensures backwards compatibility for
        ``keystone.conf`` ``[signing] token_format`` until Havana + 2.

        Return the provider based on ``token_format`` if ``provider`` is not
        set. Otherwise, ignore ``token_format`` and return the configured
        ``provider`` instead.

        """

        if CONF.signing.token_format:
            LOG.warn(_('[signing] token_format is deprecated. '
                       'Please change to setting the [token] provider '
                       'configuration value instead'))
            try:

                mapped = _FORMAT_TO_PROVIDER[CONF.signing.token_format]
            except KeyError:
                raise exception.UnexpectedError(
                    _('Unrecognized keystone.conf [signing] token_format: '
                      'expected either \'UUID\' or \'PKI\''))
            return mapped

        if CONF.token.provider is None:
            return UUID_PROVIDER
        else:
            return CONF.token.provider

    def __init__(self):
        super(Manager, self).__init__(self.get_token_provider())
        self._register_callback_listeners()

    def _register_callback_listeners(self):
        # This is used by the @dependency.provider decorator to register the
        # provider (token_provider_api) manager to listen for trust deletions.
        callbacks = {
            notifications.ACTIONS.deleted: [
                ['OS-TRUST:trust', self._trust_deleted_event_callback],
                ['user', self._delete_user_tokens_callback],
                ['domain', self._delete_domain_tokens_callback],
            ],
            notifications.ACTIONS.disabled: [
                ['user', self._delete_user_tokens_callback],
                ['domain', self._delete_domain_tokens_callback],
                ['project', self._delete_project_tokens_callback],
            ],
            notifications.ACTIONS.internal: [
                [notifications.INVALIDATE_USER_TOKEN_PERSISTENCE,
                    self._delete_user_tokens_callback],
                [notifications.INVALIDATE_USER_PROJECT_TOKEN_PERSISTENCE,
                    self._delete_user_project_tokens_callback],
                [notifications.INVALIDATE_USER_OAUTH_CONSUMER_TOKENS,
                    self._delete_user_oauth_consumer_tokens_callback],
            ]
        }

        for event, cb_info in six.iteritems(callbacks):
            for resource_type, callback_fns in cb_info:
                notifications.register_event_callback(event, resource_type,
                                                      callback_fns)

    @property
    def _persistence(self):
        # NOTE(morganfainberg): This should not be handled via __init__ to
        # avoid dependency injection oddities circular dependencies (where
        # the provider manager requires the token persistence manager, which
        # requires the token provider manager).
        if self._persistence_manager is None:
            self._persistence_manager = persistence.PersistenceManager()
        return self._persistence_manager

    def unique_id(self, token_id):
        """Return a unique ID for a token.

        The returned value is useful as the primary key of a database table,
        memcache store, or other lookup table.

        :returns: Given a PKI token, returns it's hashed value. Otherwise,
                  returns the passed-in value (such as a UUID token ID or an
                  existing hash).
        """
        return cms.cms_hash_token(token_id, mode=CONF.token.hash_algorithm)

    def _create_token(self, token_id, token_data):
        try:
            if isinstance(token_data['expires'], six.string_types):
                token_data['expires'] = timeutils.normalize_time(
                    timeutils.parse_isotime(token_data['expires']))
            self._persistence.create_token(token_id, token_data)
        except Exception:
            exc_info = sys.exc_info()
            # an identical token may have been created already.
            # if so, return the token_data as it is also identical
            try:
                self._persistence.get_token(token_id)
            except exception.TokenNotFound:
                six.reraise(*exc_info)

    def validate_token(self, token_id, belongs_to=None):
        unique_id = self.unique_id(token_id)
        # NOTE(morganfainberg): Ensure we never use the long-form token_id
        # (PKI) as part of the cache_key.
        token = self._validate_token(unique_id)
        self._token_belongs_to(token, belongs_to)
        self._is_valid_token(token)
        return token

    def check_revocation_v2(self, token):
        try:
            token_data = token['access']
        except KeyError:
            raise exception.TokenNotFound(_('Failed to validate token'))

        if self.revoke_api is not None:
            token_values = self.revoke_api.model.build_token_values_v2(
                token_data, CONF.identity.default_domain_id)
            self.revoke_api.check_token(token_values)

    def validate_v2_token(self, token_id, belongs_to=None):
        unique_id = self.unique_id(token_id)
        # NOTE(morganfainberg): Ensure we never use the long-form token_id
        # (PKI) as part of the cache_key.
        token_ref = self._persistence.get_token(unique_id)
        token = self._validate_v2_token(token_ref)
        self.check_revocation_v2(token)
        self._token_belongs_to(token, belongs_to)
        self._is_valid_token(token)
        return token

    def check_revocation_v3(self, token):
        try:
            token_data = token['token']
        except KeyError:
            raise exception.TokenNotFound(_('Failed to validate token'))
        if self.revoke_api is not None:
            token_values = self.revoke_api.model.build_token_values(token_data)
            self.revoke_api.check_token(token_values)

    def check_revocation(self, token):
        version = self.driver.get_token_version(token)
        if version == V2:
            return self.check_revocation_v2(token)
        else:
            return self.check_revocation_v3(token)

    def validate_v3_token(self, token_id):
        unique_id = self.unique_id(token_id)
        # NOTE(morganfainberg): Ensure we never use the long-form token_id
        # (PKI) as part of the cache_key.
        try:
            token_ref = self._persistence.get_token(unique_id)
        except (exception.ValidationError, exception.UserNotFound):
            raise exception.TokenNotFound(token_id=token_id)
        token = self._validate_v3_token(token_ref)
        self._is_valid_token(token)
        return token

    @versionutils.deprecated(
        as_of=versionutils.deprecated.JUNO,
        what='token_provider_api.check_v2_token',
        in_favor_of='token_provider_api.validate_v2_token',
        remove_in=+1)
    def check_v2_token(self, token_id, belongs_to=None):
        """Check the validity of the given V2 token.

        :param token_id: identity of the token
        :param belongs_to: optional identity of the scoped project
        :returns: None
        :raises: keystone.exception.Unauthorized
        """
        # NOTE(morganfainberg): Ensure we never use the long-form token_id
        # (PKI) as part of the cache_key.
        unique_id = self.unique_id(token_id)
        self.validate_v2_token(unique_id, belongs_to=belongs_to)

    @versionutils.deprecated(
        as_of=versionutils.deprecated.JUNO,
        what='token_provider_api.check_v3_token',
        in_favor_of='token_provider_api.validate_v3_token',
        remove_in=+1)
    def check_v3_token(self, token_id):
        """Check the validity of the given V3 token.

        :param token_id: identity of the token
        :returns: None
        :raises: keystone.exception.Unauthorized
        """
        # NOTE(morganfainberg): Ensure we never use the long-form token_id
        # (PKI) as part of the cache_key.
        unique_id = self.unique_id(token_id)
        self.validate_v3_token(unique_id)

    @cache.on_arguments(should_cache_fn=SHOULD_CACHE,
                        expiration_time=EXPIRATION_TIME)
    def _validate_token(self, token_id):
        token_ref = self._persistence.get_token(token_id)
        version = self.driver.get_token_version(token_ref)
        if version == self.V3:
            return self.driver.validate_v3_token(token_ref)
        elif version == self.V2:
            return self.driver.validate_v2_token(token_ref)
        raise exception.UnsupportedTokenVersionException()

    @cache.on_arguments(should_cache_fn=SHOULD_CACHE,
                        expiration_time=EXPIRATION_TIME)
    def _validate_v2_token(self, token_id):
        return self.driver.validate_v2_token(token_id)

    @cache.on_arguments(should_cache_fn=SHOULD_CACHE,
                        expiration_time=EXPIRATION_TIME)
    def _validate_v3_token(self, token_id):
        return self.driver.validate_v3_token(token_id)

    def _is_valid_token(self, token):
        """Verify the token is valid format and has not expired."""

        current_time = timeutils.normalize_time(timeutils.utcnow())

        try:
            # Get the data we need from the correct location (V2 and V3 tokens
            # differ in structure, Try V3 first, fall back to V2 second)
            token_data = token.get('token', token.get('access'))
            expires_at = token_data.get('expires_at',
                                        token_data.get('expires'))
            if not expires_at:
                expires_at = token_data['token']['expires']
            expiry = timeutils.normalize_time(
                timeutils.parse_isotime(expires_at))
        except Exception:
            LOG.exception(_('Unexpected error or malformed token determining '
                            'token expiry: %s'), token)
            raise exception.TokenNotFound(_('Failed to validate token'))

        if current_time < expiry:
            self.check_revocation(token)
            # Token has not expired and has not been revoked.
            return None
        else:
            raise exception.TokenNotFound(_('Failed to validate token'))

    def _token_belongs_to(self, token, belongs_to):
        """Check if the token belongs to the right tenant.

        This is only used on v2 tokens.  The structural validity of the token
        will have already been checked before this method is called.

        """
        if belongs_to:
            token_data = token['access']['token']
            if ('tenant' not in token_data or
                    token_data['tenant']['id'] != belongs_to):
                raise exception.Unauthorized()

    def issue_v2_token(self, token_ref, roles_ref=None, catalog_ref=None):
        token_id, token_data = self.driver.issue_v2_token(
            token_ref, roles_ref, catalog_ref)

        data = dict(key=token_id,
                    id=token_id,
                    expires=token_data['access']['token']['expires'],
                    user=token_ref['user'],
                    tenant=token_ref['tenant'],
                    metadata=token_ref['metadata'],
                    token_data=token_data,
                    bind=token_ref.get('bind'),
                    trust_id=token_ref['metadata'].get('trust_id'),
                    token_version=self.V2)
        self._create_token(token_id, data)

        return token_id, token_data

    def issue_v3_token(self, user_id, method_names, expires_at=None,
                       project_id=None, domain_id=None, auth_context=None,
                       trust=None, metadata_ref=None, include_catalog=True,
                       parent_audit_id=None):
        token_id, token_data = self.driver.issue_v3_token(
            user_id, method_names, expires_at, project_id, domain_id,
            auth_context, trust, metadata_ref, include_catalog,
            parent_audit_id)

        if metadata_ref is None:
            metadata_ref = {}

        if 'project' in token_data['token']:
            # project-scoped token, fill in the v2 token data
            # all we care are the role IDs

            # FIXME(gyee): is there really a need to store roles in metadata?
            role_ids = [r['id'] for r in token_data['token']['roles']]
            metadata_ref = {'roles': role_ids}

        if trust:
            metadata_ref.setdefault('trust_id', trust['id'])
            metadata_ref.setdefault('trustee_user_id',
                                    trust['trustee_user_id'])

        data = dict(key=token_id,
                    id=token_id,
                    expires=token_data['token']['expires_at'],
                    user=token_data['token']['user'],
                    tenant=token_data['token'].get('project'),
                    metadata=metadata_ref,
                    token_data=token_data,
                    trust_id=trust['id'] if trust else None,
                    token_version=self.V3)

        self._create_token(token_id, data)
        return token_id, token_data

    def invalidate_individual_token_cache(self, token_id):
        # NOTE(morganfainberg): invalidate takes the exact same arguments as
        # the normal method, this means we need to pass "self" in (which gets
        # stripped off).

        # FIXME(morganfainberg): Does this cache actually need to be
        # invalidated? We maintain a cached revocation list, which should be
        # consulted before accepting a token as valid.  For now we will
        # do the explicit individual token invalidation.

        self._validate_token.invalidate(self, token_id)
        self._validate_v2_token.invalidate(self, token_id)
        self._validate_v3_token.invalidate(self, token_id)

    def revoke_token(self, token_id, revoke_chain=False):
        if self.revoke_api:
            revoke_by_expires = False
            project_id = None
            domain_id = None

            token_ref = token_model.KeystoneToken(
                token_id=token_id,
                token_data=self.validate_token(token_id))

            user_id = token_ref.user_id
            expires_at = token_ref.expires
            audit_id = token_ref.audit_id
            audit_chain_id = token_ref.audit_chain_id
            if token_ref.project_scoped:
                project_id = token_ref.project_id
            if token_ref.domain_scoped:
                domain_id = token_ref.domain_id

            if audit_id is None and not revoke_chain:
                LOG.debug('Received token with no audit_id.')
                revoke_by_expires = True

            if audit_chain_id is None and revoke_chain:
                LOG.debug('Received token with no audit_chain_id.')
                revoke_by_expires = True

            if revoke_by_expires:
                self.revoke_api.revoke_by_expiration(user_id, expires_at,
                                                     project_id=project_id,
                                                     domain_id=domain_id)
            elif revoke_chain:
                self.revoke_api.revoke_by_audit_chain_id(audit_chain_id,
                                                         project_id=project_id,
                                                         domain_id=domain_id)
            else:
                self.revoke_api.revoke_by_audit_id(audit_id)

        if CONF.token.revoke_by_id:
            self._persistence.delete_token(token_id=token_id)

    def list_revoked_tokens(self):
        return self._persistence.list_revoked_tokens()

    def _trust_deleted_event_callback(self, service, resource_type, operation,
                                      payload):
        if CONF.token.revoke_by_id:
            trust_id = payload['resource_info']
            trust = self.trust_api.get_trust(trust_id, deleted=True)
            self._persistence.delete_tokens(user_id=trust['trustor_user_id'],
                                            trust_id=trust_id)

    def _delete_user_tokens_callback(self, service, resource_type, operation,
                                     payload):
        if CONF.token.revoke_by_id:
            user_id = payload['resource_info']
            self._persistence.delete_tokens_for_user(user_id)

    def _delete_domain_tokens_callback(self, service, resource_type,
                                       operation, payload):
        if CONF.token.revoke_by_id:
            domain_id = payload['resource_info']
            self._persistence.delete_tokens_for_domain(domain_id=domain_id)

    def _delete_user_project_tokens_callback(self, service, resource_type,
                                             operation, payload):
        if CONF.token.revoke_by_id:
            user_id = payload['resource_info']['user_id']
            project_id = payload['resource_info']['project_id']
            self._persistence.delete_tokens_for_user(user_id=user_id,
                                                     project_id=project_id)

    def _delete_project_tokens_callback(self, service, resource_type,
                                        operation, payload):
        if CONF.token.revoke_by_id:
            project_id = payload['resource_info']
            self._persistence.delete_tokens_for_users(
                self.assignment_api.list_user_ids_for_project(project_id),
                project_id=project_id)

    def _delete_user_oauth_consumer_tokens_callback(self, service,
                                                    resource_type, operation,
                                                    payload):
        if CONF.token.revoke_by_id:
            user_id = payload['resource_info']['user_id']
            consumer_id = payload['resource_info']['consumer_id']
            self._persistence.delete_tokens(user_id=user_id,
                                            consumer_id=consumer_id)


@six.add_metaclass(abc.ABCMeta)
class Provider(object):
    """Interface description for a Token provider."""

    @abc.abstractmethod
    def get_token_version(self, token_data):
        """Return the version of the given token data.

        If the given token data is unrecognizable,
        UnsupportedTokenVersionException is raised.

        :param token_data: token_data
        :type token_data: dict
        :returns: token version string
        :raises: keystone.token.provider.UnsupportedTokenVersionException
        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def issue_v2_token(self, token_ref, roles_ref=None, catalog_ref=None):
        """Issue a V2 token.

        :param token_ref: token data to generate token from
        :type token_ref: dict
        :param roles_ref: optional roles list
        :type roles_ref: dict
        :param catalog_ref: optional catalog information
        :type catalog_ref: dict
        :returns: (token_id, token_data)
        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def issue_v3_token(self, user_id, method_names, expires_at=None,
                       project_id=None, domain_id=None, auth_context=None,
                       trust=None, metadata_ref=None, include_catalog=True,
                       parent_audit_id=None):
        """Issue a V3 Token.

        :param user_id: identity of the user
        :type user_id: string
        :param method_names: names of authentication methods
        :type method_names: list
        :param expires_at: optional time the token will expire
        :type expires_at: string
        :param project_id: optional project identity
        :type project_id: string
        :param domain_id: optional domain identity
        :type domain_id: string
        :param auth_context: optional context from the authorization plugins
        :type auth_context: dict
        :param trust: optional trust reference
        :type trust: dict
        :param metadata_ref: optional metadata reference
        :type metadata_ref: dict
        :param include_catalog: optional, include the catalog in token data
        :type include_catalog: boolean
        :param parent_audit_id: optional, the audit id of the parent token
        :type parent_audit_id: string
        :returns: (token_id, token_data)
        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def validate_v2_token(self, token_ref):
        """Validate the given V2 token and return the token data.

        Must raise Unauthorized exception if unable to validate token.

        :param token_ref: the token reference
        :type token_ref: dict
        :returns: token data
        :raises: keystone.exception.TokenNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def validate_v3_token(self, token_ref):
        """Validate the given V3 token and return the token_data.

        :param token_ref: the token reference
        :type token_ref: dict
        :returns: token data
        :raises: keystone.exception.TokenNotFound
        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def _get_token_id(self, token_data):
        """Generate the token_id based upon the data in token_data.

        :param token_data: token information
        :type token_data: dict
        returns: token identifier
        """
        raise exception.NotImplemented()  # pragma: no cover
