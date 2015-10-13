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

from oslo.config import cfg
from oslo import messaging


_DEFAULT_AUTH_METHODS = ['external', 'password', 'token']
_CERTFILE = '/etc/keystone/ssl/certs/signing_cert.pem'
_KEYFILE = '/etc/keystone/ssl/private/signing_key.pem'


FILE_OPTIONS = {
    None: [
        cfg.StrOpt('admin_token', secret=True, default='ADMIN',
                   help='A "shared secret" that can be used to bootstrap '
                        'Keystone. This "token" does not represent a user, '
                        'and carries no explicit authorization. To disable '
                        'in production (highly recommended), remove '
                        'AdminTokenAuthMiddleware from your paste '
                        'application pipelines (for example, in '
                        'keystone-paste.ini).'),
        cfg.StrOpt('public_bind_host',
                   default='0.0.0.0',
                   deprecated_opts=[cfg.DeprecatedOpt('bind_host',
                                                      group='DEFAULT')],
                   help='The IP address of the network interface for the '
                        'public service to listen on.'),
        cfg.StrOpt('admin_bind_host',
                   default='0.0.0.0',
                   deprecated_opts=[cfg.DeprecatedOpt('bind_host',
                                                      group='DEFAULT')],
                   help='The IP address of the network interface for the '
                        'admin service to listen on.'),
        cfg.IntOpt('compute_port', default=8774,
                   help='(Deprecated) The port which the OpenStack Compute '
                        'service listens on. This option was only used for '
                        'string replacement in the templated catalog backend. '
                        'Templated catalogs should replace the '
                        '"$(compute_port)s" substitution with the static port '
                        'of the compute service. As of Juno, this option is '
                        'deprecated and will be removed in the L release.'),
        cfg.IntOpt('admin_port', default=35357,
                   help='The port number which the admin service listens '
                        'on.'),
        cfg.IntOpt('public_port', default=5000,
                   help='The port number which the public service listens '
                        'on.'),
        cfg.StrOpt('public_endpoint',
                   help='The base public endpoint URL for Keystone that is '
                        'advertised to clients (NOTE: this does NOT affect '
                        'how Keystone listens for connections). '
                        'Defaults to the base host URL of the request. E.g. a '
                        'request to http://server:5000/v2.0/users will '
                        'default to http://server:5000. You should only need '
                        'to set this value if the base URL contains a path '
                        '(e.g. /prefix/v2.0) or the endpoint should be found '
                        'on a different server.'),
        cfg.StrOpt('admin_endpoint',
                   help='The base admin endpoint URL for Keystone that is '
                        'advertised to clients (NOTE: this does NOT affect '
                        'how Keystone listens for connections). '
                        'Defaults to the base host URL of the request. E.g. a '
                        'request to http://server:35357/v2.0/users will '
                        'default to http://server:35357. You should only need '
                        'to set this value if the base URL contains a path '
                        '(e.g. /prefix/v2.0) or the endpoint should be found '
                        'on a different server.'),
        cfg.IntOpt('public_workers',
                   help='The number of worker processes to serve the public '
                        'WSGI application. Defaults to number of CPUs '
                        '(minimum of 2).'),
        cfg.IntOpt('admin_workers',
                   help='The number of worker processes to serve the admin '
                        'WSGI application. Defaults to number of CPUs '
                        '(minimum of 2).'),
        # default max request size is 112k
        cfg.IntOpt('max_request_body_size', default=114688,
                   help='Enforced by optional sizelimit middleware '
                        '(keystone.middleware:RequestBodySizeLimiter).'),
        cfg.IntOpt('max_param_size', default=64,
                   help='Limit the sizes of user & project ID/names.'),
        # we allow tokens to be a bit larger to accommodate PKI
        cfg.IntOpt('max_token_size', default=8192,
                   help='Similar to max_param_size, but provides an '
                        'exception for token values.'),
        cfg.StrOpt('member_role_id',
                   default='9fe2ff9ee4384b1894a90878d3e92bab',
                   help='During a SQL upgrade member_role_id will be used '
                        'to create a new role that will replace records in '
                        'the assignment table with explicit role grants. '
                        'After migration, the member_role_id will be used in '
                        'the API add_user_to_project.'),
        cfg.StrOpt('member_role_name', default='_member_',
                   help='During a SQL upgrade member_role_name will be used '
                        'to create a new role that will replace records in '
                        'the assignment table with explicit role grants. '
                        'After migration, member_role_name will be ignored.'),
        cfg.IntOpt('crypt_strength', default=40000, secret=True,
                   help='The value passed as the keyword "rounds" to '
                        'passlib\'s encrypt method.'),
        cfg.BoolOpt('tcp_keepalive', default=False,
                    help='Set this to true if you want to enable '
                         'TCP_KEEPALIVE on server sockets, i.e. sockets used '
                         'by the Keystone wsgi server for client '
                         'connections.'),
        cfg.IntOpt('tcp_keepidle',
                   default=600,
                   help='Sets the value of TCP_KEEPIDLE in seconds for each '
                        'server socket. Only applies if tcp_keepalive is '
                        'true. Not supported on OS X.'),
        cfg.IntOpt('list_limit',
                   help='The maximum number of entities that will be '
                        'returned in a collection, with no limit set by '
                        'default. This global limit may be then overridden '
                        'for a specific driver, by specifying a list_limit '
                        'in the appropriate section (e.g. [assignment]).'),
        cfg.BoolOpt('domain_id_immutable', default=True,
                    help='Set this to false if you want to enable the '
                         'ability for user, group and project entities '
                         'to be moved between domains by updating their '
                         'domain_id. Allowing such movement is not '
                         'recommended if the scope of a domain admin is being '
                         'restricted by use of an appropriate policy file '
                         '(see policy.v3cloudsample as an example).'),
        cfg.BoolOpt('strict_password_check', default=False,
                    help='If set to true, strict password length checking is '
                         'performed for password manipulation. If a password '
                         'exceeds the maximum length, the operation will fail '
                         'with an HTTP 403 Forbidden error. If set to false, '
                         'passwords are automatically truncated to the '
                         'maximum length.')],
    'identity': [
        cfg.StrOpt('default_domain_id', default='default',
                   help='This references the domain to use for all '
                        'Identity API v2 requests (which are not aware of '
                        'domains). A domain with this ID will be created '
                        'for you by keystone-manage db_sync in migration '
                        '008. The domain referenced by this ID cannot be '
                        'deleted on the v3 API, to prevent accidentally '
                        'breaking the v2 API. There is nothing special about '
                        'this domain, other than the fact that it must '
                        'exist to order to maintain support for your v2 '
                        'clients.'),
        cfg.BoolOpt('domain_specific_drivers_enabled',
                    default=False,
                    help='A subset (or all) of domains can have their own '
                         'identity driver, each with their own partial '
                         'configuration file in a domain configuration '
                         'directory. Only values specific to the domain '
                         'need to be placed in the domain specific '
                         'configuration file. This feature is disabled by '
                         'default; set to true to enable.'),
        cfg.StrOpt('domain_config_dir',
                   default='/etc/keystone/domains',
                   help='Path for Keystone to locate the domain specific '
                        'identity configuration files if '
                        'domain_specific_drivers_enabled is set to true.'),
        cfg.StrOpt('driver',
                   default=('keystone.identity.backends'
                            '.sql.Identity'),
                   help='Identity backend driver.'),
        cfg.IntOpt('max_password_length', default=4096,
                   help='Maximum supported length for user passwords; '
                        'decrease to improve performance.'),
        cfg.IntOpt('list_limit',
                   help='Maximum number of entities that will be returned in '
                        'an identity collection.'),
    ],
    'identity_mapping': [
        cfg.StrOpt('driver',
                   default=('keystone.identity.mapping_backends'
                            '.sql.Mapping'),
                   help='Keystone Identity Mapping backend driver.'),
        cfg.StrOpt('generator',
                   default=('keystone.identity.id_generators'
                            '.sha256.Generator'),
                   help='Public ID generator for user and group entities. '
                        'The Keystone identity mapper only supports '
                        'generators that produce no more than 64 characters.'),
        cfg.BoolOpt('backward_compatible_ids',
                    default=True,
                    help='The format of user and group IDs changed '
                         'in Juno for backends that do not generate UUIDs '
                         '(e.g. LDAP), with keystone providing a hash mapping '
                         'to the underlying attribute in LDAP. By default '
                         'this mapping is disabled, which ensures that '
                         'existing IDs will not change. Even when the '
                         'mapping is enabled by using domain specific '
                         'drivers, any users and groups from the default '
                         'domain being handled by LDAP will still not be '
                         'mapped to ensure their IDs remain backward '
                         'compatible. Setting this value to False will '
                         'enable the mapping for even the default LDAP '
                         'driver. It is only safe to do this if you do not '
                         'already have assignments for users and '
                         'groups from the default LDAP domain, and it is '
                         'acceptable for Keystone to provide the different '
                         'IDs to clients than it did previously.  Typically '
                         'this means that the only time you can set this '
                         'value to False is when configuring a fresh '
                         'installation.'),
    ],
    'trust': [
        cfg.BoolOpt('enabled', default=True,
                    help='Delegation and impersonation features can be '
                         'optionally disabled.'),
        cfg.StrOpt('driver',
                   default='keystone.trust.backends.sql.Trust',
                   help='Trust backend driver.')],
    'os_inherit': [
        cfg.BoolOpt('enabled', default=False,
                    help='role-assignment inheritance to projects from '
                         'owning domain can be optionally enabled.'),
    ],
    'token': [
        cfg.ListOpt('bind', default=[],
                    help='External auth mechanisms that should add bind '
                         'information to token, e.g., kerberos,x509.'),
        cfg.StrOpt('enforce_token_bind', default='permissive',
                   help='Enforcement policy on tokens presented to Keystone '
                        'with bind information. One of disabled, permissive, '
                        'strict, required or a specifically required bind '
                        'mode, e.g., kerberos or x509 to require binding to '
                        'that authentication.'),
        cfg.IntOpt('expiration', default=3600,
                   help='Amount of time a token should remain valid '
                        '(in seconds).'),
        cfg.StrOpt('provider',
                   help='Controls the token construction, validation, and '
                        'revocation operations. Core providers are '
                        '"keystone.token.providers.[pkiz|pki|uuid].'
                        'Provider". The default provider is uuid.'),
        cfg.StrOpt('driver',
                   default='keystone.token.persistence.backends.sql.Token',
                   help='Token persistence backend driver.'),
        cfg.BoolOpt('caching', default=True,
                    help='Toggle for token system caching. This has no '
                         'effect unless global caching is enabled.'),
        cfg.IntOpt('revocation_cache_time', default=3600,
                   help='Time to cache the revocation list and the revocation '
                        'events if revoke extension is enabled (in seconds). '
                        'This has no effect unless global and token '
                        'caching are enabled.'),
        cfg.IntOpt('cache_time',
                   help='Time to cache tokens (in seconds). This has no '
                        'effect unless global and token caching are '
                        'enabled.'),
        cfg.BoolOpt('revoke_by_id', default=True,
                    help='Revoke token by token identifier. Setting '
                    'revoke_by_id to true enables various forms of '
                    'enumerating tokens, e.g. `list tokens for user`. '
                    'These enumerations are processed to determine the '
                    'list of tokens to revoke. Only disable if you are '
                    'switching to using the Revoke extension with a '
                    'backend other than KVS, which stores events in memory.'),
        cfg.StrOpt('hash_algorithm', default='md5', secret=True,
                   help="The hash algorithm to use for PKI tokens. This can "
                        "be set to any algorithm that hashlib supports. "
                        "WARNING: Before changing this value, the auth_token "
                        "middleware must be configured with the "
                        "hash_algorithms, otherwise token revocation will "
                        "not be processed correctly."),
        cfg.IntOpt('forbidden_delay', default = 300),
        cfg.IntOpt('forbidden_times', default = 5),
        cfg.BoolOpt('id_no_catalog', default=False,
                    help='Determine whether the token_id contains catalog info.'),
    ],
    'revoke': [
        cfg.StrOpt('driver',
                   default='keystone.contrib.revoke.backends.kvs.Revoke',
                   help='An implementation of the backend for persisting '
                        'revocation events.'),
        cfg.IntOpt('expiration_buffer', default=1800,
                   help='This value (calculated in seconds) is added to token '
                        'expiration before a revocation event may be removed '
                        'from the backend.'),
        cfg.BoolOpt('caching', default=True,
                    help='Toggle for revocation event caching. This has no '
                         'effect unless global caching is enabled.'),
    ],
    'cache': [
        cfg.StrOpt('config_prefix', default='cache.keystone',
                   help='Prefix for building the configuration dictionary '
                        'for the cache region. This should not need to be '
                        'changed unless there is another dogpile.cache '
                        'region with the same configuration name.'),
        cfg.IntOpt('expiration_time', default=600,
                   help='Default TTL, in seconds, for any cached item in '
                        'the dogpile.cache region. This applies to any '
                        'cached method that doesn\'t have an explicit '
                        'cache expiration time defined for it.'),
        # NOTE(morganfainberg): the dogpile.cache.memory acceptable in devstack
        # and other such single-process/thread deployments. Running
        # dogpile.cache.memory in any other configuration has the same pitfalls
        # as the KVS token backend. It is recommended that either Redis or
        # Memcached are used as the dogpile backend for real workloads. To
        # prevent issues with the memory cache ending up in "production"
        # unintentionally, we register a no-op as the keystone default caching
        # backend.
        cfg.StrOpt('backend', default='keystone.common.cache.noop',
                   help='Dogpile.cache backend module. It is recommended '
                        'that Memcache with pooling '
                        '(keystone.cache.memcache_pool) or Redis '
                        '(dogpile.cache.redis) be used in production '
                        'deployments.  Small workloads (single process) '
                        'like devstack can use the dogpile.cache.memory '
                        'backend.'),
        cfg.MultiStrOpt('backend_argument', default=[],
                        help='Arguments supplied to the backend module. '
                             'Specify this option once per argument to be '
                             'passed to the dogpile.cache backend. Example '
                             'format: "<argname>:<value>".'),
        cfg.ListOpt('proxies', default=[],
                    help='Proxy classes to import that will affect the way '
                         'the dogpile.cache backend functions. See the '
                         'dogpile.cache documentation on '
                         'changing-backend-behavior.'),
        cfg.BoolOpt('enabled', default=False,
                    help='Global toggle for all caching using the '
                         'should_cache_fn mechanism.'),
        cfg.BoolOpt('debug_cache_backend', default=False,
                    help='Extra debugging from the cache backend (cache '
                         'keys, get/set/delete/etc calls). This is only '
                         'really useful if you need to see the specific '
                         'cache-backend get/set/delete calls with the '
                         'keys/values.  Typically this should be left set '
                         'to false.'),
        cfg.ListOpt('memcache_servers', default=['localhost:11211'],
                    help='Memcache servers in the format of "host:port".'
                    ' (dogpile.cache.memcache and keystone.cache.memcache_pool'
                    ' backends only)'),
        cfg.IntOpt('memcache_dead_retry',
                   default=5 * 60,
                   help='Number of seconds memcached server is considered dead'
                   ' before it is tried again. (dogpile.cache.memcache and'
                   ' keystone.cache.memcache_pool backends only)'),
        cfg.IntOpt('memcache_socket_timeout',
                   default=3,
                   help='Timeout in seconds for every call to a server.'
                   ' (dogpile.cache.memcache and keystone.cache.memcache_pool'
                   ' backends only)'),
        cfg.IntOpt('memcache_pool_maxsize',
                   default=10,
                   help='Max total number of open connections to every'
                   ' memcached server. (keystone.cache.memcache_pool backend'
                   ' only)'),
        cfg.IntOpt('memcache_pool_unused_timeout',
                   default=60,
                   help='Number of seconds a connection to memcached is held'
                   ' unused in the pool before it is closed.'
                   ' (keystone.cache.memcache_pool backend only)'),
        cfg.IntOpt('memcache_pool_connection_get_timeout',
                   default=10,
                   help='Number of seconds that an operation will wait to get '
                        'a memcache client connection.'),
    ],
    'ssl': [
        cfg.BoolOpt('enable', default=False,
                    help='Toggle for SSL support on the Keystone '
                         'eventlet servers.'),
        cfg.StrOpt('certfile',
                   default="/etc/keystone/ssl/certs/keystone.pem",
                   help='Path of the certfile for SSL. For non-production '
                        'environments, you may be interested in using '
                        '`keystone-manage ssl_setup` to generate self-signed '
                        'certificates.'),
        cfg.StrOpt('keyfile',
                   default='/etc/keystone/ssl/private/keystonekey.pem',
                   help='Path of the keyfile for SSL.'),
        cfg.StrOpt('ca_certs',
                   default='/etc/keystone/ssl/certs/ca.pem',
                   help='Path of the ca cert file for SSL.'),
        cfg.StrOpt('ca_key',
                   default='/etc/keystone/ssl/private/cakey.pem',
                   help='Path of the CA key file for SSL.'),
        cfg.BoolOpt('cert_required', default=False,
                    help='Require client certificate.'),
        cfg.IntOpt('key_size', default=1024,
                   help='SSL key length (in bits) (auto generated '
                        'certificate).'),
        cfg.IntOpt('valid_days', default=3650,
                   help='Days the certificate is valid for once signed '
                        '(auto generated certificate).'),
        cfg.StrOpt('cert_subject',
                   default='/C=US/ST=Unset/L=Unset/O=Unset/CN=localhost',
                   help='SSL certificate subject (auto generated '
                        'certificate).'),
    ],
    'signing': [
        cfg.StrOpt('token_format',
                   help='Deprecated in favor of provider in the '
                        '[token] section.'),
        cfg.StrOpt('certfile',
                   default=_CERTFILE,
                   help='Path of the certfile for token signing. For '
                        'non-production environments, you may be interested '
                        'in using `keystone-manage pki_setup` to generate '
                        'self-signed certificates.'),
        cfg.StrOpt('keyfile',
                   default=_KEYFILE,
                   help='Path of the keyfile for token signing.'),
        cfg.StrOpt('ca_certs',
                   default='/etc/keystone/ssl/certs/ca.pem',
                   help='Path of the CA for token signing.'),
        cfg.StrOpt('ca_key',
                   default='/etc/keystone/ssl/private/cakey.pem',
                   help='Path of the CA key for token signing.'),
        cfg.IntOpt('key_size', default=2048,
                   help='Key size (in bits) for token signing cert '
                        '(auto generated certificate).'),
        cfg.IntOpt('valid_days', default=3650,
                   help='Days the token signing cert is valid for '
                        '(auto generated certificate).'),
        cfg.StrOpt('cert_subject',
                   default=('/C=US/ST=Unset/L=Unset/O=Unset/'
                            'CN=www.example.com'),
                   help='Certificate subject (auto generated certificate) for '
                        'token signing.'),
    ],
    'assignment': [
        # assignment has no default for backward compatibility reasons.
        # If assignment driver is not specified, the identity driver chooses
        # the backend
        cfg.StrOpt('driver',
                   help='Assignment backend driver.'),
        cfg.BoolOpt('caching', default=True,
                    help='Toggle for assignment caching. This has no effect '
                         'unless global caching is enabled.'),
        cfg.IntOpt('cache_time',
                   help='TTL (in seconds) to cache assignment data. This has '
                        'no effect unless global caching is enabled.'),
        cfg.IntOpt('list_limit',
                   help='Maximum number of entities that will be returned '
                        'in an assignment collection.'),
    ],
    'credential': [
        cfg.StrOpt('driver',
                   default=('keystone.credential.backends'
                            '.sql.Credential'),
                   help='Credential backend driver.'),
    ],
    'oauth1': [
        cfg.StrOpt('driver',
                   default='keystone.contrib.oauth1.backends.sql.OAuth1',
                   help='Credential backend driver.'),
        cfg.IntOpt('request_token_duration', default=28800,
                   help='Duration (in seconds) for the OAuth Request Token.'),
        cfg.IntOpt('access_token_duration', default=86400,
                   help='Duration (in seconds) for the OAuth Access Token.'),
    ],
    'federation': [
        cfg.StrOpt('driver',
                   default='keystone.contrib.federation.'
                           'backends.sql.Federation',
                   help='Federation backend driver.'),
        cfg.StrOpt('assertion_prefix', default='',
                   help='Value to be used when filtering assertion parameters '
                        'from the environment.'),
    ],
    'policy': [
        cfg.StrOpt('driver',
                   default='keystone.policy.backends.sql.Policy',
                   help='Policy backend driver.'),
        cfg.IntOpt('list_limit',
                   help='Maximum number of entities that will be returned '
                        'in a policy collection.'),
    ],
    'ec2': [
        cfg.StrOpt('driver',
                   default='keystone.contrib.ec2.backends.kvs.Ec2',
                   help='EC2Credential backend driver.'),
    ],
    'endpoint_filter': [
        cfg.StrOpt('driver',
                   default='keystone.contrib.endpoint_filter.backends'
                           '.sql.EndpointFilter',
                   help='Endpoint Filter backend driver'),
        cfg.BoolOpt('return_all_endpoints_if_no_filter', default=True,
                    help='Toggle to return all active endpoints if no filter '
                         'exists.'),
    ],
    'endpoint_policy': [
        cfg.StrOpt('driver',
                   default='keystone.contrib.endpoint_policy.backends'
                           '.sql.EndpointPolicy',
                   help='Endpoint policy backend driver'),
    ],
    'stats': [
        cfg.StrOpt('driver',
                   default=('keystone.contrib.stats.backends'
                            '.kvs.Stats'),
                   help='Stats backend driver.'),
    ],
    'ldap': [
        cfg.StrOpt('url', default='ldap://localhost',
                   help='URL for connecting to the LDAP server.'),
        cfg.StrOpt('user',
                   help='User BindDN to query the LDAP server.'),
        cfg.StrOpt('password', secret=True,
                   help='Password for the BindDN to query the LDAP server.'),
        cfg.StrOpt('suffix', default='cn=example,cn=com',
                   help='LDAP server suffix'),
        cfg.BoolOpt('use_dumb_member', default=False,
                    help='If true, will add a dummy member to groups. This is '
                         'required if the objectclass for groups requires the '
                         '"member" attribute.'),
        cfg.StrOpt('dumb_member', default='cn=dumb,dc=nonexistent',
                   help='DN of the "dummy member" to use when '
                        '"use_dumb_member" is enabled.'),
        cfg.BoolOpt('allow_subtree_delete', default=False,
                    help='Delete subtrees using the subtree delete control. '
                         'Only enable this option if your LDAP server '
                         'supports subtree deletion.'),
        cfg.StrOpt('query_scope', default='one',
                   help='The LDAP scope for queries, this can be either '
                        '"one" (onelevel/singleLevel) or "sub" '
                        '(subtree/wholeSubtree).'),
        cfg.IntOpt('page_size', default=0,
                   help='Maximum results per page; a value of zero ("0") '
                        'disables paging.'),
        cfg.StrOpt('alias_dereferencing', default='default',
                   help='The LDAP dereferencing option for queries. This '
                        'can be either "never", "searching", "always", '
                        '"finding" or "default". The "default" option falls '
                        'back to using default dereferencing configured by '
                        'your ldap.conf.'),
        cfg.IntOpt('debug_level',
                   help='Sets the LDAP debugging level for LDAP calls. '
                        'A value of 0 means that debugging is not enabled. '
                        'This value is a bitmask, consult your LDAP '
                        'documentation for possible values.'),
        cfg.BoolOpt('chase_referrals',
                    help='Override the system\'s default referral chasing '
                         'behavior for queries.'),
        cfg.StrOpt('user_tree_dn',
                   help='Search base for users.'),
        cfg.StrOpt('user_filter',
                   help='LDAP search filter for users.'),
        cfg.StrOpt('user_objectclass', default='inetOrgPerson',
                   help='LDAP objectclass for users.'),
        cfg.StrOpt('user_id_attribute', default='cn',
                   help='LDAP attribute mapped to user id. '
                        'WARNING: must not be a multivalued attribute.'),
        cfg.StrOpt('user_name_attribute', default='sn',
                   help='LDAP attribute mapped to user name.'),
        cfg.StrOpt('user_mail_attribute', default='mail',
                   help='LDAP attribute mapped to user email.'),
        cfg.StrOpt('user_pass_attribute', default='userPassword',
                   help='LDAP attribute mapped to password.'),
        cfg.StrOpt('user_enabled_attribute', default='enabled',
                   help='LDAP attribute mapped to user enabled flag.'),
        cfg.BoolOpt('user_enabled_invert', default=False,
                    help='Invert the meaning of the boolean enabled values. '
                         'Some LDAP servers use a boolean lock attribute '
                         'where "true" means an account is disabled. Setting '
                         '"user_enabled_invert = true" will allow these lock '
                         'attributes to be used. This setting will have no '
                         'effect if "user_enabled_mask" or '
                         '"user_enabled_emulation" settings are in use.'),
        cfg.IntOpt('user_enabled_mask', default=0,
                   help='Bitmask integer to indicate the bit that the enabled '
                        'value is stored in if the LDAP server represents '
                        '"enabled" as a bit on an integer rather than a '
                        'boolean. A value of "0" indicates the mask is not '
                        'used. If this is not set to "0" the typical value '
                        'is "2". This is typically used when '
                        '"user_enabled_attribute = userAccountControl".'),
        cfg.StrOpt('user_enabled_default', default='True',
                   help='Default value to enable users. This should match an '
                        'appropriate int value if the LDAP server uses '
                        'non-boolean (bitmask) values to indicate if a user '
                        'is enabled or disabled. If this is not set to "True" '
                        'the typical value is "512". This is typically used '
                        'when "user_enabled_attribute = userAccountControl".'),
        cfg.ListOpt('user_attribute_ignore',
                    default=['default_project_id', 'tenants'],
                    help='List of attributes stripped off the user on '
                         'update.'),
        cfg.StrOpt('user_default_project_id_attribute',
                   help='LDAP attribute mapped to default_project_id for '
                        'users.'),
        cfg.BoolOpt('user_allow_create', default=True,
                    help='Allow user creation in LDAP backend.'),
        cfg.BoolOpt('user_allow_update', default=True,
                    help='Allow user updates in LDAP backend.'),
        cfg.BoolOpt('user_allow_delete', default=True,
                    help='Allow user deletion in LDAP backend.'),
        cfg.BoolOpt('user_enabled_emulation', default=False,
                    help='If true, Keystone uses an alternative method to '
                         'determine if a user is enabled or not by checking '
                         'if they are a member of the '
                         '"user_enabled_emulation_dn" group.'),
        cfg.StrOpt('user_enabled_emulation_dn',
                   help='DN of the group entry to hold enabled users when '
                        'using enabled emulation.'),
        cfg.ListOpt('user_additional_attribute_mapping',
                    default=[],
                    help='List of additional LDAP attributes used for mapping '
                         'additional attribute mappings for users. Attribute '
                         'mapping format is <ldap_attr>:<user_attr>, where '
                         'ldap_attr is the attribute in the LDAP entry and '
                         'user_attr is the Identity API attribute.'),

        cfg.StrOpt('project_tree_dn',
                   deprecated_opts=[cfg.DeprecatedOpt(
                       'tenant_tree_dn', group='ldap')],
                   help='Search base for projects'),
        cfg.StrOpt('project_filter',
                   deprecated_opts=[cfg.DeprecatedOpt(
                       'tenant_filter', group='ldap')],
                   help='LDAP search filter for projects.'),
        cfg.StrOpt('project_objectclass', default='groupOfNames',
                   deprecated_opts=[cfg.DeprecatedOpt(
                       'tenant_objectclass', group='ldap')],
                   help='LDAP objectclass for projects.'),
        cfg.StrOpt('project_id_attribute', default='cn',
                   deprecated_opts=[cfg.DeprecatedOpt(
                       'tenant_id_attribute', group='ldap')],
                   help='LDAP attribute mapped to project id.'),
        cfg.StrOpt('project_member_attribute', default='member',
                   deprecated_opts=[cfg.DeprecatedOpt(
                       'tenant_member_attribute', group='ldap')],
                   help='LDAP attribute mapped to project membership for '
                        'user.'),
        cfg.StrOpt('project_name_attribute', default='ou',
                   deprecated_opts=[cfg.DeprecatedOpt(
                       'tenant_name_attribute', group='ldap')],
                   help='LDAP attribute mapped to project name.'),
        cfg.StrOpt('project_desc_attribute', default='description',
                   deprecated_opts=[cfg.DeprecatedOpt(
                       'tenant_desc_attribute', group='ldap')],
                   help='LDAP attribute mapped to project description.'),
        cfg.StrOpt('project_enabled_attribute', default='enabled',
                   deprecated_opts=[cfg.DeprecatedOpt(
                       'tenant_enabled_attribute', group='ldap')],
                   help='LDAP attribute mapped to project enabled.'),
        cfg.StrOpt('project_domain_id_attribute',
                   deprecated_opts=[cfg.DeprecatedOpt(
                       'tenant_domain_id_attribute', group='ldap')],
                   default='businessCategory',
                   help='LDAP attribute mapped to project domain_id.'),
        cfg.ListOpt('project_attribute_ignore', default=[],
                    deprecated_opts=[cfg.DeprecatedOpt(
                        'tenant_attribute_ignore', group='ldap')],
                    help='List of attributes stripped off the project on '
                         'update.'),
        cfg.BoolOpt('project_allow_create', default=True,
                    deprecated_opts=[cfg.DeprecatedOpt(
                        'tenant_allow_create', group='ldap')],
                    help='Allow project creation in LDAP backend.'),
        cfg.BoolOpt('project_allow_update', default=True,
                    deprecated_opts=[cfg.DeprecatedOpt(
                        'tenant_allow_update', group='ldap')],
                    help='Allow project update in LDAP backend.'),
        cfg.BoolOpt('project_allow_delete', default=True,
                    deprecated_opts=[cfg.DeprecatedOpt(
                        'tenant_allow_delete', group='ldap')],
                    help='Allow project deletion in LDAP backend.'),
        cfg.BoolOpt('project_enabled_emulation', default=False,
                    deprecated_opts=[cfg.DeprecatedOpt(
                        'tenant_enabled_emulation', group='ldap')],
                    help='If true, Keystone uses an alternative method to '
                         'determine if a project is enabled or not by '
                         'checking if they are a member of the '
                         '"project_enabled_emulation_dn" group.'),
        cfg.StrOpt('project_enabled_emulation_dn',
                   deprecated_opts=[cfg.DeprecatedOpt(
                       'tenant_enabled_emulation_dn', group='ldap')],
                   help='DN of the group entry to hold enabled projects when '
                        'using enabled emulation.'),
        cfg.ListOpt('project_additional_attribute_mapping',
                    deprecated_opts=[cfg.DeprecatedOpt(
                        'tenant_additional_attribute_mapping', group='ldap')],
                    default=[],
                    help='Additional attribute mappings for projects. '
                         'Attribute mapping format is '
                         '<ldap_attr>:<user_attr>, where ldap_attr is the '
                         'attribute in the LDAP entry and user_attr is the '
                         'Identity API attribute.'),

        cfg.StrOpt('role_tree_dn',
                   help='Search base for roles.'),
        cfg.StrOpt('role_filter',
                   help='LDAP search filter for roles.'),
        cfg.StrOpt('role_objectclass', default='organizationalRole',
                   help='LDAP objectclass for roles.'),
        cfg.StrOpt('role_id_attribute', default='cn',
                   help='LDAP attribute mapped to role id.'),
        cfg.StrOpt('role_name_attribute', default='ou',
                   help='LDAP attribute mapped to role name.'),
        cfg.StrOpt('role_member_attribute', default='roleOccupant',
                   help='LDAP attribute mapped to role membership.'),
        cfg.ListOpt('role_attribute_ignore', default=[],
                    help='List of attributes stripped off the role on '
                         'update.'),
        cfg.BoolOpt('role_allow_create', default=True,
                    help='Allow role creation in LDAP backend.'),
        cfg.BoolOpt('role_allow_update', default=True,
                    help='Allow role update in LDAP backend.'),
        cfg.BoolOpt('role_allow_delete', default=True,
                    help='Allow role deletion in LDAP backend.'),
        cfg.ListOpt('role_additional_attribute_mapping',
                    default=[],
                    help='Additional attribute mappings for roles. Attribute '
                         'mapping format is <ldap_attr>:<user_attr>, where '
                         'ldap_attr is the attribute in the LDAP entry and '
                         'user_attr is the Identity API attribute.'),

        cfg.StrOpt('group_tree_dn',
                   help='Search base for groups.'),
        cfg.StrOpt('group_filter',
                   help='LDAP search filter for groups.'),
        cfg.StrOpt('group_objectclass', default='groupOfNames',
                   help='LDAP objectclass for groups.'),
        cfg.StrOpt('group_id_attribute', default='cn',
                   help='LDAP attribute mapped to group id.'),
        cfg.StrOpt('group_name_attribute', default='ou',
                   help='LDAP attribute mapped to group name.'),
        cfg.StrOpt('group_member_attribute', default='member',
                   help='LDAP attribute mapped to show group membership.'),
        cfg.StrOpt('group_desc_attribute', default='description',
                   help='LDAP attribute mapped to group description.'),
        cfg.ListOpt('group_attribute_ignore', default=[],
                    help='List of attributes stripped off the group on '
                         'update.'),
        cfg.BoolOpt('group_allow_create', default=True,
                    help='Allow group creation in LDAP backend.'),
        cfg.BoolOpt('group_allow_update', default=True,
                    help='Allow group update in LDAP backend.'),
        cfg.BoolOpt('group_allow_delete', default=True,
                    help='Allow group deletion in LDAP backend.'),
        cfg.ListOpt('group_additional_attribute_mapping',
                    default=[],
                    help='Additional attribute mappings for groups. Attribute '
                         'mapping format is <ldap_attr>:<user_attr>, where '
                         'ldap_attr is the attribute in the LDAP entry and '
                         'user_attr is the Identity API attribute.'),

        cfg.StrOpt('tls_cacertfile',
                   help='CA certificate file path for communicating with '
                        'LDAP servers.'),
        cfg.StrOpt('tls_cacertdir',
                   help='CA certificate directory path for communicating with '
                        'LDAP servers.'),
        cfg.BoolOpt('use_tls', default=False,
                    help='Enable TLS for communicating with LDAP servers.'),
        cfg.StrOpt('tls_req_cert', default='demand',
                   help='Valid options for tls_req_cert are demand, never, '
                        'and allow.'),
        cfg.BoolOpt('use_pool', default=False,
                    help='Enable LDAP connection pooling.'),
        cfg.IntOpt('pool_size', default=10,
                   help='Connection pool size.'),
        cfg.IntOpt('pool_retry_max', default=3,
                   help='Maximum count of reconnect trials.'),
        cfg.FloatOpt('pool_retry_delay', default=0.1,
                     help='Time span in seconds to wait between two '
                          'reconnect trials.'),
        cfg.IntOpt('pool_connection_timeout', default=-1,
                   help='Connector timeout in seconds. Value -1 indicates '
                        'indefinite wait for response.'),
        cfg.IntOpt('pool_connection_lifetime', default=600,
                   help='Connection lifetime in seconds.'),
        cfg.BoolOpt('use_auth_pool', default=False,
                    help='Enable LDAP connection pooling for end user '
                         'authentication. If use_pool is disabled, then this '
                         'setting is meaningless and is not used at all.'),
        cfg.IntOpt('auth_pool_size', default=100,
                   help='End user auth connection pool size.'),
        cfg.IntOpt('auth_pool_connection_lifetime', default=60,
                   help='End user auth connection lifetime in seconds.'),
    ],
    'auth': [
        cfg.ListOpt('methods', default=_DEFAULT_AUTH_METHODS,
                    help='Default auth methods.'),
        cfg.StrOpt('password',
                   default='keystone.auth.plugins.password.Password',
                   help='The password auth plugin module.'),
        cfg.StrOpt('token',
                   default='keystone.auth.plugins.token.Token',
                   help='The token auth plugin module.'),
        # deals with REMOTE_USER authentication
        cfg.StrOpt('external',
                   default='keystone.auth.plugins.external.DefaultDomain',
                   help='The external (REMOTE_USER) auth plugin module.'),
    ],
    'paste_deploy': [
        cfg.StrOpt('config_file', default='keystone-paste.ini',
                   help='Name of the paste configuration file that defines '
                        'the available pipelines.'),
    ],
    'memcache': [
        cfg.ListOpt('servers', default=['localhost:11211'],
                    help='Memcache servers in the format of "host:port".'),
        cfg.IntOpt('dead_retry',
                   default=5 * 60,
                   help='Number of seconds memcached server is considered dead'
                        ' before it is tried again. This is used by the key '
                        'value store system (e.g. token '
                        'pooled memcached persistence backend).'),
        cfg.IntOpt('socket_timeout',
                   default=3,
                   help='Timeout in seconds for every call to a server. This '
                        'is used by the key value store system (e.g. token '
                        'pooled memcached persistence backend).'),
        cfg.IntOpt('pool_maxsize',
                   default=10,
                   help='Max total number of open connections to every'
                        ' memcached server. This is used by the key value '
                        'store system (e.g. token pooled memcached '
                        'persistence backend).'),
        cfg.IntOpt('pool_unused_timeout',
                   default=60,
                   help='Number of seconds a connection to memcached is held'
                        ' unused in the pool before it is closed. This is used'
                        ' by the key value store system (e.g. token pooled '
                        'memcached persistence backend).'),
        cfg.IntOpt('pool_connection_get_timeout',
                   default=10,
                   help='Number of seconds that an operation will wait to get '
                        'a memcache client connection. This is used by the '
                        'key value store system (e.g. token pooled memcached '
                        'persistence backend).'),
    ],
    'catalog': [
        cfg.StrOpt('template_file',
                   default='default_catalog.templates',
                   help='Catalog template file name for use with the '
                        'template catalog backend.'),
        cfg.StrOpt('driver',
                   default='keystone.catalog.backends.sql.Catalog',
                   help='Catalog backend driver.'),
        cfg.BoolOpt('caching', default=True,
                    help='Toggle for catalog caching. This has no '
                         'effect unless global caching is enabled.'),
        cfg.IntOpt('cache_time',
                   help='Time to cache catalog data (in seconds). This has no '
                        'effect unless global and catalog caching are '
                        'enabled.'),
        cfg.IntOpt('list_limit',
                   help='Maximum number of entities that will be returned '
                        'in a catalog collection.'),
        cfg.ListOpt('endpoint_substitution_whitelist',
                    default=['tenant_id', 'user_id', 'public_bind_host',
                             'admin_bind_host', 'compute_host', 'compute_port',
                             'admin_port', 'public_port', 'public_endpoint',
                             'admin_endpoint'],
                    help='(Deprecated) List of possible substitutions for use '
                         'in formatting endpoints. Use caution when modifying '
                         'this list. It will give users with permission to '
                         'create endpoints the ability to see those values '
                         'in your configuration file. This option will be '
                         'removed in Juno.'),
    ],
    'kvs': [
        cfg.ListOpt('backends', default=[],
                    help='Extra dogpile.cache backend modules to register '
                         'with the dogpile.cache library.'),
        cfg.StrOpt('config_prefix', default='keystone.kvs',
                   help='Prefix for building the configuration dictionary '
                        'for the KVS region. This should not need to be '
                        'changed unless there is another dogpile.cache '
                        'region with the same configuration name.'),
        cfg.BoolOpt('enable_key_mangler', default=True,
                    help='Toggle to disable using a key-mangling function '
                         'to ensure fixed length keys. This is toggle-able '
                         'for debugging purposes, it is highly recommended '
                         'to always leave this set to true.'),
        cfg.IntOpt('default_lock_timeout', default=5,
                   help='Default lock timeout for distributed locking.'),
    ],
    'saml': [
        cfg.IntOpt('assertion_expiration_time', default=3600,
                   help='Default TTL, in seconds, for any generated SAML '
                        'assertion created by Keystone.'),
        cfg.StrOpt('xmlsec1_binary',
                   default='xmlsec1',
                   help='Binary to be called for XML signing. Install the '
                        'appropriate package, specify absolute path or adjust '
                        'your PATH environment variable if the binary cannot '
                        'be found.'),
        cfg.StrOpt('certfile',
                   default=_CERTFILE,
                   help='Path of the certfile for SAML signing. For '
                        'non-production environments, you may be interested '
                        'in using `keystone-manage pki_setup` to generate '
                        'self-signed certificates. Note, the path cannot '
                        'contain a comma.'),
        cfg.StrOpt('keyfile',
                   default=_KEYFILE,
                   help='Path of the keyfile for SAML signing. Note, the path '
                        'cannot contain a comma.'),
        cfg.StrOpt('idp_entity_id',
                   help='Entity ID value for unique Identity Provider '
                        'identification. Usually FQDN is set with a suffix. '
                        'A value is required to generate IDP Metadata. '
                        'For example: https://keystone.example.com/v3/'
                        'OS-FEDERATION/saml2/idp'),
        cfg.StrOpt('idp_sso_endpoint',
                   help='Identity Provider Single-Sign-On service value, '
                        'required in the Identity Provider\'s metadata. '
                        'A value is required to generate IDP Metadata. '
                        'For example: https://keystone.example.com/v3/'
                        'OS-FEDERATION/saml2/sso'),
        cfg.StrOpt('idp_lang', default='en',
                   help='Language used by the organization.'),
        cfg.StrOpt('idp_organization_name',
                   help='Organization name the installation belongs to.'),
        cfg.StrOpt('idp_organization_display_name',
                   help='Organization name to be displayed.'),
        cfg.StrOpt('idp_organization_url',
                   help='URL of the organization.'),
        cfg.StrOpt('idp_contact_company',
                   help='Company of contact person.'),
        cfg.StrOpt('idp_contact_name',
                   help='Given name of contact person'),
        cfg.StrOpt('idp_contact_surname',
                   help='Surname of contact person.'),
        cfg.StrOpt('idp_contact_email',
                   help='Email address of contact person.'),
        cfg.StrOpt('idp_contact_telephone',
                   help='Telephone number of contact person.'),
        cfg.StrOpt('idp_contact_type', default='other',
                   help='Contact type. Allowed values are: '
                        'technical, support, administrative '
                        'billing, and other'),
        cfg.StrOpt('idp_metadata_path',
                   default='/etc/keystone/saml2_idp_metadata.xml',
                   help='Path to the Identity Provider Metadata file. '
                        'This file should be generated with the '
                        'keystone-manage saml_idp_metadata command.'),
    ],
}


CONF = cfg.CONF
messaging.set_transport_defaults(control_exchange='keystone')


def _register_auth_plugin_opt(conf, option):
    conf.register_opt(option, group='auth')


def setup_authentication(conf=None):
    # register any non-default auth methods here (used by extensions, etc)
    if conf is None:
        conf = CONF
    for method_name in conf.auth.methods:
        if method_name not in _DEFAULT_AUTH_METHODS:
            option = cfg.StrOpt(method_name)
            _register_auth_plugin_opt(conf, option)


def configure(conf=None):
    if conf is None:
        conf = CONF

    conf.register_cli_opt(
        cfg.BoolOpt('standard-threads', default=False,
                    help='Do not monkey-patch threading system modules.'))
    conf.register_cli_opt(
        cfg.StrOpt('pydev-debug-host',
                   help='Host to connect to for remote debugger.'))
    conf.register_cli_opt(
        cfg.IntOpt('pydev-debug-port',
                   help='Port to connect to for remote debugger.'))

    for section in FILE_OPTIONS:
        for option in FILE_OPTIONS[section]:
            if section:
                conf.register_opt(option, group=section)
            else:
                conf.register_opt(option)

    # register any non-default auth methods here (used by extensions, etc)
    setup_authentication(conf)


def list_opts():
    """Return a list of oslo.config options available in Keystone.

    The returned list includes all oslo.config options which are registered as
    the "FILE_OPTIONS" in keystone.common.config. This list will not include
    the options from the oslo-incubator library or any options registered
    dynamically at run time.

    Each object in the list is a two element tuple. The first element of
    each tuple is the name of the group under which the list of options in the
    second element will be registered. A group name of None corresponds to the
    [DEFAULT] group in config files.

    This function is also discoverable via the 'oslo.config.opts' entry point
    under the 'keystone.config.opts' namespace.

    The purpose of this is to allow tools like the Oslo sample config file
    generator to discover the options exposed to users by this library.

    :returns: a list of (group_name, opts) tuples
    """
    return FILE_OPTIONS.items()
