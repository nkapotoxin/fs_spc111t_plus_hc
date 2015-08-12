# Copyright 2014, Huawei, Inc.
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

import functools
from oslo.config import cfg

from neutron import context as n_context
from neutron.openstack.common import importutils
from neutron.openstack.common import log as logging
from neutron.openstack.common import excutils

logger = logging.getLogger(__name__)

from neutron.plugins.l2_proxy.agent import neutron_proxy_context
from neutron.plugins.l2_proxy.agent import neutron_keystoneclient as hkc
from novaclient import client as novaclient
from novaclient import shell as novashell
from neutronclient.common import exceptions

try:
    from swiftclient import client as swiftclient
except ImportError:
    swiftclient = None
    logger.info('swiftclient not available')
try:
    from neutronclient.v2_0 import client as neutronclient
except ImportError:
    neutronclient = None
    logger.info('neutronclient not available')
try:
    from cinderclient import client as cinderclient
except ImportError:
    cinderclient = None
    logger.info('cinderclient not available')

try:
    from ceilometerclient.v2 import client as ceilometerclient
except ImportError:
    ceilometerclient = None
    logger.info('ceilometerclient not available')


cloud_opts = [
    cfg.StrOpt('cloud_backend',
               default=None,
               help="Cloud module to use as a backend. Defaults to OpenStack.")
]
cfg.CONF.register_opts(cloud_opts)

CASCADING = 'cascading'
CASCADED = 'cascaded'

class OpenStackClients(object):

    '''
    Convenience class to create and cache client instances.
    '''

    def __init__(self, context):
        self.context = context
        self._nova = {}
        self._keystone = None
        self._swift = None
        self._neutron = None
        self._cinder = None
        self._ceilometer = None

    @property
    def auth_token(self):
        # if there is no auth token in the context
        # attempt to get one using the context username and password
        return self.context.auth_token or self.keystone().auth_token

    def keystone(self):
        if self._keystone:
            return self._keystone

        self._keystone = hkc.KeystoneClient(self.context)
        return self._keystone

    def url_for(self, **kwargs):
        return self.keystone().url_for(**kwargs)

    def nova(self, service_type='compute'):
        if service_type in self._nova:
            return self._nova[service_type]

        con = self.context
        if self.auth_token is None:
            logger.error("Nova connection failed, no auth_token!")
            return None

        computeshell = novashell.OpenStackComputeShell()
        extensions = computeshell._discover_extensions("1.1")

        args = {
            'project_id': con.tenant_id,
            'auth_url': con.auth_url,
            'service_type': service_type,
            'username': None,
            'api_key': None,
            'extensions': extensions
        }

        client = novaclient.Client(1.1, **args)

        management_url = self.url_for(
            service_type=service_type,
            attr='region',
            filter_value='RegionTwo')
        client.client.auth_token = self.auth_token
        client.client.management_url = management_url
        self._nova[service_type] = client

        return client

    def swift(self):
        if swiftclient is None:
            return None
        if self._swift:
            return self._swift

        con = self.context
        if self.auth_token is None:
            logger.error("Swift connection failed, no auth_token!")
            return None

        args = {
            'auth_version': '2.0',
            'tenant_name': con.tenant_id,
            'user': con.username,
            'key': None,
            'authurl': None,
            'preauthtoken': self.auth_token,
            'preauthurl': self.url_for(service_type='object-store')
        }
        self._swift = swiftclient.Connection(**args)
        return self._swift

    def neutron(self):
        if neutronclient is None:
            return None
        if self._neutron:
            return self._neutron

        con = self.context
        if self.auth_token is None:
            logger.error("Neutron connection failed, no auth_token!")
            return None

        if self.context.region_name is None:
            management_url = self.url_for(service_type='network',
                                          endpoint_type='publicURL')
        else:
            management_url = self.url_for(
                service_type='network',
                attr='region',
                endpoint_type='publicURL',
                filter_value=self.context.region_name)
        args = {
            'auth_url': con.auth_url,
            'insecure': self.context.insecure,
            'service_type': 'network',
            'token': self.auth_token,
            'endpoint_url': management_url
        }

        self._neutron = neutronclient.Client(**args)

        return self._neutron

    def cinder(self):
        if cinderclient is None:
            return self.nova('volume')
        if self._cinder:
            return self._cinder

        con = self.context
        if self.auth_token is None:
            logger.error("Cinder connection failed, no auth_token!")
            return None

        args = {
            'service_type': 'volume',
            'auth_url': con.auth_url,
            'project_id': con.tenant_id,
            'username': None,
            'api_key': None
        }

        self._cinder = cinderclient.Client('1', **args)
        management_url = self.url_for(service_type='volume')
        self._cinder.client.auth_token = self.auth_token
        self._cinder.client.management_url = management_url

        return self._cinder

    def ceilometer(self):
        if ceilometerclient is None:
            return None
        if self._ceilometer:
            return self._ceilometer

        if self.auth_token is None:
            logger.error("Ceilometer connection failed, no auth_token!")
            return None
        con = self.context
        args = {
            'auth_url': con.auth_url,
            'service_type': 'metering',
            'project_id': con.tenant_id,
            'token': lambda: self.auth_token,
            'endpoint': self.url_for(service_type='metering'),
        }

        client = ceilometerclient.Client(**args)

        self._ceilometer = client
        return self._ceilometer


if cfg.CONF.cloud_backend:
    cloud_backend_module = importutils.import_module(cfg.CONF.cloud_backend)
    Clients = cloud_backend_module.Clients
else:
    Clients = OpenStackClients

logger.debug('Using backend %s' % Clients)

def get_cascade_neutron_client(mode):
    if mode == CASCADING:
        region_name = cfg.CONF.AGENT.region_name
    elif mode == CASCADED:
        region_name = cfg.CONF.AGENT.neutron_region_name
    else:
        logger.error(_('Must be input mode(cascading or cascaded).'))
        raise

    context = n_context.get_admin_context_without_session()
    neutron_admin_auth_url = cfg.CONF.AGENT.neutron_admin_auth_url
    kwargs = {'auth_token': None,
              'username': cfg.CONF.AGENT.neutron_admin_user,
              'password': cfg.CONF.AGENT.admin_password,
              'aws_creds': None,
              'tenant': cfg.CONF.AGENT.neutron_admin_tenant_name,
              'auth_url': neutron_admin_auth_url,
              'insecure': cfg.CONF.AGENT.auth_insecure,
              'roles': context.roles,
              'is_admin': context.is_admin,
              'region_name': region_name}
    reqCon = neutron_proxy_context.RequestContext(**kwargs)
    openStackClients = OpenStackClients(reqCon)
    neutronClient = openStackClients.neutron()
    return neutronClient

def check_neutron_client_valid(function):

    @functools.wraps(function)
    def decorated_function(self, method_name, *args, **kwargs):
        retry = 0
        while(True):
            try:
                return function(self, method_name, *args, **kwargs)
            except exceptions.Unauthorized:
                retry = retry + 1
                if(retry <= 3):
                    self.client = get_cascade_neutron_client(self.mode)
                    continue
                else:
                    with excutils.save_and_reraise_exception():
                        logger.error(_('Try 3 times, Unauthorized.'))
                        return None

    return decorated_function

class CascadeNeutronClient(object):
    def __init__(self, mode):
        #mode is cascading or cascaded
        self.mode = mode
        self.client = get_cascade_neutron_client(self.mode)

    @check_neutron_client_valid
    def __call__(self, method_name, *args, **kwargs):
        method = getattr(self.client, method_name)
        if method:
            return method(*args, **kwargs)
        else:
            raise Exception('can not find the method')

    @check_neutron_client_valid
    def execute(self, method_name, *args, **kwargs):
        method = getattr(self.client, method_name)
        if method:
            return method(*args, **kwargs)
        else:
            raise Exception('can not find the method')
