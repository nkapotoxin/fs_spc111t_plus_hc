# Copyright (c) 2013 OpenStack Foundation.
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
from neutron.common import constants as const
from neutron.openstack.common import log as logging
from neutron.plugins.ml2 import driver_api as api
from neutronclient.common import exceptions
from neutron.openstack.common import local
from neutron.openstack.common import context
from neutron import context as n_context
from neutron.openstack.common import importutils
from neutron.openstack.common import excutils
from neutron.plugins.l2_proxy.agent import neutron_keystoneclient as hkc

LOG = logging.getLogger(__name__)

try:
    from neutronclient.v2_0 import client as neutronclient
except ImportError:
    neutronclient = None
    LOG.info('neutronclient not available')

CASCADING = 'cascading'

class RequestContext(context.RequestContext):

    """
    Stores information about the security context under which the user
    accesses the system, as well as additional request information.
    """

    def __init__(self, auth_token=None, username=None, password=None,
                 aws_creds=None, tenant=None,
                 tenant_id=None, auth_url=None, roles=None, is_admin=False,
                 insecure=True,region_name=None, read_only=False,
                 show_deleted=False,owner_is_tenant=True, overwrite=True,
                 trust_id=None, trustor_user_id=None,
                 **kwargs):
        """
        :param overwrite: Set to False to ensure that the greenthread local
            copy of the index is not overwritten.

         :param kwargs: Extra arguments that might be present, but we ignore
            because they possibly came in from older rpc messages.
        """
        super(RequestContext, self).__init__(auth_token=auth_token,
                                             user=username, tenant=tenant,
                                             is_admin=is_admin,
                                             read_only=read_only,
                                             show_deleted=show_deleted,
                                             request_id='unused')

        self.username = username
        self.password = password
        self.aws_creds = aws_creds
        self.tenant_id = tenant_id
        self.auth_url = auth_url
        self.roles = roles or []
        self.region_name = region_name
        self.insecure = insecure
        self.owner_is_tenant = owner_is_tenant
        if overwrite or not hasattr(local.store, 'context'):
            self.update_store()
        self._session = None
        self.trust_id = trust_id
        self.trustor_user_id = trustor_user_id

    def update_store(self):
        local.store.context = self

    def to_dict(self):
        return {'auth_token': self.auth_token,
                'username': self.username,
                'password': self.password,
                'aws_creds': self.aws_creds,
                'tenant': self.tenant,
                'tenant_id': self.tenant_id,
                'trust_id': self.trust_id,
                'insecure': self.insecure,
                'trustor_user_id': self.trustor_user_id,
                'auth_url': self.auth_url,
                'roles': self.roles,
                'is_admin': self.is_admin,
                'region_name': self.region_name}

    @classmethod
    def from_dict(cls, values):
        return cls(**values)

    @property
    def owner(self):
        """Return the owner to correlate with an image."""
        return self.tenant if self.owner_is_tenant else self.user


def get_admin_context(read_deleted="no"):
    return RequestContext(is_admin=True)

class OpenStackClients(object):

    '''
    Convenience class to create and cache client instances.
    '''

    def __init__(self, context):
        self.context = context
        self._neutron = None
        self._keystone = None

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

    def neutron(self):
        if neutronclient is None:
            return None
        if self._neutron:
            return self._neutron

        con = self.context
        if self.auth_token is None:
            LOG.error("Neutron connection failed, no auth_token!")
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

def get_cascading_neutron_client():
    context = n_context.get_admin_context_without_session()
    auth_url = 'https://%s:%s/%s/%s' %(cfg.CONF.keystone_authtoken.auth_host,
                                            cfg.CONF.keystone_authtoken.auth_port,
                                            cfg.CONF.keystone_authtoken.auth_admin_prefix,
                                            cfg.CONF.keystone_authtoken.auth_version)
    kwargs = {'auth_token': None,
              'username': cfg.CONF.keystone_authtoken.admin_user,
              'password': cfg.CONF.keystone_authtoken.admin_password,
              'aws_creds': None,
              'tenant': cfg.CONF.keystone_authtoken.admin_tenant_name,
              'auth_url': auth_url,
              'insecure': cfg.CONF.keystone_authtoken.insecure,
              'roles': context.roles,
              'is_admin': context.is_admin,
              'region_name': cfg.CONF.cascading_os_region_name}
    reqCon = RequestContext(**kwargs)
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
                    self.client = get_cascading_neutron_client()
                    continue
                else:
                    with excutils.save_and_reraise_exception():
                        LOG.error(_('Try 3 times, Unauthorized.'))
                        return None

    return decorated_function

class CascadeNeutronClient(object):
    def __init__(self):
        #mode is cascading or cascaded
        self.client = get_cascading_neutron_client()

    @check_neutron_client_valid
    def __call__(self, method_name, *args, **kwargs):
        method = getattr(self.client, method_name)
        if method:
            return method(*args, **kwargs)
        else:
            raise Exception('Can not find the method')

    @check_neutron_client_valid
    def execute(self, method_name, *args, **kwargs):
        method = getattr(self.client, method_name)
        if method:
            return method(*args, **kwargs)
        else:
            raise Exception('Can not find the method')


class Cascaded2MechanismDriver(api.MechanismDriver):

    def __init__(self):
        super(Cascaded2MechanismDriver, self).__init__()
        self.notify_cascading = False
        if cfg.CONF.cascading_os_region_name:
            self.cascading_neutron_client = CascadeNeutronClient()
            self.notify_cascading = True

    def initialize(self):
        LOG.debug(_("Experimental L2 population driver"))
        self.rpc_ctx = n_context.get_admin_context_without_session()
    
    def get_cascading_port_id(self, cascaded_port_name):
        try:
            return cascaded_port_name.split('@')[1]
        except Exception:
            return None

    def update_port_postcommit(self, context):
        if not self.notify_cascading:
            return
        cur_port = context.current
        orig_port = context._original_port
        LOG.debug(_("update_port_postcommit update "
                    "current_port:%s original:%s") % (cur_port, orig_port))
        if not (context.original_host and context.host
            and const.DEVICE_OWNER_COMPUTER in cur_port['device_owner']):
            return
        if context.host != context.original_host:
            cascading_port_id = self.get_cascading_port_id(cur_port['name'])
            if cascading_port_id:
                update_attrs = {'port': {'binding:profile': {'refresh_notify': True}}}
                for i in range(const.UPDATE_RETRY):
                    try:
                        self.cascading_neutron_client('update_port', cascading_port_id, update_attrs)
                        LOG.debug(_("host_id(%s -> %s) changed, notify the cascading")
                        %(context.original_host, context.host))
                        break
                    except Exception as e:
                        LOG.debug(_("Notify cascading refresh port failed(%s)! try %d") % (str(e), i))
                        continue
