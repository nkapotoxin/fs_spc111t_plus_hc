# Copyright (C) 2011 Midokura KK
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

"""The virtual interfaces extension."""

import webob
from webob import exc

from nova.api.openstack import extensions
from nova.api.openstack import wsgi
from nova import compute
from nova import exception
from nova.huawei.network import api
from nova.openstack.common.gettextutils import _
from nova.openstack.common import log as logging


LOG = logging.getLogger(__name__)
authorize = extensions.extension_authorizer('compute', 'virtual_interfaces')


class ServerIPController(wsgi.Controller):
    """The instance VIF API controller for the OpenStack API.
    """

    def __init__(self):
        self.compute_api = compute.API()
        self.network_api = api.HuaweiAPI()
        super(ServerIPController, self).__init__()

    def update(self, req, server_id, id, body):
        """Update address of virtual interfaces."""
        context = req.environ['nova.context']
        authorize(context)

        fixed_ip = body['fixed_ips'][0]
        network_uuid = fixed_ip['net_id']
        ip_address = fixed_ip['ip_address']
        if not network_uuid or not ip_address:
            raise exc.HTTPBadRequest()

        try:
            instance = self.compute_api.get(context, server_id,
                                            want_objects=True)
            self.network_api.update_interface_address(context, server_id,
                                                      id, network_uuid,
                                                      ip_address)
            self.network_api.update_vif_pg_info(context, instance)
        except exception.InstanceNotFound:
            raise exc.HTTPNotFound(_("Server not found"))
        except exception.NotFound as e:
            raise exc.HTTPNotFound()
        except exception.FixedIpAlreadyInUse as e:
            LOG.exception(e)
            msg = _("Fixed Ip already in use")
            raise exc.HTTPConflict(explanation=msg)
        except NotImplementedError:
            msg = _("Network driver does not support this function.")
            raise exc.HTTPNotImplemented(explanation=msg)
        except exception.InterfaceAttachFailed as e:
            msg = _("Failed to attach interface")
            raise exc.HTTPInternalServerError(explanation=msg)
        except Exception as e:
            LOG.exception(e)
            msg = _("Failed to attach interface")
            raise exc.HTTPInternalServerError(explanation=msg)

        return webob.Response(status_int=202)


class Server_ip(extensions.ExtensionDescriptor):
    """Virtual interface support."""

    name = "ServerIp"
    alias = "server-ip"
    namespace = ("http://docs.openstack.org/compute/ext/"
                 "server_ip/api/v1.1")
    updated = "2014-05-26T00:00:00+00:00"

    def get_resources(self):
        resources = []

        res = extensions.ResourceExtension(
            'os-server-ip',
            controller=ServerIPController(),
            parent=dict(member_name='server', collection_name='servers'))
        resources.append(res)

        return resources
