#   Copyright 2013 OpenStack Foundation
#
#   Licensed under the Apache License, Version 2.0 (the "License"); you may
#   not use this file except in compliance with the License. You may obtain
#   a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#   License for the specific language governing permissions and limitations
#   under the License.

from webob import exc

from nova.api.openstack import extensions
from nova.api.openstack import wsgi
from nova import exception
from nova.i18n import _
from nova.openstack.common import log as logging
from nova import utils

LOG = logging.getLogger(__name__)


class MigrateHostController(wsgi.Controller):
    def __init__(self, *args, **kwargs):
        super(MigrateHostController, self).__init__(*args, **kwargs)

    @wsgi.extends(action='migrate')
    def _migrate(self, req, id, body):
        if body.get('migrate') is not None:
            if not self.is_valid_body(body, 'migrate'):
                raise exc.HTTPBadRequest(
                    explanation=_("Malformed request body"))
            try:
                host = body.get('migrate').get('host')
                if host is not None:
                    utils.check_string_length(host, 'host',
                                              min_length=1, max_length=255)
            except exception.InvalidInput as e:
                raise exc.HTTPBadRequest(explanation=e.format_message())
        yield


class Migrate_host(extensions.ExtensionDescriptor):
    """Migrate instance with host."""

    name = "MigrateHost"
    alias = "os-migrate-host"
    namespace = ("http://docs.openstack.org/compute/ext/"
                 "migrate_host/api/v1.1")
    updated = "2015-03-12T00:00:00Z"

    def get_controller_extensions(self):
        controller = MigrateHostController()
        extension = extensions.ControllerExtension(self, 'servers', controller)
        return [extension]
