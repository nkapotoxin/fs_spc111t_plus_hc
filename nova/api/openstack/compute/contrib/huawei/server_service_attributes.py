from nova.api.openstack import extensions
from nova.api.openstack import wsgi
from nova.api.openstack import xmlutil
from nova import compute
from nova import context as nova_context
from nova.i18n import _LW
from nova.openstack.common import log as logging
from nova import servicegroup

LOG = logging.getLogger(__name__)


class Controller(wsgi.Controller):
    def __init__(self, ext_mgr=None, *args, **kwargs):
        self.host_api = compute.HostAPI()
        self.servicegroup_api = servicegroup.API()
        self.ext_mgr = ext_mgr

    def _extend_servers(self, req, servers):
        if not self.ext_mgr.is_loaded('os-extended-services'):
            LOG.warn(_LW('System does not support os-extended-services.'))
            return

        host_servers_dict = {}
        host_services_dict = {}
        for server in servers:
            if server['hostId'] not in host_servers_dict:
                host_servers_dict[server['hostId']] = []
            host_servers_dict[server['hostId']].append(server)

        admin_context = nova_context.get_admin_context()
        filters = {'binary': 'nova-compute'}
        services = self.host_api.service_get_all(admin_context, filters=filters)
        for service in services:
            host_services_dict[service.host] = service

        key = "%s:service_state" % Server_service_attributes.alias
        for host_id, server_list in host_servers_dict.items():
            db_instance = req.get_db_instance(server_list[0]['id'])
            host = db_instance['host']
            if host_id and host and (host in host_services_dict):
                svc = host_services_dict[host]
                service_state = 'up' if self.servicegroup_api.service_is_up(
                    svc) else 'down'
            else:
                service_state = None
            for server in server_list:
                server[key] = service_state

    @wsgi.extends
    def show(self, req, resp_obj, id):
        # Attach our slave template to the response object
        resp_obj.attach(xml=ExtendedServerServiceAttributeTemplate())
        server = resp_obj.obj['server']
        self._extend_servers(req, [server])

    @wsgi.extends
    def detail(self, req, resp_obj):
        # Attach our slave template to the response object
        resp_obj.attach(xml=ExtendedServerServiceAttributesTemplate())
        servers = list(resp_obj.obj['servers'])
        self._extend_servers(req, servers)


class Server_service_attributes(extensions.ExtensionDescriptor):
    """Server_service_attributes Extension."""

    name = "Server_service_attributes"
    alias = "OS-EXT-SERVICE"
    namespace = "http://docs.openstack.org/compute/ext/"\
                "server_service_attributes/api/v1.1"
    updated = "2015-02-14T00:00:00+00:00"

    def get_controller_extensions(self):
        controller = Controller(self.ext_mgr)
        extension = extensions.ControllerExtension(self, 'servers', controller)
        return [extension]


def make_server(elem):
    elem.set('{%s}service_state' % Server_service_attributes.namespace,
             '%s:service_state' % Server_service_attributes.alias)


class ExtendedServerServiceAttributeTemplate(xmlutil.TemplateBuilder):
    def construct(self):
        root = xmlutil.TemplateElement('server', selector='server')
        make_server(root)
        alias = Server_service_attributes.alias
        namespace = Server_service_attributes.namespace
        return xmlutil.SlaveTemplate(root, 1, nsmap={alias: namespace})


class ExtendedServerServiceAttributesTemplate(xmlutil.TemplateBuilder):
    def construct(self):
        root = xmlutil.TemplateElement('servers')
        elem = xmlutil.SubTemplateElement(root, 'server', selector='servers')
        make_server(elem)
        alias = Server_service_attributes.alias
        namespace = Server_service_attributes.namespace
        return xmlutil.SlaveTemplate(root, 1, nsmap={alias: namespace})
