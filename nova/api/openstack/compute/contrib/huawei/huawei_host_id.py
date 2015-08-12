from nova.api.openstack.compute import servers
from nova.api.openstack import extensions
from nova.api.openstack import wsgi


class Controller(servers.Controller):
    def _modify_host_id(self, req, servers):
        for server in servers:
            db_instance = req.get_db_instance(server['id'])
            server['hostId'] = db_instance['host']

    @wsgi.extends
    def show(self, req, resp_obj, id):
        if 'server' in resp_obj.obj:
            server = resp_obj.obj['server']
            self._modify_host_id(req, [server])

    @wsgi.extends
    def detail(self, req, resp_obj):
        if 'servers' in resp_obj.obj:
            servers = resp_obj.obj['servers']
            self._modify_host_id(req, servers)


class Huawei_host_id(extensions.ExtensionDescriptor):
    """Huawei_host_id Extension."""

    name = "Huawei_host_id"
    alias = "os-huawei-host-id"
    namespace = "http://docs.openstack.org/compute/ext/huawei_host_id/api/v1.1"
    updated = "2014-03-19T00:00:00+00:00"

    def get_controller_extensions(self):
        controller = Controller(self.ext_mgr)
        extension = extensions.ControllerExtension(self, 'servers', controller)
        return [extension]
