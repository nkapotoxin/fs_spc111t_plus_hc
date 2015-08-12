from webob import exc

from nova.api.openstack.compute import servers
from nova.api.openstack import extensions
from nova.api.openstack import wsgi
from nova.api.openstack import xmlutil
from nova import objects
from nova.openstack.common import jsonutils
from nova.openstack.common import log as logging

LOG = logging.getLogger(__name__)
authorize = extensions.soft_extension_authorizer('compute', 'numa')


class ServerNumaOptsTemplate(xmlutil.TemplateBuilder):
    def construct(self):
        root = xmlutil.TemplateElement('server')
        root.set('numaOpts', 'numaOpts')
        root.set('evsOpts', 'evsOpts')
        return xmlutil.SlaveTemplate(root, 1)


class ServersNumaOptsTemplate(xmlutil.TemplateBuilder):
    def construct(self):
        root = xmlutil.TemplateElement('servers')
        elem = xmlutil.SubTemplateElement(root, 'server', selector='servers')
        elem.set('numaOpts', 'numaOpts')
        elem.set('evsOpts', 'evsOpts')
        return xmlutil.SlaveTemplate(root, 1)


class Controller(servers.Controller):
    def _add_numaOpts(self, context, servers):
        for server in servers:
            hw_inst_extra = objects.HuaweiInstanceExtra.get_by_instance_uuid(
                context, server['id'])
            if hw_inst_extra:
                scheduler_hints = jsonutils.loads(
                    hw_inst_extra.scheduler_hints or '{}')
                scheduler_hints.setdefault('numaOpts', 0)
                scheduler_hints.setdefault('evsOpts', 0)
                server.update(scheduler_hints)

    def _validate_evs_opts(self, context, body):

        try:
            evs_opts = int(body['os:scheduler_hints'].setdefault(
                'evsOpts', 0))
        except ValueError:
            msg = ('Parameter evsOpts should be 0 or 1')
            raise exc.HTTPBadRequest(explanation=msg)

        numa_opts = int(body['os:scheduler_hints']['numaOpts'])

        if evs_opts not in (0,1):
            msg = ('Parameter evsOpts must be 0 or 1')
            raise exc.HTTPBadRequest(explanation=msg)

        if evs_opts and not numa_opts:
            msg = ('numaOpts must be enabled when evsOpts is enabled')
            raise exc.HTTPBadRequest(explanation=msg)

    @wsgi.extends
    def create(self, req, body):
        context = req.environ['nova.context']
        if authorize(context):
            if 'os:scheduler_hints' in body:
                body['os:scheduler_hints'].setdefault('numaOpts', 0)
                numa_opts = body['os:scheduler_hints']['numaOpts']
                try:
                    body['os:scheduler_hints']['numaOpts'] = int(numa_opts)
                except ValueError:
                    msg = ('Parameter numaOpts %s should be one of: 0,1,2'
                           % numa_opts)
                    raise exc.HTTPBadRequest(explanation=msg)
                if int(numa_opts) not in (0, 1, 2):
                    msg = ('Parameter numaOpts %s should be one of: 0,1,2'
                           % numa_opts)
                    raise exc.HTTPBadRequest(explanation=msg)
                self._validate_evs_opts(context, body)
        yield

    @wsgi.extends
    def show(self, req, resp_obj, id):
        context = req.environ['nova.context']
        if authorize(context):
            if 'server' in resp_obj.obj:
                resp_obj.attach(xml=ServerNumaOptsTemplate())
                server = resp_obj.obj['server']
                self._add_numaOpts(context, [server])

    @wsgi.extends
    def detail(self, req, resp_obj):
        context = req.environ['nova.context']
        if 'servers' in resp_obj.obj and authorize(context):
            resp_obj.attach(xml=ServersNumaOptsTemplate())
            servers = resp_obj.obj['servers']
            self._add_numaOpts(context, servers)


class Numa(extensions.ExtensionDescriptor):
    """Huawei_numa Extension."""

    name = "Numa"
    alias = "os-numa"
    namespace = "http://docs.openstack.org/compute/ext/Numa/api/v1.1"
    updated = "2014-03-19T00:00:00+00:00"

    def get_controller_extensions(self):
        controller = Controller(self.ext_mgr)
        extension = extensions.ControllerExtension(self, 'servers', controller)
        return [extension]
    