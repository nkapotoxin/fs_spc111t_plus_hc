import six
from webob import exc

from nova.api.openstack.compute import servers
from nova.api.openstack import extensions
from nova.api.openstack import wsgi
from nova.api.openstack import xmlutil
from nova import objects
from nova.openstack.common import jsonutils
#from nova.openstack.common import hw_host_networklist

authorize = extensions.soft_extension_authorizer('compute', 'affinity_mask')


class ServerAffinityMaskTemplate(xmlutil.TemplateBuilder):
    def construct(self):
        root = xmlutil.TemplateElement('server')
        root.set('vcpuAffinity', 'vcpuAffinity')
        root.set('hyperThreadAffinity', 'hyperThreadAffinity')
        return xmlutil.SlaveTemplate(root, 1)


class ServersAffinityMaskTemplate(xmlutil.TemplateBuilder):
    def construct(self):
        root = xmlutil.TemplateElement('servers')
        elem = xmlutil.SubTemplateElement(root, 'server', selector='servers')
        elem.set('vcpuAffinity', 'vcpuAffinity')
        elem.set('hyperThreadAffinity', 'hyperThreadAffinity')
        return xmlutil.SlaveTemplate(root, 1)


class Controller(servers.Controller):

    def _add_affinity_mask(self, context, req, servers):
        for server in servers:
            hw_inst_extra = objects.HuaweiInstanceExtra.get_by_instance_uuid(
                context, server['id'])
            if hw_inst_extra:
                scheduler_hints = jsonutils.loads(
                    hw_inst_extra.scheduler_hints or '{}')
                scheduler_hints.setdefault('vcpuAffinity', [0])
                scheduler_hints.setdefault('hyperThreadAffinity', 'any')
                server.update(scheduler_hints)
            #if db_server['request_network'] is not None and utils.is_neutron():
            #    host_network = hw_host_networklist.HostNetworkList('{}', None)
            #    networks = host_network.format_request_network(db_server['request_network'])
            #    server['networks'] = networks

    def _validate_vcpuAffinity(self, vcpuAffinity):
        if vcpuAffinity == []:
            expl =  'Parameter vcpuAffinity is empty'
            raise exc.HTTPBadRequest(explanation=expl)
        if not isinstance(vcpuAffinity, list):
            expl =  'Parameter vcpuAffinity is not list'
            raise exc.HTTPBadRequest(explanation=expl)
        length = len(vcpuAffinity)
        if length < 1 or length > 32:
            expl =  ("Parameter vcpuAffinity\'s length is more than 32"
                     " or less than 1")
            raise exc.HTTPBadRequest(explanation=expl)
        
        for item in vcpuAffinity:
            if item not in (0,"0",1,"1"):
                expl =  'Parameter vcpuAffinity is not 0, "0", 1 or "1"'
                raise exc.HTTPBadRequest(explanation=expl)
        
        if vcpuAffinity[0] in (0,"0"):
            for item in vcpuAffinity:
                if item not in (0,"0"):
                    expl =  ('Parameter vcpuAffinity is not of the '
                             'same number')
                    raise exc.HTTPBadRequest(explanation=expl)            
        if vcpuAffinity[0] in (1,"1"):
            for item in vcpuAffinity:
                if item not in (1,"1"):
                    expl =  ('Parameter vcpuAffinity is not of the '
                             'same number')
                    raise exc.HTTPBadRequest(explanation=expl)
                
    def _validate_hyperThreadAffinity(self,hyperThreadAffinity):
        if not hyperThreadAffinity:
            expl =  'Parameter hyperThreadAffinity is empty'
            raise exc.HTTPBadRequest(explanation=expl)
        if hyperThreadAffinity not in ("any", "none", "internal", "sync", "lock"):
            msg =  ('Parameter hyperThreadAffinity isn\'t in '
                     '(any, none, internal, sync, lock)')
            raise exc.HTTPBadRequest(explanation=msg)

    @wsgi.extends
    def create(self, req, body):
        context = req.environ['nova.context']
        if authorize(context):
            if 'os:scheduler_hints' in body:
                body['os:scheduler_hints'].setdefault('vcpuAffinity', [0])
                body['os:scheduler_hints'].setdefault(
                    'hyperThreadAffinity', 'any')
                vcpu_aff =  body['os:scheduler_hints']['vcpuAffinity']
                ht = body['os:scheduler_hints']['hyperThreadAffinity']
                try:
                    vcpu_aff = (jsonutils.loads(vcpu_aff) if
                                isinstance(vcpu_aff, six.string_types
                                ) else vcpu_aff)
                except ValueError:
                    msg = ('The format of vcpuAffinity is invalid, must be'
                           ' a list of int')
                    raise exc.HTTPBadRequest(explanation=msg)
                self._validate_vcpuAffinity(vcpu_aff)
                self._validate_hyperThreadAffinity(ht)
                if ht == 'internal' and vcpu_aff[0] not in (0,"0"):
                    msg = ('In internal mode,  Parameter vcpuAffinity must be'
                           ' 0 or "0"')
                    raise exc.HTTPBadRequest(explanation=msg)
                if ht in ("none", "sync", "lock") and vcpu_aff[0] not in (1,"1"):
                    msg = ('In "none" , "sync" or "lock" mode, '
                           'Parameter vcpuAffinity must be 1 or "1"')
                    raise exc.HTTPBadRequest(explanation=msg)

                try:
                    numa_opts = int(body['os:scheduler_hints'].get(
                        'numaOpts', 0))
                except ValueError:
                    msg = ('Parameter numaOpts should be one of: 0,1,2')
                    raise exc.HTTPBadRequest(explanation=msg)

                if ht == 'lock' and not numa_opts:
                    msg = ('numaOpts must be enabled when hyperThreadAffinity is lock')
                    raise exc.HTTPBadRequest(explanation=msg)

                body['os:scheduler_hints']['vcpuAffinity'] = vcpu_aff
                body['os:scheduler_hints']['hyperThreadAffinity'] = ht
        yield

    @wsgi.extends
    def show(self, req, resp_obj, id):
        context = req.environ['nova.context']
        if authorize(context):
            if 'server' in resp_obj.obj:
                resp_obj.attach(xml=ServerAffinityMaskTemplate())
                server = resp_obj.obj['server']
                self._add_affinity_mask(context, req, [server])

    @wsgi.extends
    def detail(self, req, resp_obj):
        context = req.environ['nova.context']
        if 'servers' in resp_obj.obj and authorize(context):
            resp_obj.attach(xml=ServersAffinityMaskTemplate())
            servers = resp_obj.obj['servers']
            self._add_affinity_mask(context, req, servers)


class Affinity_mask(extensions.ExtensionDescriptor):
    """Cpu Opts Extension."""

    name = "CpuOpts"
    alias = "os-cpu-opts"
    namespace = "http://docs.openstack.org/compute/ext/cpu_opts/api/v1.1"
    updated = "2013-07-19T00:00:00+00:00"

    def get_controller_extensions(self):
        controller = Controller(self.ext_mgr)
        extension = extensions.ControllerExtension(self, 'servers', controller)
        return [extension]
