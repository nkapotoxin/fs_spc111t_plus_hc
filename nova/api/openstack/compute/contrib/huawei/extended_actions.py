
import webob

from nova.api.openstack import extensions
from nova.api.openstack import wsgi
from nova import compute
from nova import exception
from nova.openstack.common import log as logging
from nova.openstack.common.gettextutils import _

LOG = logging.getLogger(__name__)


class ExtendedActionsController(wsgi.Controller):
    def __init__(self, *args, **kwargs):
        super(ExtendedActionsController, self).__init__(*args, **kwargs)
        self.compute_api = compute.API()

    def _get_instance(self, context, instance_uuid):
        try:
            instance = self.compute_api.get(context, instance_uuid,
                                            want_objects=True)
        except exception.NotFound:
            msg = _("Instance could not be found")
            raise webob.exc.HTTPNotFound(explanation=msg)

        return instance

    @wsgi.action('reschedule')
    def reschedule_server(self, req, id, body):
        """rescheduler an instance."""
        context = req.environ['nova.context']
        instance = self._get_instance(context, id)
        LOG.debug('reschedule instance', instance=instance)
        try:
            self.compute_api.reschedule(context, instance)
        except exception.InstanceNotReady as e:
            raise webob.exc.HTTPConflict(explanation=e.format_message())
        return webob.Response(status_int=202)


class Extended_actions(extensions.ExtensionDescriptor):
    """Start/Stop instance compute API support."""

    name = "ExtendedActionsController"
    alias = "Extended_Server_Actions"
    namespace = ""
    updated = "2013-09-22T00:00:00+00:00"

    def get_controller_extensions(self):
        controller = ExtendedActionsController()
        extension = extensions.ControllerExtension(self, 'servers', controller)
        return [extension]
