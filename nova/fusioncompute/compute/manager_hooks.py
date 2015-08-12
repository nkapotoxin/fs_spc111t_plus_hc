from oslo.config import cfg
from nova.openstack.common import log as logging

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

class ManagerInitHostHook(object):
    def __init__(self):
        self._compute_manager = None

    def pre(self, *args, **kwargs):
        pass

    def post(self, rv, *args, **kwargs):
        pass
