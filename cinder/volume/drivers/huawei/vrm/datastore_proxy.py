# vim: tabstop=4 shiftwidth=4 softtabstop=4

"""
[VRM DRIVER] VRM CLIENT.

"""

from cinder.openstack.common import log as logging
from cinder.openstack.common.gettextutils import _

from cinder.volume.drivers.huawei.vrm.base_proxy import BaseProxy

TASK_WAITING = 'waiting'
TASK_RUNNING = 'running'
TASK_SUCCESS = 'success'
TASK_FAILED = 'failed'
TASK_CANCELLING = 'cancelling'
TASK_UNKNOWN = 'unknown'

LOG = logging.getLogger(__name__)


class DatastoreProxy(BaseProxy):
    '''
    DatastoreProxy
    '''
    def __init__(self):
        super(DatastoreProxy, self).__init__()


    def list_datastore(self, **kwargs):
        '''

        :param kwargs:
        :return:
        '''
        LOG.info(_("[VRM-CINDER] start list_datastore()"))
        uri = '/datastores'
        method = 'GET'
        path = self.site_uri + uri

        offset = 0
        datastores = []
        while True:
            parames = {'limit': self.limit,
                       'offset': offset,
                       'scope': kwargs.get('scope')}

            appendix = self._joined_params(parames)
            new_url = self._generate_url(path, appendix)
            resp, body = self.vrmhttpclient.request(new_url, method)
            total = int(body.get('total') or 0)
            if total > 0:
                res = body.get('datastores')
                datastores += res
                offset += len(res)
                if offset >= total or len(datastores) >= total or len(res) < self.limit:
                    break
            else:
                break

        return datastores


