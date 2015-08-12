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


class ClusterProxy(BaseProxy):
    '''

    '''
    def __init__(self):
        super(ClusterProxy, self).__init__()


    def list_cluster(self):
        '''
        Get <cluster_uri>?tag=xxx&clusterUrns=urn1&clusterUrns=urn2 HTTP/1.1
        Host: https://<ip>:<port>
        Accept: application/json;version=<version>; charset=UTF-8
        X-Auth-Token: <Authen_TOKEN>

        :param kwargs:
        :return:
        '''
        LOG.info(_("[VRM-CINDER] start list_cluster()"))
        uri = '/clusters'
        method = 'GET'
        path = self.site_uri + uri

        new_url = self._generate_url(path)
        resp, body = self.vrmhttpclient.request(new_url, method)
        clusters = body.get('clusters')

        return clusters


