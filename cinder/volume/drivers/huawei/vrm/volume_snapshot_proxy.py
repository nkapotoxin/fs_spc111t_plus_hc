# vim: tabstop=4 shiftwidth=4 softtabstop=4

"""
[VRM DRIVER] VRM CLIENT.

"""
import json

from cinder.openstack.common import log as logging
from cinder.volume.drivers.huawei.vrm import exception as driver_exception
from cinder.openstack.common.gettextutils import _
from cinder.volume.drivers.huawei.vrm.base_proxy import BaseProxy
from cinder.volume.drivers.huawei.vrm.task_proxy import TaskProxy

try:
    from eventlet import sleep
except ImportError:
    from time import sleep

TASK_WAITING = 'waiting'
TASK_RUNNING = 'running'
TASK_SUCCESS = 'success'
TASK_FAILED = 'failed'
TASK_CANCELLING = 'cancelling'
TASK_UNKNOWN = 'unknown'

LOG = logging.getLogger(__name__)


class VolumeSnapshotProxy(BaseProxy):
    def __init__(self, *args, **kwargs):
        super(VolumeSnapshotProxy, self).__init__()
        LOG.debug(_("[VRM-CINDER] start __init__()"))
        self.task_proxy = TaskProxy()


    def query_volumesnapshot(self, **kwargs):
        '''
            'list_volumesnapshot': ('GET',
                                ('/volumesnapshots', None, kwargs.get('uuid'), None),
                                {'limit': kwargs.get('limit'),
                                 'offset': kwargs.get('offset'),
                                 'scope': kwargs.get('scope')
                                },
                                {},
                                False),
        '''
        LOG.debug(_("[VRM-CINDER] start query_volumesnapshot()"))
        uri = '/volumesnapshots'
        method = 'GET'
        path = self.site_uri + uri + '/' + kwargs.get('uuid')
        body = None
        offset = 0
        datastores = []
        new_url = self._generate_url(path)
        try:
            resp, body = self.vrmhttpclient.request(new_url, method)
        except driver_exception.ClientException as ex:
            LOG.debug(_("[VRM-CINDER] query snapshot (%s)"), ex.errorCode)
            if ex.errorCode == "10430051":
                return None
            else:
                raise ex

        '''
        error_code = body.get('errorCode')
        if error_code != None:
            if '10430010' == error_code:
                LOG.debug(_("[VRM-CINDER] snapshot not exist"))
                return None
        '''

        return body

    def list_snapshot(self, **kwargs):
        '''
            'list_volumesnapshot': ('GET',
                                ('/volumesnapshots', None, kwargs.get('uuid'), None),
                                {'limit': kwargs.get('limit'),
                                 'offset': kwargs.get('offset'),
                                 'scope': kwargs.get('scope')
                                },
                                {},
                                False),
        '''
        LOG.debug(_("[VRM-CINDER] start list_snapshot()"))
        uri = '/volumesnapshots/queryVolumeSnapshots'
        method = 'GET'
        path = self.site_uri + uri
        body = None
        offset = 0

        snapshots = []
        while True:
            parames = {
                'limit': self.limit,
               'offset': offset
               }
            appendix = self._joined_params(parames)
            new_url = self._generate_url(path, appendix)
            resp, body = self.vrmhttpclient.request(new_url, method)
            total = int(body.get('total') or 0)
            if total > 0:
                res = body.get('snapshots')
                snapshots += res
                offset += len(res)
                if offset >= total or len(snapshots) >= total or len(res) < self.limit:
                    break
            else:
                break
       
        return snapshots
        
    def create_volumesnapshot(self, **kwargs):
        '''
            'create_volumesnapshot': ('POST',
                                  ('/volumesnapshots', None, None, None),
                                  {},
                                  {'volumeUrn': kwargs.get('vol_urn'), 'snapshotUuid': kwargs.get('uuid'),
                                  },
                                  False),
        '''
        LOG.debug(_("[VRM-CINDER] start create_volumesnapshot()"))
        uri = '/volumesnapshots'
        method = 'POST'
        path = self.site_uri + uri
        body = {
            'volumeUrn': kwargs.get('vol_urn'),
            'snapshotUuid': kwargs.get('snapshot_uuid')
        }
        new_url = self._generate_url(path)
        resp, body = self.vrmhttpclient.request(new_url, method, body=json.dumps(body))
        task_uri = body.get('taskUri')
        if task_uri is not None:
            self.task_proxy.wait_task(task_uri=task_uri)
        return body

    def delete_volumesnapshot(self, **kwargs):
        '''
                    'delete_volumesnapshot': ('DELETE',
                                          ('/volumesnapshots', None, None, kwargs.get('id')),
                                          {},
                                          {
                                              'snapshotUuid': kwargs.get('snapshotUuid'),
                                          },
                                          True),
        '''
        LOG.debug(_("[VRM-CINDER] start delete_volumesnapshot()"))
        uri = '/volumesnapshots'
        method = 'DELETE'
        path = self.site_uri + uri + '/' + kwargs.get('id')
        body = {
            'volumeUrn': kwargs.get('vol_urn'),
            'snapshotUuid': kwargs.get('snapshot_uuid')}
        new_url = self._generate_url(path)
        resp, body = self.vrmhttpclient.request(new_url, method)
        task_urn_ = body.get('taskUrn')
        task_uri = body.get('taskUri')
        self.task_proxy.wait_task(task_uri=task_uri)

    def create_volume_from_snapshot(self, **kwargs):
        '''
            'createvolumefromsnapshot': ('POST',
                                         ('/volumesnapshots', None, "createvol", None),
                                         {},
                                         {'snapshotUuid': kwargs.get('uuid'),
                                          'volumeName': kwargs.get('name'),
                                          'volumeType': normal/share
                                          'volumeUuid': uuid
                                          'snapshotVolumeType': 0/1
                                         },
                                         True),
        '''
        LOG.debug(_("[VRM-CINDER] start createvolumefromsnapshot()"))
        uri = '/volumesnapshots/createvol'
        method = 'POST'
        path = self.site_uri + uri
        snapshotVolumeType = 0
        if str(kwargs.get('full_clone')) == '0':
            snapshotVolumeType = 1
        body = {
            'snapshotUuid': kwargs.get('snapshot_uuid'),
            'volumeName': kwargs.get('volume_name'),
            'volumeType': kwargs.get('type'),
            'volumeUuid': kwargs.get('volume_uuid'),
            'snapshotVolumeType': snapshotVolumeType,
        }
        new_url = self._generate_url(path)
        resp, body = self.vrmhttpclient.request(new_url, method, body=json.dumps(body))
        task_urn_ = body.get('taskUrn')
        task_uri = body.get('taskUri')
        self.task_proxy.wait_task(task_uri=task_uri)
        return body



