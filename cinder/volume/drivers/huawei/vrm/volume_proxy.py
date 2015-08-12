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


class VolumeProxy(BaseProxy):
    def __init__(self):
        super(VolumeProxy, self).__init__()
        self.task_proxy = TaskProxy()


    def query_volume(self, **kwargs):
        '''
                'query_volume': ('GET',
                                 ('/volumes', kwargs.get(self.RESOURCE_URI), None, kwargs.get('id')),
                                 {'limit': kwargs.get('limit'),
                                  'offset': kwargs.get('offset'),
                                  'scope': kwargs.get('scope')
                                 },
                                 {},
                                 False),
        '''
        LOG.debug(_("[VRM-CINDER] start query_volume()"))
        uri = '/volumes'
        method = 'GET'
        path = self.site_uri + uri + '/' + kwargs.get('id')

        new_url = self._generate_url(path)
        resp, body = self.vrmhttpclient.request(new_url, method)
        return body

    def list_volumes(self, **kwargs):
        '''
                'list_volumes': ('GET',
                                 ('/volumes', kwargs.get(self.RESOURCE_URI), None, kwargs.get('id')),
                                 {'limit': kwargs.get('limit'),
                                  'offset': kwargs.get('offset'),
                                  'scope': kwargs.get('scope')
                                 },
                                 {},
                                 False),
        '''
        LOG.debug(_("[VRM-CINDER] start query_volumesnapshot()"))
        uri = '/volumes'
        method = 'GET'
        path = self.site_uri + uri

        offset = 0
        volumes = []
        while True:
            parames = {
                'limit': self.limit,
                'offset': offset,
                'scope': kwargs.get('scope'),
                'uuid':kwargs.get('uuid')
            }
            appendix = self._joined_params(parames)
            new_url = self._generate_url(path, appendix)
            resp, body = self.vrmhttpclient.request(new_url, method)
            total = int(body.get('total') or 0)
            if total > 0:
                res = body.get('volumes')
                volumes += res
                offset += len(res)
                if offset >= total or len(volumes) >= total or len(res) < self.limit:
                    break
            else:
                break

        return volumes


    def create_volume(self, **kwargs):
        '''
                'create_volume': ('POST',
                                  ('/volumes', None, None, None),
                                  {},
                                  {'name': kwargs.get('name'),
                                   'quantityGB': kwargs.get('quantityGB'),
                                   'datastoreUrn': kwargs.get('datastoreUrn'),
                                   'uuid': kwargs.get('uuid'),
                                   'isThin': kwargs.get('isThin'),
                                   'type': kwargs.get('type'),
                                   'indepDisk': kwargs.get('indepDisk'),
                                   'persistentDisk': kwargs.get('persistentDisk'),
                                   'volumeId': kwargs.get('volumeId'),
                                    'snapshotUuid': kwargs.get('snapshotUuid'),
                                   'imageUrl': kwargs.get('imageUrl'),
                                  },
                                  True),
        '''
        LOG.debug(_("[VRM-CINDER] start create_volume()"))
        uri = '/volumes'
        method = 'POST'
        path = self.site_uri + uri
        new_url = self._generate_url(path)
        body = {
            'name': kwargs.get('name'),
            'quantityGB': kwargs.get('size'),
            'datastoreUrn': kwargs.get('ds_urn'),
            'uuid': kwargs.get('uuid'),
            'isThin': kwargs.get('is_thin'),
            'type': kwargs.get('type'),
            'indepDisk': kwargs.get('independent')
        }
        resp, body = self.vrmhttpclient.request(new_url, method, body=json.dumps(body))
        task_uri = body.get('taskUri')
        self.task_proxy.wait_task(task_uri=task_uri)
        return body

    def delete_volume(self, **kwargs):
        '''
                'delete_volume': ('DELETE',
                                  ('/volumes', kwargs.get(self.RESOURCE_URI), None, None),
                                  {},
                                  {},
                                  True),
        '''
        LOG.debug(_("[VRM-CINDER] start delete_vm()"))
        uri = '/volumes'
        method = 'DELETE'
        path = kwargs.get('volume_uri')
        new_url = self._generate_url(path)
        try:
            resp, body = self.vrmhttpclient.request(new_url, method)
            task_uri = body.get('taskUri')
            self.task_proxy.wait_task(task_uri=task_uri)
        except driver_exception.ClientException as ex:
            LOG.debug(_("[VRM-CINDER] delete volume (%s)"), ex.errorCode)
            if ex.errorCode == "10420004":
                return
            else:
                raise ex

    def clone_volume(self, **kwargs):
        '''
                        'clone_volume': ('POST',
                                 ('/volumes', None, kwargs.get('src_name'), 'action/copyVol'),
                                 {},
                                 {'destinationVolumeID': kwargs.get('dest_name')
                                 },
                                 True),
        '''
        LOG.debug(_("[VRM-CINDER] start clone_volume()"))
        uri = '/volumes'
        method = 'POST'
        path = self.site_uri + uri + '/' + kwargs.get('src_volume_id') + '/action/copyVol'
        body = {'dstVolUrn': kwargs.get('dest_volume_urn')}
        new_url = self._generate_url(path)
        resp, body = self.vrmhttpclient.request(new_url, method, body=json.dumps(body))
        task_uri = body.get('taskUri')
        self.task_proxy.wait_task(task_uri=task_uri)


    def _copy_nfs_image_to_volume(self, **kwargs):
        '''
                'copy_image_to_volume': ('POST',
                                         ('/volumes/imagetovolume', None, None, None),
                                         {},
                                         {
                                             'volumePara': {
                                                 'quantityGB': kwargs.get('volume_size'),
                                                 'urn': kwargs.get('volume_urn')
                                             },
                                             'imagePara': {
                                                 'id': kwargs.get('image_id'),
                                                 'url': kwargs.get('image_location')
                                             },
                                             'location': kwargs.get('cluster_urn'),
                                             'needCreateVolume': False
                                         },
                                         True),
        '''
        LOG.debug(_("[VRM-CINDER] start copy_image_to_volume()"))
        uri = '/volumes/imagetovolume'
        method = 'POST'
        path = self.site_uri + uri
        new_url = self._generate_url(path)
        body = {
            'volumePara': {
                'quantityGB': kwargs.get('volume_size'),
                'urn': kwargs.get('volume_urn')
            },
            'imagePara': {
                'id': kwargs.get('image_id'),
                'url': kwargs.get('image_location')
            },
            'location': kwargs.get('cluster_urn'),
            'needCreateVolume': False
        }
        resp, body = self.vrmhttpclient.request(new_url, method, body=json.dumps(body))
        task_uri = body.get('taskUri')
        self.task_proxy.wait_task(task_uri=task_uri)

    def _copy_volume_to_image(self, **kwargs):
        '''
                'copy_volume_to_image': ('POST',
                                         ('/volumes/volumetoimage', None, None, None),
                                         {},
                                         {
                                             'volumePara': {'urn': kwargs.get('volume_urn'),
                                                            'quantityGB': kwargs.get('volume_size')},
                                             'imagePara': {'id': kwargs.get('image_id'), 'url': kwargs.get('image_url')}
                                         },
                                         True),
        '''

        LOG.debug(_("[VRM-CINDER] start stop_vm()"))
        uri = '/volumes/volumetoimage'
        method = 'POST'
        path = self.site_uri + uri
        new_url = self._generate_url(path)

        body = {
            'volumePara': {
                'urn': kwargs.get('volume_urn'),
                'quantityGB': kwargs.get('volume_size')},
            'imagePara': {
                'id': kwargs.get('image_id'),
                'url': kwargs.get('image_url')}
        }
        resp, body = self.vrmhttpclient.request(new_url, method, body=json.dumps(body))
        task_uri = body.get('taskUri')
        self.task_proxy.wait_task(task_uri=task_uri)

    def manage_existing(self, **kwargs):
        '''
                'manage_existing': ('POST',
                                  ('/volumes', None, None, None),
                                  {},
                                  {'name': kwargs.get('name'),
                                   'quantityGB': kwargs.get('quantityGB'),
                                   'datastoreUrn': kwargs.get('datastoreUrn'),
                                   'uuid': kwargs.get('uuid'),
                                   'type': kwargs.get('type'),
                                   'indepDisk': kwargs.get('indepDisk'),
                                   'persistentDisk': kwargs.get('persistentDisk'),
                                   'volumeId': kwargs.get('volumeId'),
                                   'snapshotUuid': kwargs.get('snapshotUuid'),
                                   'imageUrl': kwargs.get('imageUrl'),
                                  },
                                  True),
        '''
        LOG.debug(_("[VRM-CINDER] start create_volume()"))
        uri = '/volumes/registevol'
        method = 'POST'
        path = self.site_uri + uri
        new_url = self._generate_url(path)
        body = {
            'name': kwargs.get('name'),
            'quantityGB': kwargs.get('quantityGB'),
            'volInfoUrl': kwargs.get('volInfoUrl'),
            'uuid': kwargs.get('uuid'),
            'type': kwargs.get('type'),
            'maxReadBytes': kwargs.get('maxReadBytes'),
            'maxWriteBytes': kwargs.get('maxWriteBytes'),
            'maxReadRequest': kwargs.get('maxReadRequest'),
            'maxWriteRequest': kwargs.get('maxWriteRequest')}

        resp, body = self.vrmhttpclient.request(new_url, method, body=json.dumps(body))
        return body

    def unmanage(self, **kwargs):
        '''
                'unmanage': ('DELETE',
                                  ('/volumes?isOnlyDelDB=1', kwargs.get(self.RESOURCE_URI), None, None),
                                  {},
                                  {},
                                  True),
        '''
        LOG.debug(_("[VRM-CINDER] start unmanage()"))
        method = 'DELETE'
        path = kwargs.get('volume_uri') + '?isOnlyDelDB=1'
        new_url = self._generate_url(path)
        try:
            resp, body = self.vrmhttpclient.request(new_url, method)
            task_uri = body.get('taskUri')
            self.task_proxy.wait_task(task_uri=task_uri)
        except driver_exception.ClientException as ex:
            LOG.debug(_("[VRM-CINDER] unmanage volume (%s)"), ex.errorCode)
            if ex.errorCode == "10420004":
                return
            else:
                raise ex

    def migrate_volume(self, **kwargs):
        '''
            Post <vol_uri>/<volid>/action/migratevol HTTP/1.1
            Host https://<ip>:<port>
            Accept application/json;version=<version>; charset=UTF-8
            X-Auth-Token: <Authen_TOKEN>
            {
            'datastoreUrn':string,
            'speed': integer
            }
        '''
        LOG.debug(_("[VRM-CINDER] start migrate_volume()"))
        uri = '/volumes'
        method = 'POST'
        mig_type = 1

        path = self.site_uri + uri + '/' + kwargs.get('volume_id') + '/action/migratevol'
        body = {'datastoreUrn': kwargs.get('dest_ds_urn'),
                'speed': kwargs.get('speed'),
                'migrateType': kwargs.get('migrate_type')}
        new_url = self._generate_url(path)
        resp, body = self.vrmhttpclient.request(new_url, method, body=json.dumps(body))
        task_uri = body.get('taskUri')
        self.task_proxy.wait_task(task_uri=task_uri)

    def modify_volume(self, **kwargs):
        LOG.debug(_("[VRM-CINDER] start modify_volume()"))
        uri = '/volumes'
        method = 'PUT'
        path = self.site_uri + uri + '/' + kwargs.get('volume_id')
        body = {'type': kwargs.get('type')}
        new_url = self._generate_url(path)
        resp, body = self.vrmhttpclient.request(new_url, method, body=json.dumps(body))
        if resp.status_code not in (200, 204):
            raise driver_exception.ClientException(101)

    def extend_volume(self,**kwargs):
        '''
                'extend_volume': ('POST',
                                  (kwargs.get('volume_uri'),'/action/expandVol',  None, None),
                                  {},
                                  {},
                                  True),
        '''
        LOG.debug(_("[VRM-CINDER] start extend_volume()"))
        method='POST'
        body = {'size': kwargs.get('size')}
        volume_uri = kwargs.get('volume_uri')

        path =  volume_uri + '/action/expandVol'
        new_url = self._generate_url(path)

        try:
            resp, body = self.vrmhttpclient.request(new_url, method, body=json.dumps(body))

            task_uri = body.get('taskUri')

            self.task_proxy.wait_task(task_uri=task_uri)
        except driver_exception.ClientException as ex:
            LOG.debug(_("[VRM-CINDER] extend volume (%s)"), ex.errorCode)
            raise ex
        except Exception as ex:
            LOG.debug(_("[VRM-CINDER] extend volume (%s)"), ex)
            raise ex
