# vim: tabstop=4 shiftwidth=4 softtabstop=4

"""
[VRM DRIVER] VRM CLIENT.

"""
import time

from oslo.config import cfg
from cinder.openstack.common import log as logging
from cinder.volume.drivers.huawei.vrm import exception as driver_exception
from cinder.openstack.common.gettextutils import _
from cinder.volume.drivers.huawei.vrm.base_proxy import BaseProxy

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

CONF = cfg.CONF

LOG = logging.getLogger(__name__)


class TaskProxy(BaseProxy):
    '''
    TaskProxy
    '''
    def __init__(self):
        super(TaskProxy, self).__init__()


    def wait_task(self, **kwargs):
        '''

        :param kwargs:
        :return:
        '''
        LOG.debug(_("[VRM-CINDER] start wait_task()"))

        task_uri = kwargs.get('task_uri')
        method = 'GET'
        if task_uri is None:
            LOG.debug(_("[VRM-CINDER] task_uri is none."))
            raise driver_exception.ClientException(101)
        else:
            new_url = self._generate_url(task_uri)
            expiration = time.time() + int(CONF.vrm_timeout)
            status = TASK_UNKNOWN
            retry = 0
            error_num = 0
            while retry < int(CONF.vrm_timeout):

                if retry > 10:
                    retry += 5
                    sleep(5)
                else:
                    retry += 1
                    sleep(1)

                body = None
                try:
                    resp, body = self.vrmhttpclient.request(new_url, method)
                except Exception as ex:
                    LOG.debug(_("[VRM-CINDER] querytask request exception."))
                    error_num += 1
                    if 30 < error_num:
                        LOG.debug(_("[VRM-CINDER] querytask request exception."))
                        raise ex
                    else:
                        continue

                if body:
                    status = body.get('status')
                    if status in [TASK_WAITING, TASK_RUNNING]:
                        LOG.debug(_("[VRM-CINDER] continue wait_task()"))
                        continue
                    elif status in [TASK_SUCCESS]:
                        LOG.debug(_("[VRM-CINDER] return TASK_SUCCESS wait_task()"))
                        return status
                    elif status in [TASK_FAILED, TASK_CANCELLING]:
                        LOG.debug(_("[VRM-CINDER] return TASK_FAILED wait_task()"))
                        raise driver_exception.ClientException(101)
                    else:
                        LOG.debug(_("[VRM-CINDER] pass wait_task()"))
                        error_num += 1
                        if 30 < error_num:
                            raise driver_exception.ClientException(101)
                        else:
                            continue
                else:
                    LOG.debug(_("[VRM-CINDER] body is none."))
                    error_num += 1
                    if 30 < error_num:
                        raise driver_exception.ClientException(101)
                    else:
                        continue


