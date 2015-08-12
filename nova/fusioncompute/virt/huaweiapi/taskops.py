"""
    Task operation
"""

import functools

from nova.openstack.common import loopingcall
from nova.openstack.common.gettextutils import _
from nova.fusioncompute.virt.huaweiapi import ops_base
from nova.fusioncompute.virt.huaweiapi import exception as fc_exc
from nova.fusioncompute.virt.huaweiapi.utils import LOG

def wait_task_done(task_ops, exc=None):
    """
    Send message and wait task result. Only for the function(func) whose
    return like {"taskUrn": string, "taskUri": string} format, if you
    won't want to send and wait the result, return {} instead of
    {"taskUrn": string, "taskUri": string} format

    :param task_ops: the task monitor object
    :param exc: when monitor the task failed, raise this exception object
    :return:
    """
    def wrap(func):
        """
        wrap function

        :param func: the function will be decorated
        :return:
        """
        @functools.wraps(func)
        def inner(*args, **kwargs):
            """
            inner function

            :param args: the list format args of function that will
            be decorated
            :param kwargs: the dict format args of function that will
            be decorated
            :return:
            """
            try:
                resp = func(*args, **kwargs)
            except fc_exc.RequestError as req_exc:
                if exc:
                    raise exc(str(req_exc.kwargs['reason']))
                raise req_exc

            if isinstance(resp, dict) and resp.get('taskUri'):
                success, reason = task_ops.wait_task_done(resp['taskUri'])
                if not success:
                    LOG.error(_('task failed: %s'), reason)
                    if exc:
                        raise exc(str(reason))
                    raise fc_exc.FusionComputeTaskException(reason=reason)

            return resp
        return inner
    return wrap


class TaskOperation(ops_base.OpsBase):
    """
    task operation object
    """
    def __init__(self, fc_client):
        """
        TaskOperation init func
        :param fc_client:
        :return:
        """
        super(TaskOperation, self).__init__(fc_client)

    def wait_task_done(self, task_uri, interval=3):
        """

        :param task_uri:
        :param interval:
        :return:
        """
        ret = {'success': False, 'reason': None}

        def _wait_done():
            """
            wait task result
            """

            task = self.get_task(task_uri)

            if task['status'] == "success":
                LOG.info(_("Task [%s] is successfully." % task_uri))
                ret['success'] = True
                raise loopingcall.LoopingCallDone()
            elif task['status'] == "failed":
                LOG.info(_("Task [%s] is failed, the reason is %s."),
                         task_uri, task['reasonDes'])
                ret['reason'] = task['reasonDes']
                raise loopingcall.LoopingCallDone()
            else:
                LOG.info(_("Task [%s] is running, the progress is %s."),
                         task_uri, task['progress'])

        timer = loopingcall.FixedIntervalLoopingCall(_wait_done)
        timer.start(interval=interval).wait()
        return ret['success'], ret['reason']

    def get_task(self, task_uri):
        """
        get task uri info
        :param task_uri:
        :return:
        """
        return self.get(task_uri)
