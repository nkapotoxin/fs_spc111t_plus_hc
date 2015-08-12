# -*- coding: UTF-8 -*-
"""
            功    能：Future类，注册回调函数的父类
            版权信息：华为技术有限公司，版本所有(C) 2014
            作者：
            修改记录：2014-11-3 14:30  Future 创建
"""

import threading
from neutron.plugins.openvswitch.common.exceptions import SyncConnectionException, TimeoutException
from neutron.plugins.openvswitch.common.log import getLogger

logger = getLogger(__name__)


class Future():
    def __init__(self):
        self.callback = None
        self.result = None
        self._futureLock = threading.Lock()
        self.event = threading.Event()
        self.error = None

    def register(self, callback):
        self.callback = callback

    def sync(self, request_id, method):
        logger.debug("rpc sync function acquire lock, requestId=%s, method=%s",
                     request_id, method)
        self.event.clear()

    def get_result(self, timeout):
        self.event.wait(timeout)
        if not self.event.isSet():
            self.event.set()
            raise TimeoutException()
        if self.error:
            raise SyncConnectionException(self.error)
        else:
            return self.result

    def notify(self, request_id, result, error):
        self.result = result
        self.error = error
        logger.debug("rpc sync function release lock, requestId=%s",
                     request_id)
        self.event.set()

    def set_error(self, error):
        self.error = error
        logger.debug("rpc sync function release lock")
        self.event.set()