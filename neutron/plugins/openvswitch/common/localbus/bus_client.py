# -*- coding: UTF-8 -*-

# 功能：
# 版权信息：华为技术有限公司，版本所有(C)
# 修改记录：2015/4/30 10:26  创建
import time
from neutron.plugins.openvswitch.common.rpc.rpc_business.rpc_client import RpcClient
from neutron.plugins.openvswitch.common.log import getLogger
from concurrent.futures import ThreadPoolExecutor

LOG = getLogger(__name__)
REMOTE = ("localhost", 12581)


class BusClientFactory():
    def __init__(self):
        self.port = 0
        self.interface = None
        self.name = None
        self.client = None
        self.executor = ThreadPoolExecutor(max_workers=1)

    def setPort(self, port):
        '''
        设置该client使用的端口号，不设置则会分配一个随机端口号
        :param port:
        :return:
        '''
        self.port = port

    def setInterface(self, interface):
        '''
        设置该client所能提供的服务
        :param interface:
        :return:
        '''
        self.interface = interface

    def setName(self, name):
        '''
        设置该client的名称
        :param interface:
        :return:
        '''
        self.name = name

    def createClient(self, try_times=60):
        '''
        生成一个client实例 ,失败时重连try_time次，重连间隔一秒
        :return:
        '''
        self.executor.submit(self._create)

    def _create(self):
        START = 5
        STEP = 5
        MAX = 300
        times = START
        self.client = RpcClient(False)
        self.client.add_client(REMOTE, ("localhost", self.port), None,
                               self._rpc_disconn, "", False)
        self.client.register_all(self.interface)
        self.client.start_client(REMOTE)
        while True:
            if times < MAX:
                times += STEP
            try:
                terminal = self.client.get_terminal(REMOTE)
                future = terminal.register(self.name)
                if future.get_result(1) == "success":
                    return terminal
            except Exception, e:
                LOG.debug(e.message)
            time.sleep(times)
        return None

    def _rpc_disconn(self, term):
        self.executor.submit(self._reconn)
    
    def _reconn(self):
        while True:
            try:
                terminal = self.client.get_terminal(REMOTE)
                terminal.register(self.name)
                future = terminal.check_client_online(self.name)
                if future.get_result(1):
                    return
                time.sleep(0.1)
            except Exception, e:
                LOG.exception(e)