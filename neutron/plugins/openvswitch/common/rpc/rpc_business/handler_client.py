# -*- coding: UTF-8 -*-
"""
            功    能：ClientHandler类，rpc客户端新增断开连接的处理类
            版权信息：华为技术有限公司，版本所有(C) 2014
            作者：
            修改记录：2014-11-3 14:30  ClientHandler 创建
"""
from neutron.plugins.openvswitch.common.rpc.rpc_inner.server_aware import ServerAware
from neutron.plugins.openvswitch.common.log import getLogger

logger = getLogger(__name__)


class ClientHandler(ServerAware):
    def __init__(self, addCallback, removeCallback):
        self.addCallback = addCallback
        self.removeCallback = removeCallback

    def added(self, terminal):
        logger.info("rpc client add terminal, address=%s", terminal.address)
        if self.addCallback:
            self.addCallback(terminal)

    def removed(self, terminal):
        logger.info("rpc client remove terminal, address=%s", terminal.address)
        if self.removeCallback:
            self.removeCallback(terminal)