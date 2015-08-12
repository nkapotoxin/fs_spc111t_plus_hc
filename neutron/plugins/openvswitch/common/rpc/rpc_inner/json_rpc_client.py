# -*- coding: UTF-8 -*-
"""
            功    能：JsonClient类，客户端的jsonrpc数据收发类
            版权信息：华为技术有限公司，版本所有(C) 2014
            作者：
            修改记录：2014-11-3 14:30  JsonClient 创建
"""
from _ssl import PROTOCOL_TLSv1
import os
import select
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
import thread
from neutron.plugins.openvswitch.common.exceptions import NoTerminalFromIpException
from neutron.plugins.openvswitch.common.rpc.rpc_inner.json_rpc_terminal import \
    JsonRpcTerminal
from neutron.plugins.openvswitch.common.log import getLogger
from neutron.plugins.openvswitch.common.rpc.rpc_config.config import \
    rpc_handle_max_workers, socket_timeout
import ssl

logger = getLogger(__name__)


class JsonRpcClient():
    def __init__(self, remote_address, local_address, aware,
                 ssl_crt_file_path, needSsl=True):
        self.client = None
        self.needSsl = needSsl
        self.remote_address = remote_address
        self.local_address = local_address
        self.ssl_crt_file_path = ssl_crt_file_path
        self.inputs = []
        self.outputs = []
        self.aware = aware
        self.input_executor = ThreadPoolExecutor(
            max_workers=rpc_handle_max_workers)
        self.terminal = JsonRpcTerminal(self.client, self.remote_address,
                                        self.input_executor)
        self.terminal.start_req_timeout()
        self.shutdown = True
        self.lock = thread.allocate_lock()

    def start(self):
        curr_thread = threading.currentThread()
        curr_thread.setName("JsonRpcClient")
        while not self.inputs is None:
            if self.shutdown:
                logger.debug("rpc client shutdown")
                # self.terminal._shutdown()
                break
            readable, writable, exceptional = select.select(self.inputs,
                                                            self.outputs,
                                                            self.inputs, 1)
            if not (readable or writable or exceptional):
                continue
            for s in readable:
                tm = self.terminal
                if tm._read() == -1:
                    self.close()

            for s in exceptional:
                logger.error("rpc client connection exception, remove "
                             "connection %s", s.getpeername())
                self.close()

    def get_terminal(self):
        if self._is_terminal_work():
            return self.terminal
        else:
            raise NoTerminalFromIpException()

    def _is_terminal_work(self):
        return self.terminal.connection is not None or self.shutdown is False

    def has_terminal(self):
        return self._is_terminal_work()

    def connect(self):
        with self.lock:
            self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if self.needSsl:
                self.client = self._sslWrap(self.client)
            if self.local_address:
                logger.debug("json_rpc_client: bind address: %s",
                             self.local_address)
                self.client.bind(self.local_address)
            self.client.settimeout(socket_timeout)
            self.client.connect(self.remote_address)
            self.client.settimeout(None)
            self.inputs.append(self.client)
            self.terminal.connection = self.client
            self.aware.added(self.terminal)
            self.shutdown = False

    def _sslWrap(self, socket):
        return ssl.wrap_socket(socket,
                             cert_reqs=ssl.CERT_NONE,
                             ssl_version=PROTOCOL_TLSv1)

    def close(self):
        with self.lock:
            logger.debug("json_rpc_client: close client")
            if self.client:
                if self.client in self.inputs:
                    self.inputs.remove(self.client)
                    try:
                        self.client.close()
                    except socket.error, e:
                        logger.error("close socket error,ip=%s",
                                     self.remote_address)
                        logger.error(e)
                    self.terminal.connection = None
                    self.terminal.pre_buffer = []
                    self.shutdown = True
                    self.aware.removed(self.terminal)

    def register(self, handler):
        self.terminal._register(handler)

    def _get_ca_certs(self):
        ca_path = os.path.join(self.ssl_crt_file_path)
        if os.path.exists(ca_path):
            return ca_path
        else:
            logger.error("%s is not found", ca_path)
            return None