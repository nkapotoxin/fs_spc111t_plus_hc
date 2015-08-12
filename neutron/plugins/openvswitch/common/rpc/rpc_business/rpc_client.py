# -*- coding: UTF-8 -*-
"""
            功    能：RpcClient类，rpc客户端启动类
            版权信息：华为技术有限公司，版本所有(C) 2014
            作者：
            修改记录：2014-11-3 14:30  RpcClient 创建
"""
import sched
import socket
import threading

from concurrent.futures import ThreadPoolExecutor
import thread
import time
from neutron.plugins.openvswitch.common.exceptions import \
    NoRpcClientFromIpException, NoTerminalFromIpException, TimeoutException, \
    SyncConnectionException
from neutron.plugins.openvswitch.common.rpc.rpc_business.handler_client import \
    ClientHandler
from neutron.plugins.openvswitch.common.rpc.rpc_config import config
from neutron.plugins.openvswitch.common.rpc.rpc_config.config import \
    reconnect_monitor_time, reconnect_time, rpc_client_max_workers, \
    DEFAULT_PERIOD
from neutron.plugins.openvswitch.common.rpc.rpc_inner.json_rpc_client import \
    JsonRpcClient
from neutron.plugins.openvswitch.common.log import getLogger

logger = getLogger(__name__)


class RpcClient():
    def __init__(self, monitorOn=True, max_workers=rpc_client_max_workers):
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.json_rpc_clients = {}
        self.locks = {}
        self.futures = {}
        self.is_connected = False
        self.monitor_executor = ThreadPoolExecutor(max_workers=max_workers)
        self.schedule = sched.scheduler(time.time, time.sleep)
        self.monitorOn = monitorOn
        self.is_echo = False

    def add_client(self, remote_address, local_address, add_callback,
                   remove_callback, ssl_crt_file_path, needSsl=True):
        self.json_rpc_clients[remote_address] = \
            JsonRpcClient(remote_address,
                          local_address,
                          ClientHandler(
                              add_callback,
                              remove_callback), ssl_crt_file_path, needSsl)
        self.locks[remote_address] = thread.allocate_lock()

    def _start(self, remote_address):
        logger.debug("rpcClient start success, address = %s",
                     self.json_rpc_clients[remote_address].local_address)
        self.json_rpc_clients[remote_address].start()
        logger.debug("rpcClient stopped! address = %s",
                     self.json_rpc_clients[remote_address].local_address)
        self.is_connected = False
        return

    def start_client(self, remote_address):
        logger.debug("rpcClient try to establish an connection %s",
                     remote_address)
        if self.json_rpc_clients.get(remote_address):
            json_rpc_client = self.json_rpc_clients[remote_address]
        else:
            raise NoRpcClientFromIpException()
        try:
            json_rpc_client.connect()
            self.is_connected = True
            logger.debug("connection established %s, ready for starting "
                         "rpcClient", remote_address)
            self.futures[remote_address] = self.executor.submit(self._start,
                                                                remote_address)
        except socket.error, e:
            logger.debug(
                "connection established fail %s, ready for starting "
                "rpcClient",
                remote_address)
            logger.error(e)
        finally:
            if self.monitorOn:
                self.schedule.enter(DEFAULT_PERIOD, 0, self._monitor,
                                    (remote_address,))
                self.monitor_executor.submit(self.schedule.run)

    def get_terminal(self, remote_address):
        if self.json_rpc_clients.get(remote_address):
            with self.locks.get(remote_address):
                client = self.json_rpc_clients[remote_address]
                if client.has_terminal():
                    return client.get_terminal()
                else:
                    try:
                        client.connect()
                        self.is_connected = True
                        is_submit = self.submit_client(remote_address)
                        logger.debug("rpc_client: submit client Thread %s",
                                     is_submit)
                        return client.get_terminal()
                    except Exception, e:
                        logger.error(e)
                        raise NoTerminalFromIpException()
        else:
            raise NoRpcClientFromIpException()

    def submit_client(self, remote_address):
        if self.futures.get(remote_address):
            is_running = self.futures[remote_address].running()
            while is_running:
                self.futures[remote_address].cancel()
                is_running = self.futures[remote_address].running()
                logger.debug("submit_client: former thread is running: %s",
                             is_running)
                time.sleep(0.1)
        self.futures[remote_address] = self.executor.submit(self._start,
                                                            remote_address)
        return True

    def start_monitor_echo(self):
        if self.is_echo:
            logger.warn("rpc_client: echo monitor has started")
            return
        self.is_echo = True

    def stop_monitor_echo(self):
        self.is_echo = False

    def _monitor(self, remote_address):
        curr_thread = threading.currentThread()
        curr_thread.setName("monitor_echo")
        try:
            terminal = self.get_terminal(remote_address)
            if self.futures[remote_address].running():
                if self.is_echo:
                    future = terminal.echo(config.echo_content)
                    try:
                        future.get_result(config.echo_timeout)
                    except (TimeoutException, SyncConnectionException), e:
                        logger.error("rpc_client: echo error: %s", e)
                        self.json_rpc_clients.get(remote_address).close()
            else:
                try:
                    ex = self.futures[remote_address].exception(1)
                    if ex is not None:
                        logger.error("rpc_client: start thread "
                                     "exception: %s", ex)
                        self.json_rpc_clients.get(
                            remote_address).close()
                except Exception, e:
                    logger.error("rpc_client: future.exception catch "
                                 "exception: %s", e)
            self.schedule.enter(reconnect_monitor_time, 0, self._monitor,
                                (remote_address,))
        except (NoTerminalFromIpException,
                NoRpcClientFromIpException):
            self.schedule.enter(reconnect_time, 0, self._monitor,
                                (remote_address,))
        except Exception, e:
            logger.exception(e)
            self.schedule.enter(reconnect_time, 0, self._monitor,
                                (remote_address,))

    def register_all(self, handler):
        for v in self.json_rpc_clients.itervalues():
            v.register(handler)