# -*- coding: UTF-8 -*-
"""
            功    能：JsonRpcTerminal类，rpc内部处理数据的类
            版权信息：华为技术有限公司，版本所有(C) 2014
            作者：
            修改记录：2014-11-3 14:30  JsonRpcTerminal 创建
"""
import sched
import socket
import threading
import uuid
import json
import thread
import time
from neutron.plugins.openvswitch.common.exceptions import JsonLengthException
from neutron.plugins.openvswitch.common.rpc.rpc_config.config import rpc_default_timeout
from neutron.plugins.openvswitch.common.rpc.rpc_inner.rpc_future import Future
from neutron.plugins.openvswitch.common.log import getLogger

logger = getLogger(__name__)
ECHO = "echo"
VERIFY = "verifyAgent"
UTF8 = "utf-8"

class JsonRpcTerminal():
    def __init__(self, connection, address, input_executor):
        self.connection = connection
        self.address = address
        self.input_executor = input_executor
        self.requests = {}
        self.buffer_length = 1024 * 1024
        self.handlers = []
        self.pre_buffer = []
        self.schedule = sched.scheduler(time.time, time.sleep)
        self.req_lock = thread.allocate_lock()
        self.send_lock = thread.allocate_lock()
        self.is_req_timeout_shutdown = False
        self.is_req_timeout_running = False
        self.echo_future = Future()

    def _add_request(self, request):
        self.requests[request.id] = (request, rpc_default_timeout)

    def _handle_msg(self, buf):
        if (len(self.pre_buffer) + len(buf)) > self.buffer_length:
            raise JsonLengthException("Exceed max length : " +
                                      str(self.buffer_length))
        msg = self._get_json(self.pre_buffer, buf)
        if len(msg) > 0:
            self._handle_request(msg)

    def _handle_request(self, msg):
        for m in msg:
            logger.debug("rpc_terminal:_handleRequest, m = %s", m)
            request = json.loads(m.encode(UTF8))
            self.echo_future.notify(ECHO, ECHO, None)
            if request.get("id") == ECHO:
                continue
            if request["id"] in self.requests.keys():
                self.input_executor.submit(self._get_return, request)
            else:
                self.input_executor.submit(self._get_service, request)

    def _get_return(self, req):
        try:
            curr_thread = threading.currentThread()
            curr_thread.setName("rpc_getReturn")
            logger.debug("rpc getReturn: return = %s, error = %s",
                         req.get("result", "not provided"),
                         req.get("error", "not provided"))
            request = self._get_request_from_dict(req["id"])
            if request is not None:
                if not request.future.callback:
                    return
                else:
                    callback = request.future.callback
                    if isinstance(callback, str) and callback == "sync":
                        future = request.future
                        future.notify(req["id"], req["result"], req["error"])
                    else:
                        self._callback(request, req)
        except Exception, e:
            logger.error("rpc getReturn raise Exception")
            logger.exception(e)
        finally:
            self._delete_request_from_dict(req["id"])

    def _callback(self, request, req):
        error = req.get("error")
        if error:
            callback_method = request.future.callback.returnFail
            result = error
        else:
            callback_method = request.future.callback.returnSuccess
            result = req.get("result")
        callback_method(self.address, result)

    def _get_service(self, req):
        try:
            curr_thread = threading.currentThread()
            curr_thread.setName("rpc_getService_%s" %
                                req.get("method", "not provided"))
            logger.debug("rpc getService: getService...")
            if not self.handlers:
                logger.warn("rpc getService: no handler registered but "
                            "request received")
                return
            if req.get("method") is None:
                logger.warn("rpc getService: this msg should not be handled "
                            "here, there must be some error in param[id] or "
                            "this request has been time out")
                logger.debug("rpc getService: request = %s", req)
                return
            for handler in self.handlers:
                if "default" != getattr(handler, req["method"], "default"):
                    params = req.get('params', [])
                    try:
                        obj = getattr(handler, req["method"])(*params)
                        json_ret = {"id": req["id"], "result": obj,
                                    "error": None}
                        logger.debug("rpc getService: json_ret = %s", json_ret)
                        self._write(json.dumps(json_ret))
                    except Exception, e:
                        logger.exception(e)
                        json_ret = {"id": req["id"], "result": None,
                                    "error": e.message}
                        logger.debug("rpc getService: raise a exception, "
                                     "json_ret = %s", json_ret)
                        self._write(json.dumps(json_ret))
                    break
            else:
                logger.info(
                    "rpc getService: there is no handler for your request")
                error_info = "no handler for request"
                json_ret = {"id": req["id"], "result": None,
                            "error": error_info}
                self._write(json.dumps(json_ret))
        except Exception, e:
            logger.error("rpc getService raise Exception")
            logger.exception(e)

    def _get_json(self, pre_buf, buf):
        msg = []
        open_braces = 0
        if len(pre_buf) > 0:
            new_buf = pre_buf + buf
        else:
            new_buf = buf
        read_index = 0
        json_start = 0
        json_end = 0
        for c in new_buf:
            if c == '{' or c == '[':
                open_braces += 1
                if open_braces == 1:
                    json_start = read_index
            if c == '}' or c == ']':
                open_braces -= 1
                if open_braces == 0:
                    json_end = read_index
                    msg.append(new_buf[json_start:json_end + 1])
            read_index += 1
        if open_braces != 0:
            self.pre_buffer = new_buf[json_start:]
        else:
            self.pre_buffer = []
        return msg

    def _read(self):
        try:
            buf = self.connection.recv(self.buffer_length)
            if buf:
                self._handle_msg(buf)
                return len(buf)
            else:
                logger.debug("rpc_terminal:buf is None")
                return -1
        except socket.error, e:
            logger.exception(e)
            return -1
        except JsonLengthException, e:
            logger.error(e)
            return -1
        except Exception, e:
            logger.exception(e)
            return -1

    def _write(self, buf):
        with self.send_lock:
            try:
                if self.connection:
                    self.connection.sendall(buf)
                else:
                    logger.error("rpc_terminal: connection is None but call "
                                 "connection.sendall")
            except socket.error, e:
                logger.error("rpc_terminal: connection.sendall error: %s", e)

    def _register(self, h):
        self.handlers.append(h)

    def _get_request_from_dict(self, key):
        with self.req_lock:
            if self.requests.get(key) is not None:
                return self.requests.get(key)[0]
            return None

    def _delete_request_from_dict(self, key):
        with self.req_lock:
            if self.requests.get(key) is not None:
                del self.requests[key]

    def _handler_timeout_from_dict(self, key):
        with self.req_lock:
            value = self.requests.get(key)
            if value is not None:
                if value[1] == 1:
                    logger.debug("rpc_terminal:remove timeout request: %s",
                                 self.requests[key])
                    del self.requests[key]
                else:
                    self.requests[key] = (value[0], value[1] - 1)

    def start_req_timeout(self):
        if not self.is_req_timeout_running:
            self.is_req_timeout_running = True
            thread.start_new_thread(self._start_timeout, ())

    def _start_timeout(self):
        curr_thread = threading.currentThread()
        curr_thread.setName("rpc_terminal_req_timeout")
        self.schedule.enter(0, 0, self._start_req_timeout, ())
        self.schedule.run()
        self.is_req_timeout_running = False

    def _start_req_timeout(self):
        for k in self.requests.keys():
            self._handler_timeout_from_dict(k)
        if not self.is_req_timeout_shutdown:
            self.schedule.enter(1, 0, self._start_req_timeout, ())

    def shutdown_req_timeout(self):
        self.is_req_timeout_shutdown = True

    def get_terminal_ip(self):
        if self.connection:
            return self.connection.getsockname()[0]
        return None

    def get_terminal_address(self):
        return self.address


    def echo(self, param):
        """
        单独处理心跳
        :param param:
        :return:
        """
        self.echo_future = Future()
        try:
            self.echo_future.register("sync")
            echo_uuid = ECHO
            self.echo_future.sync(echo_uuid, ECHO)
            params = [param]
            json_request = {"id": echo_uuid, "method": ECHO,
                            "params": params}
            logger.debug("rpc send echo: %s", json_request)
            req = json.dumps(json_request)
            self._write(req)
        except Exception, e:
            logger.exception(e)
            self.echo_future.set_error(e.message)
        return self.echo_future

    def verifyAgent(self, user, pwd, isVrm):
        """
        发送密码至server端校验，
        :param param:
        :return:
        """
        try:
            params = [user, pwd, isVrm]
            json_request = {"id": VERIFY, "method": VERIFY,
                            "params": params}
            logger.debug("rpc send password")
            req = json.dumps(json_request)
            self._write(req)
        except Exception, e:
            logger.exception(e)
        return self.echo_future

    def __getattr__(self, item):
        return Request(item, self)


class Request():
    def __init__(self, method, terminal):
        self.method = method
        self.terminal = terminal
        self.id = uuid.uuid4().__str__()
        self.future = Future()

    def __call__(self, *args, **kwargs):
        try:
            if "callbackFunc" in kwargs.keys():
                self.future.register(kwargs["callbackFunc"])
            else:
                self.future.register("sync")
                self.future.sync(self.id, self.method)
            params = list(args)
            json_request = {"id": self.id, "method": self.method,
                            "params": params}
            logger.debug("rpc send req: json_req = %s", json_request)
            req = json.dumps(json_request)
            self.terminal._add_request(self)
            self.terminal._write(req)
        except Exception, e:
            logger.exception(e)
            self.future.set_error(e.message)
        return self.future