# -*- coding: UTF-8 -*-

# 功能：
# 版权信息：华为技术有限公司，版本所有(C)
# 作者：
# 修改记录：14-11-3 下午8:03    创建

"""
OAM base exception handling.
"""


_FATAL_EXCEPTION_FORMAT_ERRORS = False


class OamException(Exception):
    """Base OAM Exception.

    To correctly use this class, inherit from it and define
    a 'message' property. That message will get printf'd
    with the keyword arguments provided to the constructor.
    """
    message = "An unknown exception occurred."

    def __init__(self, message=None, **kwargs):
        message = message or self.message
        try:
            message = message % kwargs
            super(OamException, self).__init__(message)
        except Exception:
            if _FATAL_EXCEPTION_FORMAT_ERRORS:
                raise
            else:
                # at least get the core message out if something happened
                super(OamException, self).__init__(self.message)


class ExampleOne(OamException):
    """
    raise ExampleOne(num=1)
    """
    message = "This is an example for OamException, num: %(num)s"


class ExampleTwo(OamException):
    def __init__(self, message=None, **kwargs):
        super(ExampleTwo, self).__init__(message, **kwargs)


class TimeoutException(OamException):
    message = "Timeout"


class JsonLengthException(OamException):
    def __init__(self, msg="Exceed max length"):
        self.message = msg


class SyncConnectionException(OamException):
    def __init__(self, msg="Sync connection exception"):
        self.message = msg


class MultiTerminalException(OamException):
    message = "One ip-port should not have more than one terminal."


class NoTerminalFromIpException(OamException):
    message = "There is no terminal from your ip"


class NoRpcClientFromIpException(OamException):
    message = "There is no RpcClient from your ip"


class NoPortException(OamException):
    message = "No such Port"


class NoBondException(OamException):
    message = "No such Bond"


class PortDownException(OamException):
    message = "Port is down"


class InternalError(OamException):
    message = "Internal Error"


class UnpackException(OamException):
    message = "Can't unpack"


class PackException(OamException):
    message = "Can't pack"

class VportStatisticException(OamException):
    message = "Query vport statistic error"


class QueryKernelFlowFailedException(OamException):
    def __init__(self, msg="query kernel flow failed"):
        self.message = msg


class KernelPortNotFoundException(OamException):
    def __init__(self, msg="port in kernel_flow not found in "
                           "kernel_port_list"):
        self.message = msg


class QueryFlowEntryFailedException(OamException):
    def __init__(self, msg="query kernel flow failed"):
        self.message = msg


class PingCmdException(OamException):
    def __init__(self, message="ping cmd exception"):
        self.message = message


class DvrParameterException(OamException):
    def __init__(self, message="rpc parameter exception"):
        self.message = message


class DvrCheckCmdException(OamException):
    def __init__(self, message="Dvr check cmd exception"):
        self.message = message