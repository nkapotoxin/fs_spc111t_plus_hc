import socket
import re
import six

from nova.openstack.common import local

from logging import handlers
from nova.huawei.openstack.common import HWExtend
from nova.huawei.openstack.common import utils as h_utils

class BMULogHandler(handlers.DatagramHandler):
    """
    A handler class which writes logging records. add header to logging
    content.
    """

    def __init__(self, host, port, log_file):
        """
        Initializes the handler with log_file_path
        """
        handlers.DatagramHandler.__init__(self, host, port)
        self.logfile = log_file
        self.logdict = {"nova-compute": "nova_compute",
                        "quantum-openvswitch-agent": "quantum_agent"}

    def emit(self, record):
        """
        add header to logging content
        """
        try:
            msg = self.format(record)
        except:
            raise

        header = self.logdict.get(self.logfile)
        msg = '[' + header + ']' + msg

        try:
            self.send(msg)
        except (KeyboardInterrupt, SystemExit):
            raise
        except:
            self.handleError(record)


def _dictify_context(context):
    if context is None:
        return None
    if not isinstance(context, dict) and getattr(context, 'to_dict', None):
        context = context.to_dict()
    return context


class FSSysLogHandler(handlers.SysLogHandler):
    def __init__(self, facility):
        handlers.SysLogHandler.__init__(self, facility=facility)
        self.socket.bind(("127.0.0.1", 0))

    def emit(self, record):
        """
        Emit a record.

        The record is formatted, and then sent to the syslog server. If
        exception information is present, it is NOT sent to the server.
        """
        # NOTE(): If msg is not unicode, coerce it into unicode
        #                before it can get to the python logging and
        #                possibly cause string encoding trouble
        if not isinstance(record.msg, six.text_type):
            record.msg = six.text_type(record.msg)

        # store request info
        context = getattr(local.store, 'context', None)
        if context:
            d = _dictify_context(context)
            for k, v in d.items():
                setattr(record, k, v)

        # NOTE(): default the fancier formatting params
        # to an empty string so we don't throw an exception if
        # they get used
        for key in ('instance', 'color', 'user_identity', 'request_id'):
            if key not in record.__dict__:
                record.__dict__[key] = ''

        msg = self.format(record)
        """
        We need to convert record level to lowercase, maybe this will
        change in the future.
        """
        msg = self.log_format_string % (
            self.encodePriority(self.facility,
                                self.mapPriority(record.levelname)),
            msg)
        # Treat unicode messages as required by RFC 5424
        if handlers._unicode and type(msg) is unicode:
            msg = msg.encode('utf-8')
            if handlers.codecs:
                msg = msg
        try:
            if "postgresql:" in msg:
                return
            if r"'token'" in msg:
                msg = re.sub(r"(?<='token':).+?(?<=').+?(?=')",
                             'u\'<SANITIZED>', msg)
            if HWExtend.hasSensitiveStr(msg):
                return

            msg = h_utils._filter_sensitive_data(msg)

            if self.unixsocket:
                try:
                    self.socket.send(msg)
                except socket.error:
                    self._connect_unixsocket(self.address)
                    self.socket.send(msg)
            else:
                self.socket.sendto(msg, self.address)
        except (KeyboardInterrupt, SystemExit):
            raise
        except:
            self.handleError(record)