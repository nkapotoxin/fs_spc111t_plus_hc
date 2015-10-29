import socket
from logging import handlers
from glance.huawei.openstack.common import HWExtend
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
            if HWExtend.hasSensitiveStr(msg):
                return
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
