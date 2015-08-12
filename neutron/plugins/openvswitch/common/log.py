import logging
import logging.handlers
import socket
import os
import time
import re

LOG_FACILITY = 'local1'
LOG_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
LOG_FORMAT = 'oam-network-agent %(levelname)s [pid:%(process)d] [%(threadName)s]' \
             ' [%(filename)s:%(lineno)d %(funcName)s] %(message)s'
LOG_FORMAT_VRM = '%(asctime)s oam-network-agent %(levelname)s [pid:%(' \
                 'process)d] [%(threadName)s] [%(filename)s:%(lineno)d %(' \
                 'funcName)s] %(message)s'
LOG_DEBUG = True
LOG_VERBOSE = True


def getLogger(name):
    return logging.getLogger(name)


def _find_facility_from_conf():
    facility_names = logging.handlers.SysLogHandler.facility_names
    facility = getattr(logging.handlers.SysLogHandler,
                       LOG_FACILITY,
                       None)

    if facility is None and LOG_FACILITY in facility_names:
        facility = facility_names.get(LOG_FACILITY)

    return facility


def setup_logging():
    log_root = logging.getLogger(None)
    for handler in log_root.handlers:
        log_root.removeHandler(handler)

    facility = _find_facility_from_conf()
    syslog = FSSysLogHandler(facility=facility)
    log_root.addHandler(syslog)

    for handler in log_root.handlers:
        handler.setFormatter(logging.Formatter(fmt=LOG_FORMAT,
                                               datefmt=LOG_DATE_FORMAT))

    if LOG_DEBUG:
        log_root.setLevel(logging.DEBUG)
    elif LOG_VERBOSE:
        log_root.setLevel(logging.INFO)
    else:
        log_root.setLevel(logging.WARNING)

def setup_logging_vrm(path, filename, maxBytes, backupCount=10, interval=15,
                      when="m", level="debug"):
    if not os.path.exists(path):
        os.makedirs(path)

    log_root = logging.getLogger(None)
    for handler in log_root.handlers:
        log_root.removeHandler(handler)

    handler = EnhancedRotatingFileHandler(os.path.join(path, filename),
                                     maxBytes=maxBytes, backupCount=backupCount,
                                     when=when, interval=interval)
    format = logging.Formatter(LOG_FORMAT_VRM)
    handler.setFormatter(format)
    log_root.addHandler(handler)

    log_level = _get_log_level(level)
    log_root.setLevel(log_level)

def _get_log_level(level):
    level_string = str(level).lower()

    if level_string == "info":
        log_level = logging.INFO
    elif level_string == "warning":
        log_level = logging.WARNING
    elif level_string == "error":
        log_level = logging.ERROR
    elif level_string == "critical":
        log_level = logging.CRITICAL
    else:
        log_level = logging.DEBUG
    return log_level

class FSSysLogHandler(logging.handlers.SysLogHandler):
    def __init__(self, facility):
        logging.handlers.SysLogHandler.__init__(self, facility=facility)
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
        if logging.handlers._unicode and type(msg) is unicode:
            msg = msg.encode('utf-8')
            if logging.handlers.codecs:
                # msg = codecs.BOM_UTF8 + msg
                msg = msg
        try:
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


class NullHandler(logging.Handler):
    def emit(self, record):
        pass

class EnhancedRotatingFileHandler(logging.handlers.TimedRotatingFileHandler):
    def __init__(self, filename, when='h', interval=1, backupCount=0, encoding=None, delay=0, utc=0, maxBytes=0):
        """ This is just a combination of TimedRotatingFileHandler and RotatingFileHandler (adds maxBytes to TimedRotatingFileHandler)  """
        logging.handlers.TimedRotatingFileHandler.__init__(self, filename, when, interval, backupCount, encoding, delay, utc)
        self.maxBytes=maxBytes

        self.extMatch_vrm = ""
        if self.when == 'S':
            self.interval = 1 # one second
            self.suffix = "%Y-%m-%d_%H-%M-%S"
            self.extMatch_vrm = r"^\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}"
        elif self.when == 'M':
            self.interval = 60 # one minute
            self.suffix = "%Y-%m-%d_%H-%M"
            self.extMatch_vrm = r"^\d{4}-\d{2}-\d{2}_\d{2}-\d{2}"
        elif self.when == 'H':
            self.interval = 60 * 60 # one hour
            self.suffix = "%Y-%m-%d_%H"
            self.extMatch_vrm = r"^\d{4}-\d{2}-\d{2}_\d{2}"
        elif self.when == 'D' or self.when == 'MIDNIGHT':
            self.interval = 60 * 60 * 24 # one day
            self.suffix = "%Y-%m-%d"
            self.extMatch_vrm = r"^\d{4}-\d{2}-\d{2}"
        elif self.when.startswith('W'):
            self.interval = 60 * 60 * 24 * 7 # one week
            if len(self.when) != 2:
                raise ValueError("You must specify a day for weekly rollover from 0 to 6 (0 is Monday): %s" % self.when)
            if self.when[1] < '0' or self.when[1] > '6':
                raise ValueError("Invalid day specified for weekly rollover: %s" % self.when)
            self.dayOfWeek = int(self.when[1])
            self.suffix = "%Y-%m-%d"
            self.extMatch_vrm = r"^\d{4}-\d{2}-\d{2}"
        else:
            raise ValueError("Invalid rollover interval specified: %s" % self.when)

        self.extMatch = re.compile(self.extMatch_vrm)
        self.interval = self.interval * interval

    def shouldRollover(self, record):
        """
        Determine if rollover should occur.

        Basically, see if the supplied record would cause the file to exceed
        the size limit we have.

        we are also comparing times
        """
        if self.stream is None:                 # delay was set...
            self.stream = self._open()
        if self.maxBytes > 0:                   # are we rolling over?
            msg = "%s\n" % self.format(record)
            self.stream.seek(0, 2)  #due to non-posix-compliant Windows feature
            if self.stream.tell() + len(msg) >= self.maxBytes:
                return 1
        t = int(time.time())
        if t >= self.rolloverAt:
            return 1
        #print "No need to rollover: %d, %d" % (t, self.rolloverAt)
        return 0

    def doRollover(self):
        """
        do a rollover; in this case, a date/time stamp is appended to the filename
        when the rollover happens.  However, you want the file to be named for the
        start of the interval, not the current time.  If there is a backup count,
        then we have to get a list of matching filenames, sort them and remove
        the one with the oldest suffix.
        """
        if self.stream:
            self.stream.close()
        # get the time that this sequence started at and make it a TimeTuple
        t = self.rolloverAt - self.interval
        if self.utc:
            timeTuple = time.gmtime(t)
        else:
            timeTuple = time.localtime(t)
        dfn = self.baseFilename + "." + time.strftime(self.suffix, timeTuple)
        if self.backupCount > 0:
            cnt=1
            dfn2="%s.%03d"%(dfn,cnt)
            while os.path.exists(dfn2):
                dfn2="%s.%03d"%(dfn,cnt)
                cnt+=1
            os.rename(self.baseFilename, dfn2)
            for s in self.getFilesToDelete():
                os.remove(s)
        else:
            if os.path.exists(dfn):
                os.remove(dfn)
            os.rename(self.baseFilename, dfn)
        #print "%s -> %s" % (self.baseFilename, dfn)
        self.mode = 'w'
        self.stream = self._open()
        currentTime = int(time.time())
        newRolloverAt = self.computeRollover(currentTime)
        while newRolloverAt <= currentTime:
            newRolloverAt = newRolloverAt + self.interval
        #If DST changes and midnight or weekly rollover, adjust for this.
        if (self.when == 'MIDNIGHT' or self.when.startswith('W')) and not self.utc:
            dstNow = time.localtime(currentTime)[-1]
            dstAtRollover = time.localtime(newRolloverAt)[-1]
            if dstNow != dstAtRollover:
                if not dstNow:  # DST kicks in before next rollover, so we need to deduct an hour
                    newRolloverAt = newRolloverAt - 3600
                else:           # DST bows out before next rollover, so we need to add an hour
                    newRolloverAt = newRolloverAt + 3600
        self.rolloverAt = newRolloverAt