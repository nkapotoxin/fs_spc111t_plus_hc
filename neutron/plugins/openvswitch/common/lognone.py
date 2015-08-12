# -*- coding: UTF-8 -*-


class LogNone(object):
    def debug(self, msg, *args):
        pass

    def warn(self, msg, *args):
        pass

    def warning(self, msg, *args):
        pass

    def exception(self, msg, *args):
        pass

    def error(self, msg, *args):
        pass

    def info(self, msg, *args):
        pass


def getLogger(*args):
    return LogNone()