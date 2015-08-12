#!/usr/bin/env python
# -*- encoding: utf-8 -*-

import logging as stdlib_logging

from nova.i18n import _LE
from nova.openstack.common import log as logging
from nova import utils


LOG = logging.getLogger(__name__)


def send_alarm(alarm_id, moc, resource_id, location, alarm_type=0,
               level=1, cause=0, time='', addition='',
               raise_exception=False):
    """
    :param alarm_id: type id of alarm
    :param moc: source of alarm
    :param resource_id: id of this alarm instance
    :param location: helpful information for alarm location
    :param alarm_type: 0 - fault, 1 - clear, 2 - event, 4 - update, set by FMS
    :param level: level of alarm
    :param cause: code of alarm reason
    :param time: occur time
    :param addition: additional information of this alarm
    :return: std out, std err of command
    """
    try:
        return utils.execute('sendAlarm',
                             alarm_id, alarm_type, level, cause, time, moc,
                             resource_id, location, addition,
                             run_as_root=True,
                             check_exit_code=[0],
                             loglevel=stdlib_logging.INFO)
    except Exception as e:
        LOG.error(_LE('send alarm failed: %s'), e)

        if raise_exception:
            raise e
        else:
            return '', ''