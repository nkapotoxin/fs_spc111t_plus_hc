# Copyright (c) 2011 OpenStack Foundation
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""Compute-related Utilities and helpers."""

import threading
import traceback
import time
import random
import string
from nova.i18n import _
from nova import objects
from oslo.config import cfg
from lxml import etree
from nova.openstack.common import log
from nova.openstack.common import timeutils

CONF = cfg.CONF

LOG = log.getLogger(__name__)

SUPPORTED_BOOT_DEVS = ['hd', 'network', 'cdrom']


def is_boot_from_volume(context, instance, bdms=None):
    """
    decide whether the instance is boot from volume or not.
    :param instance: the instance object
    :return: True if instance booted from volume, otherwise False.
    """

    instance_uuid = None
    if isinstance(instance, dict) and instance.get("instance_uuid"):
        # if the operation is resize/migrate, instance_uuid exited.
        instance_uuid = instance.get("instance_uuid")

    if not bool(instance.get('image_ref')) and not instance_uuid:
        LOG.debug(_("image ref does not exited..."))
        return True
    else:
        # if the boot_index is zero and destination type is volume, the
        # instance is boot from volume
        if not instance_uuid:
            instance_uuid = instance.get('uuid')

        if bdms is None:
            bdms = objects.BlockDeviceMappingList.get_by_instance_uuid(
                context, instance_uuid)

        root_bdm = bdms.root_bdm()
        if root_bdm and root_bdm.is_volume:
            LOG.debug(_("is root bdm and is volume..."))
            return True

    return False


def regex_escape(regex_str):
    """
    change the reserved char to escape sequence
    :param regex_str: the input regex string
    :return: the string
    """
    escape_sequence = "\\"
    regex_str = regex_str.replace("\\", ''.join([escape_sequence, "\\"]))

    reserved_words = ["(", ")", "^", "$", "*", "+", "?", "{", "}", "."]
    for word in reserved_words:
        regex_str = regex_str.replace(word, ''.join([escape_sequence, word]))
    return regex_str


def is_valid_boot_option(boot_option):
    """
    arguments:
            boot_option: boot option string like 'hd,network'
    """
    boot_option_list = boot_option.split(',')
    if len(boot_option_list) != len(set(boot_option_list)):
        return False
    for boot_dev in boot_option_list:
        if boot_dev not in SUPPORTED_BOOT_DEVS:
            return False
    return True


def heartbeat_period_task(time_interval, monitor_file):
    def _write_time_into_file():
        """
        Monitor the periodic tasks is alive.
        Write the heart message in CONF.monitor_file
        """
        while True:
            try:
                with open(monitor_file, 'w+') as f:
                    cur_time = timeutils.utcnow()
                    f.write(str(cur_time))
            except Exception:
                LOG.error("Write the monitor file failed. except: %s" %
                          traceback.format_exc())
            time.sleep(time_interval)

    task_thread = threading.Thread(target=_write_time_into_file)
    task_thread.setDaemon(True)
    task_thread.start()


def get_random_passwd(**kwargs):
    """
    generate random password, include eight letters(upper + lower), eight
    digits.

    upper_num: the number of upper cases. must lower than 27
    lower_num: the number of lower cases. must lower than 27
    digit_num: the number of digits. must lower than 11
    special_num: the number of special cases. must lower than 33

    :return: password as string
    """
    password_list = []
    special_words = ['`', '~', '!', '@', '#', '$', '%', '^', '&', '*',
                     '(', ')', '-', '_', '+', '=', '\\', '|', '[', ']', '{',
                     '}', ':', ';', '\'', '"', ',', '<', '>', '.', '/','?']

    if "upper_num" in kwargs:
        password_list.extend(random.sample(string.uppercase,
                                           int(kwargs['upper_num'])))
    if "lower_num" in kwargs:
        password_list.extend(random.sample(string.lowercase,
                                           int(kwargs['lower_num'])))
    if "digit_num" in kwargs:
        password_list.extend(random.sample(string.digits,
                                           int(kwargs['digit_num'])))
    if "special_num" in kwargs:
        password_list.extend(random.sample(special_words,
                                           int(kwargs['special_num'])))

    # random places
    random.shuffle(password_list)
    return ''.join(password_list)