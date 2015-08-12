"""
    FC Driver utils function
"""

import sys
import traceback
import hashlib

from cinder.openstack.common.gettextutils import _
from cinder.openstack.common import log as logging



LOG = logging.getLogger(__name__)


def log_exception(exception=None):
    """

    :param exception:
    :return:
    """

    if exception:
        # TODO
        pass

    etype, value, track_tb = sys.exc_info()
    error_list = traceback.format_exception(etype, value, track_tb)
    for error_info in error_list:
        LOG.error(error_info)


def str_drop_password_key(str_data):
    """
    remove json password key item
    :param data:
    :return:
    """
    null = "null"
    true = "true"
    false = "false"
    dict_data = eval(str_data)
    if isinstance(dict_data, dict):
        drop_password_key(dict_data)
        return str(dict_data)
    else:
        LOG.debug(_("[BRM-DRIVER] str_data can't change to dict, str_data:(%s) "), str_data)
        return


def drop_password_key(data):
    """
    remove json password key item
    :param data:
    :return:
    """
    encrypt_list = ['password', 'vncpassword', 'oldpassword',
                    'domainpassword', 'vncoldpassword', 'vncnewpassword',
                    'auth_token', 'token', 'fc_pwd', 'accessKey',
                    'secretKey']
    for key in data.keys():
        if key in encrypt_list:
            del data[key]
        elif data[key] and isinstance(data[key], dict):
            drop_password_key(data[key])

def sha256_based_key(key):
    """
    generate sha256 based key
    :param key:
    :return:
    """
    hash_ = hashlib.sha256()
    hash_.update(key)
    return hash_.hexdigest()