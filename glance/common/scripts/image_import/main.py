# Copyright 2014 OpenStack Foundation
# All Rights Reserved.
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

__all__ = [
    'run',
]

import six

from glance.api.v2 import images as v2_api
from glance.common import exception
from glance.common.scripts import utils as script_utils
from glance.common import utils as common_utils
from glance import i18n
from glance.openstack.common import excutils
from glance.openstack.common import lockutils
import glance.openstack.common.log as logging


_LE = i18n._LE
_LI = i18n._LI
_LW = i18n._LW
LOG = logging.getLogger(__name__)


def run(t_id, context, task_repo, image_repo, image_factory):
    LOG.info(_LI('Task %(task_id)s beginning import '
                 'execution.') % {'task_id': t_id})
    _execute(t_id, task_repo, image_repo, image_factory)


# NOTE(nikhil): This lock prevents more than N number of threads to be spawn
# simultaneously. The number N represents the number of threads in the
# executor pool. The value is set to 10 in the eventlet executor.
@lockutils.synchronized("glance_import")
def _execute(t_id, task_repo, image_repo, image_factory):
    task = script_utils.get_task(task_repo, t_id)

    if task is None:
        # NOTE: This happens if task is not found in the database. In
        # such cases, there is no way to update the task status so,
        # it's ignored here.
        return

    try:
        task_input = script_utils.unpack_task_input(task)

        uri = script_utils.validate_location_uri(task_input.get('import_from'))
        image_id = import_image(image_repo, image_factory, task_input, t_id,
                                uri)

        task.succeed({'image_id': image_id})
    except Exception as e:
        # Note: The message string contains Error in it to indicate
        # in the task.message that it's a error message for the user.

        #TODO(nikhil): need to bring back save_and_reraise_exception when
        # necessary
        err_msg = ("Error: " + six.text_type(type(e)) + ': ' +
                   common_utils.exception_to_str(e))
        log_msg = _LE(err_msg + ("Task ID %s" % task.task_id))
        LOG.exception(log_msg)

        task.fail(_LE(err_msg))
    finally:
        task_repo.save(task)


def import_image(image_repo, image_factory, task_input, task_id, uri):
    original_image = create_image(image_repo, image_factory,
                                  task_input.get('image_properties'), task_id)
    # NOTE: set image status to saving just before setting data
    original_image.status = 'saving'
    image_repo.save(original_image)
    set_image_data(original_image, uri, None)

    # NOTE: Check if the Image is not deleted after setting the data
    # before setting it's status to active. We need to set the status
    # explicitly here using the Image object returned from image_repo .The
    # Image object returned from create_image method does not have appropriate
    # factories wrapped around it.
    image_id = original_image.image_id
    new_image = image_repo.get(image_id)
    if new_image.status in ['saving']:
        new_image.status = 'active'
        new_image.size = original_image.size
        new_image.virtual_size = original_image.virtual_size
        new_image.checksum = original_image.checksum
    else:
        msg = _LE("The Image %(image_id)s object being created by this task "
                  "%(task_id)s, is no longer in valid status for further "
                  "processing." % {"image_id": new_image.image_id,
                                   "task_id": task_id})
        raise exception.Conflict(msg)
    image_repo.save(new_image)

    return image_id


def create_image(image_repo, image_factory, image_properties, task_id):
    _base_properties = []
    for k, v in v2_api.get_base_properties().items():
        _base_properties.append(k)

    properties = {}
    # NOTE: get the base properties
    for key in _base_properties:
        try:
            properties[key] = image_properties.pop(key)
        except KeyError:
            msg = _("Task ID %(task_id)s: Ignoring property %(k)s for setting "
                    "base properties while creating "
                    "Image.") % {'task_id': task_id, 'k': key}
            LOG.debug(msg)

    # NOTE: get the rest of the properties and pass them as
    # extra_properties for Image to be created with them.
    properties['extra_properties'] = image_properties
    script_utils.set_base_image_properties(properties=properties)

    image = image_factory.new_image(**properties)
    image_repo.add(image)
    return image


def set_image_data(image, uri, task_id):
    data_iter = None
    try:
        LOG.info(_LI("Task %(task_id)s: Got image data uri %(data_uri)s to be "
                 "imported") % {"data_uri": uri, "task_id": task_id})
        data_iter = script_utils.get_image_data_iter(uri)
        image.set_data(data_iter)
    except Exception as e:
        with excutils.save_and_reraise_exception():
            LOG.warn(_LW("Task %(task_id)s failed with exception %(error)s") %
                     {"error": common_utils.exception_to_str(e),
                      "task_id": task_id})
            LOG.info(_LI("Task %(task_id)s: Could not import image file"
                         " %(image_data)s") % {"image_data": uri,
                                               "task_id": task_id})
    finally:
        if isinstance(data_iter, file):
            data_iter.close()
