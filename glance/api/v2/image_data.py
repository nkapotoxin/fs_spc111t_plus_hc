# Copyright 2012 OpenStack Foundation.
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

import webob.exc

import glance_store

import glance.api.policy
from glance.common import exception
from glance.common import utils
from glance.common import wsgi
import glance.db
import glance.gateway
import glance.notifier
from glance.openstack.common import excutils
from glance.openstack.common import gettextutils
import glance.openstack.common.log as logging


LOG = logging.getLogger(__name__)
_LE = gettextutils._LE


class ImageDataController(object):
    def __init__(self, db_api=None, store_api=None,
                 policy_enforcer=None, notifier=None,
                 gateway=None):
        if gateway is None:
            db_api = db_api or glance.db.get_api()
            store_api = store_api or glance_store
            policy = policy_enforcer or glance.api.policy.Enforcer()
            notifier = notifier or glance.notifier.Notifier()
            gateway = glance.gateway.Gateway(db_api, store_api,
                                             notifier, policy)
        self.gateway = gateway

    def _restore(self, image_repo, image):
        """
        Restore the image to queued status.

        :param image_repo: The instance of ImageRepo
        :param image: The image will be restored
        """
        try:
            if image_repo and image:
                image.status = 'queued'
                image_repo.save(image)
        except Exception as e:
            msg = (_LE("Unable to restore image %(image_id)s: %(e)s") %
                   {'image_id': image.image_id,
                    'e': utils.exception_to_str(e)})
            LOG.exception(msg)

    @utils.mutating
    def upload(self, req, image_id, data, size):
        image_repo = self.gateway.get_repo(req.context)
        image = None
        try:
            image = image_repo.get(image_id)
            image.status = 'saving'
            try:
                image_repo.save(image)
                image.set_data(data, size)
                image_repo.save(image, from_state='saving')
            except (exception.NotFound, exception.Conflict) as e:
                msg = (_("Image %(id)s could not be found after upload."
                         "The image may have been deleted during the upload: "
                         "%(error)s Cleaning up the chunks uploaded") %
                       {'id': image_id,
                        'error': utils.exception_to_str(e)})
                LOG.warn(msg)
                # NOTE(sridevi): Cleaning up the uploaded chunks.
                try:
                    image.delete()
                except exception.NotFound:
                    # NOTE(sridevi): Ignore this exception
                    pass
                raise webob.exc.HTTPGone(explanation=msg,
                                         request=req,
                                         content_type='text/plain')

        except ValueError as e:
            LOG.debug("Cannot save data for image %(id)s: %(e)s",
                      {'id': image_id, 'e': utils.exception_to_str(e)})
            self._restore(image_repo, image)
            raise webob.exc.HTTPBadRequest(explanation=
                                           utils.exception_to_str(e))

        except glance_store.StoreAddDisabled:
            msg = _("Error in store configuration. Adding images to store "
                    "is disabled.")
            LOG.exception(msg)
            self._restore(image_repo, image)
            raise webob.exc.HTTPGone(explanation=msg, request=req,
                                     content_type='text/plain')

        except exception.InvalidImageStatusTransition as e:
            msg = utils.exception_to_str(e)
            LOG.debug(msg)
            raise webob.exc.HTTPConflict(explanation=e.msg, request=req)

        except exception.Forbidden as e:
            msg = ("Not allowed to upload image data for image %s" %
                   image_id)
            LOG.debug(msg)
            raise webob.exc.HTTPForbidden(explanation=msg, request=req)

        except exception.NotFound as e:
            raise webob.exc.HTTPNotFound(explanation=e.msg)

        except glance_store.StorageFull as e:
            msg = _("Image storage media "
                    "is full: %s") % utils.exception_to_str(e)
            LOG.error(msg)
            self._restore(image_repo, image)
            raise webob.exc.HTTPRequestEntityTooLarge(explanation=msg,
                                                      request=req)

        except exception.StorageQuotaFull as e:
            msg = _("Image exceeds the storage "
                    "quota: %s") % utils.exception_to_str(e)
            LOG.error(msg)
            self._restore(image_repo, image)
            raise webob.exc.HTTPRequestEntityTooLarge(explanation=msg,
                                                      request=req)

        except exception.ImageSizeLimitExceeded as e:
            msg = _("The incoming image is "
                    "too large: %s") % utils.exception_to_str(e)
            LOG.error(msg)
            self._restore(image_repo, image)
            raise webob.exc.HTTPRequestEntityTooLarge(explanation=msg,
                                                      request=req)

        except glance_store.StorageWriteDenied as e:
            msg = _("Insufficient permissions on image "
                    "storage media: %s") % utils.exception_to_str(e)
            LOG.error(msg)
            self._restore(image_repo, image)
            raise webob.exc.HTTPServiceUnavailable(explanation=msg,
                                                   request=req)

        except webob.exc.HTTPGone as e:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Failed to upload image data due to HTTP error"))

        except webob.exc.HTTPError as e:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Failed to upload image data due to HTTP error"))
                self._restore(image_repo, image)

        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE("Failed to upload image data due to "
                                  "internal error"))
                self._restore(image_repo, image)

    def download(self, req, image_id):
        image_repo = self.gateway.get_repo(req.context)
        try:
            image = image_repo.get(image_id)
            if not image.locations:
                raise exception.ImageDataNotFound()
        except exception.ImageDataNotFound as e:
            raise webob.exc.HTTPNoContent(explanation=e.msg)
        except exception.NotFound as e:
            raise webob.exc.HTTPNotFound(explanation=e.msg)
        except exception.Forbidden as e:
            raise webob.exc.HTTPForbidden(explanation=e.msg)

        return image


class RequestDeserializer(wsgi.JSONRequestDeserializer):

    def upload(self, request):
        try:
            request.get_content_type(('application/octet-stream',))
        except exception.InvalidContentType as e:
            raise webob.exc.HTTPUnsupportedMediaType(explanation=e.msg)

        image_size = request.content_length or None
        return {'size': image_size, 'data': request.body_file}


class ResponseSerializer(wsgi.JSONResponseSerializer):

    def download(self, response, image):
        offset, chunk_size = 0, None
        range_val = response.request.get_content_range()

        if range_val:
            # NOTE(flaper87): if not present, both, start
            # and stop, will be None.
            if range_val.start is not None:
                offset = range_val.start

            if range_val.stop is not None:
                chunk_size = range_val.stop - offset

        response.headers['Content-Type'] = 'application/octet-stream'

        try:
            # NOTE(markwash): filesystem store (and maybe others?) cause a
            # problem with the caching middleware if they are not wrapped in
            # an iterator very strange
            response.app_iter = iter(image.get_data(offset=offset,
                                                    chunk_size=chunk_size))
        except glance_store.NotFound as e:
            raise webob.exc.HTTPNotFound(explanation=e.msg)
        except exception.Forbidden as e:
            raise webob.exc.HTTPForbidden(explanation=e.msg)
        #NOTE(saschpe): "response.app_iter = ..." currently resets Content-MD5
        # (https://github.com/Pylons/webob/issues/86), so it should be set
        # afterwards for the time being.
        if image.checksum:
            response.headers['Content-MD5'] = image.checksum
        #NOTE(markwash): "response.app_iter = ..." also erroneously resets the
        # content-length
        response.headers['Content-Length'] = str(image.size)

    def upload(self, response, result):
        response.status_int = 204


def create_resource():
    """Image data resource factory method"""
    deserializer = RequestDeserializer()
    serializer = ResponseSerializer()
    controller = ImageDataController()
    return wsgi.Resource(controller, deserializer, serializer)
