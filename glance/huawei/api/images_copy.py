import copy
import eventlet
import json
import urllib
import urlparse

from FSComponentUtil import crypt
import glanceclient
import glance_store
from glance_store import exceptions
from oslo.config import cfg
import six.moves.urllib.parse as urlparse
import webob.exc

from glance.api import policy
from glance.common import exception
from glance.common import wsgi
import glance.db
import glance.domain
import glance.notifier
from glance.openstack.common import gettextutils
import glance.openstack.common.log as logging
from glance.openstack.common import timeutils
import glance.schema


LOG = logging.getLogger(__name__)
_ = gettextutils._
_LI = gettextutils._LI
_LW = gettextutils._LW

CONF = cfg.CONF
CONF.import_opt('disk_formats', 'glance.common.config', group='image_format')
CONF.import_opt('container_formats', 'glance.common.config',
                group='image_format')


class ImagesCopyController(object):
    def __init__(self, db_api=None, policy_enforcer=None, notifier=None,
                 store_api=None):
        self.db_api = db_api or glance.db.get_api()
        self.policy = policy_enforcer or policy.Enforcer()
        self.notifier = notifier or glance.notifier.Notifier()
        self.store_api = store_api or glance_store
        self.gateway = glance.gateway.Gateway(self.db_api, self.store_api,
                                              self.notifier, self.policy)
        self.pool = eventlet.GreenPool(size=1024)

    def decrypt_uri(self, uri, has_quoted=True):
        old_uri = uri
        uri = ''.join(uri)
        start = uri.find(":")
        if uri[0:start] not in ['uds', 'uds+https']:
            raise webob.exc.HTTPForbidden(
                explanation='we can only copy images stored in uds')
        if start != -1:
            start = uri.find(":", start + 1)
            if start != -1:
                end = uri.rfind("@")
                if end != -1:
                    password = uri[start + 1:end]
                    if has_quoted:
                        password = urllib.unquote(password)
                    password = crypt.decrypt(password)
                    if has_quoted:
                        password = urllib.quote(password)
                    uri = uri[:start + 1] + password + uri[end:]
                    LOG.debug(
                        "[ENCRYPT-P-W-D] The uri has been decypted and return.")
                    return uri

    def get_src_image_meta(self, source_token, source_url, source_image_id):
        try:
            gclient = glanceclient.Client(str(2), source_url,
                                          token=source_token, insecure=True)
            src_image = gclient.images.get(source_image_id)
            LOG.debug('[IMAGE_COPY]src_image=%s' % src_image)
        except Exception, ex:
            msg = ("Fail to get source image."
                   "Check the source_url[%s] you provide." % (source_url))
            LOG.exception(msg)
            raise webob.exc.HTTPNotFound(explanation=msg)
        return src_image

    def parse_direct_url(self, direct_url):
        direct_url = self.decrypt_uri(direct_url)
        o = urlparse.urlparse(direct_url)
        if o.scheme not in ['uds', 'uds+https']:
            raise webob.exc.HTTPForbidden(
                explanation="We can only copy images stored in uds.")
        temp, src_bucket_name, src_key = o.path.split('/')
        return src_bucket_name

    def get_image_meta(self, src_image):
        _disallowed_properties = ['direct_url', 'self', 'file', 'schema']
        _readonly_properties = ['created_at', 'updated_at', 'status',
                                'checksum',
                                'direct_url', 'self', 'file', 'schema']
        _reserved_properties = ['owner', 'is_public', 'location', 'deleted',
                                'deleted_at']
        _base_properties = ['checksum', 'created_at', 'container_format',
                            'disk_format', 'id', 'min_disk', 'min_ram', 'name',
                            'size', 'status', 'tags', 'updated_at',
                            'visibility',
                            'protected']
        image = {}
        properties = {}

        for attr in src_image:
            if attr in _disallowed_properties + _readonly_properties + _reserved_properties:
                continue
            elif attr in _base_properties:
                image[attr] = getattr(src_image, attr)
            else:
                properties[attr] = getattr(src_image, attr)

        image.pop("id")
        image.pop('status', None)
        image.pop('size', None)
        tags = image.pop('tags')

        return image, properties, tags

    @staticmethod
    def _get_reserved_properties(extra_properties):
        reserved_properties = {}
        RESERVED_PROPERTIES = ('__imagetype',
                               '__originalimageid',
                               '__originalimagename',
                               '__platform')

        for key, value in extra_properties.items():
            if key in RESERVED_PROPERTIES:
                reserved_properties[key] = value
                del extra_properties[key]

        return reserved_properties

    def _set_reserved_properties(self, req, image_id, reserved_properties):
        image_repo = self.gateway.get_repo(self.elevated(req.context))
        image = image_repo.get(image_id)

        for key, value in reserved_properties.items():
            image.extra_properties[key] = value

        image_repo.save(image)

    def elevated(self, context):
        admin_context = copy.deepcopy(context)
        admin_context.is_admin = True

        if 'admin' not in admin_context.roles:
            admin_context.roles.append('admin')

        return admin_context

    def create_image_in_queued(self, req, src_image, name=None,
                               description=None):
        image_dict, extra_properties, tags = self.get_image_meta(src_image)
        if name:
            image_dict["name"] = name
        if description:
            extra_properties["__description"] = description

        image_factory = self.gateway.get_image_factory(req.context)
        image_repo = self.gateway.get_repo(req.context)
        reserved_properties = self._get_reserved_properties(extra_properties)
        try:
            image_proxy = image_factory.new_image(
                extra_properties=extra_properties, tags=tags, **image_dict)
            image_repo.add(image_proxy)
        except exception.Duplicate, ex:
            LOG.exception(ex)
            raise webob.exc.HTTPConflict(explanation=ex, request=req)
        except exception.Forbidden, ex:
            LOG.exception(ex)
            raise webob.exc.HTTPForbidden(explanation=ex, request=req)
        if reserved_properties:
            self._set_reserved_properties(req, image_proxy.image_id,
                                          reserved_properties)
        image_repo_proxy = image_repo.get(image_proxy.image_id)
        return image_repo_proxy

    def _copy_members(self, context, source_token, source_url, src_image_id,
                      dst_image):
        src_glanceclient = glanceclient.Client(str(2), source_url,
                                               token=source_token,
                                               insecure=True)
        members = src_glanceclient.image_members.list(src_image_id)
        image_member_factory = self.gateway.get_image_member_factory(context)
        member_repo = dst_image.get_member_repo()
        for member in members:
            new_member = image_member_factory.new_image_member(dst_image,
                                                               member.member_id)
            new_member.status = member.status
            member_repo.add(new_member)

    def copy_to_backend(context, new_key_name, src_bucket_name, src_key_name,
                        src_size):
        store = glance_store.backend.get_store_from_scheme(
            glance_store.backend.CONF.glance_store.default_store)
        store_scheme = store.get_schemes
        LOG.info('store scheme is %s' % store_scheme)
        try:
            return store.copy(new_key_name, src_bucket_name, src_key_name,
                              src_size)
        except NotImplementedError:
            raise exceptions.StoreCopyNotSupported
        except Exception as e:
            raise

    def _restore(self, image_repo, image):
        try:
            if image_repo and image:
                image.status = 'queued'
                image_repo.save(image)
        except Exception as e:
            msg = ("Unable to restore image %(image_id)s: %(e)s") % \
                  {'image_id': image.image_id, 'e': unicode(e)}
            LOG.exception(msg)

    def _do_copy_file(self, context, new_image, src_bucket_name, src_key_name,
                      src_size, src_check_sum):
        image_repo = self.gateway.get_repo(context)
        try:
            loc = self.copy_to_backend(new_key_name=new_image.image_id,
                                       src_bucket_name=src_bucket_name,
                                       src_key_name=src_key_name,
                                       src_size=src_size)
        except Exception, ex:
            LOG.exception("[IMAGE_COPY]Fail to copy image data. Image[%s] "
                          "will roll back to queued." % new_image.image_id)
            self._restore(image_repo, new_image)
            raise

        new_image.status = 'active'
        new_image.size = src_size
        new_image.checksum = src_check_sum
        new_image.locations = [{'url': loc, 'metadata': {}}]
        image_repo.save(new_image)

    def copy(self, req, source_image_id, source_url, source_token, name=None,
             description=None):
        self.policy.enforce(req.context, 'copy_image', {})
        src_image = self.get_src_image_meta(source_token, source_url,
                                            source_image_id)
        if src_image.status != 'active':
            raise webob.exc.HTTPForbidden(
                explanation='Copy inactive image is forbidden ')
        if not src_image.get('size', 0):
            raise webob.exc.HTTPForbidden(
                explanation='copy snapshot image without image file '
                            'is forbidden')

        new_image_repo_proxy = self.create_image_in_queued(req, src_image, name,
                                                           description)
        if new_image_repo_proxy.visibility != 'public':
            self._copy_members(req.context, source_token, source_url,
                               source_image_id, new_image_repo_proxy)
        image_repo = self.gateway.get_repo(req.context)
        new_image_repo_proxy.status = 'saving'
        image_repo.save(new_image_repo_proxy)
        src_bucket_name = self.parse_direct_url(src_image.direct_url)
        self.pool.spawn_n(self._do_copy_file, context=req.context,
                          new_image=new_image_repo_proxy,
                          src_bucket_name=src_bucket_name,
                          src_key_name=source_image_id,
                          src_size=src_image["size"],
                          src_check_sum=src_image["checksum"])
        return new_image_repo_proxy

    def show(self, req, image_id):
        image_repo = self.gateway.get_repo(req.context)
        try:
            return image_repo.get(image_id)
        except exception.Forbidden as e:
            raise webob.exc.HTTPForbidden(explanation=unicode(e))
        except exception.NotFound as e:
            raise webob.exc.HTTPNotFound(explanation=unicode(e))

    def delete(self, req, image_id):
        image_repo = self.gateway.get_repo(req.context)
        try:
            image = image_repo.get(image_id)

            #Add for hw extention
            if hasattr(image,
                       'extra_properties') and image.extra_properties.get(
                    'volume_image_id'):
                volume_image_id = image.extra_properties['volume_image_id']
                LOG.debug(
                    "Try to delete volume_image_id[%s] in v2" % volume_image_id)
                try:
                    self.delete(req, volume_image_id)
                except:
                    LOG.exception("Fail to delete volume image.")
            image.delete()
            image_repo.remove(image)
        except exception.Forbidden as e:
            raise webob.exc.HTTPForbidden(explanation=unicode(e))
        except exception.NotFound as e:
            msg = ("Failed to find image %(image_id)s to delete" % locals())
            LOG.info(msg)
            raise webob.exc.HTTPNotFound(explanation=msg)


class RequestDeserializer(wsgi.JSONRequestDeserializer):
    def __init__(self, schema=None):
        super(RequestDeserializer, self).__init__()
        self.schema = schema or get_schema()

    def _get_request_body(self, request):
        output = super(RequestDeserializer, self).default(request)
        if 'body' not in output:
            msg = _('Body expected in request.')
            raise webob.exc.HTTPBadRequest(explanation=msg)
        return output['body']

    def copy(self, request):
        body = self._get_request_body(request)
        try:
            params = body["copyImage"]
            source_image_id = params["sourceImageId"]
            source_url = params["sourceURL"]
            source_token = params["sourceToken"]
            name = params.get("newImageName", None)
            description = params.get("newDescription", None)
        except KeyError, ex:
            LOG.exception("")
            raise webob.exc.HTTPBadRequest(explanation=ex)

        return dict(source_image_id=source_image_id,
                    source_url=source_url,
                    source_token=source_token,
                    name=name,
                    description=description)


class ResponseSerializer(wsgi.JSONResponseSerializer):
    def __init__(self, schema=None):
        super(ResponseSerializer, self).__init__()
        self.schema = schema or get_schema()

    def _get_image_href(self, image, subcollection=''):
        base_href = '/v2/images/%s' % image.image_id
        if subcollection:
            base_href = '%s/%s' % (base_href, subcollection)
        return base_href

    def _format_image(self, image):
        image_view = dict()
        try:
            image_view = dict(image.extra_properties)
            attributes = ['name', 'disk_format', 'container_format',
                          'visibility', 'size', 'status', 'checksum',
                          'protected', 'min_ram', 'min_disk', 'owner']
            for key in attributes:
                image_view[key] = getattr(image, key)
            image_view['id'] = image.image_id
            image_view['created_at'] = timeutils.isotime(image.created_at)
            image_view['updated_at'] = timeutils.isotime(image.updated_at)

            if CONF.show_multiple_locations:
                if image.locations:
                    image_view['locations'] = list(image.locations)
                else:
                    # NOTE (): We will still show "locations": [] if
                    # image.locations is None to indicate it's allowed to show
                    # locations but it's just non-existent.
                    image_view['locations'] = []

            if CONF.show_image_direct_url and image.locations:
                image_view['direct_url'] = image.locations[0]['url']

            image_view['tags'] = list(image.tags)
            image_view['self'] = self._get_image_href(image)
            image_view['file'] = self._get_image_href(image, 'file')
            image_view['schema'] = '/v2/schemas/image'
            image_view = self.schema.filter(image_view)  # domain
        except exception.Forbidden as e:
            raise webob.exc.HTTPForbidden(unicode(e))
        return image_view

    def copy(self, response, image):
        image_view = self._format_image(image)
        body = json.dumps(image_view, ensure_ascii=False)
        response.unicode_body = unicode(body)
        response.content_type = 'application/json'


def _get_base_properties():
    return {
        'id': {
            'type': 'string',
            'description': _('An identifier for the image'),
            'pattern': ('^([0-9a-fA-F]){8}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}'
                        '-([0-9a-fA-F]){4}-([0-9a-fA-F]){12}$'),
        },
        'name': {
            'type': 'string',
            'description': _('Descriptive name for the image'),
            'maxLength': 255,
        },
        'status': {
            'type': 'string',
            'description': _('Status of the image (READ-ONLY)'),
            'enum': ['queued', 'saving', 'active', 'killed',
                     'deleted', 'pending_delete'],
        },
        'visibility': {
            'type': 'string',
            'description': _('Scope of image accessibility'),
            'enum': ['public', 'private'],
        },
        'protected': {
            'type': 'boolean',
            'description': _('If true, image will not be deletable.'),
        },
        'checksum': {
            'type': 'string',
            'description': _('md5 hash of image contents. (READ-ONLY)'),
            'maxLength': 32,
        },
        'owner': {
            'type': 'string',
            'description': _('Owner of the image'),
            'maxLength': 255,
        },
        'size': {
            'type': 'integer',
            'description': _('Size of image file in bytes (READ-ONLY)'),
        },
        'virtual_size': {
            'type': 'integer',
            'description': _('Virtual size of image in bytes (READ-ONLY)'),
        },
        'container_format': {
            'type': 'string',
            'description': _('Format of the container'),
            'enum': CONF.image_format.container_formats,
        },
        'disk_format': {
            'type': 'string',
            'description': _('Format of the disk'),
            'enum': CONF.image_format.disk_formats,
        },
        'created_at': {
            'type': 'string',
            'description': _('Date and time of image registration'
                             ' (READ-ONLY)'),
            #TODO(): our jsonschema library doesn't seem to like the
            # format attribute, figure out why!
            #'format': 'date-time',
        },
        'updated_at': {
            'type': 'string',
            'description': _('Date and time of the last image modification'
                             ' (READ-ONLY)'),
            #'format': 'date-time',
        },
        'tags': {
            'type': 'array',
            'description': _('List of strings related to the image'),
            'items': {
                'type': 'string',
                'maxLength': 255,
            },
        },
        'direct_url': {
            'type': 'string',
            'description': _('URL to access the image file kept in external '
                             'store (READ-ONLY)'),
        },
        'min_ram': {
            'type': 'integer',
            'description': _('Amount of ram (in MB) required to boot image.'),
        },
        'min_disk': {
            'type': 'integer',
            'description': _('Amount of disk space (in GB) required to boot '
                             'image.'),
        },
        'self': {
            'type': 'string',
            'description': '(READ-ONLY)'
        },
        'file': {
            'type': 'string',
            'description': '(READ-ONLY)'
        },
        'schema': {
            'type': 'string',
            'description': '(READ-ONLY)'
        },
        'locations': {
            'type': 'array',
            'items': {
                'type': 'object',
                'properties': {
                    'url': {
                        'type': 'string',
                        'maxLength': 255,
                    },
                    'metadata': {
                        'type': 'object',
                    },
                },
                'required': ['url', 'metadata'],
            },
            'description': _('A set of URLs to access the image file kept in '
                             'external store'),
        },
    }


def _get_base_links():
    return [
        {'rel': 'self', 'href': '{self}'},
        {'rel': 'enclosure', 'href': '{file}'},
        {'rel': 'describedby', 'href': '{schema}'},
    ]


def get_schema(custom_properties=None):
    properties = _get_base_properties()
    links = _get_base_links()
    if CONF.allow_additional_image_properties:
        schema = glance.schema.PermissiveSchema('image', properties, links)
    else:
        schema = glance.schema.Schema('image', properties)

    if custom_properties:
        for property_value in custom_properties.values():
            property_value['is_base'] = False
        schema.merge_properties(custom_properties)
    return schema


def create_resource(custom_properties=None):
    """Images resource factory method"""
    schema = get_schema(custom_properties)
    deserializer = RequestDeserializer(schema)
    serializer = ResponseSerializer(schema)
    controller = ImagesCopyController()
    return wsgi.Resource(controller, deserializer, serializer)