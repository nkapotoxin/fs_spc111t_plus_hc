import copy
from oslo.config import cfg
import six.moves.urllib.parse as urlparse

import glanceclient
import glanceclient.exc
import keystoneclient.v2_0.client as ksclient
from nova.openstack.common import log as logging
from nova.image import glance
from nova.huawei.image.download import direct_io
from nova.i18n import _

CONF = cfg.CONF
CONF.import_opt('auth_protocol', 'keystoneclient.middleware.auth_token', group='keystone_authtoken')
CONF.import_opt('auth_host', 'keystoneclient.middleware.auth_token', group='keystone_authtoken')
CONF.import_opt('auth_port', 'keystoneclient.middleware.auth_token', group='keystone_authtoken')
CONF.import_opt('auth_version', 'keystoneclient.middleware.auth_token', group='keystone_authtoken')
CONF.import_opt('admin_tenant_name', 'keystoneclient.middleware.auth_token', group='keystone_authtoken')
CONF.import_opt('admin_user', 'keystoneclient.middleware.auth_token', group='keystone_authtoken')
CONF.import_opt('admin_password', 'keystoneclient.middleware.auth_token', group='keystone_authtoken')

LOG = logging.getLogger(__name__)

class HuaweiGlanceImageService(glance.GlanceImageService):

    def __init__(self, client=None):
        super(HuaweiGlanceImageService, self).__init__(client)

    def create(self, context, image_meta, data=None):
        reserved_properties = {}
        RESERVED_PROPERTIES = (
        '__imagetype', '__originalimageid', '__originalimagename', '__platform')

        properties = {}
        properties.update(image_meta.get('properties', {}))
        for key in properties:
            if key in RESERVED_PROPERTIES:
                reserved_properties[key] = image_meta['properties'][key]
                del image_meta['properties'][key]

        if reserved_properties.get('__imagetype', None) == 'Gold':
            reserved_properties['__imagetype'] = 'Service'

        recv_service_image_meta = super(HuaweiGlanceImageService, self).create(context, image_meta, data)
        if reserved_properties:
            try:
                auth_url = "%s://%s:%s/identity/%s" % (CONF.keystone_authtoken.auth_protocol,
                                            CONF.keystone_authtoken.auth_host,
                                            CONF.keystone_authtoken.auth_port,
                                            CONF.keystone_authtoken.auth_version)
                nova_context = ksclient.Client(
                                                 tenant_name=CONF.keystone_authtoken.admin_tenant_name,
                                                 username=CONF.keystone_authtoken.admin_user,
                                                 password=CONF.keystone_authtoken.admin_password,
                                                 auth_url=auth_url,
                                                 insecure=True)
                admin_context = copy.deepcopy(context)
                admin_context.auth_token = nova_context.auth_token
                LOG.debug("Start to update image, reserved properties:%s" % reserved_properties)
                recv_service_image_meta = self.update(admin_context, recv_service_image_meta['id'],
                                                      {'properties': reserved_properties},
                                                      purge_props=False)

            except glanceclient.exc.HTTPException:
                glance._reraise_translated_exception()

        return recv_service_image_meta

    def download(self, context, image_id, data=None, dst_path=None):
        """Calls out to Glance for data and writes data."""
        if CONF.glance.allowed_direct_url_schemes and dst_path is not None:
            image = self.show(context, image_id, include_locations=True)
            for entry in image.get('locations', []):
                loc_url = entry['url']
                loc_meta = entry['metadata']
                o = urlparse.urlparse(loc_url)
                xfer_mod = self._get_transfer_module(o.scheme)
                if xfer_mod:
                    try:
                        xfer_mod.download(context, o, dst_path, loc_meta)
                        msg = _("Successfully transferred "
                                "using %s") % o.scheme
                        LOG.info(msg)
                        return
                    except Exception as ex:
                        LOG.exception(ex)

        try:
            image_chunks = self._client.call(context, 1, 'data', image_id)
        except Exception:
            glance._reraise_translated_image_exception(image_id)

        close_file = False
        if data is None and dst_path:
            direct_io.write(dst_path, image_chunks)
            return

        if data is None:
            return image_chunks
        else:
            try:
                for chunk in image_chunks:
                    data.write(chunk)
            finally:
                if close_file:
                    data.close()
