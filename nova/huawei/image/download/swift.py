import logging
from oslo.config import cfg
import six.moves.urllib.parse as urlparse
import swiftclient
import urllib
from FSComponentUtil import crypt

from nova.huawei.image.download import direct_io
import nova.exception as nova_exception
import nova.image.download.base as xfer_base


LOG = logging.getLogger(__name__)

CONF = cfg.CONF
CONF.import_opt("os_region_name", "nova.huawei.virt.libvirt.driver_hooks")
CONF.import_opt("host", "nova.image.glance")


class SwiftDownload(xfer_base.TransferBase):
    def __init__(self):
        self.CHUNKSIZE = 1024 * 64

    def glance_is_local(self):
        if CONF.os_region_name and CONF.os_region_name in CONF.glance.host:
            return True
        else:
            return False

    def get_connection(self, uri):
        self.parse_uri(uri)

        os_options = {}
        os_options["region_name"] = CONF.os_region_name
        os_options["endpoint_type"] = "internalURL"
        os_options["service_type"] = "object-store"

        return swiftclient.Connection(
            self.auth_url, self.user, self.key, insecure=True,
            tenant_name=self.tenant, auth_version='2',
            os_options=os_options, ssl_compression=False)

    def parse_uri(self, pieces):
        """
            swift+https://account:user:pass@authurl.com/container/obj
        """
        self.scheme = pieces.scheme
        if pieces.scheme == "swift+https":
            self.scheme = "https"
        else:
            self.scheme = "http"

        netloc = pieces.netloc
        path = pieces.path.lstrip('/')

        try:
            cred, netloc = netloc.split('@')
            cred = urllib.unquote(cred)
            self.tenant, self.user, self.key = cred.split(':')
            self.key = crypt.decrypt(self.key)
            path_parts = path.split('/')
            self.obj = path_parts.pop()
            self.container = path_parts.pop()
            path_parts.insert(0, netloc)
            self.auth_url = self.scheme + '://' + '/'.join(path_parts)
        except:
            LOG.exception("Fail to parse the direct_url.")
            raise

    def download(self, context, url_parts, dst_path, *args, **kwargs):
        if not self.glance_is_local():
            raise nova_exception.NovaException("Cannot use direct_url to"
                " download, cause glance is not as this az.")

        try:
            connection = self.get_connection(url_parts)
            resp_headers, resp_body = connection.get_object(
                container=self.container, obj=self.obj,
                resp_chunk_size=self.CHUNKSIZE)
        except:
            LOG.exception("Fail to download image by direct_url.")
            raise

        direct_io.write(dst_path, resp_body)


def get_download_handler():
    return SwiftDownload()


def get_schemes():
    return ['swift', 'swift+https']