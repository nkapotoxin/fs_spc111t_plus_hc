# Copyright (c) 2012 OpenStack Foundation
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

'''
Websocket proxy that is compatible with OpenStack Nova.
Leverages websockify.py by Joel Martin
'''

import Cookie
import socket
import urlparse

from oslo.config import cfg
import websockify

from nova.consoleauth import rpcapi as consoleauth_rpcapi
from nova import context
from nova import exception
from nova.i18n import _
from nova.openstack.common import log as logging
from nova.openstack.common import timeutils
from nova.huawei.openstack.common import HWExtend
import log as operationlog
LOG = logging.getLogger(__name__)
operationlog.init('nova-api')

CONF = cfg.CONF
CONF.import_opt('novncproxy_base_url', 'nova.vnc')
CONF.import_opt('html5proxy_base_url', 'nova.spice', group='spice')
CONF.import_opt('base_url', 'nova.console.serial', group='serial_console')


class NovaProxyRequestHandlerBase(object):
    def verify_origin_proto(self, console_type, origin_proto):
        if console_type == 'novnc':
            expected_proto = \
                urlparse.urlparse(CONF.novncproxy_base_url).scheme
        elif console_type == 'spice-html5':
            expected_proto = \
                urlparse.urlparse(CONF.spice.html5proxy_base_url).scheme
        elif console_type == 'serial':
            expected_proto = \
                urlparse.urlparse(CONF.serial_console.base_url).scheme
        else:
            detail = _("Invalid Console Type for WebSocketProxy: '%s'") % \
                        console_type
            raise exception.ValidationError(detail=detail)
        return origin_proto == expected_proto

    def new_websocket_client(self):
        """Called after a new WebSocket connection has been established."""
        # Reopen the eventlet hub to make sure we don't share an epoll
        # fd with parent and/or siblings, which would be bad
        from eventlet import hubs
        hubs.use_hub()

        # The nova expected behavior is to have token
        # passed to the method GET of the request
        query = urlparse.urlparse(self.path).query
        token = urlparse.parse_qs(query).get("token", [""]).pop()
        if not token:
            # NoVNC uses it's own convention that forward token
            # from the request to a cookie header, we should check
            # also for this behavior
            hcookie = self.headers.getheader('cookie')
            if hcookie:
                cookie = Cookie.SimpleCookie()
                cookie.load(hcookie)
                if 'token' in cookie:
                    token = cookie['token'].value

        ctxt = context.get_admin_context()
        rpcapi = consoleauth_rpcapi.ConsoleAuthAPI()
        connect_info = rpcapi.check_token(ctxt, token=token)

        if not connect_info:
            raise Exception(_("Invalid Token"))

        # Verify Origin
        expected_origin_hostname = self.headers.getheader('Host')
        if ':' in expected_origin_hostname:
            e = expected_origin_hostname
            expected_origin_hostname = e.split(':')[0]
        origin_url = self.headers.getheader('Origin')
        # missing origin header indicates non-browser client which is OK
        if origin_url is not None:
            origin = urlparse.urlparse(origin_url)
            origin_hostname = origin.hostname
            origin_scheme = origin.scheme
            if origin_hostname == '' or origin_scheme == '':
                detail = _("Origin header not valid.")
                raise exception.ValidationError(detail=detail)
            if expected_origin_hostname != origin_hostname:
                detail = _("Origin header does not match this host.")
                raise exception.ValidationError(detail=detail)
            if not self.verify_origin_proto(connect_info['console_type'],
                                              origin.scheme):
                detail = _("Origin header protocol does not match this host.")
                raise exception.ValidationError(detail=detail)

        self.msg(_('connect info: %s'), str(connect_info))
        host = connect_info['host']
        port = int(connect_info['port'])

        # Connect to the target
        self.msg(_("connecting to: %(host)s:%(port)s") % {'host': host,
                                                          'port': port})
        tsock = self.socket(host, port, connect=True)

        # Handshake as necessary
        if connect_info.get('internal_access_path'):
            tsock.send("CONNECT %s HTTP/1.1\r\n\r\n" %
                        connect_info['internal_access_path'])
            while True:
                data = tsock.recv(4096, socket.MSG_PEEK)
                if data.find("\r\n\r\n") != -1:
                    if not data.split("\r\n")[0].find("200"):
                        raise Exception(_("Invalid Connection Info"))
                    tsock.recv(len(data))
                    break

        instance_id = connect_info.get('instance_uuid', 'None')
        # Start proxying
        try:
            operationlog.info(
                "VNC: host:%s, port:%s, is connecting to vm %s, at %s" % (
                host, port, instance_id, timeutils.utcnow()),
                extra={"type": "operate"})
            self.do_proxy(tsock)
        except Exception:
            if tsock:
                tsock.shutdown(socket.SHUT_RDWR)
                tsock.close()
                operationlog.info(
                    "VNC: host:%s, port:%s, lost connection with vm %s, at %s"
                    % (host, port, instance_id, timeutils.utcnow()),
                    extra={"type": "operate"})
                self.vmsg(_("%(host)s:%(port)s: Target closed") %
                          {'host': host, 'port': port})
                LOG.audit("%s:%s: Target closed" % (host, port))
            raise


# TODO(sross): when the websockify version is bumped to be >=0.6,
#              remove the if-else statement and make the if branch
#              contents the only code.
if getattr(websockify, 'ProxyRequestHandler', None) is not None:
    class NovaProxyRequestHandler(NovaProxyRequestHandlerBase,
                                  websockify.ProxyRequestHandler):
        def __init__(self, *args, **kwargs):
            websockify.ProxyRequestHandler.__init__(self, *args, **kwargs)

        def socket(self, *args, **kwargs):
            return websockify.WebSocketServer.socket(*args, **kwargs)

    class NovaWebSocketProxy(websockify.WebSocketProxy):
        @staticmethod
        def get_logger():
            return LOG

else:
    import sys

    class NovaWebSocketProxy(NovaProxyRequestHandlerBase,
                             websockify.WebSocketProxy):
        def __init__(self, *args, **kwargs):
            del kwargs['traffic']
            del kwargs['RequestHandlerClass']
            websockify.WebSocketProxy.__init__(self, *args,
                                               target_host='ignore',
                                               target_port='ignore',
                                               unix_target=None,
                                               target_cfg=None,
                                               ssl_target=None,
                                               **kwargs)

        def new_client(self):
            self.new_websocket_client()

        def msg(self, *args, **kwargs):
            LOG.info(*args, **kwargs)

        def vmsg(self, *args, **kwargs):
            LOG.debug(*args, **kwargs)

        def warn(self, *args, **kwargs):
            LOG.warn(*args, **kwargs)

        def print_traffic(self, token="."):
            if self.traffic:
                sys.stdout.write(token)
                sys.stdout.flush()

    class NovaProxyRequestHandler(object):
        pass
