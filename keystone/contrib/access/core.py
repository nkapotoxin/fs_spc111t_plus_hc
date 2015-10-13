# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import sys
reload(sys)
sys.setdefaultencoding('utf-8')
import webob.dec
import base64
import hashlib
import log
from keystone.common import wsgi
from keystone.openstack.common import timeutils
from keystone import HWExtend

log.init('keystone-api')
APACHE_TIME_FORMAT = '%d/%b/%Y:%H:%M:%S'
APACHE_LOG_FORMAT = (
    '%(remote_addr)s - %(remote_user)s [%(datetime)s] "%(method)s %(url)s '
    '%(http_version)s" %(status)s %(content_length)s')
DRM_LOG_FORMAT = ('%(remote_addr)s - %(remote_user)s - %(token_id)s '
                  '[%(request_datetime)s][%(response_datetime)s]'
                  ' %(method)s %(url)s %(http_version)s %(status)s'
                  ' %(content_length)s %(request_body)s')

class AccessLogMiddleware(wsgi.Middleware):
    """Writes an access log to INFO."""

    @webob.dec.wsgify
    def __call__(self, request):
        now = timeutils.utcnow()
        reqBody = "-"
        if 'xml' in str(request.content_type) or 'json' in str(request.content_type):
            if request.content_length is not None and request.content_length < 10240:
                reqBody = str(request.body) or '-'
                if HWExtend.hasSensitiveStr(reqBody):
                    reqBody = '-'
                elif "token" in reqBody:
                    Pos = reqBody.find('{"token": {"id": "')+18
                    if "MII" in reqBody:
                        Pos = reqBody.find('MII')
                    endPos = reqBody.find('"',Pos)
                    tokens = reqBody[Pos:endPos]
                    reqBody = reqBody.replace(tokens, HWExtend.b64encodeToken(tokens))
        data = {
            'remote_addr': request.remote_addr,
            'remote_user': request.remote_user or '-',
            'token_id':"None",
            'request_datetime':'%s' % now.strftime(APACHE_TIME_FORMAT),
            'response_datetime':'%s' % now.strftime(APACHE_TIME_FORMAT),
            'method': request.method,
            'url': request.url,
            'http_version': request.http_version,
            'status': 500,
            'content_length': '-',
            'request_body':reqBody}
        token = ''
        try:
            token = request.headers['X-Auth-Token']
            token = HWExtend.b64encodeToken(token)
        except:
            token = "-"
        try:
            response = request.get_response(self.application)
            data['status'] = response.status_int
            data['content_length'] = response.content_length or '-'
        finally:
            # must be calculated *after* the application has been called
            now = timeutils.utcnow()
            data['token_id'] = token
            if "GET" in data['method'] and "/tokens/" in data['url']:
                Pos = data['url'].find("tokens") + 7
                logToken = data['url'][Pos:Pos+32]
                encodedToken = HWExtend.b64encodeToken(logToken)
                data['url'] = data['url'].replace(logToken,encodedToken)
            # timeutils may not return UTC, so we can't hardcode +0000
            data['response_datetime'] = '%s' % (now.strftime(APACHE_TIME_FORMAT))
            log.info(DRM_LOG_FORMAT % data, extra={"type":"operate"})
        return response
    


