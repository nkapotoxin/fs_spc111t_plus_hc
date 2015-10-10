import sys
reload(sys)
sys.setdefaultencoding('utf-8')
import webob.dec
import base64
import hashlib
import log
import json
from cinder import wsgi
from cinder.openstack.common import timeutils
from cinder import HWExtend
from oslo.config import cfg


CONF = cfg.CONF


log.init('cinder-api')
APACHE_TIME_FORMAT = '%d/%b/%Y:%H:%M:%S'
APACHE_LOG_FORMAT = (
    '%(remote_addr)s - %(remote_user)s [%(datetime)s] "%(method)s %(url)s '
    '%(http_version)s" %(status)s %(content_length)s')


DRM_LOG_FORMAT = ('%(remote_addr)s - %(remote_user)s - %(token_id)s '
                  '[%(request_datetime)s][%(response_datetime)s]'
                  ' %(method)s %(url)s %(http_version)s %(status)s'
                  ' %(content_length)s %(request_body)s %(instance_id)s')


class AccessLogMiddleware(wsgi.Middleware):
    """Writes an access log to INFO."""

    @webob.dec.wsgify
    def __call__(self, request):
        now = timeutils.utcnow()
       
        heartBeatLog = False
        reqBody = "-"
        
        if 'xml' in str(request.content_type) or 'json' in str(request.content_type):
            if request.content_length is not None and request.content_length < 10240:
                reqBody = str(request.body) or '-'
                if HWExtend.hasSensitiveStr(reqBody):
                    reqBody = '-'
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
            'request_body':reqBody,
            'instance_id':'-'}
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
            elif ("POST" in data['method']) and (data['url'].endswith("/volumes")):
                if int(data['status']) < 400:
                    try:
                        resp_body = json.loads(response.body)
                        volume = resp_body.get('volume', None)
                        if volume is not None:
                            instance_id = volume.get('id', None)
                            if instance_id is not None:
                                data['instance_id'] = instance_id
                    except Exception:
                        pass 
            
            #'''---------snapshots ID -----------'''
            elif "POST" in data['method'] and data['url'].endswith("/snapshots"):
                if int(data['status']) < 400:
                    try:
                        resp_body = json.loads(response.body)
                        snapshots = resp_body.get('snapshot', None)
                        if snapshots is not None:
                            instance_id = snapshots.get('id', None)
                            if instance_id is not None:
                                data['instance_id'] = instance_id
                    except Exception:
                        pass 
        
            #'''---------backups ID ----------'''
            elif "POST" in data['method'] and data['url'].endswith("/backups"):
                if int(data['status']) < 400:
                    try:
                        resp_body = json.loads(response.body)
                        backups = resp_body.get('backup', None)
                        if backups is not None:
                            instance_id = backups.get('id', None)
                            if instance_id is not None:
                                data['instance_id'] = instance_id
                    except Exception:
                        pass
            elif "OPTIONS" in data['method'] and data['url'].endswith(":"+str(CONF.osapi_volume_listen_port)+"/"):
                heartBeatLog = True

            if heartBeatLog != True:
                data['response_datetime'] = '%s' % (now.strftime(APACHE_TIME_FORMAT))
                log.info(DRM_LOG_FORMAT % data, extra={"type":"operate"})
        return response
    


