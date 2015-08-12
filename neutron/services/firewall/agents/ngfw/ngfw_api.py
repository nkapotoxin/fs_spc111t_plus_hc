# Copyright 2013 ngfw Networks Inc.
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

import base64
import commands
import httplib
import urllib
import json
import sys
import time
from oslo.config import cfg

from neutron.openstack.common import jsonutils
from neutron.openstack.common import log as logging
from neutron.services.firewall.agents.ngfw import ngfw_utils

TOTALNUM_KEY_BEGIN = '<summary><totalnumber>'
TOTALNUM_KEY_END = '</totalnumber>'
NGFW_PAGESIZE = 15

OPTS = [
    cfg.StrOpt('director', default='localhost',
               help=_("ngfw director ip")),
    cfg.StrOpt('director_port', default='8448',
               help=_("ngfw director port")),
    cfg.StrOpt('ngfw_username',
               help=_("ngfw director username")),
    cfg.StrOpt('ngfw_password', secret=True,
               help=_("ngfw director password")),
    cfg.StrOpt('director_for_acl', default='localhost',
               help=_("ngfw director ip for acl")),
    cfg.StrOpt('director_for_fip', default='localhost',
               help=_("ngfw director ip for fip")), ]

cfg.CONF.register_opts(OPTS, "ngfw")

class LogClass(object):
    def __init__(self):
        pass
    
    def debug(self, *str):
        pass
    
    def warn(self, *str):
        pass
    
    def error(self, *str):
        pass
        
if __name__ == '__main__':
    LOG = LogClass()
else:
    LOG = logging.getLogger(__name__)


class ngfwAPIException(Exception):
    message = _("An unknown exception.")

    def __init__(self, **kwargs):
        try:
            self.err = self.message % kwargs

        except Exception:
            self.err = self.message

    def __str__(self):
        return self.err


class AuthenticationFailure(ngfwAPIException):
    message = _("Invalid login credential.")


class AuthenticationNoResponse(ngfwAPIException):
    message = _("No response from NGFW")

class ngfwRestAPI(object):

    def __init__(self):
        LOG.debug(_('ngfwRestAPI: started'))
        self.user = cfg.CONF.ngfw.ngfw_username
        self.passwd = cfg.CONF.ngfw.ngfw_password
        self.server = cfg.CONF.ngfw.director
        self.port = cfg.CONF.ngfw.director_port
        self.director_for_acl = cfg.CONF.ngfw.director_for_acl
        self.director_for_fip = cfg.CONF.ngfw.director_for_fip
        self.timeout = 5
        self.retry = 3
        self.retry_delay = 0.1

    def fix_header(self, resp_headers, body_len):
        headers=ngfw_utils.NGFW_DEFAULT_HEADER.copy()
        for head in resp_headers.keys():
            if head.lower() == 'token':
                headers.update({head:resp_headers[head]})
            if head.lower() == 'cookie':
                headers.update({head:resp_headers[head]})
            if head.lower() == 'sn':
                headers.update({'SN':str(int(resp_headers[head])+1)})
        headers.update({'Content-Length':str(body_len)})
        return headers
    
    def send_request(self, httpClient, method, uri, body, headers):
        if httpClient is None:
            httpClient = httplib.HTTPConnection(host=self.server, port=self.port, timeout=self.timeout)
        try:
            httpClient.request(method, uri, body, headers)
            response = httpClient.getresponse()            
            return (httpClient, response)
        except Exception:
            LOG.error(_('ngfwRestAPI: Could not establish HTTP connection'))
            return (httpClient, None)
            
    def auth(self):
        headers = ngfw_utils.NGFW_DEFAULT_HEADER.copy()
        body='username=%s&password=%s' % (self.user, self.passwd)
        (httpClient, resp) = self.send_request(None, 'POST', ngfw_utils.NGFW_URL_AUTH, body, headers)
        if resp is None:
            LOG.error(_('ngfwRestAPI: auth failed, resp is None'))
            httpClient.close()
            raise AuthenticationNoResponse()
        elif resp.status >=400:
            LOG.error(_('ngfwRestAPI: auth failed, resp.status is %d'), resp.status)
            resp.read()
            httpClient.close()
            self.retry = 1
            raise AuthenticationFailure()
        return (httpClient, resp)
                 
    def rest_api_once(self, method, url, body=None, headers=None):
        try:
            httpClient,response = self.auth()
            response.read()
            req_headers = dict(response.getheaders())
            
            if headers:
                req_headers.update(headers)

            if body:
                body_data = body
            else:
                body_data = ''
            body_len = len(body_data)
            req_headers=self.fix_header(req_headers,body_len)

            (httpClient, resp) = self.send_request(httpClient, method, url, body_data, req_headers)
            if resp:
                resp_status = resp.status
                resp_str=resp.read()
            else:
                resp_status = 500
                resp_str="we send request, but no response received from NGFW"

            httpClient.close()

            return {"status": resp_status,
                    "body": "%s" % resp_str}

        except AuthenticationNoResponse:
            return {"status": 500, "body": "Authentication failed, No response from NGFW"}
        except AuthenticationFailure:
            return {"status": 500, "body": "Authentication failed"}
        except Exception:
            LOG.error(_('ngfwRestAPI: rest_api_once send has exception'))
            return {"status": 500, "body": "unknown exception catched"}


    def rest_api_multi(self, method, url, body=None, headers=None):
        count = 0
        resp = {"status": 500, "body": ""}
        while count < self.retry:
            count = count + 1
            resp = self.rest_api_once(method, url, body, headers)
            if resp["status"] >=400:
                time.sleep(self.retry_delay)
                continue
            return resp
        return resp
    

    def _rest_api(self, method, url, body=None, headers=None, device_ip=None):
        if body is None:
            body = ''
        if headers is None:
            headers = ''
        confile = ""
        for argument in sys.argv:
            if '--config-file' in argument:
                confile = confile + "**&&**" + argument

        file_path = '/usr/lib64/python2.6/site-packages/neutron/services/firewall/agents/ngfw/ngfw_api.py'
        if not device_ip:
            cmd = 'python %s %s \'%s\' \'%s\' \'%s\' \'%s\'' % (file_path, method, url, body, headers, confile)
        else:
            cmd = 'python %s %s \'%s\' \'%s\' \'%s\' \'%s\' \'%s\'' % (file_path, method, url, body, headers, confile, device_ip)

        rest, StrOut = commands.getstatusoutput(cmd)

        if "psk" in cmd or "psk" in StrOut:
            LOG.debug(_("request related to ike peer, status: %s" % rest))
        else:
            LOG.debug(_('cmd:%s, rest:%s, StrOut:%s' % (cmd, rest, StrOut)))

        if rest != 0:
            LOG.error(_('run cmd:%s failed, rest is:%s, StrOut is :%s' % (cmd, rest, StrOut)))
            return {"status": 500, "body": ""}
        
        try:
            StrOutTrans = StrOut.replace("\'", "\"")
            StrOutTrans = json.loads(StrOutTrans)
        except Exception:
            LOG.error(_('ngfwRestAPI: rest_api has exception %s'), StrOut)
            return {"status": 500, "body": ""}
        if "psk" not in str(StrOutTrans):
            LOG.debug(_('StrOutTrans is :%s.' % (StrOutTrans)))
        return StrOutTrans

    def rest_api(self, method, url, body=None, headers=None, device_ip=None):
        if method.lower() == 'get':
            #first get totalnum
            result = {"status": 500, "body":""}
            body_store = ''
            if '?' in url:
                flag = '&'
            else:
                flag = '?'
            uri = url + flag + 'pageindex=1&pagesize=1'
            resp = self._rest_api(method, uri, body, headers, device_ip)
            if resp['status'] >= 400:
                return resp
            total_num_list = ngfw_utils.parse_xml_name(json.dumps(resp), TOTALNUM_KEY_BEGIN, TOTALNUM_KEY_END)
            if not total_num_list:
                return resp
            times = int(total_num_list[0]) / NGFW_PAGESIZE
            left = int(total_num_list[0]) % NGFW_PAGESIZE
            for i in range(times):
                uri = url + flag + 'pageindex=%d&pagesize=%d' % (1+i, NGFW_PAGESIZE)
                temp = self._rest_api(method, uri, body, headers, device_ip)
                if temp['status'] >= 400:
                    return temp                
                body_store = body_store + temp['body']
            if left:
                uri = url + flag + 'pageindex=%d&pagesize=%d' % (1+times, NGFW_PAGESIZE)
                temp = self._rest_api(method, uri, body, headers, device_ip)
                if temp['status'] >= 400:
                    return temp                
                body_store = body_store + temp['body']
            result['status'] = 200
            result['body'] = body_store
        else:
            result = self._rest_api(method, url, body, headers, device_ip)
        return result
               
#self test command:
#1. modify conf option in the file
#2. python ngfw_api.py get /system/information
if __name__ == '__main__':
    if len(sys.argv) < 3:
        print({"status": 500, "body": ""})
        exit(1)
    method = sys.argv[1]
    url = sys.argv[2]
    if len(sys.argv) > 3:
        body = sys.argv[3]
    else:
        body = None
    if len(sys.argv) > 4:
        headers = sys.argv[4]
    else:
        headers = None

    if len(sys.argv) > 5:
        confile = sys.argv[5]
        confile_list_temp = confile.split('**&&**')
        confile_list = []
        for confile_item in confile_list_temp:
            if "" != confile_item:
                confile_list.append(confile_item)
        cfg.CONF(args=confile_list)
    else:
        confile = None        

    ngfwcls = ngfwRestAPI()
    if len(sys.argv) > 6:
        ip_addr = sys.argv[6]
        ngfwcls.server = ip_addr

    response = ngfwcls.rest_api_multi(method, url, body, headers)    
    print {"status":response["status"], "body":response["body"]}
    exit(0)
