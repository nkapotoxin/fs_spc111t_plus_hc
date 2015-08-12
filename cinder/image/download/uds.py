# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Red Hat, Inc.
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

import logging

from oslo.config import cfg

import boto
import os
import mmap
import time
from FSComponentUtil import crypt

s3_opts = [
    cfg.StrOpt('s3_store_bucket_url_format', default='path',
               help='The S3 calling format used to determine the bucket. '
                      'Either subdomain or path can be used.'),
]

CONF = cfg.CONF
CONF.register_opts(s3_opts)
CONF = cfg.CONF
LOG = logging.getLogger(__name__)


def get_calling_format(bucket_format=None):
    import boto.s3.connection

    if bucket_format is None:
        bucket_format = CONF.s3_store_bucket_url_format
    if bucket_format.lower() == 'path':
        return boto.s3.connection.OrdinaryCallingFormat()
    else:
        return boto.s3.connection.SubdomainCallingFormat()

class UdsDownload(object):

    def __init__(self):
        pass

    CHUNKSIZE = 8192

    def get_file_with_direct_io(self, key, dst_path):
        LOG.debug(
            "Start to download image from uds, using direct IO to write the file[%s]." % dst_path)
        key.open('r')
        #open the file with direct IO        
        fp_direct_io = os.open(dst_path, os.O_RDWR | os.O_DIRECT | os.O_CREAT)
        m = mmap.mmap(-1, self.CHUNKSIZE)

        #write the file with direct IO
        try:
            for bytes in key:
                if len(bytes) < self.CHUNKSIZE:
                    break
                m.seek(0)
                m.write(bytes)
                os.write(fp_direct_io, m)
                time.sleep(0)
        finally:
            os.close(fp_direct_io)

            #write the last part of the file with normal method
        try:
            fp_normal = None
            if len(bytes) < self.CHUNKSIZE:
                LOG.debug("Left data len: %d", len(bytes))
                fp_normal = open(dst_path, "a")
                fp_normal.write(bytes)

        finally:
            if fp_normal:
                fp_normal.close()

            key.close()
        LOG.debug(
            "Finished downloading image from uds, using direct IO to write the file[%s]." % dst_path)


    def download(self, context, url_parts, dst_file, metadata, **kwargs):
        from boto.s3.connection import S3Connection
        from boto.s3.key import Key

        LOG.debug("start downloaded %(dst_file)s using %(module_str)s" %
                  {'dst_file': dst_file, 'module_str': str(self)})
        password = decrypt(url_parts.password)
        s3_conn = S3Connection(url_parts.username,
                               password,
                               host="%s:%s" % (
                                   url_parts.hostname, url_parts.port),
                               is_secure=(url_parts.scheme == 'uds+https'),
                               calling_format=get_calling_format())
        temp, bucket_name, object_key = url_parts.path.split('/')

        bucket = s3_conn.get_bucket(bucket_name)
        key = bucket.get_key(object_key)

        self.get_file_with_direct_io(key, dst_file)

        LOG.info("Downloaded %(dst_file)s using %(module_str)s" %
                 {'dst_file': dst_file, 'module_str': str(self)})


def get_download_handler(**kwargs):
    return UdsDownload()


def get_schemes():
    return ['uds', 'uds+https']


def decrypt(data):
    return crypt.decrypt(data)