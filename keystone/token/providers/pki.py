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

"""Keystone PKI Token Provider"""

from keystoneclient.common import cms

from keystone.common import environment
from keystone import config
from keystone import exception
from keystone.i18n import _
from keystone.openstack.common import jsonutils
from keystone.openstack.common import log
from keystone.token.providers import common


CONF = config.CONF

LOG = log.getLogger(__name__)


class Provider(common.BaseProvider):
    def _get_token_id(self, token_data):
        try:
            # force conversion to a string as the keystone client cms code
            # produces unicode.  This can be removed if the client returns
            # str()
            # TODO(ayoung): Make to a byte_str for Python3
            import copy
            token_cp = copy.deepcopy(token_data)
            if CONF.token.id_no_catalog:
                
                try:
                    # v3 token
                    if 'token' in token_cp:
                        # process problem that token is too long
                        token_cp['token'].pop('catalog', None)
                    # v2.0 token
                    if 'access' in token_cp:
                        # process problem that token is too long
                        token_cp['access'].pop('serviceCatalog', None)
                except:
                    import traceback
                    LOG.error("_get_token_id except:%s" % (traceback.format_exc()))

            token_id = str(cms.cms_sign_token(jsonutils.dumps(token_cp),
                                              CONF.signing.certfile,
                                              CONF.signing.keyfile))
            return token_id
        except environment.subprocess.CalledProcessError:
            LOG.exception(_('Unable to sign token'))
            raise exception.UnexpectedError(_(
                'Unable to sign token.'))
