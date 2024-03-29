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
from nova.i18n import _
from nova.console import type


class HuaweiConsoleVNC(type.ConsoleVNC):
    """
    Version 1.0 Huawei console vnc class, add password verification function
    """
    def __init__(self, host, port, password, internal_access_path=None):
        super(HuaweiConsoleVNC, self).__init__(host, port,
                                               internal_access_path)
        self.password = password


    def get_connection_info(self, token, access_url):
        """Returns an unreferenced dict with connection information."""
        ret = super(HuaweiConsoleVNC, self).get_connection_info(token,
                                                          access_url)

        # add password to access url
        if self.password:
            ret['access_url'] = _("%s&password=encode-%s" % (
                access_url, base64.b64encode(self.password)))

        return ret