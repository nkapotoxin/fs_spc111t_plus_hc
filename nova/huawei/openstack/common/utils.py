# Copyright (c) 2011 OpenStack Foundation
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

"""Compute-related Utilities and helpers."""
import re


def _filter_sensitive_data(msg):
    # expand the list if need to filter other data
    filter_reg_list = ["(?<=user_data=)(.*?)(?=,)",
                       "(?<=user_data.:)(.*?)(?=,)"]

    for filter_reg in filter_reg_list:
        msg = re.sub(filter_reg, 'u\'<SANITIZED>', msg)

    return msg