# Copyright (c) 2011 OpenStack Foundation
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

"""
Scheduler host weights
"""

from nova import weights
from nova.scheduler import weights as base_weights


class HuaweiHostWeightHandler(weights.BaseWeightHandler):
    object_class = base_weights.WeighedHost

    def __init__(self):
        super(HuaweiHostWeightHandler, self).__init__(
            base_weights.BaseHostWeigher)


def all_weighers():
    """Return a list of weight plugin classes found in this directory."""
    return HuaweiHostWeightHandler().get_all_classes()
