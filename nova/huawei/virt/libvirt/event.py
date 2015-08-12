# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Red Hat, Inc.
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
Asynchronous event notifications from virtualization drivers.

This module defines a set of classes representing data for
various asynchronous events that can occurr in a virtualization
driver.
"""

from nova.virt import event as virtevent

class Extend_LifecycleEvent(virtevent.LifecycleEvent):
    """Get the detail of event message. 
    When the instance stop normal, the detail is 0.
    When the instance destroy by virsh destroy, the detail is 1.
    When the instance qemu process quit abnormal, the detail is 5.
    """

    def __init__(self, uuid, transition, detail, timestamp=None):
        super(Extend_LifecycleEvent, self).__init__(uuid, transition, timestamp)

        self.detail = detail

    def get_detail(self):
        return self.detail
