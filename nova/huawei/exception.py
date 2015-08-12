# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
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

"""Nova base exception handling.

Includes decorator for re-raising Nova-type exceptions.

SHOULD include dedicated exception logging.

"""


from nova.i18n import _
from nova.exception import NovaException
from nova.exception import InvalidInput
from nova.exception import NotFound
from nova.exception import Invalid


class PciSlotNotFree(NovaException):
    msg_fmt = _("Cannot find available PCI slot number.")


class BandwidthInfoError(InvalidInput):
    msg_fmt = _("Port info in metadata and requested_network not match")


class VirtualInterfaceNotFound(NotFound):
    msg_fmt = _("Virtual Interface %(id)s could not be found.")


class VirtualInterfaceNotInUse(NovaException):
    msg_fmt = _("Virtual Interface %(vif_id)s is not in use.")


class AffinityGroupError(NovaException):
    msg_fmt = _("AffinityGroup %(affinitygroup_id)s: action '%(action)s' "
                "caused an error: %(reason)s.")


class AffinityGroupNotFound(NotFound):
    msg_fmt = _("AffinityGroup %(affinitygroup_id)s could not be found.")


class AffinityGroupNameExists(NovaException):
    msg_fmt = _("AffinityGroup %(affinitygroup_name)s already exists.")


class AffinityGroupVMNotFound(NotFound):
    msg_fmt = _("AffinityGroup %(affinitygroup_id)s has no vm %(vm)s.")


class AffinityGroupMetadataNotFound(NotFound):
    msg_fmt = _("AffinityGroup %(affinitygroup_id)s has no metadata with "
                "key %(metadata_key)s.")


class AffinityGroupVMExists(NovaException):
    msg_fmt = _("AffinityGroup %(affinitygroup_id)s already has "
                "vm %(vm)s.")


class InvalidAffinityGroupAction(Invalid):
    msg_fmt = _("Cannot perform action '%(action)s' on affinitygroup "
                "%(affinitygroup_id)s. Reason: %(reason)s.")


class AffinityGroupOneVMExists(AffinityGroupError):
    msg_fmt = _("AffinityGroup %(affinitygroup_id)s can not has only one vm.")


class IronicVolumeNotFound(NotFound):
    msg_fmt = _("Ironic Volume %(node_uuid)s could not be found.")

