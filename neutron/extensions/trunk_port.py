#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.
from oslo.config import cfg

from neutron.api import extensions
from neutron.api.v2 import attributes
from neutron.common import constants
from neutron.common import exceptions as n_exc
from neutron.openstack.common import log


LOG = log.getLogger(__name__)


TRUNKPORT_OPTS = [
    cfg.BoolOpt('enable_trunkport',
               default=False,
               help=_('Enable trunk port support.'))
]

cfg.CONF.register_opts(TRUNKPORT_OPTS)


def _disable_extension(extension, aliases):
    if extension in aliases:
        aliases.remove(extension)


def disable_trunk_port_extension_by_config(aliases):
    if not cfg.CONF.enable_trunkport:
        LOG.info(_('Disabled trunk-port extension.'))
        _disable_extension('trunk-port', aliases)


#trunkport exceptions

class NetworkTypeInvalid(n_exc.InvalidInput):
    message = _("The %(type)s type network unsupported for trunk-port")


class TrunkPortTypeRequired(n_exc.InvalidInput):
    message = _("Attribute trunkport:type is required for trunk-port")


class TrunkPortCannotHasParentVid(n_exc.InvalidInput):
    message = _("Attributes trunkport:parent_id and trunkport:vid "
                "is not allowed for trunk type port")


class SubPortRequireParentVid(n_exc.InvalidInput):
    message = _("Attributes trunkport:parent_id and trunkport:vid "
                "must be provided for subport type port")


class ParentPortRequireTrunkType(n_exc.InvalidInput):
    message = _("Parent port %(port_id)s for subport must be trunk type")


class InvalidTrunkPortVid(n_exc.InvalidInput):
    message = _("Trunkport:vid %(vid)s not consistent with "
                "network vlan id %(vlanid)s")


class TrunkPortPhysicalNetworksNotMatch(n_exc.InvalidInput):
    message = _("Networks subport and parent port allocated "
                "does not match in physical network")


def _validate_vid(vid, key_specs=None):
    if vid is None:
        return None
    if vid == '':
        return None
    return attributes._validate_range(vid,
                                  [constants.MIN_VLAN_TAG, constants.MAX_VLAN_TAG])


def _validate_trunk_type(t_type, key_specs=None):
    if t_type is None:
        return None
    if t_type == "trunk":
        return None
    if t_type == "subport":
        return None
    return _("'%s' is not a valid trunk type") % (t_type)


attributes.validators['type:vid'] = _validate_vid
attributes.validators['type:trunk_type'] = _validate_trunk_type

TRUNKPORT_TYPE = 'trunkport:type'
TRUNKPORT_PARENT = 'trunkport:parent_id'
TRUNKPORT_VID = 'trunkport:vid'


TRUNK_TYPE_TRUNK = 'trunk'

EXTENDED_ATTRIBUTES_2_0 = {
    'ports': {
        TRUNKPORT_TYPE: {'allow_post': True, 'allow_put': False,
                         'validate': {'type:trunk_type': None},
                         'default': attributes.ATTR_NOT_SPECIFIED,
                         'enforce_policy': True,
                         'is_visible': True},
        TRUNKPORT_PARENT: {'allow_post': True, 'allow_put': False,
                           'validate': {'type:uuid': None},
                           'default': attributes.ATTR_NOT_SPECIFIED,
                           'enforce_policy': True,
                           'is_visible': True},
        TRUNKPORT_VID: {'allow_post': True, 'allow_put': False,
                        'convert_to': attributes.convert_to_int,
                        'validate': {'type:vid': None},
                        'default': attributes.ATTR_NOT_SPECIFIED,
                        'enforce_policy': True,
                        'is_visible': True}
    }
}


SUBPORT = 'subport'
SUBPORTS = SUBPORT + 's'


class Trunk_port(extensions.ExtensionDescriptor):
    """Extension class supporting trunk port."""

    @classmethod
    def get_name(cls):
        return "Trunk Port"

    @classmethod
    def get_alias(cls):
        return "trunk-port"

    @classmethod
    def get_description(cls):
        return "Adds trunk port attribute to port resource"

    @classmethod
    def get_namespace(cls):
        return "http://docs.openstack.org/ext/neutron/trunk_port/api/v1.0"

    @classmethod
    def get_updated(cls):
        return "2014-01-14T10:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
