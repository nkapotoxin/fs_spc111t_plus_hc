# Copyright (c) 2014 Huawei Technologies Co., Ltd.
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

"""The Aggregate admin API extension."""

import datetime

import webob
from webob import exc

from nova.api.openstack import extensions
from nova.compute import api as compute_api
from nova import exception
from nova.huawei.compute import affinity_api
from nova.huawei import exception as huawei_exception
from nova.openstack.common.gettextutils import _
from nova.openstack.common import log as logging
from nova import utils

LOG = logging.getLogger(__name__)
authorize = extensions.extension_authorizer('compute', 'affinity-group')


def _get_context(req):
    return req.environ['nova.context']


class AffinityGroupController(object):
    """The Affinity Group of VMs API controller for the OpenStack API."""
    def __init__(self):
        self.api = affinity_api.AffinityGroupAPI()
        self.compute_api = compute_api.API()

    def index(self, req):
        """Returns a list a affinity_group's id, name, type, vm list."""
        context = _get_context(req)
        authorize(context)
        affinity_groups = self.api.get_affinity_group_list(context)
        return {'os-affinity-group':
                    [self._marshall_affinity_group(a)['affinity_group']
                               for a in affinity_groups]}

    def create(self, req, body):
        """Creates an affinity group, given its name and type."""
        context = _get_context(req)
        authorize(context)

        if len(body) != 1:
            raise exc.HTTPBadRequest()
        try:
            affinity_group = body["os-affinity-group"]
            name = affinity_group.get("name")
            description = affinity_group.get("description", "")
            affinity_type = affinity_group.get("type", "affinity")
            metadata = affinity_group.get("metadata", {})
        except KeyError:
            raise exc.HTTPBadRequest()

        try:
            utils.check_string_length(name, "Affinity Group Name", 1, 255)
        except exception.InvalidInput as e:
            raise exc.HTTPBadRequest(explanation=e.format_message())


        try:
            affinityGroup = self.api.create_affinity_group(context, name,
                                                       description,
                                                       affinity_type,
                                                       metadata)
        except huawei_exception.AffinityGroupNameExists as e:
            LOG.info(e)
            raise exc.HTTPConflict()
        except huawei_exception.InvalidAffinityGroupAction as e:
            LOG.info(e)
            raise
        return self._marshall_affinity_group(affinityGroup)

    def show(self, req, id):
        """Shows the details of an affinity group,
        hosts and metadata included."""
        context = _get_context(req)
        authorize(context)
        try:
            affinityGroup = self.api.get_affinitygroup(context, id)
        except huawei_exception.AffinityGroupNotFound:
            LOG.info(_("Cannot show affinityGroup: %s"), id)
            raise exc.HTTPNotFound()
        return self._marshall_affinity_group(affinityGroup)

    def update(self, req, id, body):
        """Updates the name and/or description of given affinity group."""
        context = _get_context(req)
        authorize(context)

        if len(body) != 1:
            raise exc.HTTPBadRequest()
        description = ""
        try:
            affinitygroup_updates = body["os-affinity-group"]
            name = affinitygroup_updates.get("name", None)
            description = affinitygroup_updates.get("description", None)
        except KeyError:
            raise exc.HTTPBadRequest()

        try:
            if name != None:
                utils.check_string_length(name, "Affinity Group name", 1, 255)
            if description != None:
                utils.check_string_length(description,
                                          "Affinity Group description",
                                          1, 255)
        except exception.InvalidInput as e:
            raise exc.HTTPBadRequest(explanation=e.format_message())

        try:
            affinity_group = self.api.update_affinitygroup(context,
                                                           id,
                                                        affinitygroup_updates)
        except huawei_exception.AffinityGroupNotFound:
            LOG.info(_('Cannot update affinity_group: %s'), id)
            raise exc.HTTPNotFound()

        return self._marshall_affinity_group(affinity_group)

    def delete(self, req, id):
        """Removes an affinity group by id."""
        context = _get_context(req)
        if id:
            try:
                self.api.delete_affinity_group(context, id)
            except KeyError:
                raise exc.HTTPBadRequest()
        else:
            msg = _('the affinitygroup_id is None')
            raise exc.HTTPBadRequest(explanation=msg)
        return webob.Response(status_int=200)

    def action(self, req, id, body):
        _actions = {
            'add_vm': self._add_vms,
            'remove_vm': self._remove_vms,
        }
        for action, data in body.iteritems():
            if action not in _actions.keys():
                msg = _('Affinity Group does not have %s action') % action
                raise exc.HTTPBadRequest(explanation=msg)
            if not data.get('vm_list'):
                msg = _("Affinity Group does not have 'vm_list'")
                raise exc.HTTPBadRequest(explanation=msg)
            return _actions[action](req, id, data['vm_list'])

        raise exc.HTTPBadRequest(explanation=_("Invalid request body"))

    def _add_vms(self, req, affinity_id, vm_ids):
        """Adds a list of  vms to the specified affinity group."""
        context = _get_context(req)
        authorize(context)

        try:
            vm_list = []
            for vm_id in vm_ids:
                vm = self.compute_api.get(context, vm_id, want_objects=True)
                vm_list.append(vm)
            self.api.add_vms_to_affinity_group(context, affinity_id, vm_list)
        except (huawei_exception.AffinityGroupNotFound):
            LOG.info(_('Cannot add vms %(vms)s in affinity_group %(id)s'),
                     {'vms': vm_ids, 'id': affinity_id})
            raise exc.HTTPNotFound()
        except (huawei_exception.AffinityGroupVMExists,
                huawei_exception.InvalidAffinityGroupAction) as e:
            LOG.info(_('Cannot add vms %(vms)s in affinity_group %(id)s'),
                     {'vms': vm_ids, 'id': affinity_id})
            raise exc.HTTPConflict(explanation=e.format_message())
        except exception.InstanceNotFound:
            raise exc.HTTPNotFound(_("Server not found"))

        return webob.Response(status_int=202)

    def _remove_vms(self, req, affinity_id, vm_ids):
        """Removes vms from the specified affinity group."""
        context = _get_context(req)
        authorize(context)

        try:
            vm_list = []
            for vm_id in vm_ids:
                vm = self.compute_api.get(context, vm_id, want_objects=True)
                vm_list.append(vm)
            self.api.remove_vms_from_affinity_group(context, affinity_id,
                                                    vm_list)
        except (huawei_exception.AffinityGroupNotFound):
            LOG.info(_('Cannot remove vms %(vms)s from affinity_group %(id)s'),
                     {'vms': vm_ids, 'id': affinity_id})
            raise exc.HTTPNotFound()
        except (huawei_exception.AffinityGroupVMExists,
                huawei_exception.InvalidAffinityGroupAction) as e:
            LOG.info(_('Cannot remove vms %(vms)s from affinity_group %(id)s'),
                     {'vms': vm_ids, 'id': affinity_id})
            raise exc.HTTPConflict(explanation=e.format_message())
        except huawei_exception.AffinityGroupError as e:
            raise exc.HTTPBadRequest(explanation=e.format_message())
        except exception.InstanceNotFound:
            raise exc.HTTPNotFound(_("Server not found"))

        return webob.Response(status_int=202)

    def _marshall_affinity_group(self, affinityGroup):
        _affinityGroup = {}
        for key, value in affinityGroup.items():
            # NOTE: The original API specified non-TZ-aware timestamps
            if isinstance(value, datetime.datetime):
                value = value.replace(tzinfo=None)
            _affinityGroup[key] = value
        return {"affinity_group": _affinityGroup}


class Affinity_group(extensions.ExtensionDescriptor):
    """Affinity Group"""

    name = "AffinityGroup"
    alias = "os-affinity-group"
    namespace = "http://docs.openstack.org/compute/ext/affinitygroup" \
                "/api/v2"
    updated = "2014-05-17T00:00:00+00:00"

    def __init__(self, ext_mgr):
        ext_mgr.register(self)

    def get_resources(self):
        resources = []
        res = extensions.ResourceExtension('os-affinity-group',
                                           AffinityGroupController(),
                member_actions={"action": "POST", })
        resources.append(res)
        return resources
