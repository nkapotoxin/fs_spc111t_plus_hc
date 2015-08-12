# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# Copyright 2011 Piston Cloud Computing, Inc.
# Copyright 2012-2013 Red Hat, Inc.
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

"""Handles all requests relating to compute resources (e.g. guest VMs,
networking and storage of VMs, and compute hosts on which they run)."""

from nova.db import base
from nova import exception
from nova.huawei import exception as huawei_exception
from nova.compute import api as core_api
from nova.huawei.compute import rpcapi as affinity_rpcapi
from nova.huawei.objects import affinity_group as affinitygroup_obj
from nova.openstack.common.gettextutils import _
from nova.openstack.common import log as logging

LOG = logging.getLogger(__name__)


class AffinityGroupAPI(base.Base):
    """Sub-set of the Compute Manager API for managing affinity group."""
    def __init__(self, **kwargs):
        self.compute_rpcapi = affinity_rpcapi.HuaweiComputeAPI()
        self.compute_api = core_api.API()
        super(AffinityGroupAPI, self).__init__(**kwargs)

    def create_affinity_group(self, context, affinity_name, description, type,
                              metadata):
        """Creates the model for the affinity group."""

        affinitygroup = affinitygroup_obj.AffinityGroup()
        affinitygroup.name = affinity_name
        affinitygroup.description = description
        affinitygroup.type = type
        affinitygroup.metadata = metadata

        affinitygroup.create(context)

        affinitygroup = self._reformat_affinitygroup_info(affinitygroup)
        return affinitygroup

    def get_affinity_group_list(self, context):
        """Get all the affinity_group_list."""
        affinitygroups = affinitygroup_obj.AffinityGroupList.get_all(context)
        vm_id = None
        affinity_group = None
        for affinitygroup in affinitygroups:
            affinity_group = affinitygroup
            for vm_id_temp in affinitygroup.vms:
                try:
                    vm_id = vm_id_temp
                    self.compute_api.get(context, vm_id_temp, want_objects=True)
                except exception.InstanceNotFound:
                    affinity_group.delete_vm(context, str(vm_id))
        return [self._reformat_affinitygroup_info(element) for element in
                affinitygroups]

    def _reformat_affinitygroup_info(self, affinitygroup):
        """Builds a dictionary with aggregate props, metadata and hosts."""
        return dict(affinitygroup.iteritems())
    ## delete affinitygroup by id

    def delete_affinity_group(self, context, affinitygroup_id):
        """Delete affinity group by affinitygroup_id"""
        affinitygroup = affinitygroup_obj.AffinityGroup()
        affinitygroup.id = affinitygroup_id
        affinitygroup = affinitygroup_obj.AffinityGroup.get_by_id(context,
                                                                  affinitygroup_id)
        action_name = "delete"
        if (affinitygroup.vms is not None) and (affinitygroup.vms != []):
            msg = ("Can't delete affinity group with instances in it",
                   affinitygroup.vms)
            raise huawei_exception.InvalidAffinityGroupAction(
                action=action_name, affinitygroup_id=affinitygroup_id,
                reason=msg)
        affinitygroup.destroy(context)

    def update_affinitygroup(self, context, affinitygroup_id, values):
        """Update the properties of given affinity group."""
        affinitygroup = affinitygroup_obj.AffinityGroup.get_by_id(context,
                                                                  affinitygroup_id)
        if 'name' in values:
            affinitygroup.name = values.pop('name')
        if 'description' in values:
            affinitygroup.description = values.pop('description')
        if "metadata" in values:
            affinitygroup.metadata = values.pop('metadata')

        affinitygroup.save()
        return self._reformat_affinitygroup_info(affinitygroup)

    def get_affinitygroup(self, context, affinitygroup_id):
        """get the details of an affinitygroup by the given affinitygroup_id"""
        affinitygroup = affinitygroup_obj.AffinityGroup.get_by_id(context,
                                                              affinitygroup_id)
        vm_id = None
        for vm_id_temp in affinitygroup.vms:
            try:
                vm_id = vm_id_temp
                self.compute_api.get(context, vm_id_temp, want_objects=True)
            except exception.InstanceNotFound:
                affinitygroup.delete_vm(context, str(vm_id))
        showinfo = self._reformat_affinitygroup_info(affinitygroup)
        # get the detailed infomation about the vms
        instance_ids = affinitygroup.vms
        if instance_ids:
            vmsinfo = {}
            for instance_id in instance_ids:
                instance = self.compute_api.get(context, instance_id)
                vmsinfo[instance_id] = instance
            showinfo['vmsinfo'] = vmsinfo

        return showinfo

    def _check_vms_in_affinity_group(self, context, vm_list,
                                     affinity_group_id):
        for vm in vm_list:
            try:
                affinitygroup = affinitygroup_obj.AffinityGroup.get_by_vm_id(
                    context, str(vm['id']))
            except huawei_exception.AffinityGroupNotFound:
                continue
            if affinitygroup:
                LOG.debug(_("instance %s has been added to a affinity "
                            "group %s")  %(vm['uuid'], affinitygroup.name))
                action_name = "add vms to affinitygroup"
                msg = "instance has been added to a affinity group"
                raise huawei_exception.InvalidAffinityGroupAction(
                    action=action_name, affinitygroup_id=str(affinity_group_id),
                    reason=msg)

    def add_vms_to_affinity_group(self, context, affinity_group_id, vm_list):
        affinitygroup = affinitygroup_obj.AffinityGroup.get_by_id(context,
                                                                  affinity_group_id)
        availability_zone = affinitygroup.availability_zone
        self._check_vms_in_affinity_group(context, vm_list, affinity_group_id)
        if availability_zone:
            for vm in vm_list:
                cluster_temp = vm['node'].split('(')
                cluster_temp = cluster_temp[1].split(')')
                cluster = cluster_temp[0]
                if availability_zone != cluster:
                    LOG.debug(_("affinity availability_zone %s, "
                                "is not same with %s") %(availability_zone, cluster))
                    action_name = "add vms to affinitygroup"
                    msg = "affinity availability_zone is not same with vm"
                    raise huawei_exception.InvalidAffinityGroupAction(
                        action=action_name, affinitygroup_id=affinity_group_id,
                                                               reason=msg)
            self.compute_rpcapi.add_vms_to_affinity_group(context,
                                                          affinity_group_id,
                                                          vm_list)
        else:
            vm_zone = vm_list[0]['node']
            for vm in vm_list:
                if vm_zone != vm['node']:
                    LOG.debug(_("vm is not same with a availability_zone"))
                    action_name = "add vms to affinitygroup"
                    msg = "vm is not same with a availability_zone"
                    raise huawei_exception.InvalidAffinityGroupAction(
                        action=action_name, affinitygroup_id=affinity_group_id,
                        reason=msg)
            self.compute_rpcapi.add_vms_to_affinity_group(context,
                                                                affinity_group_id,
                                                                 vm_list)

    def remove_vms_from_affinity_group(self, context, affinity_group_id,
                                       vm_list):
        affinitygroup = affinitygroup_obj.AffinityGroup.get_by_id(context,
                                                                  affinity_group_id)
        availability_zone = affinitygroup.availability_zone

        if availability_zone:
            for vm in vm_list:
                cluster_temp = vm['node'].split('(')
                cluster_temp = cluster_temp[1].split(')')
                cluster = cluster_temp[0]
                if availability_zone != cluster:
                    LOG.debug(_("affinity availability_zone %s, "
                                "is not same with %s") %(availability_zone, cluster))
                    action_name = "add vms to affinitygroup"
                    msg = "affinity availability_zone is not same with vm"
                    raise huawei_exception.InvalidAffinityGroupAction(
                        action=action_name, affinitygroup_id=affinity_group_id,
                        reason=msg)
            self.compute_rpcapi.remove_vms_from_affinity_group(context,
                                                          affinity_group_id, vm_list)
        else:
            vm_zone = vm_list[0]['node']
            for vm in vm_list:
                if vm_zone != vm['node']:
                    LOG.debug(_("vm is not same with a availability_zone"))
                    action_name = "add vms to affinitygroup"
                    msg = "vm is not same with a availability_zone"
                    raise huawei_exception.InvalidAffinityGroupAction(
                        action=action_name, affinitygroup_id=affinity_group_id,
                        reason=msg)
            self.compute_rpcapi.remove_vms_from_affinity_group(context,
                                                          affinity_group_id,
                                                          vm_list)
