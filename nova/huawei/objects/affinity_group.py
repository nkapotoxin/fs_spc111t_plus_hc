#    Copyright (c) 2014 Huawei Technologies Co., Ltd.
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


from nova.compute import utils as compute_utils
from nova.huawei.db import affinity_db_api as db
from nova import exception
from nova.huawei import exception as huawei_exception
from nova.objects import base
from nova.objects import fields


class AffinityGroup(base.NovaPersistentObject, base.NovaObject):
    # Version 1.0: Initial version
    # Version 1.1: String attributes updated to support unicode
    VERSION = '1.1'

    fields = {
        'id': fields.IntegerField(),
        'name': fields.StringField(nullable=True),
        'description': fields.StringField(nullable=True),
        'type': fields.StringField(nullable=True),
        'vms':fields.ListOfStringsField(nullable=True),
        'metadata': fields.DictOfStringsField(nullable=True),
        }

    obj_extra_fields = ['availability_zone']

    @staticmethod
    def _from_db_object(context, affinitygroup, db_affinitygroup):
        for key in affinitygroup.fields:
            if key == 'metadata':
                db_key = 'metadetails'
            else:
                db_key = key
            affinitygroup[key]= db_affinitygroup[db_key]
        affinitygroup._context = context
        affinitygroup.obj_reset_changes()
        return affinitygroup

    def _assert_no_vms(self, action):
        if 'vms' in self.obj_what_changed():
            raise exception.ObjectActionError(
                action=action,
                reason='hosts updated inline')

    @base.remotable_classmethod
    def get_by_id(cls, context, affinitygroup_id):
        db_affinitygroup = db.affinitygroup_get(context, affinitygroup_id)
        return cls._from_db_object(context, cls(), db_affinitygroup)

    @base.remotable_classmethod
    def get_by_vm_id(cls, context, vm_id):
        db_affinitygroup = db.affinitygroup_get_by_vm(context,
                                                      vm_id)
        return cls._from_db_object(context, cls(), db_affinitygroup)

    @base.remotable
    def create(self, context):
        self._assert_no_vms('create')
        updates = self.obj_get_changes()
        metadata = updates.pop('metadata', None)
        db_affinitygroup = db.affinitygroup_create(context, updates,
                                               metadata=metadata)
        self._from_db_object(context, self, db_affinitygroup)
        
    @base.remotable
    def save(self, context):
        self._assert_no_vms('save')
        updates = self.obj_get_changes()
        updates.pop('id', None)
        db_aggregate = db.affinitygroup_update(context, self.id, updates)
        return self._from_db_object(context, self, db_aggregate)

    @base.remotable
    def update_metadata(self, context, updates):
        to_add = {}
        for key, value in updates.items():
            if value is None:
                try:
                    db.affinitygroup_metadata_delete(context, self.id, key)
                except huawei_exception.AffinityGroupMetadataNotFound:
                    pass
                try:
                    self.metadata.pop(key)
                except KeyError:
                    pass
            else:
                to_add[key] = value
                self.metadata[key] = value
        db.affinitygroup_metadata_add(context, self.id, to_add)
        self.obj_reset_changes(fields=['metadata'])

    @base.remotable
    def destroy(self, context):
        db.affinitygroup_delete(context, self.id)

    @base.remotable
    def add_vm(self, context, vm):
        db.affinitygroup_vm_add(context, self.id, vm)
        if self.vms is None:
            self.vms = []
        self.vms.append(vm)
        self.obj_reset_changes(fields=['vms'])

    @base.remotable
    def delete_vm(self, context, vm):
        db.affinitygroup_vm_delete(context, self.id, vm)
        self.vms.remove(vm)
        self.obj_reset_changes(fields=['vms'])

    @base.remotable
    def add_vms(self, context, vm_list):
        db.affinitygroup_vms_add(context, self.id, vm_list)
        if self.vms is None:
            self.vms = []
        self.vms = self.vms + vm_list
        self.obj_reset_changes(fields=['vms'])

    @base.remotable
    def delete_vms(self, context, vm_list):
        db.affinitygroup_vms_delete(context, self.id, vm_list)
        self.vms = list(set(self.vms) - set(vm_list))
        self.obj_reset_changes(fields=['vms'])

    @base.remotable
    def get_all_vms(self, context):
        return db.affinitygroup_vm_get_all(context, self.id)

    @property
    def availability_zone(self):
        return self.metadata.get('availability_zone', None)

class AffinityGroupList(base.ObjectListBase, base.NovaObject):

    fields = {
        'objects': fields.ListOfObjectsField('AffinityGroup'),
        }

    @base.remotable_classmethod
    def get_all(cls, context):
        db_affinitygroups = db.affinitygroup_get_all(context)
        return base.obj_make_list(context, AffinityGroupList(), AffinityGroup,
                                  db_affinitygroups)

    @base.remotable_classmethod
    def get_by_vm(cls, context, vm):
        db_affinitygroups = db.affinitygroup_get_by_vm(context, vm)
        return base.obj_make_list(context, AffinityGroupList(), AffinityGroup,
                                  db_affinitygroups)
