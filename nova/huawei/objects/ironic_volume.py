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


from nova.objects import base
from nova.objects import fields
from nova.huawei.db import affinity_db_api as db
from nova.openstack.common import jsonutils

class VolumeConnector(base.NovaPersistentObject, base.NovaObject):
    # Version 1.0: Initial version

    VERSION = '1.0'
    fields = {
        'id': fields.IntegerField(),
        'node_uuid': fields.StringField(nullable=True),
        'connector': fields.StringField(nullable=True),
        }

    @staticmethod
    def _from_db_object(context, ironicVolume, db_ironicVolumee):

        fields = set(ironicVolume.fields)
        for key in fields:
            ironicVolume[key] = db_ironicVolumee[key]

        ironicVolume._context = context
        ironicVolume.obj_reset_changes()
        return ironicVolume

    def _convert_connector_to_db_format(self, updates):
        connector = updates.pop('connector', None)
        if connector is not None:
            updates['connector'] = jsonutils.dumps(connector)

    @base.remotable_classmethod
    def get_by_id(cls, context, node_uuid):
        db_volume =  db.ironic_connector_get(context, node_uuid)
        return cls._from_db_object(context, cls(), db_volume)

    @base.remotable
    def create(self, context):
        updates = self.obj_get_changes()
        return db.ironic_connector_create(context, updates)


    @base.remotable
    def delete(self, context, node_uuid):
        return db.ironic_connector_delete(context, node_uuid)
