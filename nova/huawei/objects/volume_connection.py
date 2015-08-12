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


from nova.huawei.db import affinity_db_api as db
from nova.objects import base
from nova.objects import fields


class VolumeConnection(base.NovaPersistentObject, base.NovaObject):
    # Version 1.0: Initial version

    VERSION = '1.0'
    fields = {
        'id': fields.IntegerField(),
        'instance_uuid': fields.StringField(nullable=True),
        'volume_id': fields.StringField(nullable=True),
        'host': fields.StringField(nullable=True),
        }

    @base.remotable_classmethod
    def count(cls, context, volume_id, host):
        return db.volume_connection_get_num(context, volume_id, host)

    @base.remotable_classmethod
    def set(cls, context, volume_id,
                                   instance_uuid, host):
        # set connection
        return db.volume_connection_set(context, volume_id, instance_uuid, host)

    @base.remotable_classmethod
    def unset(cls, context, volume_id,
                                     instance_uuid, host):
        # unset or delete, depend on condition
        return db.volume_connection_unset(context, volume_id, instance_uuid, host)

