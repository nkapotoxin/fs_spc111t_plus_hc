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

from nova import db
from nova import exception
from nova.objects import base
from nova.objects import fields


class HuaweiInstanceExtra(base.NovaPersistentObject, base.NovaObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    fields = {
        'instance_uuid': fields.UUIDField(nullable=False),
        'vcpu_topology': fields.StringField(nullable=True),
        'scheduler_hints': fields.StringField(nullable=True),
        'core_bind': fields.StringField(nullable=True),
        'request_network': fields.StringField(nullable=True),
        'stats': fields.StringField(nullable=True),
        'injected_files': fields.StringField(nullable=True)
    }

    @staticmethod
    def _from_db_object(context, huawei_extra, db_huawei_extra):

        for key in huawei_extra.fields:
            if key != 'injected_files':
                huawei_extra[key] = db_huawei_extra[key]
        huawei_extra._context = context
        huawei_extra.obj_reset_changes()
        return huawei_extra

    @base.remotable_classmethod
    def get_by_instance_uuid(cls, context, instance_uuid):
        db_huawei_inst_extra = db.huawei_instance_extra_get_by_instance_uuid(
            context, instance_uuid)
        if not db_huawei_inst_extra:
            return None
        return cls._from_db_object(context, cls(), db_huawei_inst_extra)

    @base.remotable_classmethod
    def get_by_host(cls, context, host):
        db_huawei_inst_extras = db.huawei_instance_extra_get_by_host(
            context, host)
        ret_extras = []
        for extra in db_huawei_inst_extras:
            ret_extras.append(cls._from_db_object(context, cls(), extra))
        return ret_extras

    @base.remotable
    def create(self, context):
        updates = self.obj_get_changes()
        db_huawei_instance_extra = db.huawei_instance_extra_create(
            context, self.instance_uuid, updates)
        return  self._from_db_object(context, self, db_huawei_instance_extra)
