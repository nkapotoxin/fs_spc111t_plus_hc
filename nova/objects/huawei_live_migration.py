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
from nova import objects
from nova.objects import base
from nova.objects import fields
from nova.openstack.common import jsonutils


class HuaweiLiveMigration(base.NovaPersistentObject, base.NovaObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    fields = {
        'id': fields.IntegerField(),
        'instance_uuid': fields.UUIDField(nullable=False),
        'source_host': fields.StringField(nullable=True),
        'dest_host': fields.StringField(nullable=True),
        'dest_addr': fields.IPV4AddressField(nullable=True),
        'block_migration': fields.StringField(nullable=True),
        'migrate_data': fields.StringField(nullable=True)
        }

    @staticmethod
    def _from_db_object(context, live_migration, db_live_migration):
        for key in live_migration.fields:
            live_migration[key] = db_live_migration[key]
        live_migration._context = context
        live_migration.obj_reset_changes()
        return live_migration

    @base.remotable_classmethod
    def get_by_instance_uuid(cls, context, instance_uuid):
        db_live_migration = db.livemigrations_get_by_uuid(context, instance_uuid)
        if db_live_migration is None:
            return None
        return cls._from_db_object(context, cls(), db_live_migration)

    @base.remotable
    def create(self, context):
        if self.obj_attr_is_set('id'):
            raise exception.ObjectActionError(action='create',
                                              reason='already created')
        updates = self.obj_get_changes()
        dest_addr = updates.pop('dest_addr', None)
        if dest_addr:
            updates['dest_addr'] = str(dest_addr)
        db_live_migration = db.livemigrations_create(context, updates)
        self._from_db_object(context, self, db_live_migration)

    @base.remotable
    def destroy(self, context):
        db.livemigrations_destroy(context, self.instance_uuid)
        self.obj_reset_changes()

    @property
    def instance(self):
        inst = objects.Instance.get_by_uuid(self._context, self.instance_uuid,
                                            expected_attrs=['system_metadata'])
        sys_meta = inst.system_metadata
        numa_topology = jsonutils.loads(sys_meta.get('new_numa_topo', '{}'))
        if numa_topology and numa_topology.get('cells'):
            cells = []
            for cell in numa_topology['cells']:
                cells.append(objects.InstanceNUMACell(
                    id=cell['id'], cpuset=set(cell['cpuset']),
                    memory=cell['memory'],
                    pagesize=cell.get('pagesize')))

            format_inst_numa = objects.InstanceNUMATopology(
                cells=cells, instance_uuid=inst.uuid)
            inst.numa_topology = format_inst_numa
        return inst


class HuaweiLiveMigrationList(base.ObjectListBase, base.NovaObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    fields = {
        'objects': fields.ListOfObjectsField('HuaweiLiveMigration'),
        }
    @base.remotable_classmethod
    def get_all(cls, context):
        db_tasks = db.livemigrations_get_all(context)
        return base.obj_make_list(context, cls(context), objects.HuaweiLiveMigration,
                                  db_tasks)

    @base.remotable_classmethod
    def get_by_host(cls, context, host):
        db_tasks = db.livemigrations_get_all_by_host(context, host)
        return base.obj_make_list(context, cls(context), objects.HuaweiLiveMigration,
                                  db_tasks)
