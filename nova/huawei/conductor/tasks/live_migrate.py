import operator
from nova.conductor.tasks.live_migrate import *
from nova.huawei.scheduler import utils as hwutils
from nova.huawei import utils as h_utils
from nova.i18n import _
from nova import network
from nova import objects
from nova.openstack.common import jsonutils
from nova import utils
from nova.virt import hardware
from nova.network import model

class HuaweiLiveMigrationTask(LiveMigrationTask):
    def __init__(self, context, instance, destination,
                 block_migration, disk_over_commit):
        super(HuaweiLiveMigrationTask, self).__init__(context, 
                 instance, destination,
                 block_migration, disk_over_commit)
        self.network_api = network.API()

    def _check_pci_network(self):
        if not utils.is_neutron():
            LOG.warn(_("Not implement neutron. Can't check sriov."))
            return

        # now, evs, sriov and netmap instance don't support
        # live migrate
        unsupported_port_type = [model.VNIC_TYPE_VHOSTUSER,
                                 model.VNIC_TYPE_DIRECT,
                                 "softdirect"]
        unsupported_port_trunktype = ["trunk"]
        search_opt = {'device_id': self.instance['uuid'],
                      'tenant_id': self.instance['project_id']}
        ports = self.network_api.list_ports(self.context, **search_opt)['ports']
        for p in ports:
            if p['binding:vnic_type'] in unsupported_port_type:
                raise exception.MigrationPreCheckError(
                    reason="Instance with pci network dose not support "
                           "live migration")
            if p.get('trunkport:type', None) in unsupported_port_trunktype:
                raise exception.MigrationPreCheckError(
                    reason="Instance with network dose not support invalid trunkport "
                           "while living migration")

    def _check_hyperthread(self):
        src = self._get_compute_info(self.source)
        dest = self._get_compute_info(self.destination)
        
        source_numa = jsonutils.loads(src.numa_topology)
        dest_numa = jsonutils.loads(dest.numa_topology)
        source_numa = hwutils.convert_host_numa_topology(source_numa)
        dest_numa = hwutils.convert_host_numa_topology(dest_numa)
        if operator.xor(hwutils.is_host_enable_hyperthread(source_numa),
                        hwutils.is_host_enable_hyperthread(dest_numa)):
            raise exception.MigrationPreCheckError(
                  reason="src and dest have different hyperthreading.")

    def _find_destination(self):
        # TODO() this retry loop should be shared
        attempted_hosts = [self.source]
        image = None
        if self.instance.image_ref:
            image = compute_utils.get_image_metadata(self.context,
                                                     self.image_api,
                                                     self.instance.image_ref,
                                                     self.instance)
        request_spec = scheduler_utils.build_request_spec(self.context, image,
                                                          [self.instance])

        host = None
        while host is None:
            self._check_not_over_max_retries(attempted_hosts)
            filter_properties = {'ignore_hosts': attempted_hosts}
			
            scheduler_utils.setup_instance_group(self.context, request_spec,
                                                 filter_properties)
            # get scheduler_hints for cpu_filter
            info = objects.HuaweiInstanceExtra.get_by_instance_uuid(
                                self.context, self.instance.uuid)
            if not info.scheduler_hints:
                sch_hints = {}
            else:
                sch_hints = jsonutils.loads(info.scheduler_hints)
                
            filter_properties['scheduler_hints'] = sch_hints            
            
            host = self.scheduler_client.select_destinations(self.context,
                            request_spec, filter_properties)[0]['host']
            try:
                self._check_compatible_with_source_hypervisor(host)
                self._call_livem_checks_on_host(host)
            except exception.Invalid as e:
                LOG.debug("Skipping host: %(host)s because: %(e)s",
                    {"host": host, "e": e})
                attempted_hosts.append(host)
                host = None
        return host

    def _check_destination_has_enough_memory(self):
        avail = self._get_compute_info(self.destination)['free_ram_mb']
        mem_inst = self.instance.memory_mb
        free_huge = 0
        instance_uuid = self.instance.uuid
        dest = self.destination
        if not self.instance.system_metadata.get(
                'instance_type_extra_hw:mem_page_size'):
            host_topology, _fmt = hardware.host_topology_and_format_from_host(
                self._get_compute_info(self.destination))
            cells = host_topology.cells or []
            for cell in cells:
                for page in cell.mempages or []:
                    if page.size_kb != 4:
                        free_huge += (page.total - page.used) * \
                            page.size_kb / 1024
            avail = avail - free_huge
        if not mem_inst or avail <= mem_inst:
            reason = _("Unable to migrate %(instance_uuid)s to %(dest)s: "
                       "Lack of memory(host:%(avail)s <= "
                       "instance:%(mem_inst)s)")
            raise exception.MigrationPreCheckError(reason=reason % dict(
                    instance_uuid=instance_uuid, dest=dest, avail=avail,
                    mem_inst=mem_inst))

    def execute(self):
        self._check_instance_is_running()
        self._check_host_is_up(self.source)
        self._check_pci_network()
        if not self.destination:
            self.destination = self._find_destination()
        else:
            self._check_requested_destination()

        self._check_hyperthread()

        # TODO() need to move complexity out of compute manager
        # TODO() disk_over_commit?
        LOG.debug("live migration  %(instance_uuid)s from  %(source)s to host %(host)s ",
                 {"instance_uuid":self.instance["uuid"], "source":self.source, "host":self.destination})
        return self.compute_rpcapi.live_migration(self.context,
                host=self.source,
                instance=self.instance,
                dest=self.destination,
                block_migration=self.block_migration,
                migrate_data=self.migrate_data)
        
def execute(context, instance, destination,
            block_migration, disk_over_commit):
    task = HuaweiLiveMigrationTask(context, instance,
                                   destination,
                                   block_migration,
                                   disk_over_commit)
    # TODO() create a superclass that contains a safe_execute call
    return task.execute()       
