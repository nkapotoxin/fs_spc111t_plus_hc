"""
  controller fc vm info
"""

import time

from nova import exception
from nova.compute import power_state
from nova.openstack.common.gettextutils import _

from nova.fusioncompute.virt.huaweiapi import ops_base
from nova.fusioncompute.virt.huaweiapi import utils
from nova.fusioncompute.virt.huaweiapi import constant
from nova.fusioncompute.virt.huaweiapi.utils import LOG

class FCInstance(dict):
    """
    fc vm class
    """
    def __init__(self, ini_dict):
        super(FCInstance, self).__init__()
        for key in ini_dict:
            self[key] = ini_dict[key]

    def get_vm_action_uri(self, action):
        """
        return fc vms uri info
        :param action:
        :return:
        """
        return self.uri + constant.VM_URI_MAP[action]

    def __getattr__(self, name):
        return self.get(name)

class FCInstanceOps(ops_base.OpsBase):
    """
    fc instances manager
    """

    def _query_vm(self, **kwargs):
        """Query VMs.

        :param kwargs:
                    name: VM name
                    status: VM status
                    scope: VM in certain scope
        :return: list of VMs
        """
        return self.get(utils.build_uri_with_params(self.site.vm_uri, kwargs))

    def _get_fc_vm(self, vm_info, limit=1, offset=0, detail=2, **kwargs):
        """
        get fv vm info by conditions
        :param vm_info:
        :param limit:
        :param offset:
        :param detail:
        :param kwargs:
        :return:
        """
        instances = self._query_vm(limit=limit, offset=offset, detail=detail,
                                  **kwargs)
        if not instances or not instances['vms']:
            LOG.error(_("can not find instance %s."), vm_info)
            raise exception.InstanceNotFound(instance_id=vm_info)
        return FCInstance(instances['vms'][0])

    def get_vm_state(self, instance):
        """
        Here use detail=0 for vm status info only
        :param instance:
        :return:
        """
        uuid = instance['uuid']
        return self._get_fc_vm(uuid, uuid=uuid, detail=0)

    def get_total_vm_numbers(self, **kwargs):
        """
        Get total numbers in fc
        :return:
        """
        instances = self._query_vm(limit=1, offset=0, detail=0, **kwargs)
        if not instances or not instances.get('total'):
            return 0
        total = int(instances.get('total'))
        LOG.info(_("total instance number is %d."), total)
        return total

    def get_all_vms_info(self,**kwargs):
        """
        Get all vms info by paging query
        :return: {uuid:state, ...},{uuid:name, ....}
        """

        limit = 100
        states = {}
        names = {}
        total = self.get_total_vm_numbers(**kwargs)
        while len(states) < total:
            last_total = len(states)
            instances = self._query_vm(limit=limit, offset=len(states),
                                       detail=0, **kwargs)
            for instance in instances.get('vms'):
                states[instance['uuid']] = \
                    constant.VM_POWER_STATE_MAPPING.get(instance['status'],
                        power_state.NOSTATE)
                names[instance['uuid']] = instance['name']
            if len(instances.get('vms')) < limit:
                break
            if last_total == len(states):
                break
            time.sleep(0.005)
        return states,names

    def get_all_vms(self, **kwargs):
        """
        Get all vms by paging query
        Here only return at most 100 vms to avoid timeout in db query
        :return:
        """

        instances = []
        total = self.get_total_vm_numbers(**kwargs)
        while len(instances) < total:
            paging_instances = self._query_vm(limit=100, offset=len(instances),
                detail=1, **kwargs)
            instances += paging_instances.get('vms')
            break
        return instances

    def get_vm_by_uuid(self, instance):
        """
        get vm info by vm uuid
        :param instance: openstack vm info
        :return:inner vm info
        """
        return self._get_fc_vm(instance['uuid'], uuid=instance['uuid'])

    def get_vm_by_id(self, vm_id):
        """

        :param vm_id:
        """
        return self._get_fc_vm(vm_id, vmId=vm_id)

    def get_vm_by_name(self, instance_name):
        """
        # NOTE: this method is used for implementing
        # nova.virt.driver.ComputeDriver#instance_exists
        :param instance_name:
        :return:
        """
        return self._get_fc_vm(instance_name, name=instance_name)

FC_INSTANCE_MANAGER = FCInstanceOps(None)
