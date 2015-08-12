'''
Created on 2015-03-04

'''
from nova import utils
from nova import exception
from nova.openstack.common import log as logging
from nova.scheduler import filters
from nova.huawei.scheduler import utils as h_utils
LOG = logging.getLogger(__name__)

class CoreReserveFilter(filters.BaseHostFilter):
    """Coure reserve filter"""

    def host_passes(self, host_state, filter_properties):
        """
        :param host_state:
        :param filter_properties:
        :return:
        """
        instance_type = filter_properties.get('instance_type')

        instance_cpu_reverse = h_utils.get_instance_cpu_reserve(instance_type)
        host_cpu_reverse = h_utils.get_host_cpu_reserve(host_state)

        if instance_cpu_reverse is None or host_cpu_reverse is None:
            return True

        if host_cpu_reverse >= instance_cpu_reverse:
            return True

        LOG.debug("CoreReserveFilter pass 0 host, instance_cpu_reverse=%(instance_cpu_reverse)s"
                  ",host_cpu_reverse=%(host_cpu_reverse)s",
                  {'instance_cpu_reverse': instance_cpu_reverse,
                   'host_cpu_reverse': host_cpu_reverse})
        return False
