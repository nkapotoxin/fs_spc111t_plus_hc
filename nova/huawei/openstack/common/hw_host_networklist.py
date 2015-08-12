
from nova import db
from nova import context as nova_context
from nova import exception
from nova import network
from nova import objects
from nova.openstack.common import jsonutils
from nova.openstack.common import log as logging
from neutronclient.common import exceptions as n_exc

LOG = logging.getLogger(__name__)

# example: {'net':{'network_uuid':('phisical_network_name', 'network_type')}, 'port':{}}
_networks_info_cache = {'net':{}, 'port':{}}

class HostNetworkList(object):

    """
    Format the network info from compute.
    """
    
    def __init__(self, netInfo, host):
        self.host = host
        self.network_api = network.API()
        self._network_plans = jsonutils.loads(netInfo)
        self._admin_context = nova_context.get_admin_context()
        self._instanceList = None

    def get_instanceList(self):
        'get all vm in this host'
        self._instanceList = db.instance_get_all_by_host(self._admin_context,
                                                         self.host)
        return self._instanceList
    
    def set_instanceList(self, instances):
        self._instanceList = instances

    def _init_network_plans(self):
        for plan in self._network_plans.keys():
            network_plan = self._network_plans.get(plan)
            network_plan['used_bandwidth'] = '0'
            self._network_plans[plan].update(network_plan)
        
    def get_new_networkInfo(self, clean_all, sign):
        'get the changed networkinfo from decreating the network resources'
        LOG.debug("begin to get new network info, clean_all: "
                  "%s sign: %s" % (clean_all, sign))
        if sign not in (1, -1):
            raise exception.NovaException("invalid sign: %s" % sign)
        self._get_remain_resources(clean_all, sign)
        return self._network_plans
    
    def get_networkInfo(self):
        return self._network_plans
    
    def get_instance_nwinfo(self, request_network, cached = False):
        'get the network info by request' 
        if request_network.has_key('uuid') and request_network['uuid']:
            network_uuid = request_network.get('uuid')
            network = _networks_info_cache['net'].get(network_uuid)
            if not network:
                LOG.debug("no network info, "
                          "begin to get network: %s" % network_uuid)
                nw = self.network_api.get(self._admin_context, network_uuid)
                if cached:
                    _networks_info_cache['net'][network_uuid] = (
                                        nw.get('provider:physical_network'),
                                        nw.get('provider:network_type'))
                    LOG.debug("cached network %s info" % network_uuid)
                return (nw.get('provider:physical_network'),
                        nw.get('provider:network_type'))
        elif request_network.has_key(
                                    'port_id') and request_network['port_id']:
            port_id = request_network.get('port_id')
            network = _networks_info_cache['port'].get(port_id)
            if not network:
                LOG.debug("no network info, begin to get port: %s" % port_id)
                port = self.get_port_by_id(port_id)['port']
                nw = self.network_api.get(self._admin_context,
                                          port['network_id'])
                if cached:
                    _networks_info_cache['port'][port_id] = (
                                        nw.get('provider:physical_network'),
                                        nw.get('provider:network_type'))
                    LOG.debug("cached port %s info" % port_id)
                return (nw.get('provider:physical_network'),
                        nw.get('provider:network_type'))
        return (None, None)

    def _get_remain_resources(self, clean_all, sign):
        self.get_instanceList()
        if clean_all:
            self._init_network_plans()
        for instance in self._instanceList:
            task_state = instance.get('task_state')
            if 'deleting' == task_state:
                continue
            metadata_dict = {}
            for metadata in instance['metadata']:
                metadata_dict[metadata['key']] = metadata['value']
            for phy_net, net_type, bandwidth in self.get_nw_info_from_meta(
                                                            metadata_dict):
                self._update_bandwidth_by_vnicType((phy_net, net_type),
                                                   bandwidth, sign)  
                
    def get_nw_info_from_meta(self, metadata):
        for key, value in metadata.iteritems():
            key = key.strip()
            if key.startswith('vnic_info'):
                port_id = key.split(':')[1]
                port = self.get_port_by_id(port_id)['port']
                if port['binding:vnic_type'] not in ['direct',
                                                     'netmap', 'macvtap']:
                    continue
                bandwith = value.strip().split(':')[1]
                phy_net, net_type = self.get_instance_nwinfo(
                                                    {'port_id': port_id})
                if phy_net not in self._network_plans:
                    continue
                yield (phy_net, net_type, bandwith)

    def get_remain_bandwidth(self, physical_name):
        self._get_remain_resources(False, 1)
        if physical_name in self._network_plans:
            network_plan = self._network_plans.get(physical_name)
            total_bandwidth = network_plan.get('total_bandwidth')
            used_bandwidth = network_plan.get('used_bandwidth')
            return str(int(total_bandwidth) - int(used_bandwidth))
        return '0'
    
    def _update_bandwidth_by_vnicType(self, nwinfo, bandwidth, sign = 1):
        network_type = nwinfo[1]
        if network_type in ['flat', 'vlan']:
            physical_network = nwinfo[0]
            network_plan = self._network_plans.get(physical_network)
            old_used = int(network_plan.get('used_bandwidth'))
            used_bandwidth = old_used + sign * int(bandwidth)
            total_bandwidth = int(network_plan.get('total_bandwidth'))
            need_update = True
            if total_bandwidth < used_bandwidth:
                need_update = False
                LOG.info("used_bandwidth %s is more than total_bandwidth %s, "
                         "bandwidth:%s" % (used_bandwidth,
                                           total_bandwidth, bandwidth))
            if used_bandwidth < 0:
                need_update = False
                LOG.error("old used bandwidth %s is insufficient "
                          "to release %s" % (old_used, bandwidth))
            if need_update:
                network_plan['used_bandwidth'] = str(used_bandwidth)
        elif network_type == 'vxlan':
            LOG.info("not update bandwidth usage for vxlan network.")
    
    def change_str_to_list(self, request_network):
        req_network = []
        if '[]' in request_network:
            return req_network
        request_network=request_network.replace('u\'', '')
        begin = request_network.find('(')
        end = request_network.rfind(')')
        request_network = request_network[begin+1:end].replace(
                            '\'', '').replace('[(', '').replace(
                            ')]', '').replace(' ', '')
        nlist = request_network.split('),(')
        for e in nlist:
            elment = e.split(',')
            req_network.append(tuple(elment))
        return req_network
    
    def get_instance_nw_info(self, instance_uuid):
        context = self._admin_context
        instance = objects.Instance.get_by_uuid(context,
                                        instance_uuid,
                                        use_slave=False)  
        network_info = self.network_api.get_instance_nw_info(context,
                                                     instance)
        return network_info

    def get_port_by_id(self, port_id):
        return self.network_api.show_port(self._admin_context, port_id)
