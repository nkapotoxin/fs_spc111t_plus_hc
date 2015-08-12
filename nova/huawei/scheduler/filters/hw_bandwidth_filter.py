'''
Created on 2014-11-12

'''
from nova import utils
from nova import exception
from nova.openstack.common import log as logging
from nova.scheduler import filters
from nova.openstack.common import jsonutils
from nova.pci import pci_manager
from nova.huawei.openstack.common import hw_host_networklist
LOG = logging.getLogger(__name__)

class BandwidthFilter(filters.BaseHostFilter):
    """Filter network bandwidth"""
    
    def __init__(self):
        self.host_net = None
          
    def _get_total_bandwidths(self, pci_stats):
        total_bandwidths = {}
        for pool in pci_stats.pools:
            physical_network = pool.get('physical_network', None)
            bandwidths = pool.get('bandwidths', None)
            if physical_network and bandwidths:
                if physical_network not in total_bandwidths:
                    total_bandwidths[physical_network] = bandwidths
        return total_bandwidths
    
    def _get_bandwidth_req(self, filter_properties):
        bandwidth_req = {}
        metadata = filter_properties['request_spec'][
                                        'instance_properties']['metadata']
        for phy_net, __, bandwidth in self.host_net.get_nw_info_from_meta(
                                                                metadata):
            if phy_net in bandwidth_req:
                bandwidth_req[phy_net] += int(bandwidth)
            else:
                bandwidth_req[phy_net] = int(bandwidth)
        return bandwidth_req

    def host_passes(self, host_state, filter_properties):
        if not utils.is_neutron():
            return True
        pci_requests = filter_properties.get('pci_requests')

        if not pci_requests:
            LOG.info("pci_requests is empty in filter_properties, "
                     "BandwidthFilter passed")
            return True
        
        if isinstance(host_state, dict):
            pci_stats = host_state.get('pci_stats', '{}')
            host = host_state['hypervisor_hostname']
        else:
            pci_stats = host_state.pci_stats
            host = host_state.host
        
        try:
            netInfo = {}
            for phy_net, bandwidth in self._get_total_bandwidths(
                                                    pci_stats).iteritems():
                netInfo[phy_net] = {'type':'passthrough',
                                    'total_bandwidth':bandwidth,
                                    'used_bandwidth':'0'}
            
            if len(netInfo) == 0:
                LOG.info("pci_stats is empty in host_state, "
                         "BandwidthFilter passed")
                return True
            
            self.host_net = hw_host_networklist.HostNetworkList(
                                            jsonutils.dumps(netInfo), host)
            bandwidth_req = self._get_bandwidth_req(filter_properties)
            for phy_net, bandwidth in bandwidth_req.iteritems():
                if phy_net not in netInfo:
                    LOG.error("the host do not have plane with name %s. "
                              "host:%s" % (phy_net, host))
                    return False
                remain_bandwidth = self.host_net.get_remain_bandwidth(phy_net)
                if int(remain_bandwidth) < int(bandwidth):
                    LOG.error("Need bandwidth %s, the host has %s, host:%s" %
                                  (bandwidth, remain_bandwidth, host))
                    return False
                
        except Exception:
            LOG.exception("BandwidthFilter failed")
            return False
        return True            