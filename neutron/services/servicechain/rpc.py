

from neutron.openstack.common import log as logging
from neutron.services.servicechain import constants
from neutron.db.servicechain import servicechain_db
from neutron.common import topics

LOG = logging.getLogger(__name__)

class ServiceChainRpcCallbackMixin(object):
    
    def get_portflows_by_host_portid(self, context, **kwargs):
        host = kwargs.get('host')
        port_id = kwargs.get('port_id')
        pfs = servicechain_db.get_portflows_by_host_portid(context, host, port_id)
        LOG.info(_('agent->server, get_portflows_by_host_portid: host=%s, portflows=%s'), host, pfs)
        return pfs
        
    def update_portflows_status(self, context, **kwargs):
        chain_id = kwargs.get('chain_id')
        ports_id_status = kwargs.get('ports_id_status')
        host = kwargs.get('host')
        LOG.info(_('agent->server, update_portflows_status: chain_id=%s, ports_id_status=%s'), chain_id, ports_id_status)
        servicechain_db.update_portflows_status(context, host, chain_id, ports_id_status)

    def get_instance_classifier_by_host_portid(self, context, **kwargs):
        host = kwargs.get('host')
        port_id = kwargs.get('port_id')
        pfs = servicechain_db.get_instance_classifier_by_host_portid(context, host, port_id)
        LOG.info(_('agent->server, get_instance_classifier_by_host_portid: host=%s, instance_classifier info=%s'), host, pfs)
        return pfs        
        
        
    
class ServiceChainNotifierRpcApiMixin(object):
    """Agent side of the openvswitch rpc API.

    """
    
    def add_port_flows(self, context, flows):
        LOG.debug(_('add_port_flows:%(flows)s'),{'flows':flows})
        self.topic_sc_create = constants.SERVICECHAIN_AGENT_TOPIC
        
        hosts_flows = {}
        if not hosts_flows.has_key(flows['host_id']):
            hosts_flows[flows['host_id']] = []
        hosts_flows[flows['host_id']].append(flows)        
        
        
        for host in hosts_flows:
            LOG.debug(_('add flows to host %(host)s, flows:%(flows)s'),
                      {'host':host, 'flows':hosts_flows[host]})

        topic = topics.get_topic_name(self.topic,
                                      'port_flows',
                                      'add',
                                      flows['host_id'])                                   
        self.cast(context,
                      self.make_msg('add_port_flows',
                                    port_flows=hosts_flows[host]),
                                    topic=topic)
            
            
    def delete_port_flows(self, context, flows):
        LOG.debug(_('delete_port_flows:%(flows)s'),{'flows':flows})
        self.topic_sc_delete = constants.SERVICECHAIN_AGENT_TOPIC

        hosts_flows = {}
        if not hosts_flows.has_key(flows['host_id']):
            hosts_flows[flows['host_id']] = []
        hosts_flows[flows['host_id']].append(flows)     

        for host in hosts_flows:
            LOG.debug(_('add flows to host %(host)s, flows:%(flows)s'),
                      {'host':host, 'flows':hosts_flows[host]})
            
        topic = topics.get_topic_name(self.topic,
                                      'port_flows',
                                      'delete',
                                      flows['host_id'])                                   
        self.cast(context,
                      self.make_msg('delete_port_flows',
                                    port_flows=hosts_flows[host]),
                                    topic=topic)  
        

    def set_port_type(self, context, ports_info):      
        LOG.debug(_('set_port_type:%(ports_info)s'),{'ports_info':ports_info})
        
        if not ports_info.get('host_id', None):
            return  
                
        self.topic_sc_create = constants.SERVICECHAIN_AGENT_TOPIC
        
        hosts_flows = {}
        if not hosts_flows.has_key(ports_info['host_id']):
            hosts_flows[ports_info['host_id']] = []
        hosts_flows[ports_info['host_id']].append(ports_info)        
        
        
        for host in hosts_flows:
            LOG.debug(_('add flows to host %(host)s, flows:%(flows)s'),
                      {'host':host, 'flows':hosts_flows[host]})

        topic = topics.get_topic_name(self.topic,
                                      'port_type',
                                      'set',
                                      ports_info['host_id'])                                   
        self.cast(context,
                      self.make_msg('set_port_type',
                                    ports_info=hosts_flows[host]),
                                    topic=topic)
            
            
    def clear_port_type(self, context, ports_info):

 
        LOG.debug(_('clear_port_type:%(ports_info)s'),{'ports_info':ports_info})
        
        if not ports_info.get('host_id', None):
            return        
        self.topic_sc_create = constants.SERVICECHAIN_AGENT_TOPIC
        
        hosts_flows = {}
        if not hosts_flows.has_key(ports_info['host_id']):
            hosts_flows[ports_info['host_id']] = []
        hosts_flows[ports_info['host_id']].append(ports_info)        
        
        
        for host in hosts_flows:
            LOG.debug(_('clear_port_type to host %(host)s, flows:%(flows)s'),
                      {'host':host, 'flows':hosts_flows[host]})

        topic = topics.get_topic_name(self.topic,
                                      'port_type',
                                      'clear',
                                      ports_info['host_id'])                                   
        self.cast(context,
                      self.make_msg('clear_port_type',
                                    ports_info=hosts_flows[host]),
                                    topic=topic)                 


        
        
