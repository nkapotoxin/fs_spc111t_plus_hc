
import re

from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils
from neutron.openstack.common import jsonutils
from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)

def get_tag_by_port_name(root_helper, port_name):
    args = ['ovs-vsctl', '--format=json', '--', '--columns=tag',
            'list', 'port',
            '%s' %port_name]
    result = utils.execute(args, root_helper=root_helper).strip()
    if not result:
        return
    json_result = jsonutils.loads(result)
    try:
        return json_result['data'][0][0]
    except Exception as e:
        LOG.warn(_("Unable to get_type_port_by_id. Exception: %s"), e)
        return None

def get_mac_by_port_name(root_helper, port_name):
    args = ['ovs-vsctl',  '--', '--columns=external_ids',
            'list', 'interface',
            '%s' %port_name]
    result = utils.execute(args, root_helper=root_helper).strip()
    
    try:
        if result:
            re_port= re.compile('.*attached-mac=(.*?),.*', re.M | re.X)
            match = re_port.search(result).group(1)        
            return match
        else:
            return None
    except Exception as e:
        LOG.warn(_("Unable to get_type_port_by_id. Exception: %s"), e)
        return None
        

def get_type_by_port_name(root_helper, port_name):
    args = ['ovs-vsctl', '--', '--columns=other_config',
            'list', 'port',
            '%s' %port_name]
    result = utils.execute(args, root_helper=root_helper).strip()

    try:
        if result:
            re_port= re.compile('.*sc_type=(.*?),.*', re.M | re.X)
            match = re_port.search(result).group(1)        
            return match
        else:
            return None
    except Exception as e:
        LOG.warn(_("Unable to get_type_port_by_id. Exception: %s"), e)
        return None

def set_sc_port_type(port_name, type, sf_port_id, root_helper):
    args = ['ovs-vsctl', 'set', 'port', '%s' %port_name, "other_config:sc_type=%s" %type,
            "other_config:sf_port_id=%s" %sf_port_id]
    try:
        return utils.execute(args, root_helper=root_helper).strip()
    except Exception as e:
        LOG.error(_("Unable to execute %(cmd)s. Exception: %(exception)s"),
                  {'cmd': args, 'exception': e})
        
def clear_sc_port_type(port_name, type, root_helper):
    args = ['ovs-vsctl', 'set', 'port', '%s' %port_name, "other_config:sc_type=%s" %type]
    try:
        return utils.execute(args, root_helper=root_helper).strip()
    except Exception as e:
        LOG.error(_("Unable to execute %(cmd)s. Exception: %(exception)s"),
                  {'cmd': args, 'exception': e})        


def get_bridge_for_port(root_helper, port_id):
    args = ["ovs-vsctl", "--timeout=2", "port-to-br", port_id]
    try:
        return utils.execute(args, root_helper=root_helper).strip()
    except Exception:
        LOG.exception(_("Interface %s not found."), port_id)
        return None

    
def remove_ip_mac_pair(br_name, ip_addr, root_helper):
    args = ['ovs-vsctl', 'remove', 'bridge','%s' %br_name, 'ip_mac','%s' %ip_addr]
    try:
        return utils.execute(args, root_helper)
    except Exception as e:
        LOG.error(_("Unable to execute %(cmd)s. Exception: %(exception)s"),
                  {'cmd': args, 'exception': e})
        
def set_ip_mac_pair(br_name, ip_addr, mac, root_helper):
    args = ['ovs-vsctl', 'set', 'bridge', '%s' %br_name, "ip_mac:%s=%s" % (ip_addr, mac)]
    try:
        return utils.execute(args, root_helper=root_helper).strip()
    except Exception as e:
        LOG.error(_("Unable to execute %(cmd)s. Exception: %(exception)s"),
                  {'cmd': args, 'exception': e})
    
def is_phy_port(port_name, root_helper):
    args = ['ovs-vsctl', 'list', 'port', '%s' %port_name]
    try:
        out = utils.execute(args, root_helper=root_helper).strip()
        if 2 == len(out.split('port_type=physical')):
            return True
    except Exception as e:
        LOG.error(_("Unable to execute %(cmd)s. Exception: %(exception)s"),
                  {'cmd': args, 'exception': e})
    return False

def get_ofport_by_name(br_name, port_name, root_helper):
    args = ['ovs-ofctl', 'show', '%s' %br_name]
    try:
        out = utils.execute(args, root_helper=root_helper).strip()
        return out.split('(%s)' %port_name)[0].split()[-1]
    except Exception as e:
        LOG.error(_("Unable to execute %(cmd)s. Exception: %(exception)s"),
                  {'cmd': args, 'exception': e})



                
def get_vif_port_by_mac(port_mac, root_helper):
    args = ['ovs-vsctl', '--', '--columns=ofport',
            'find', 'Interface',
            'external_ids:attached-mac="%s"' % port_mac]
    try:
        result=utils.execute(args, root_helper=root_helper).strip()
        if not result:
            return None
        
        re_port= re.compile('ofport\s*:\s(?P<ofport>-?\d+)', re.M | re.X)
        match = re_port.search(result)
        ofport = int(match.group('ofport'))
        return ofport
    
    except Exception as e:
        LOG.info(_("Unable to parse regex results. Exception: %s"), e)
        return None
    

def get_ip_mac_pair(br_name, root_helper):
    args = ['ovs-vsctl', '--', '--columns=ip_mac',
            'list', 'bridge','%s' %br_name]
    try:
        result = utils.execute(args, root_helper=root_helper).strip()
        if not result:
            return None        
        p=r'(?<![\.\d])(?:\d{1,3}\.){3}\d{1,3}(?![\.\d])'
        IP_result = re.findall(p,result)   
        return IP_result      
    except Exception as e:
        LOG.error(_("Unable to execute %(cmd)s. Exception: %(exception)s"),
                  {'cmd': args, 'exception': e})    