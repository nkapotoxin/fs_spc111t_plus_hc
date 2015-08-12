# Copyright 2013 ngfw Networks Inc.
# All Rights Reserved.
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

from neutron.openstack.common import log as logging
from neutron.services.firewall.agents.ngfw import ngfw_api
from neutron.services.firewall.agents.ngfw import ngfw_utils
from neutron.services.firewall import ngfw_plugin
from neutron.services.firewall.drivers import fwaas_base
from neutron.extensions import firewall as fw_ext
from oslo.config import cfg
import ConfigParser
import hashlib
import json

LOG = logging.getLogger(__name__)

RULE_NAME_KEY_BEGIN='<static-rule><name>'
RULE_NAME_KEY_END='</name>'


class ngfwFwaasDriver(fwaas_base.FwaasDriverBase):
    def __init__(self):
        LOG.debug(_("Initializing fwaas ngfw driver"))

        self.rest = ngfw_api.ngfwRestAPI()
        self.agent = ngfw_plugin.NGFWAgentUtils()           
        self.plugutil = ngfw_plugin.NGFWPluginUtils()
        self.addr_set_cache = {}
        self.addr_set_cache_init()
        self.director_for_acl = self._get_director_for_acl()
        self.rule_failed_rollback = cfg.CONF.ngfw.rule_failed_rollback
                
    def create_firewall(self, agent_mode, apply_list, firewall):
        LOG.debug(_('ngfw create_firewall (%s)'), firewall)

        firewall['created'] = True
        exec_result = self.update_firewall(agent_mode, apply_list, firewall)
        if not exec_result:
            LOG.error(_('create_firewall raise FirewallInternalDriverError'))
            raise fw_ext.FirewallInternalDriverError()
        
        return exec_result        

    def update_firewall(self, agent_mode, apply_list, firewall):
        LOG.debug(_("ngfw update_firewall (%s)"), firewall)
            
        if firewall['admin_state_up']:
            exec_result = self._update_firewall(apply_list, firewall)
        else:
            exec_result = self.apply_default_policy(agent_mode, apply_list, firewall)

        if not exec_result:
            LOG.error(_('update_firewall raise FirewallInternalDriverError'))
            raise fw_ext.FirewallInternalDriverError()
        
        return exec_result        
        
    def delete_firewall(self, agent_mode, apply_list, firewall):
        LOG.debug(_("ngfw delete_firewall (%s)"), firewall)

        firewall['deleted'] = True
        exec_result = self.apply_default_policy(agent_mode, apply_list, firewall)
        if not exec_result:
            LOG.error(_('delete_firewall raise FirewallInternalDriverError'))
            raise fw_ext.FirewallInternalDriverError()
        
        return exec_result        
        
    def apply_default_policy(self, agent_mode, apply_list, firewall):
        LOG.debug(_("apply_default_policy:%s" % firewall))

        for ri in apply_list:
            result = self._clear_policy(ri, firewall)
            if result == False:
                return result
            
        return True

    def _update_firewall(self, apply_list, firewall):
        LOG.debug(_("Updating firewall (%s)"), firewall)

        for ri in apply_list:
            result = self._clear_policy(ri, firewall)
            if result == False:
                return result
            result = self._setup_policy(ri, firewall)
            if result == False:
                if self.rule_failed_rollback == True:
                    self._clear_policy(ri, firewall, roll_back=True)
                return result
            
        return True

    def _whether_monopolism_traffic_policy_rule(self, rule):
        LOG.debug(_("check if the rule is a monopolism traffic policy rule: %s"), rule)
        label = self.traffic_policy_name_hash(rule['name'])
        return self.plugutil.check_whether_my_label(label)

    def traffic_policy_name_hash(self, policy_name):
        if policy_name:
            return 0
        num = int(hashlib.sha224(policy_name).hexdigest()[:4], base=16)
        return num % cfg.CONF.ngfw.ngfw_agent_count

    def _whether_my_firewall_rule(self, rule):
        LOG.info(_("firewall rule is: %s" % rule))
        if rule.has_key("destination_ip_address"):
            result = self.plugutil._check_ip_in_ip_pool(rule['destination_ip_address'], self.agent.fip_slb_ip_pool)
            if result:
                LOG.info(_("the rule belong the agent."))
                return True

        if rule.has_key("source_ip_address"):
            result = self.plugutil._check_ip_in_ip_pool(rule['source_ip_address'], self.agent.fip_slb_ip_pool)
            if result:
                LOG.info(_("the rule belong the agent."))
                return True            
        
        return False

    def _is_monopolism_traffic_policy(self, rule):
        LOG.info(_("check the traffic policy is monopolism or not"))
        if rule.has_key('mode') and rule['mode'] == 'profile':
            if not rule.get('source_ip_address') and not rule.get('destination_ip_address'):
                return True
        return False

    def _is_shared_traffic_policy(self, rule):
        LOG.info(_("check the traffic policy is shared or not"))
        if rule.has_key('mode') and rule['mode'] == 'profile':
            if rule.get('source_ip_address') or rule.get('destination_ip_address'):
                return True
        return False

    def _setup_policy(self, ri, fw):
        result = True
        is_profile = False
        for rule in fw['firewall_rule_list']:
            if rule.get('mode', None) and rule['mode'].lower() == 'profile':
                is_profile = True
            break

        if is_profile:
            list_to_insert, list_to_remove = self._get_rule_list_to_update(fw)
            for rule in list_to_insert:
                if not rule['enabled']:
                    continue
                if self._whether_my_firewall_rule(rule):
                    result = self._make_shared_traffic_policy(rule)
                    if not result:
                        return False
                elif self._is_monopolism_traffic_policy(rule):
                    result = self._make_monopolism_traffic_policy(rule)
                    if not result:
                        return False
                else:
                    LOG.debug(_('the traffic profile rule do not belong to me'))
        else:
            cnt = 0
            body = ""
            for rule in fw['firewall_rule_list']:
                if not rule['enabled']:
                    continue

                if rule['ip_version'] == 4:
                    if self._whether_my_firewall_rule(rule):
                        cnt = cnt + 1
                        if cnt == 1:
                            body = "<sec-policy><static-policy>"
                        if cfg.CONF.ngfw.acl_separate_name:
                            target_rule = cfg.CONF.ngfw.acl_separate_name
                        else:
                            target_rule = None
                        bodyinfo = ngfw_utils.get_security_policy_body(ri, fw, rule, target_rule)
                        body = body + bodyinfo
                        if cnt == ngfw_utils.NGFW_MAX_OBJ_CNT:
                            cnt = 0
                            body = body + "</static-policy></sec-policy>"
                            response = self.rest.rest_api('PUT', ngfw_utils.NGFW_URL_POLICY_SECURITY, body, device_ip=self.director_for_acl)
                            if response['status'] >= 400:
                                LOG.error(_('_make_policy failed (%s) (%s)'), fw['id'], body)
                                return False
                            LOG.debug(_('_make_policy success (%s) (%s)'), fw['id'], body)
                else:
                    LOG.warn(_("Unsupported IP version rule."))

            if cnt != 0:
                body = body + "</static-policy></sec-policy>"
                response = self.rest.rest_api('PUT', ngfw_utils.NGFW_URL_POLICY_SECURITY, body, device_ip=self.director_for_acl)
                if response['status'] >= 400:
                    LOG.error(_('_make_policy failed (%s) (%s)'), fw['id'], body)
                    return False
                LOG.debug(_('_make_policy success (%s) (%s)'), fw['id'], body)
        return result
    

    def _get_security_policy_list(self):
        policy_security_str = ''
        result = True
        response = self.rest.rest_api('GET', ngfw_utils.NGFW_URL_POLICY_SECURITY)
        if response['status'] >= 200 and response['status'] < 300:
            policy_security_str = response['body']
        else:
            LOG.error(_('_get_security_policy_list error (%s)'), response['status'])
            result = False

        return result, policy_security_str


    def _delete_security_policy_rule(self, rule_name_list):
        if not rule_name_list:
            return True
        result = False
        body = "<sec-policy><static-policy>"
        for name in rule_name_list:
            static_rule = ngfw_utils.get_security_policy_rule(name)
            body = body + static_rule
        body = body + "</static-policy></sec-policy>"
        LOG.debug(_('_clear_policy body (%s)'), body)
        response = self.rest.rest_api('DELETE', ngfw_utils.NGFW_URL_POLICY_SECURITY, body, device_ip=self.director_for_acl)
        error_message = 'The specified rule does not exist yet'
        if response['status'] == 400 and error_message in response['body']:
            result = True
        if response['status'] >= 200 and response['status'] < 300:
            result = True
            
        return result

    def _delete_shared_traffic_policy_rule(self, firewall_rule):
        addr_set_name, ip_addr = self._get_addr_set_and_ip_from_firewall_rule(firewall_rule)
        if (addr_set_name, ip_addr) != (None, None):
            return self.del_addr_set_api(addr_set_name, ip_addr)
        return False

    def _get_addr_set_and_ip_from_firewall_rule(self, firewall_rule):
        if firewall_rule.has_key('mode') and firewall_rule['mode'] == 'profile':
            ip_addr = None
            if firewall_rule['source_ip_address']:
                ip_addr = firewall_rule['source_ip_address']
            if firewall_rule['destination_ip_address']:
                ip_addr = firewall_rule['destination_ip_address']
            try:
                rule_profile = json.loads(firewall_rule['rule_profile'])
            except:
                LOG.error(_('get addr set and ip from firewall rule error,parse json failed'))
                return None, None
            if not rule_profile.get('traffic-policy'):
                LOG.debug(_('traffic policy rule profile is illegal'))
                return None, None
            if not self._check_traffic_policy_rule_add('traffic-policy', rule_profile):
                return None, None
            if not rule_profile['traffic-policy']['add-body'].get('rule'):
                LOG.debug(_('rule profile %s is illegal, add-body has no rule'))
                return None, None
            if not rule_profile['traffic-policy']['add-body']['rule'].get('name'):
                LOG.debug(_('rule profile %s is illegal, rule has no name'))
                return None, None
            traffic_policy_name = rule_profile['traffic-policy']['add-body']['rule']['name']
            addr_set_name = 'addr_set_' + traffic_policy_name
            return addr_set_name, ip_addr
        return None, None

    def _delete_monopolism_traffic_policy_rule(self, firewall_rule):
        if not firewall_rule.get('rule_profile'):
            LOG.debug(_('delete traffic policy: firewall_rule %s have no rule_profile'), firewall_rule['id'])
            return False
        try:
            rule_profile = json.loads(firewall_rule['rule_profile'])
        except:
            LOG.debug(_('delete traffic policy, json data is illegal'))
            return True
        if rule_profile.get('traffic-policy'):
            if not self._check_traffic_policy_rule_del('traffic-policy', rule_profile):
                return False
            bodyinfo = ngfw_utils.xmldumps(rule_profile.get('traffic-policy').get('del-body'))
            bodyinfo = ngfw_utils.build_traffic_policy("traffic-policy", bodyinfo)
            response = self.rest.rest_api('DELETE', ngfw_utils.NGFW_URL_TRAFFIC_POLICY, bodyinfo)
            if response['status'] > 400:
                LOG.error(_('delete traffic policy failed (%s)'), bodyinfo)
                return False
            LOG.debug(_('delete traffic policy success (%s)'), bodyinfo)
        elif rule_profile.get('time-range'):
            if not self._check_traffic_policy_rule_del('time-range', rule_profile):
                return False
            bodyinfo = ngfw_utils.xmldumps(rule_profile.get('time-range').get('del-body'))
            bodyinfo = ngfw_utils.build_traffic_policy("time-range", bodyinfo)
            response = self.rest.rest_api('DELETE', ngfw_utils.NGFW_URL_TRAFFIC_POLICY_TIME_RANGE, bodyinfo)
            if response['status'] > 400:
                LOG.error(_('create/update traffic policy time range failed (%s)'), bodyinfo)
                return False
            LOG.debug(_('create/update traffic policy time range success (%s)'), bodyinfo)
        elif rule_profile.get('addr-set'):
            if not self._check_traffic_policy_rule_del('addr-set', rule_profile):
                return False
            bodyinfo = ngfw_utils.xmldumps(rule_profile.get('addr-set').get('del-body'))
            bodyinfo = ngfw_utils.build_traffic_policy("address-set", bodyinfo)
            response = self.rest.rest_api('DELETE', ngfw_utils.NGFW_URL_TRAFFIC_POLICY_ADDR_SET, bodyinfo)
            if response['status'] > 400:
                LOG.error(_('create/update traffic policy address set failed (%s)'), bodyinfo)
                return False
            LOG.debug(_('create/update traffic policy address set success (%s)'), bodyinfo)

        return True

    def _get_rule_list_to_update(self, fw):
        list_to_insert = []
        list_to_remove = []
        if fw.get('created'):
            list_to_insert = fw['firewall_rule_list']
            return list_to_insert, list_to_remove
        if not fw.get('delete-rule-list'):
            if fw.get('deleted', None):
                list_to_remove = fw['firewall_rule_list']
                return list_to_insert, list_to_remove
            else:
                list_to_insert = fw['firewall_rule_list']
                return list_to_insert, list_to_remove
        else:
            delete_rule_list = fw['delete-rule-list']
            firewall_rule_list = fw['firewall_rule_list']
            for r1 in firewall_rule_list:
                flag = True
                for r2 in delete_rule_list:
                    if r1['id'] == r2['id']:
                        if self._is_rule_the_same(r1, r2):
                            flag = False
                        else:
                            flag = True
                        break
                if flag:
                    list_to_insert.append(r1)
            for r1 in delete_rule_list:
                flag = True
                for r2 in firewall_rule_list:
                    if r1['id'] == r2['id']:
                        if self._is_rule_the_same(r1, r2):
                            flag = False
                        else:
                            flag = True
                        break
                if flag:
                    list_to_remove.append(r1)
            LOG.debug(_('list_to_insert: %s , list_to_remove: 2 %s'), list_to_insert, list_to_remove)
            return list_to_insert, list_to_remove

    def _is_rule_the_same(self, r1, r2):
        property_list = ['destination_ip_address', 'enabled', 'mode', 'rule_profile', 'source_ip_address']
        for property in property_list:
            if r1[property] != r2[property]:
                LOG.debug(_('rule1: %s , rule2: %s, different property: %s'), r1, r2, property)
                return False
        return True


    def _clear_traffic_policy(self, fw):
        list_to_insert, list_to_remove = self._get_rule_list_to_update(fw)
        for delete_rule in list_to_remove:
            if self._is_monopolism_traffic_policy(delete_rule):
                if not self._delete_monopolism_traffic_policy_rule(delete_rule):
                    return False
            elif self._is_shared_traffic_policy(delete_rule):
                if not self._delete_shared_traffic_policy_rule(delete_rule):
                    return False
        return True

    def _clear_security_policy(self, ri, fw):
        result = True
        if fw.get('created'):
            return True
        if not fw.get('delete-rule-list'):
            if fw.get('deleted', None):
                delete_rule_list = fw['firewall_rule_list']
            else:
                return True
        else:
            delete_rule_list = fw['delete-rule-list']
        rule_name_list = []
        cnt = 0
        for delete_rule in delete_rule_list:
            rule_name = ngfw_utils.get_firewall_policy_name(ri, fw, delete_rule)
            rule_name_list.append(rule_name)
            cnt = cnt + 1
            if cnt == ngfw_utils.NGFW_MAX_OBJ_CNT:
                result = self._delete_security_policy_rule(rule_name_list)
                if result == False:
                    LOG.error(_('_clear_policy failed (%s) (%s)'), fw['id'], rule_name_list)
                    return result
                cnt = 0
                rule_name_list = []
        if rule_name_list != []:
            result = self._delete_security_policy_rule(rule_name_list)
        if result == False:
            LOG.error(_('_clear_policy failed (%s) (%s)'), fw['id'], rule_name_list)
            return result
        LOG.debug(_('_clear_policy success (%s) (%s)'), fw['id'], rule_name_list)
        return True


    def _clear_policy(self, ri, fw, roll_back=False):
        result = True
        is_profile = False
        firewall_rule_list = fw['firewall_rule_list']
        if firewall_rule_list:
            for rule in firewall_rule_list:
                if rule.get('mode', None) and rule['mode'].lower() == 'profile':
                    is_profile = True
                break
        else:
            if not fw.get('delete-rule-list'):
                return True
            else:
                for rule in fw['delete-rule-list']:
                    if rule.get('mode', None) and rule['mode'].lower() == 'profile':
                        is_profile = True
                    break

        if not is_profile:
            result = self._clear_security_policy(ri, fw)
            if not result:
                return False
            if roll_back:
                return True
        else:
            result = self._clear_traffic_policy(fw)
            if not result:
                return False
        return True

    def _make_policy(self, ri, fw, rule):
        if cfg.CONF.ngfw.acl_separate_name:
            target_rule = cfg.CONF.ngfw.acl_separate_name
        else:
            target_rule = None
        bodyinfo = ngfw_utils.get_security_policy(ri, fw, rule, target_rule)
        LOG.debug(_('_make_policy body (%s) (%s)'), rule, bodyinfo)
        response = self.rest.rest_api('PUT', ngfw_utils.NGFW_URL_POLICY_SECURITY, bodyinfo, device_ip=self.director_for_acl)
        if response['status'] >= 400:
            LOG.error(_('_make_policy failed (%s) (%s)'), fw['id'], rule)
            self._clear_policy(ri, fw)
            return False
        LOG.debug(_('_make_policy success (%s) (%s)'), fw['id'], rule)
        return True

    def _make_shared_traffic_policy(self, rule):
        result = self._put_shared_traffic_policy(rule)
        LOG.debug(_('put shared traffic policy rule (%s)'), rule)
        return result

    def _make_monopolism_traffic_policy(self, rule):
        result = self._put_monopolism_traffic_policy(rule)
        LOG.debug(_('put monopolism traffic policy rule (%s)'), rule)
        return result

    def _check_traffic_policy_rule_add(self, key, rule_profile):
        if not rule_profile.get(key).get('add-body'):
            LOG.debug(_('rule profile %s is illegal, no add-body'), key)
            return False
        return True

    def _check_traffic_policy_rule_del(self, key, rule_profile):
        if not rule_profile.get(key).get('del-body'):
            LOG.debug(_('rule profile %s is illegal, no del-body'), key)
            return False
        return True

    def _put_shared_traffic_policy(self, rule):
        addr_set_name, ip_addr = self._get_addr_set_and_ip_from_firewall_rule(rule)
        if (addr_set_name, ip_addr) != (None, None):
            return self.update_addr_set_api(addr_set_name, ip_addr)
        return False

    def _put_monopolism_traffic_policy(self, rule):
        if not rule.get('rule_profile'):
            LOG.debug(_('put traffic policy: firewall_rule %s have no rule_profile'), rule['id'])
            return False
        try:
            rule_profile = json.loads(rule["rule_profile"] )
        except:
            LOG.error(_('put monopolism traffic policy error, parse json failed'))
            return False
        if rule_profile.get('traffic-policy'):
            if not self._check_traffic_policy_rule_add('traffic-policy', rule_profile):
                return False
            bodyinfo = ngfw_utils.xmldumps(rule_profile.get('traffic-policy').get('add-body'))
            bodyinfo = ngfw_utils.build_traffic_policy("traffic-policy", bodyinfo)
            response = self.rest.rest_api('PUT', ngfw_utils.NGFW_URL_TRAFFIC_POLICY, bodyinfo)
            if response['status'] >= 400:
                LOG.error(_('create/update traffic policy failed (%s)'), bodyinfo)
                return False
            LOG.debug(_('create/update traffic policy success (%s)'), bodyinfo)
        elif rule_profile.get('time-range'):
            if not self._check_traffic_policy_rule_add('time-range', rule_profile):
                return False
            bodyinfo = ngfw_utils.xmldumps(rule_profile.get('time-range').get('add-body'))
            bodyinfo = ngfw_utils.build_traffic_policy("time-range", bodyinfo)
            response = self.rest.rest_api('PUT', ngfw_utils.NGFW_URL_TRAFFIC_POLICY_TIME_RANGE, bodyinfo)
            if response['status'] >= 400:
                LOG.error(_('create/update traffic policy time range failed (%s)'), bodyinfo)
                return False
            LOG.debug(_('create/update traffic policy time range success (%s)'), bodyinfo)
        elif rule_profile.get('addr-set'):
            if not self._check_traffic_policy_rule_add('addr-set', rule_profile):
                return False
            bodyinfo = ngfw_utils.xmldumps(rule_profile.get('addr-set').get('add-body'))
            bodyinfo = ngfw_utils.build_traffic_policy("address-set", bodyinfo)
            response = self.rest.rest_api('PUT', ngfw_utils.NGFW_URL_TRAFFIC_POLICY_ADDR_SET, bodyinfo)
            if response['status'] >= 400:
                LOG.error(_('create/update traffic policy address set failed (%s)'), bodyinfo)
                return False
            LOG.debug(_('create/update traffic policy address set success (%s)'), bodyinfo)
        return True

    def addr_set_cache_init(self):
        result = self.get_addr_set_from_ngfw()
        if result:
            self.addr_set_cache = self.get_addr_set_from_ngfw()

    def addr_set_cache_get(self, addr_set_name):
        addr_object_list = self.addr_set_cache.get('addr-object', None)
        if addr_object_list:
            for addr_object in addr_object_list:
                if addr_object['name'] == addr_set_name:
                    return addr_object['elements']
        return None

    def _addr_set_cache_update(self, addr_set_group, ip):
        ele = {}
        addr_obj = {}
        if ip.find('/') == -1:
            ip += '/32'
        addr_object_list = self.addr_set_cache.get('addr-object', None)
        if addr_object_list:
            for addr_object in addr_object_list:
                if addr_object['name'].startswith(addr_set_group):
                    elements = addr_object['elements']
                    for element in elements:
                        if element['address-ipv4'] == ip:
                            ele = element
                            addr_obj['name'] = addr_object['name']
                            addr_obj['elements'] = ele
                            return addr_obj
                    if len(elements) >= cfg.CONF.ngfw.addr_set_capacity:
                        continue
                    else:
                        ele['address-ipv4'] = ip
                        if len(elements) != 0:
                            ele['id'] = int(elements[len(elements)-1]['id']) + 1
                        else:
                            ele['id'] = 0
                        addr_obj['name'] = addr_object['name']
                        addr_obj['elements'] = ele
                        return addr_obj
        return None


    def _addr_set_cache_del(self, addr_set_group, ip):
        addr_obj = {}
        if ip.find('/') == -1:
            ip += '/32'
        addr_object_list = self.addr_set_cache.get('addr-object', None)
        if addr_object_list:
            for addr_object in addr_object_list:
                if addr_object['name'].startswith(addr_set_group):
                    elements = addr_object['elements']
                    for element in elements:
                        if element['address-ipv4'] == ip:
                            ele = element
                            addr_obj['name'] = addr_object['name']
                            addr_obj['elements'] = ele
                            return addr_obj
        return None

    def addr_set_cache_flush(self, address_object, action):
        address_object_list = self.addr_set_cache['addr-object']
        if action == 'update':
            for addr_object in address_object_list:
                if addr_object['name'] == address_object['name']:
                    addr_object['elements'].append(address_object['elements'])
        elif action == 'delete':
            for addr_object in address_object_list:
                if addr_object['name'] == address_object['name']:
                    addr_object['elements'].remove(address_object['elements'])

    def update_addr_set_api(self, addr_set_group, ip):
        address_object = self._addr_set_cache_update(addr_set_group, ip)
        if not address_object:
            LOG.error(_('address set cache update error, no address set found : '
                        'address_set %s'), addr_set_group)
            return False

        bodyinfo = ngfw_utils.get_addr_set(address_object)
        LOG.debug(_('update address_set ,xml body is: %s' % bodyinfo))
        response = self.rest.rest_api('PUT', ngfw_utils.NGFW_URL_ADDR_SET, bodyinfo)
        if response['status'] >= 400:
            LOG.error(_('update address_set failed.'))
            return False
        LOG.debug(_('update address_set success.'))
        self.addr_set_cache_flush(address_object, 'update')
        return True

    def del_addr_set_api(self, addr_set_group, ip):
        address_object = self._addr_set_cache_del(addr_set_group, ip)
        if not address_object:
            LOG.debug(_('addr_set element has been deleted, no address set found : '
                        'address_set %s'), addr_set_group)
            return True

        bodyinfo = ngfw_utils.get_addr_set(address_object)
        LOG.debug(_('delete address_set ,xml body is: %s' % bodyinfo))
        response = self.rest.rest_api('DELETE', ngfw_utils.NGFW_URL_ADDR_SET, bodyinfo)
        if response['status'] > 400:
            LOG.error(_('delete address_set failed.'))
            return False
        LOG.debug(_('delete address_set success.'))
        self.addr_set_cache_flush(address_object, 'delete')
        return True

    def get_addr_set_from_ngfw(self):
        LOG.debug(_('get all address set information from ngfw'))
        response = self.rest.rest_api('GET', ngfw_utils.NGFW_URL_ADDR_SET)
        if response['status'] >= 400:
            LOG.error(_('get address set information from ngfw failed'))
            return None
        LOG.debug(_('get address set information from ngfw success'))

        bodyinfo = response['body']
        if not bodyinfo:
            return None
        address_set = self.analysis_address_set(bodyinfo)
        return address_set

    def analysis_address_set(self, address_set_info):
        address_set = {}
        address_set['addr-object'] = []
        address_set['addr-group'] = []
        bodyinfo = address_set_info
        while bodyinfo:
            index_1 = bodyinfo.find('<addr-object>')
            index_2 = bodyinfo.find('<addr-group>')
            if index_1 == -1 and index_2 == -1:
                break
            if index_1 == -1:
                index = index_2
            elif index_2 == -1:
                index = index_1
            else:
                index = min(index_1, index_2)
            bodyinfo = bodyinfo[index:]
            if bodyinfo.startswith('<addr-object>'):
                addr_object_info = ngfw_utils.get_value_from_xml('addr-object', bodyinfo)
                addr_object = ngfw_utils.analysis_addr_object(addr_object_info)
                address_set['addr-object'].append(addr_object)
                index = bodyinfo.find('</addr-object>')
                bodyinfo = bodyinfo[index+len('</addr-object>'):]
            if bodyinfo.startswith('<addr-group>'):
                addr_group_info = ngfw_utils.get_value_from_xml('addr-group', bodyinfo)
                addr_group = ngfw_utils.analysis_addr_group(addr_group_info)
                address_set['addr-group'].append(addr_group)
                index = bodyinfo.find('</addr-group>')
                bodyinfo = bodyinfo[index+len('</addr-group>'):]
        return address_set

    def _get_director_for_acl(self):
        try:
            director_for_acl = cfg.CONF.ngfw.director_for_acl
            ip_list = director_for_acl.split(',')
        except:
            LOG.error(_('get director ip for acl failed, invalid format'))
            return None
        ip = ip_list[0]
        if self.plugutil.is_ip(ip):
            return ip
        return None


if __name__ == '__main__':
    ngfwDriver = ngfwFwaasDriver()
    result, test = ngfwDriver._get_security_policy_list()
    rule_name_list = ngfw_utils.parse_xml_name(test,
                                               RULE_NAME_KEY_BEGIN, 
                                               RULE_NAME_KEY_END)
    print rule_name_list
