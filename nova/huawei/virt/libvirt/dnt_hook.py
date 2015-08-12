# FileName: dnt_hook.py
# Auth:
# Date: 2014-12-24
# Desc: DNT process
import os
import re
import shutil
import six
import commands
import random
import inspect
import threading
import time
import socket
import json
import Queue

from nova import network
from nova import context as nova_context
from nova.api.openstack import common
from nova.openstack.common import log as logging
from nova.virt.libvirt import driver as libvirt_driver
from eventlet import greenio
from eventlet import patcher
from eventlet import util as eventlet_util
from eventlet import greenthread
from lxml import etree

LOG = logging.getLogger(__name__)

MSG_TYPE = 0
queue_size = 10000
recv_path = "/opt/HUAWEI/dnt/bmu.drm.socket"
send_path = "/opt/HUAWEI/dnt/compute.drm.socket"

class Dnt():

    def __init__(self, virt_driver):
        self.driver = virt_driver
        self.network_api = network.API()

    def _get_instance_by_name(self, instance_name):
        """ get instance by instance_name"""
        isExist = False
        domain_name = ""
        domain_namelist = self.driver.list_instances()
        for name in domain_namelist:
            if instance_name == name:
                isExist = True
                domain_name = name
                break

        if not isExist:
            LOG.error("Can not find instance by vmname %s" % instance_name)
            return None

        try:
            uuid = self.driver._lookup_by_name(domain_name).UUIDString()
        except Exception, msg:
            LOG.error("Find domain uuid failed")
            return None

        # get context and instance
        try:
            context = nova_context.get_admin_context()
            instance = self.driver.virtapi.instance_get_by_uuid(context, uuid)
        except Exception, msg:
            LOG.error("Can't find instance by input uuid %s, message is %s"(uuid, msg))
            return None

        return instance

    def get_vnic_by_instance(self, vmname):
        """get vNet by given vmname"""
        isExist = False
        domain_name = ""
        domain_namelist = self.driver.list_instances()
        for name in domain_namelist:
            if vmname == name:
                isExist = True
                domain_name = name
                break;

        if not isExist:
            LOG.error("No vm named %s is finded" % vmname)
            return None

        vNetlist = self._get_vniclist_by_domname(domain_name)
        if not vNetlist:
            LOG.error("No vnets finded by vm %s" % vmname)
            return None

        retMsg = [{"msgType":2, "objType":"vNetPorts",
                   "vNetPorts":[{"vmName":vmname, "displayName":domain_name, "netPorts":vNetlist}]}]
        return retMsg

    def get_guestvnic_by_hostvnic(self, vnet_ports):
        """get guestVnet by given hostVnet"""
        domain_namelist = self.driver.list_instances()
        for domain_name in domain_namelist:
            vNetlist = self._get_vniclist_by_domname(domain_name)
            if not vNetlist:
                continue
            for vNet in vNetlist:
                if vnet_ports.get("type") == "direct":
                    # compare dict pci_slot  {"domain":"0000","bus":"01","slot":"07","function":"4"}
                    if cmp(vnet_ports.get("pci_slot"), vNet.get("pci_slot")) == 0:
                        return [{"msgType":2, "objType":"vNetPorts",
                                 "vNetPorts":[{"vmName":domain_name, "displayName":domain_name, "netPorts":[vNet]}]}]
                else:
                    # skip before 3 chars, it is "tap" or "qvm"
                    if vNet.get("name")[3:] == vnet_ports.get("id")[:11]:
                        return [{"msgType":2, "objType":"vNetPorts",
                            "vNetPorts":[{"vmName":domain_name, "displayName":domain_name, "netPorts":[vNet]}]}]

        return None

    def _get_vniclist_by_domname(self, vmname, vif_type=None):
        try:
            domain = self.driver._lookup_by_name(vmname)
            xml = domain.XMLDesc(0)
            xml = xml.replace("\n", "")
            regex = "> +<"
            xml, number = re.subn(regex, "><", xml)
            doc = etree.fromstring(xml)
        except Exception:
            return []
        pass

        count = 0
        vNetlist = []
        dev = ""
        address = ""
        slot = ""
        list_device_node = doc.findall('devices')
        for device_node in list_device_node:
            list_interface_node = device_node.findall('interface')
            for interface_node in list_interface_node:
                interface_type = interface_node.get('type')
                if vif_type == 'ovs' and interface_type != 'bridge':
                    continue
                if vif_type == 'vhostuser' and interface_type != 'vhostuser':
                    continue

                # get '00:e0:fc:21:a2:ea' in <mac address='00:e0:fc:21:a2:ea'/>
                list_mac_node = interface_node.findall('mac')
                address = list_mac_node[0].get("address")

                # get slot 0x05' in <address type='pci' domain='0x0000'\
                # bus='0x00' slot='0x05' function='0x0'/>
                list_address_node = interface_node.findall('address')
                slot = list_address_node[0].get("slot")

                if interface_type == 'bridge':
                    # get 'tapb468eb13-9e' in <target dev='tapb468eb13-9e'/>
                    list_target_node = interface_node.findall('target')
                    dev = list_target_node[0].get("dev")
                    vNetlist.insert(count, {"guestPortName":slot, "name":dev, "mac":address})
                    count = count + 1
                elif interface_type == 'vhostuser':
                    # get 'tap77409044-0c' in
                    # <source type='unix' path='/var/run/vhost-user/tap77409044-0c' mode='client'/>
                    list_target_node = interface_node.findall('source')
                    dev = list_target_node[0].get("path").split('/')[-1]
                    vNetlist.insert(count, {"guestPortName":slot, "name":dev, "mac":address})
                    count = count + 1
                elif interface_type == "hostdev":
                    # get address in
                    # <source><address type='pci' domain='0x0000' bus='0x01' slot='0x07' function='0x4'/></source>
                    #  get  {"domain":"0000","bus":"01","slot":"07","function":"4"}
                    list_source_node = interface_node.findall('source')
                    list_pci_node = list_source_node[0].findall('address')
                    addr_domain = list_pci_node[0].get("domain")[2:]
                    addr_bus = list_pci_node[0].get("bus")[2:]
                    addr_slot = list_pci_node[0].get("slot")[2:]
                    addr_function = list_pci_node[0].get("function")[2:]
                    vNetlist.insert(count, {"guestPortName": slot,
                        "pci_slot": {"domain": addr_domain, "bus": addr_bus, "slot": addr_slot, "function":addr_function},
                        "mac":address})
                    count = count + 1

        if not vNetlist:
            LOG.error("No vnet in vm %s" % vmname)
            return []
        new_vNetlist = sorted(vNetlist, key=lambda x:x["guestPortName"])
        count = 0
        for net in new_vNetlist:
            net["guestPortName"] = "eth" + str(count)
            count = count + 1
        return new_vNetlist

    ## ovs search
    def get_instance_by_viftype(self, vif_type):
        retMsg = []
        domain_namelist = self.driver.list_instances()
        context = nova_context.get_admin_context()
        for domain_name in domain_namelist:
            try:
                instance_uuid = self.driver._lookup_by_name(domain_name).UUIDString()
                ports = self.network_api.list_ports(context, device_id=instance_uuid)
                port_list = ports['ports']
                for port in port_list:
                    if port['binding:vif_type'] == vif_type:
                        vnet=self._get_vniclist_by_domname(domain_name, vif_type)
                        vnic=[{"vmName":domain_name, "displayName":domain_name, "netPorts":vnet}]
                        msg=[{"msgType":2, "objType":"vNetPorts", "vNetPorts":vnic}]
                        retMsg= retMsg + msg
                        break
            except Exception:
                pass
        if retMsg:
            return retMsg
        return None


class DntSocket(libvirt_driver.LibvirtDriver):
    def __init__(self):
        self._recv_sock = None
        self._send_sock = None

    def dnt_socket_chan_init(self):
        ret = 0
        try:
            self._recv_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            if os.path.exists(recv_path):
                os.unlink(recv_path)
            else:
                recv_path_tmp = os.path.dirname(recv_path)
                if not os.path.exists(recv_path_tmp):
                    os.mkdir(recv_path_tmp)
                    commands.getstatusoutput("sudo chmod g+w " + recv_path_tmp)
            self._recv_sock.bind(recv_path)
        except socket.error, msg:
            LOG.error('Create socket or bind error, msg is %s' % msg)
            ret = -1
        except Exception, msg:
            LOG.error('Init socket error, msg is %s' % msg)
            ret = -1
        return ret

    def dnt_socket_info_rcv(self):
        ret = 0
        try:
            data, newpath = self._recv_sock.recvfrom(1024)
            if not data:
                ret = -1
                LOG.debug('Dnt message is none')
            else:
                LOG.debug('Dnt message is %s' % data)
        except EOFError:
            LOG.error('Receive message occurs EOFError, message is %s' % EOFError)
            ret = -1
        except socket.error, msg:
            LOG.error('Receive msg error, msg is %s' % msg)
            ret = -1
        except Exception as msg:
            LOG.error("Receive msg error, msg is %s" % msg)
            ret = -1
        finally:
            return ret, data

    def dnt_socket_info_send(self, message, event_type=None, retry=True):
        ret = 0
        loop = 0
        try:
            if self._send_sock is None:
                self._send_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            try:
                commands.getstatusoutput("sudo chmod g+w " + send_path)
                self._send_sock.sendto(message, 0, send_path)
            except Exception, msg:
                LOG.error("Send message error, %s" % msg)
                if not retry or "compute.instance.update" == event_type:
                    raise msg
                else:
                    for loop in range(0, 100):
                        if loop < 3:
                            time.sleep(0.2)
                        else:
                            time.sleep(2)
                        try:
                            commands.getstatusoutput("sudo chmod g+w " + send_path)
                            self._send_sock.sendto(message, 0, send_path)
                            ret = 0
                            break
                        except Exception, e:
                            ret = -1
                    if ret == -1:
                        time.sleep(2)
                        commands.getstatusoutput("sudo chmod g+w " + send_path)
                        self._send_sock.sendto(message, 0, send_path)

            LOG.info("Send message successfully(%d), message is %s" % (loop, message))
        except EOFError:
            LOG.error('Send message occurs EOFError, message is %s' % EOFError)
            ret = -1
        except socket.error, msg:
            LOG.error('Send msg error(%d), msg is %s' % (loop, msg))
            ret = -1
        except Exception:
            if "compute.instance.update" == event_type:
                pass
            else:
                LOG.error("Fail to send msg to DRM_C, msg is %s" % message)
            ret = -1
        finally:
            return ret

    def dnt_socket_chan_destroy(self):
        self._recv_sock.close()
        self._send_sock.close()


class DntManager():

    def __init__(self, virt_driver):
        self.driver = virt_driver
        self._msg_queue = Queue.Queue(queue_size)
        self._dnt_socket = DntSocket()

    def init_thread(self):
        self._init_native_thread()

    def _init_native_thread(self):
        LOG.debug ("Starting the native receive thread")
        dnt_receive_thread = threading.Thread(target=self._native_receive_handle)
        dnt_receive_thread.setDaemon(True)
        dnt_receive_thread.start()

        LOG.debug ("Starting dispatch thread")
        dnt_dispatch_thread = threading.Thread(target=self._message_depatch_handle)
        dnt_dispatch_thread.setDaemon(True)
        dnt_dispatch_thread.start()

    def _put_message_to_queue(self, message):
        if message is None:
            LOG.error("The message is None!")
            return
        msg = json.loads(message)
        if ("msgType") in msg and MSG_TYPE != msg["msgType"]:
            LOG.error("msgType is not support, msg is: %s" % msg)
            return
        try:
            self._msg_queue.put(message)
        except Exception, msg:
            LOG.error("Fail to put message, the error is: %s" % msg)

    def _native_receive_handle(self):
        is_init = False
        while True:
            try:
                if is_init == False:
                    ret = self._dnt_socket.dnt_socket_chan_init()
                    if 0 == ret:
                        LOG.debug ("Called dnt_socketChanInit successfully")
                        is_init = True
                    else:
                        LOG.error("Called dnt_socketChanInit error, ret is: %s" % ret)
                        time.sleep(1)
                else:
                    (ret, message) = self._dnt_socket.dnt_socket_info_rcv()
                    if -1 == ret:
                        LOG.debug('Called the dnt_socketInfoRcv function return failed,'
                                  ' the ret is %s' % ret)
                        if message is None:
                            LOG.debug('In init_socket receive message : None')
                        else:
                            LOG.debug ("In init_socket receive message : %s" % message)
                            time.sleep(1)
                            continue
                    else:
                        self._put_message_to_queue(message)
            except Exception, msg:
                LOG.error("Called _native_receive_handle exception, message is: %s" % msg)
                time.sleep(1)

    def _message_depatch_handle(self):
        while True:
            try:
                message = self._msg_queue.get()
                self._emit_to_process(message)
            except Exception, msg:
                LOG.error("Fail to get message, the error is: %s" % msg)

    def _emit_to_process(self, message):
        try:
            LOG.debug("Get the message, %s" % message)
            msg_dispath_thread = threading.Thread(target=self._message_process_handle, kwargs={"msg": message})
            msg_dispath_thread.setDaemon(True)
            msg_dispath_thread.start()
        except Exception, err:
            LOG.error("Fail to _emit_to_dispatch, the error is: %s" % err)

    def _message_process_handle(self, msg):
        """depandon message received, call different methods"""
        LOG.debug("Handle_dnt_socket begins")
        retmsg = None
        message = json.loads(msg)

        if not ("msgType") in message or not ("objType") in message:
            LOG.error("Message must have key msgType and objType, msg is: %s" % message)
            return

        # search vm or vcpu or vnet
        if MSG_TYPE == message["msgType"]:
            if not ("attrType") in message:
                LOG.error("Message must have key attrType, msg is: %s" % message)
                return
            retmsg = self._search_device(message)
            if None == retmsg:
                LOG.error("Input msg is invalid")
                return
            if retmsg:
                for rmsg in retmsg:
                    # if received message has "param", add it into return message
                    if "param" in message:
                        param = message.get("param")
                        rmsg["param"] = param
                    self._dnt_socket.dnt_socket_info_send(json.dumps(rmsg))
            LOG.debug("Handle_dnt_socket end!")
        else:
            LOG.error("MsgType is not valid, only 0 are allowed, msg is: %s" % message)
            return

    def _search_device(self, message):
        """search vm or vcpu or vnet"""
        objType = message["objType"]
        attrType = message["attrType"]
        retmsg = None
        try:
            search_obj = Dnt(self.driver)
            # list vm on given host
            if "VM" == objType and "vGuestNetPort" == attrType and ("vmNames" in message):
                vmname = message["vmNames"]
                retmsg = search_obj.get_vnic_by_instance(vmname)
            elif "vNetPort" == objType and "vGuestNetPort" == attrType and "vNetPorts" in message:
                vNetPorts = message["vNetPorts"]
                retmsg = search_obj.get_guestvnic_by_hostvnic(vNetPorts)
            elif "vGuestNetPort" == attrType and "ovs" == objType:
                retmsg = search_obj.get_instance_by_viftype(objType)
            elif "vGuestNetPort" == attrType and "evs" == objType:
                retmsg = search_obj.get_instance_by_viftype("vhostuser")
            else:
                LOG.error("Input message is not valid, can not match any callback interface")
        except Exception, err:
            LOG.error("Dnt Search error, err is %s " % err)
        LOG.debug("retmsg= %s" %retmsg)
    
        return retmsg
