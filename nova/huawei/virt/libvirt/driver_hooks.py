#!/usr/bin/env python
# -*- encoding: utf-8 -*-

import os
import socket
import time
import thread
import threading
import eventlet

from eventlet import patcher
from eventlet import greenio
from eventlet import util as eventlet_util
from oslo.config import cfg
from lxml import etree

from nova import context as nova_context
from nova import exception
from nova import utils
from nova.compute import power_state
from nova.compute import task_states
from nova.compute import vm_states
from nova.virt import event as virtevent
from nova.openstack.common import log as logging
from nova.huawei import utils as hw_utils
from nova.huawei.virt.libvirt.dnt_hook import DntManager
from nova.huawei.openstack.common import alarm

CONF = cfg.CONF

# it is a risk for using 'os_region_name', because it deprecated in DEFAULT
# group in Juno
compute_opts = [
    cfg.StrOpt('os_region_name',
               help='region of compute',
               deprecated_group='DEFAULT',
               deprecated_name='os_region_name')
]
CONF.register_opts(compute_opts)

LOG = logging.getLogger(__name__)

native_threading = patcher.original("threading")
native_Queue = patcher.original("Queue")

uvp_fault_channel = __import__('uvp_fault_chan')

# kernel panic
RTEV_FAULT_KERNEL_PANIC = 0
# watchdog timeout
RTEV_FAULT_WDT_TMOUT = 1
# watchdog pre timeout
RTEV_FAULT_WDT_PRE_TMOUT = 2
# nmi operation finished
RTEV_NMI_OPERATION_FINISHED = 6

SOFT_REBOOT_NMI = 1 << 8
HARD_REBOOT_NMI = 2 << 8
WDT_PRE_TMOUT_NMI = 3 << 8
SOFT_POWER_OFF_NMI = 4 << 8
HARD_POWER_OFF_NMI = 5 << 8


class FaultEvent(virtevent.InstanceEvent):
    def __init__(self, uuid, event_type, event_des, timestamp=None):
        super(FaultEvent, self).__init__(uuid, timestamp)
        self.event_type = event_type
        self.event_des = event_des

    def get_event_type(self):
        return self.event_type

    def get_event_des(self):
        return self.event_des


class NmiUtil(object):
    nmi_lock = thread.allocate_lock()
    nmi_instance_list = list()

    @classmethod
    def add_instance(cls, instance_name):
        NmiUtil.nmi_lock.acquire()
        LOG.info(
            "In add_instance nmi_instance_list is %s"
            % NmiUtil.nmi_instance_list)
        if instance_name in NmiUtil.nmi_instance_list:
            NmiUtil.nmi_lock.release()
            LOG.error(
                "Instance %s already exists in nmi_instance_list"
                % instance_name)
            return False
        else:
            NmiUtil.nmi_instance_list.insert(0, instance_name)
            LOG.info(
                "In add_instance nmi_instance_list is %s"
                % NmiUtil.nmi_instance_list)
            NmiUtil.nmi_lock.release()
            return True

    @classmethod
    def remove_instance(cls, instance_name):
        NmiUtil.nmi_lock.acquire()
        if instance_name in NmiUtil.nmi_instance_list:
            NmiUtil.nmi_instance_list.remove(instance_name)
            NmiUtil.nmi_lock.release()
            return True
        else:
            NmiUtil.nmi_lock.release()
            return False

    @classmethod
    def find_instance(cls, instance_name):
        NmiUtil.nmi_lock.acquire()
        if instance_name in NmiUtil.nmi_instance_list:
            NmiUtil.nmi_lock.release()
            return True
        else:
            NmiUtil.nmi_lock.release()
            return False

    @classmethod
    def inject_nmi(cls, compute_driver, instance, nmi_flag):
        instance_name = instance['name']
        try:
            domain = compute_driver._lookup_by_name(instance_name)
            if CONF.send_nmi_message:
                domain.injectNMI(nmi_flag)
                NmiUtil.wait_for_nmi_operation(instance_name)
        except Exception, msg:
            LOG.error(msg)

    @classmethod
    def wait_for_nmi_operation(cls, instance_name):
        try:
            LOG.debug("waits for nmi operation")
            wait_time = CONF.nmi_max_wait_time
            wait_time *= 2
            LOG.debug("total wait_time is %s" % wait_time)
            NmiUtil.add_instance(instance_name)
            found = True
            while wait_time > 0:
                found = NmiUtil.find_instance(instance_name)
                if not found:
                    LOG.debug("left wait_time is %s" % wait_time)
                    break
                time.sleep(0.5)
                wait_time -= 1
            if found:
                LOG.debug("nmi operation times out")
            NmiUtil.remove_instance(instance_name)
        except Exception, msg:
            LOG.error(msg)


class DriverInitHostHook(object):
    def __init__(self):
        self._compute_driver = None
        self._fault_events_notify_send = None
        self._fault_events_notify_recv = None
        self._fault_events_queue = None
        self._fault_events_handler = None

    def pre(self, *args, **kwargs):
        pass

    def post(self, rv, *args, **kwargs):
        LOG.debug(
            "driver_init_host_hook post: rv= %s, args = %s, kwargs = %s"
            % (rv, args, kwargs))
        self._compute_driver = args[0]
        self._init_fault_events()
        LOG.debug("init the DntManager...")
        dnt_mgr = DntManager(self._compute_driver)
        dnt_mgr.init_thread()

    def _init_fault_events(self):
        """Initializes the libvirt fault events subsystem.

        This requires running a native thread to provide the
        libvirt event loop integration. This forwards events
        to a green thread which does the actual dispatching.
        """
        self._init_fault_events_pipe()

        LOG.debug("Starting native fault event thread")
        fault_event_thread = threading.Thread(
            target=self._native_fault_events_thread)
        fault_event_thread.setDaemon(True)
        fault_event_thread.start()

        LOG.debug("Starting green fault event dispatch thread")
        eventlet.spawn(self._dispatch_fault_events_thread)

        self._register_fault_events_handler(self.handle_fault_event)

    def _init_fault_events_pipe(self):
        """Create a self-pipe for the native thread to synchronize on.

        This code is taken from the eventlet tpool module, under terms
        of the Apache License v2.0."""
        self._fault_events_queue = native_Queue.Queue()
        try:
            rpipe, wpipe = os.pipe()
            self._fault_events_notify_send = greenio.GreenPipe(wpipe, 'wb', 0)
            self._fault_events_notify_recv = greenio.GreenPipe(rpipe, 'rb', 0)
        except (ImportError, NotImplementedError):
            sock = eventlet_util.__original_socket__(socket.AF_INET,
                                                     socket.SOCK_STREAM)
            sock.bind(('localhost', 0))
            sock.listen(50)
            csock = eventlet_util.__original_socket__(socket.AF_INET,
                                                      socket.SOCK_STREAM)
            csock.connect(('localhost', sock.getsockname()[1]))
            nsock, addr = sock.accept()
            self._fault_events_notify_send = nsock.makefile('wb', 0)
            gsock = greenio.GreenSocket(csock)
            self._fault_events_notify_recv = gsock.makefile('rb', 0)

    def _native_fault_events_thread(self):
        """Receives fault events coming in from libvirtd."""
        try:
            while True:
                self._receive_fault_events()
        except Exception, msg:
            LOG.error(msg)

    def _receive_fault_events(self):
        """Starts a socket server to receive fault events."""
        fault_channel = uvp_fault_channel.virFaultChannel()
        fault_channel_inited = False
        while not fault_channel_inited:
            result = fault_channel.faultChanInit()
            if 0 == result:
                LOG.debug("faultChanInit called success")
                fault_channel_inited = True
            else:
                LOG.error("faultChanInit called failed: %s" % result)
                time.sleep(1)
        while True:
            result, fault_info = fault_channel.faultInfoRcv()
            LOG.debug("faultInfoRcv called: "
                      "result is %(result)s, fault_info is %(fault_info)s"
                      % locals())
            if -1 == result:
                LOG.error("faultInfoRcv called failed")
                time.sleep(1)
                continue
            else:
                instance_uuid = fault_info.uuid
                event_type = fault_info.type
                description = fault_info.des
                LOG.debug(
                    "instance uuid is %(instance_uuid)s, fault event type is "
                    "%(event_type)s, description is %(description)s"
                    % locals())
                self._write_fault_event_to_queue(instance_uuid, event_type,
                                                 description)

    def _write_fault_event_to_queue(self, instance_uuid, event_type,
                                    description):
        if instance_uuid is not None:
            self._queue_fault_event(
                FaultEvent(instance_uuid, event_type, description))

    def _queue_fault_event(self, event):
        """Puts an fault event on the queue for dispatch.

        This method is called by the native thread to
        put events on the queue for later dispatch by the
        green thread."""
        if self._fault_events_queue is None:
            LOG.debug("Event loop thread is not active, "
                      "discarding event %s" % event)
            return

        # queue the event...
        self._fault_events_queue.put(event)

        # ...then wake up the green thread to dispatch it
        c = ' '.encode()
        self._fault_events_notify_send.write(c)
        self._fault_events_notify_send.flush()

    def _dispatch_fault_events_thread(self):
        """Dispatches fault events coming in from libvirtd.

        This is a green thread which waits for events to
        arrive from the libvirt event loop thread."""
        while True:
            self._dispatch_fault_events()

    def _dispatch_fault_events(self):
        """Wait for & dispatch fault events from native thread.

        Blocks until native thread indicates some events
        are ready. Then dispatches all queued events."""
        try:
            _c = self._fault_events_notify_recv.read(1)
            assert _c
        except ValueError:
            return
        while not self._fault_events_queue.empty():
            try:
                event = self._fault_events_queue.get(block=False)
                self._emit_fault_event(event)
            except native_Queue.Empty:
                pass

    def _emit_fault_event(self, event):
        """Emits a fault event from the queue."""
        if not self._fault_events_handler:
            LOG.debug("Discard fault event %s" % event)
            return
        try:
            self._fault_events_handler(event)
        except Exception, msg:
            LOG.error(msg)

    def _register_fault_events_handler(self, callback):
        self._fault_events_handler = callback

    def handle_fault_event(self, event):
        """Handles instance fault event"""
        instance_uuid = event.uuid
        event_type = event.event_type

        context = nova_context.get_admin_context()
        try:
            instance = self._instance_get_by_uuid(context, instance_uuid)
        except Exception, msg:
            LOG.error("Instance not found by uuid %s, detail: %s"
                      % (instance_uuid, msg))
            return

        task_state = instance.get('task_state')
        if task_state == task_states.POWERING_OFF:
            LOG.debug("The instance is powering-off, skip")
            return

        if task_state == task_states.RESIZE_MIGRATING:
            LOG.debug("The instance is resize-migrating, skip")
            return

        vm_state = instance.get('vm_state')
        if task_state == task_states.MIGRATING and \
                vm_state == vm_states.ACTIVE:
            LOG.debug("The instance is migrating, skip")
            return

        # send watchdog timeout event and kernel panic event to alarm channel
        # NOTE: before watchdog timeout event, there would be watchdog pre
        # timeout event, don't need to send alarm in this case
        if event_type != RTEV_FAULT_WDT_PRE_TMOUT:
            alarm.send_alarm(10101, 'compute', instance_uuid,
                             '%s;%s;%s' % (instance_uuid,
                                           CONF.os_region_name,
                                           instance['project_id']),
                             level=1,
                             addition='Guest_OS_Error')

        if event_type == RTEV_FAULT_KERNEL_PANIC and \
                not CONF.instance_panic_reboot:
            LOG.debug("The event type is %s, "
                      "the CONF.instance_panic_reboot is %s"
                      % (event_type, CONF.instance_panic_reboot))
            return

        if event_type == RTEV_FAULT_WDT_PRE_TMOUT:
            try:
                domain = self._compute_driver._lookup_by_name(instance['name'])
                if CONF.send_nmi_message:
                    domain.injectNMI(WDT_PRE_TMOUT_NMI)
            except Exception, msg:
                LOG.error(msg)
        elif event_type == RTEV_FAULT_WDT_TMOUT or \
                event_type == RTEV_FAULT_KERNEL_PANIC:
            try:
                self._hard_reboot_instance(context, instance)
            except Exception, msg:
                LOG.error(msg)
        elif event_type == RTEV_NMI_OPERATION_FINISHED:
            NmiUtil.remove_instance(instance['name'])
        else:
            LOG.debug("fault event type is unknown")

    def _instance_get_by_uuid(self, context, instance_uuid):
        return self._compute_driver.virtapi.instance_get_by_uuid(context,
                                                                 instance_uuid)

    def _hard_reboot_instance(self, context, instance):
        LOG.info("hard reboot instance %s" % instance['uuid'])
        network_info = self._compute_driver.virtapi.get_instance_nw_info(
            context, instance)
        block_device_info = self._compute_driver.virtapi. \
            get_instance_block_device_info(context, instance)
        try:
            self._compute_driver._hard_reboot(context, instance, network_info,
                                              block_device_info)
        except Exception, msg:
            LOG.error(msg)

    def _get_power_state(self, instance):
        try:
            return self._compute_driver.get_info(instance)["state"]
        except exception.NotFound:
            return power_state.NOSTATE

    def _instance_update(self, context, instance_uuid, **kwargs):
        self._compute_driver.virtapi.instance_update(context, instance_uuid,
                                                     **kwargs)


class SoftRebootHook(object):
    def __init__(self):
        self._compute_driver = None

    def pre(self, *args, **kwargs):
        LOG.debug("soft_reboot_hook pre: args = %s, kwargs = %s"
                  % (args, kwargs))
        self._compute_driver = args[0]
        instance = args[1]
        NmiUtil.inject_nmi(self._compute_driver, instance, SOFT_REBOOT_NMI)

    def post(self, rv, *args, **kwargs):
        pass


class HardRebootHook(object):
    def __init__(self):
        self._compute_driver = None

    def pre(self, *args, **kwargs):
        LOG.debug("hard_reboot_hook pre: args = %s, kwargs = %s"
                  % (args, kwargs))
        self._compute_driver = args[0]
        instance = args[2]
        NmiUtil.inject_nmi(self._compute_driver, instance, HARD_REBOOT_NMI)

    def post(self, rv, *args, **kwargs):
        pass


class PowerOffHook(object):
    def __init__(self):
        self._compute_driver = None

    def pre(self, *args, **kwargs):
        LOG.debug("power_off_hook pre: args = %s, kwargs = %s"
                  % (args, kwargs))
        self._compute_driver = args[0]
        instance = args[1]
        if len(args) > 2:
            timeout = args[2]
        else:
            timeout = kwargs.get('timeout', 0)
        if timeout:
            power_off_nmi = SOFT_POWER_OFF_NMI
        else:
            power_off_nmi = HARD_POWER_OFF_NMI
        NmiUtil.inject_nmi(self._compute_driver, instance, power_off_nmi)

    def post(self, rv, *args, **kwargs):
        pass


class UndefineDomainHook(object):
    def pre(self, *args, **kwargs):
        LOG.debug("undefine_domain_hook pre: args = %s, kwargs = %s"
                  % (args, kwargs))
        instance = args[1]
        self._delete_instance_kbox(instance)

    def post(self, rv, *args, **kwargs):
        pass

    def _delete_instance_kbox(self, instance):
        if CONF.use_kbox:
            try:
                utils.execute('rm', '-rf',
                              '/dev/shm/ramkbox_%s' % instance['uuid'],
                              run_as_root=True)
            except Exception, msg:
                LOG.debug("rm /dev/shm/ failed: %s", msg)
            if CONF.use_nonvolatile_ram:
                try:
                    utils.execute('kboxram-ctl', 'delete', instance['name'],
                                  run_as_root=True)
                except Exception, msg:
                    LOG.debug("kboxram-ctl delete failed: %s", msg)


class AttachInterfaceHook(object):
    def __init__(self):
        self._compute_driver = None

    def pre(self, *args, **kwargs):
        pass

    def post(self, rv, *args, **kwargs):
        LOG.debug(
            "attach_interface_hook post: rv = %s, args = %s, kwargs = %s"
            % (rv, args, kwargs))
        self._compute_driver = args[0]
        instance = args[1]
        self._update_boot_option(instance)

    def _update_boot_option(self, instance):
        try:
            domain = self._compute_driver._lookup_by_name(instance['name'])
        except exception.NotFound:
            LOG.error(
                "instance %s disappeared while update boot option"
                % instance['uuid'])
            return
        xml = domain.XMLDesc(0)
        root = etree.fromstring(xml)
        metadata = instance.get('metadata', None)
        if metadata is None:
            self._compute_driver.disable_boot_order_options(root, domain)
            self._compute_driver.set_default_boot_order(root, domain)
            return
        boot_option = None
        if isinstance(metadata, dict):
            boot_option = metadata.get('__bootDev', None)
        else:
            for item in metadata:
                if item['key'] == '__bootDev':
                    boot_option = item['value']
                    break
        if boot_option is None:
            self._compute_driver.disable_boot_order_options(root, domain)
            self._compute_driver.set_default_boot_order(root, domain)
            return
        if not hw_utils.is_valid_boot_option(boot_option):
            return
        boot_option_list = boot_option.split(',')
        self._compute_driver.disable_boot_order_options(root, domain)
        self._compute_driver.update_boot_order_option(root, domain,
                                                      boot_option_list)
