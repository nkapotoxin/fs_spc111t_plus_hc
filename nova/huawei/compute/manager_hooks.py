#!/usr/bin/env python
# -*- encoding: utf-8 -*-

import os

from oslo.config import cfg

from nova import context as nova_context
from nova import utils
from nova.openstack.common import log as logging

CONF = cfg.CONF

LOG = logging.getLogger(__name__)


class ManagerInitHostHook(object):
    def __init__(self):
        self._compute_manager = None

    def pre(self, *args, **kwargs):
        pass

    def post(self, rv, *args, **kwargs):
        LOG.debug(
            "compute_manager_init_host_hook post: "
            "rv = %s, args = %s, kwargs = %s"
            % (rv, args, kwargs))
        self._compute_manager = args[0]
        context = nova_context.get_admin_context()
        if CONF.use_kbox:
            instances = self._instance_get_all_by_host(context,
                                        self._compute_manager.host)
            self._cleanup_invalid_kbox(instances)

    def _instance_get_all_by_host(self, context, host):
        return self._compute_manager.virtapi.instance_get_all_by_host(context,
                                                                      host)

    def _cleanup_invalid_kbox(self, instances):
        kbox_dir = "/dev/shm"
        kbox_list = os.listdir(kbox_dir)
        for kbox in kbox_list:
            kbox_path = os.path.join(kbox_dir, kbox)
            if os.path.isdir(kbox_path):
                continue
            if kbox.find("ramkbox_") != 0:
                continue
            instance_uuid = kbox[8:]
            instance_matched = False
            for instance in instances:
                if instance['uuid'] == instance_uuid:
                    instance_matched = True
                    break
            if not instance_matched:
                try:
                    utils.execute('rm', '-rf', kbox_path, run_as_root=True)
                except Exception, msg:
                    LOG.debug("Revoke ram failed: %s", msg)

        if CONF.use_nonvolatile_ram:
            out, err = utils.execute('kboxram-ctl', 'list', run_as_root=True)
            kbox_list = out.split("\n")
            for kbox in kbox_list:
                kbox = kbox.replace("\n", "").replace("\r", "")
                start = kbox.find("is used by")
                if start != -1:
                    kbox = kbox[start + 11:]
                    instance_matched = False
                    for instance in instances:
                        if instance['name'] == kbox:
                            instance_matched = True
                            break
                    if not instance_matched:
                        try:
                            utils.execute('kboxram-ctl', 'delete', kbox,
                                          run_as_root=True)
                        except Exception, msg:
                            LOG.debug("Revoke nonvolatile ram failed: %s", msg)
