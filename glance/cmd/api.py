#!/usr/bin/env python

# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# Copyright 2011 OpenStack Foundation
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

"""
Glance API Server
"""

import eventlet
import os
import sys

from glance.common import utils

# Monkey patch socket, time, select, threads
eventlet.patcher.monkey_patch(all=False, socket=True, time=True,
                              select=True, thread=True, os=True)

# If ../glance/__init__.py exists, add ../ to Python search path, so that
# it will override what happens to be installed in /usr/(local/)lib/python...
possible_topdir = os.path.normpath(os.path.join(os.path.abspath(sys.argv[0]),
                                   os.pardir,
                                   os.pardir))
if os.path.exists(os.path.join(possible_topdir, 'glance', '__init__.py')):
    sys.path.insert(0, possible_topdir)

import glance_store
from oslo.config import cfg
import osprofiler.notifier
import osprofiler.web

from glance.common import config
from glance.common import exception
from glance.common import wsgi
from glance import notifier
from glance.openstack.common import log

CONF = cfg.CONF
CONF.import_group("profiler", "glance.common.wsgi")


def fail(returncode, e):
    sys.stderr.write("ERROR: %s\n" % utils.exception_to_str(e))
    sys.exit(returncode)


def main():
    try:
        config.parse_args()
        wsgi.set_eventlet_hub()
        log.setup('glance')

        glance_store.register_opts(config.CONF)
        glance_store.create_stores(config.CONF)
        glance_store.verify_default_store()

        if cfg.CONF.profiler.enabled:
            _notifier = osprofiler.notifier.create("Messaging",
                                                   notifier.messaging, {},
                                                   notifier.get_transport(),
                                                   "glance", "api",
                                                   cfg.CONF.bind_host)
            osprofiler.notifier.set(_notifier)
        else:
            osprofiler.web.disable()

        server = wsgi.Server()
        server.start(config.load_paste_app('glance-api'), default_port=9292)
        server.wait()
    except exception.WorkerCreationFailure as e:
        fail(2, e)
    except RuntimeError as e:
        fail(1, e)


if __name__ == '__main__':
    main()
