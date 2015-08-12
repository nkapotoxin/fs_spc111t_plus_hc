#!/usr/bin/env python
# -*- encoding: utf-8 -*-

from nova.openstack.common import log as logging

LOG = logging.getLogger(__name__)


### using in nova-conductot
class ColdMigrationHook(object):

    def pre(self, *args, **kwargs):
        instance = args[2]
        self.instance_uuid = instance.get('uuid')
        LOG.info("cold_migrate.start instance_uuid is %(uuid)s", {"uuid":self.instance_uuid})    

    def post(self, rv, *args, **kwargs):
        LOG.info("cold_migrate.end instance_uuid is %(uuid)s", {"uuid":self.instance_uuid})
 
        
class LiveMigrationHook(object):

    def pre(self, *args, **kwargs):
        instance = args[2]
        self.instance_uuid = instance.get('uuid')
        LOG.info("live_migrate.start instance_uuid is %(uuid)s", {"uuid":self.instance_uuid})
        
    def post(self, rv, *args, **kwargs):
        LOG.info("live_migrate.end instance_uuid is %(uuid)s", {"uuid":self.instance_uuid})

### using in nova-compute 
class ColdMigrationManagerHook(object):

    def pre(self, *args, **kwargs):
        instance = kwargs["instance"]
        self.instance_uuid = instance.get('uuid')
        LOG.info("cold_migrate.start instance_uuid is %(uuid)s", {"uuid":self.instance_uuid})

    def post(self, rv, *args, **kwargs):
        LOG.info("cold_migrate.end instance_uuid is %(uuid)s", {"uuid":self.instance_uuid})


class LiveMigrationManagerHook(object):

    def pre(self, *args, **kwargs):
        instance = kwargs["instance"]
        self.instance_uuid = instance.get('uuid')
        LOG.info("live_migrate.start instance_uuid is %(uuid)s", {"uuid":self.instance_uuid})

    def post(self, rv, *args, **kwargs):
        LOG.info("live_migrate.end instance_uuid is %(uuid)s", {"uuid":self.instance_uuid})

