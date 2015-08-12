#!/usr/bin/env python
# -*- encoding: utf-8 -*-

from nova.i18n import _
from nova.openstack.common import log as logging

LOG = logging.getLogger(__name__)


class SelectDestinationsHook(object):
    def pre(self, *args, **kwargs):
        request_spec = args[2]
        instance_uuids = request_spec.get('instance_uuids')
        LOG.info(_("select_destinations.start %(num_instances)d instance(s) "
                   "uuids: %(instance_uuids)s"),
                 {'num_instances': len(instance_uuids),
                  'instance_uuids': instance_uuids})
        LOG.debug(_("Request Spec: %s") % request_spec)

    def post(self, rv, *args, **kwargs):
        request_spec = args[2]
        instance_uuids = request_spec.get('instance_uuids')
        LOG.info(_("select_destinations.end %(num_instances)d instance(s) "
                   "uuids: %(instance_uuids)s"),
                 {'num_instances': len(instance_uuids),
                  'instance_uuids': instance_uuids})
