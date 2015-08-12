# Copyright 2012 VMware, Inc.  All rights reserved.
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

from oslo.config import cfg

from neutron import manager
from neutron.api.rpc.agentnotifiers import l3_rpc_agent_api
from neutron.api.rpc.handlers import l3_rpc
from neutron.common import constants as q_const
from neutron.common import exceptions as n_exc
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.db import common_db_mixin
from neutron.db import extraroute_db
from neutron.db import l3_db
from neutron.db import l3_dvrscheduler_db
from neutron.db import l3_gwmode_db
from neutron.db import l3_hamode_db
from neutron.db import l3_hascheduler_db
from neutron.extensions import l3
from neutron.openstack.common import importutils
from neutron.openstack.common import log as logging
from neutron.openstack.common import uuidutils
from neutron.plugins.common import constants
from neutron.services.l3_router.huawei_l3 import constants as huawei_l3_constants
from neutron.services.l3_router.huawei_l3 import huawei_l3_rpc


LOG = logging.getLogger(__name__)

EXTERNAL_GW_INFO = l3.EXTERNAL_GW_INFO

class StatusIsPending(n_exc.InUse):
    message = _("the status is pending in %(object)s %(id)s, can't %(operate)s now.")

class StatusIsError(n_exc.InUse):
    message = _("the status is error in %(object)s %(id)s, can't %(operate)s now.")

class DuplicateAssociate(n_exc.InUse):
    message = _("the floatingip %(id)s has associated, please disassociate first.")

class HuaweiL3plugin(common_db_mixin.CommonDbMixin,
                     extraroute_db.ExtraRoute_db_mixin,
                     l3_hamode_db.L3_HA_NAT_db_mixin,
                     l3_gwmode_db.L3_NAT_db_mixin,
                     l3_dvrscheduler_db.L3_DVRsch_db_mixin,
                     l3_hascheduler_db.L3_HA_scheduler_db_mixin):


    supported_extension_aliases = ["dvr", "router", "ext-gw-mode",
                                   "extraroute", "l3_agent_scheduler",
                                   "l3-ha"]


    def __init__(self):
        self.setup_rpc()
        self.router_scheduler = importutils.import_object(
            cfg.CONF.router_scheduler_driver)
        self.start_periodic_agent_status_check()
        super(HuaweiL3plugin, self).__init__()

    def setup_rpc(self):
        # RPC support
        self.topic = topics.L3PLUGIN
        self.conn = n_rpc.create_connection(new=True)
        self.agent_notifiers.update(
            {q_const.AGENT_TYPE_L3: l3_rpc_agent_api.L3AgentNotifyAPI()})
        self.endpoints = [l3_rpc.L3RpcCallback(), huawei_l3_rpc.L3RpcCallback()]
        self.conn.create_consumer(self.topic, self.endpoints,
                                  fanout=False)
        self.conn.consume_in_threads()

    def get_plugin_type(self):
        return constants.L3_ROUTER_NAT

    def get_plugin_description(self):
        """returns string description of the plugin."""
        return ("L3 Router Service Plugin for basic L3 forwarding"
                " between (L2) Neutron networks and access to external"
                " networks via a NAT gateway.")

    @property
    def _core_plugin(self):
        return manager.NeutronManager.get_plugin()

    def _create_router_db(self, context, router, tenant_id):
        """Create the DB object."""
        status = router.get('status', '')
        with context.session.begin(subtransactions=True):
            router_db = super(HuaweiL3plugin, self)._create_router_db(context,
                                                                      router,
                                                                      tenant_id)

        router_db = self.update_router_status(context,
                                              router_db['id'],
                                              status)
        return router_db

    def update_router_status(self, context, id, status):
        with context.session.begin(subtransactions=True):
            router_db = self._get_router(context, id)
            if status == huawei_l3_constants.ROUTER_STATUS_DELETED:
                #super(HuaweiL3plugin, self).delete_router(context, id)
                with context.session.begin(subtransactions=True):
                    router = self._ensure_router_not_in_use(context, id)
                    router_ports = router.attached_ports.all()
                    # Set the router's gw_port to None to avoid a constraint violation.
                    router.gw_port = None
                    for rp in router_ports:
                        self._core_plugin._delete_port(context.elevated(), rp.port.id)
                    context.session.delete(router)
            elif router_db.get('status') != status:
                router_db['status'] = status
                router_db.update(router_db)
            return router_db

    def update_floatingip_status(self, context, id, status):
        with context.session.begin(subtransactions=True):
            floatingip = self._get_floatingip(context, id)
            if status == huawei_l3_constants.FLOATINGIP_STATUS_DELETED:
                super(HuaweiL3plugin, self).delete_floatingip(context, id)
            elif status == huawei_l3_constants.FLOATINGIP_STATUS_DISASSOCIATED:
                #clear fixed_ip_address,port_id,router_id in floatingip
                #update status to down
                floatingip.update({'fixed_ip_address': None,
                                   'fixed_port_id': None,
                                   'router_id': None,
                                   'last_known_router_id': floatingip.get('router_id')})
            elif floatingip.get('status') != status:
                floatingip['status'] = status
                floatingip.update(floatingip)
        return floatingip

    def create_router(self, context, router):
        LOG.info("create_router begin in huawei_l3_db")
        r = router['router']
        gw_info = r.pop(EXTERNAL_GW_INFO, None)
        tenant_id = self._get_tenant_id_for_create(context, r)
        with context.session.begin(subtransactions=True):
            if gw_info:
                r['status'] = huawei_l3_constants.ROUTER_STATUS_PENDING_CREATE
                router_db = self._create_router_db(context, r, tenant_id)
                self._update_router_gw_info(context, router_db['id'],
                                            gw_info, router=router_db)
                self.notify_router_updated(context, router_db['id'])
            else:
                r['status'] = huawei_l3_constants.ROUTER_STATUS_DOWN
                router_db = self._create_router_db(context, r, tenant_id)
        return self._make_router_dict(router_db)

    def delete_router(self, context, id):
        LOG.info("delete_router begin in huawei_l3_db")
        #TODO l3-agent should modify?
        # when status is pending, can't delete router
        with context.session.begin(subtransactions=True):
            router_db = self._ensure_router_not_in_use(context, id)
            if router_db.get('status') in huawei_l3_constants.ROUTER_PENDING_LIST:
                raise StatusIsPending(object='router',
                                      id=id,
                                      operate='delete_router')

            if router_db.get('status') == huawei_l3_constants.ROUTER_STATUS_DOWN:
                router_ports = router_db.attached_ports.all()
                # Set the router's gw_port to None to avoid a constraint violation.
                router_db.gw_port = None
                for rp in router_ports:
                    LOG.error("router: %s has port_id: %s, but it's status is down!" % (id, rp.port.id))
                    self._core_plugin._delete_port(context.elevated(), rp.port.id)
                context.session.delete(router_db)
            else:
                self.update_router_status(context,
                                          id,
                                          huawei_l3_constants.ROUTER_STATUS_PENDING_DELETE)
                self.notify_router_deleted(context, id)

    def update_router(self, context, id, router):
        #TODO if not update gw_info, should check status, change status to pending, send rpc?
        # when status is pending, can't update router
        router_db = self.get_router(context, id)
        if router_db.get('status') in huawei_l3_constants.ROUTER_PENDING_LIST:
            raise StatusIsPending(object='router',
                                  id=id,
                                  operate='update_router')
        """
        #when status is error, can't update_router's external_gateway_info or routes
        if router_db.get('status') == huawei_l3_constants.ROUTER_STATUS_ERROR:
            if (router['router'].has_key('external_gateway_info') or
                router['router'].has_key('routes')):
                raise StatusIsError(object='router',
                                      id=id,
                                      operate='update_router')
        """

        #when update admin_state_up/gw/route, change status to pending_update
        if (router['router'].has_key('external_gateway_info') or
            router['router'].has_key('routes') or
            router['router'].get('admin_state_up')):
            router['router']['status'] = huawei_l3_constants.ROUTER_STATUS_PENDING_UPDATE
        router_dict = super(HuaweiL3plugin, self).update_router(context, id, router)
        return router_dict

    def add_router_interface(self, context, router_id, interface_info):
        # when status is pending, can't add_router_interface
        router_db = self.get_router(context, router_id)
        if router_db.get('status') in huawei_l3_constants.ROUTER_PENDING_LIST:
            raise StatusIsPending(object='router',
                                  id=router_id,
                                  operate='add_router_interface')
        """
        #when status is error, can't add_router_interface
        if router_db.get('status') == huawei_l3_constants.ROUTER_STATUS_ERROR:
            raise StatusIsError(object='router',
                                  id=router_id,
                                  operate='add_router_interface')
        """

        router_interface_info = super(HuaweiL3plugin, self).add_router_interface(context,
                                                                                 router_id,
                                                                                 interface_info)
        self.update_router_status(context, router_id, huawei_l3_constants.ROUTER_STATUS_PENDING_UPDATE)
        return router_interface_info

    def remove_router_interface(self, context, router_id, interface_info):
        # when status is pending, can't add_router_interface
        router_db = self.get_router(context, router_id)
        if router_db.get('status') in huawei_l3_constants.ROUTER_PENDING_LIST:
            raise StatusIsPending(object='router',
                                  id=router_id,
                                  operate='remove_router_interface')
        """
        #when status is error, can't remove_router_interface
        if router_db.get('status') == huawei_l3_constants.ROUTER_STATUS_ERROR:
            raise StatusIsError(object='router',
                                  id=router_id,
                                  operate='remove_router_interface')
        """

        router_interface_info = super(HuaweiL3plugin, self).remove_router_interface(context,
                                                                                    router_id,
                                                                                    interface_info)
        self.update_router_status(context, router_id, huawei_l3_constants.ROUTER_STATUS_PENDING_UPDATE)
        return router_interface_info

    def create_floatingip(self, context, floatingip):
        initial_status = huawei_l3_constants.FLOATINGIP_STATUS_DOWN
        if floatingip['floatingip'].get('port_id'):
            initial_status = huawei_l3_constants.FLOATINGIP_STATUS_PENDING_ASSOCIATE
        return super(HuaweiL3plugin, self).create_floatingip(context,
                                                             floatingip,
                                                             initial_status=initial_status)

    def update_floatingip(self, context, id, floatingip):
        """
        can't update from old_port to new port directly
        """

        #check params, then change status to pending
        new_floatingip = floatingip['floatingip']
        old_floatingip = self.get_floatingip(context, id)
        new_floatingip['tenant_id'] = old_floatingip['tenant_id']
        new_floatingip['id'] = id
        self._check_and_get_fip_assoc(context, new_floatingip, old_floatingip)

        # update port directly is Forbidden
        if (new_floatingip.get('port_id') and
            old_floatingip.get('port_id') and
            new_floatingip.get('port_id') != old_floatingip.get('port_id')):
            raise DuplicateAssociate(id=id)
        if (new_floatingip.get('fixed_ip_address') and
            old_floatingip.get('fixed_ip_address') and
            new_floatingip.get('fixed_ip_address') != old_floatingip.get('fixed_ip_address')):
            raise DuplicateAssociate(id=id)

        # when status is pending, can't update_floatingip
        if old_floatingip.get('status') in huawei_l3_constants.FLOATINGIP_PENDING_LIST:
            raise StatusIsPending(object='floatingip',
                                  id=id,
                                  operate='update_floatingip')
        #when status is error, can't remove_router_interface
        if old_floatingip.get('status') == huawei_l3_constants.FLOATINGIP_STATUS_ERROR:
            raise StatusIsError(object='floatingip',
                                  id=id,
                                  operate='update_floatingip')

        initial_status = huawei_l3_constants.FLOATINGIP_STATUS_PENDING_DISASSOCIATE
        if new_floatingip.get('port_id') or new_floatingip.get('fixed_ip_address'):
            super(HuaweiL3plugin, self).update_floatingip(context, id, floatingip)
            initial_status = huawei_l3_constants.FLOATINGIP_STATUS_PENDING_ASSOCIATE
        else:
            self.notify_router_updated(context, old_floatingip['router_id'], 'update_floatingip', {})
        self.update_floatingip_status(context,
                                      id,
                                      initial_status)
        return super(HuaweiL3plugin, self).get_floatingip(context, id)

    def delete_floatingip(self, context, id):
        # when status is pending, can't update_floatingip
        floatingip_db = self.get_floatingip(context, id)
        if floatingip_db.get('status') in huawei_l3_constants.FLOATINGIP_PENDING_LIST:
            raise StatusIsPending(object='floatingip',
                                  id=id,
                                  operate='update_floatingip')

        if floatingip_db.get('status') == huawei_l3_constants.FLOATINGIP_STATUS_DOWN:
            super(HuaweiL3plugin, self)._delete_floatingip(context, id)
        else:
            self.update_floatingip_status(context,
                                          id,
                                          huawei_l3_constants.FLOATINGIP_STATUS_PENDING_DELETE)
            floatingip = self.get_floatingip(context, id)
            router_id = floatingip['router_id']
            self.notify_router_updated(context, router_id, 'delete_floatingip', {})

    def disassociate_floatingips(self, context, port_id, do_notify=True):
        """Disassociate all floating IPs linked to specific port.

        disassociate_floatingips when delete fix port
        only update status to PENDING_DISASSOCIATE!
        """
        router_ids = set()
        with context.session.begin(subtransactions=True):
            fip_qry = context.session.query(l3_db.FloatingIP)
            floating_ips = fip_qry.filter_by(fixed_port_id=port_id)
            #if has floatingip in pending, raise error
            for floating_ip in floating_ips:
                if floating_ip.get('status') in huawei_l3_constants.FLOATINGIP_PENDING_LIST:
                    #raise DuplicateAssociate(id=floating_ip.get('id'))
                    raise StatusIsPending(object='floatingip',
                                          id=floating_ip.get('id'),
                                          operate='disassociate_floatingips')
            for floating_ip in floating_ips:
                router_ids.add(floating_ip['router_id'])
                floating_ip.update({'fixed_port_id': None,
                                    'status': huawei_l3_constants.FLOATINGIP_STATUS_PENDING_DISASSOCIATE})
        if do_notify:
            self.notify_routers_updated(context, router_ids)
            # since caller assumes that we handled notifications on its
            # behalf, return nothing
            return

        return router_ids

