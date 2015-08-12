from sqlalchemy.orm import exc
import netaddr
import copy

from neutron.openstack.common import log as logging
from neutron.common import exceptions as n_exc
from neutron import context as neutron_context
from neutron.db.servicechain import models_sc
from neutron.extensions import servicechain as sc_ex

LOG = logging.getLogger(__name__)

class SfPortGenerationFailure(n_exc.Conflict):
    message = _("No more sf Port available on network.")

class SfPortParamNeed(n_exc.Conflict):
    message = _("correct param is need.")

class SfPortAlreadyAllocate(n_exc.Conflict):
    message = _("The Port has already available sf Port on network.")

class SfPortNotFind(n_exc.Conflict):
    message = _("The Port can not find in the allocation table")

def init_servicechain_pool(sf_port_pools=[]):
    context = neutron_context.get_admin_context()
    with context.session.begin(subtransactions=True):
        add_sc_pool_set = copy.copy(sf_port_pools)
        db_sc_pools = _get_all_servicechain_pools(context)
        if len(db_sc_pools) == 0:
            for pool in add_sc_pool_set:
                sc_pool = models_sc.ServiceChainPool(sf_sc_identifier=pool['sf_sc_identifier'],
                                                     sf_port_id_begin=pool['sf_port_id_begin'],
                                                     sf_port_id_end=pool['sf_port_id_end'])

                context.session.add(sc_pool)
                sc_pool_range = models_sc.ServiceChainAvailabilityRange(servicechainpool=sc_pool,
                                                                    sf_sc_identifier=pool['sf_sc_identifier'],
                                                                    sf_port_id_begin=pool['sf_port_id_begin'],
                                                                    sf_port_id_end=pool['sf_port_id_end'])
                context.session.add(sc_pool_range)


def _get_all_servicechain_pools(context):
    return  context.session.query(models_sc.ServiceChainPool).all()

def _generate_sf_port(context, sf_st_id, identifier):
    range_qry = context.session.query(
        models_sc.ServiceChainAvailabilityRange).join(
            models_sc.ServiceChainPool).with_lockmode('update')
    scrange = range_qry.filter_by(sf_sc_identifier=identifier).first()
    if not scrange:
        LOG.debug(_("All Sf Port Id allocated"))
        raise SfPortGenerationFailure()
    sf_port_id = scrange['sf_port_id_begin']
    LOG.debug(_("Service Chain Allocated Sf Port - %(sf_port_id)s from %(sf_port_id_begin)s "
                "to %(sf_port_id_end)s"),
              {'sf_port_id': sf_port_id,
               'sf_port_id_begin': scrange['sf_port_id_begin'],
               'sf_port_id_end': scrange['sf_port_id_end']})
    if  scrange['sf_port_id_begin'] == scrange['sf_port_id_end']:
        # No more free indices on subnet => delete
        if identifier == 'service_traffic_classifier' and scrange['sf_port_id_begin'] == 20100 \
            or identifier == 'service_function_instance' and scrange['sf_port_id_begin'] == 16383 \
            or identifier == 'service_chain' and scrange['sf_port_id_begin'] == 9999 \
            or identifier == 'service_function_group' and scrange['sf_port_id_begin'] == 127 :
            LOG.debug(_("There is may No more free sf port in slice. Deleting allocation "
                            "pool."))
            raise SfPortGenerationFailure()
        else:
            context.session.delete(scrange)
    else:
        # increment the first free
        scrange['sf_port_id_begin'] = sf_port_id + 1

    return  {'sf_port_id': sf_port_id,'sc_sf_id':sf_st_id,
             'pool_id':scrange['allocation_pool_id']}


def _allocation_sf_port_id(context, port_id, service_id, identifier):
    """"allocate sf port id for instance /group /chain"""
    if port_id and service_id:
        allocation = (context.session.query(models_sc.ServiceChainAllocation).
                      filter_by(port_id=port_id).first())
    elif port_id == '' and service_id:
        allocation = (context.session.query(models_sc.ServiceChainAllocation).
                        filter_by(sf_sc_id=service_id).first())
    else:
        LOG.debug(_('input error parameters is required'))
        raise SfPortParamNeed()

    if allocation:
        LOG.debug(_('the port or chain or group id has allocated, port_id = %s,sf_port_id=%s'),
                  port_id,allocation['sf_port_id'])

        return allocation
    #allocation port id
    sf_port_dict = _generate_sf_port(context, service_id,identifier)

    new_sc_allocation = models_sc.ServiceChainAllocation(port_id=port_id,sf_sc_id=sf_port_dict['sc_sf_id'],
                                                                sf_port_id=sf_port_dict['sf_port_id'],
                                                                sf_sc_identifier=identifier,
                                                                allocation_pool_id=sf_port_dict['pool_id'])
    context.session.add(new_sc_allocation)
    return new_sc_allocation


def _delete_sc_allocation(context, port_id, service_id, identifier):
    alloc_qry = context.session.query(
            models_sc.ServiceChainAllocation).with_lockmode('update')
    if identifier in ['service_function_instance','service_traffic_classifier']:
        alloc_qry.filter_by(sf_port_id=port_id,sf_sc_id=service_id,sf_sc_identifier=identifier).delete();
    else:
        alloc_qry.filter_by(sf_port_id=port_id,sf_sc_id=service_id,sf_sc_identifier=identifier).delete()


def _recycle_sf_port_id(context, idf, service_id, sf_port_id, pool_id):
    range_qry = context.session.query(
                models_sc.ServiceChainAvailabilityRange).with_lockmode('update')
    begin = sf_port_id + 1
    end = sf_port_id - 1
    LOG.debug(_("Recycle allocation id %s"), sf_port_id)
    try:
        r1 = range_qry.filter_by(sf_sc_identifier=idf,sf_port_id_begin=begin).one()
    except:
        r1 = []
    try:
        r2 = range_qry.filter_by(sf_sc_identifier=idf,sf_port_id_end=end).one()
    except:
        r2 = []

    if r1 and r2:
        sf_port_range = models_sc.ServiceChainAvailabilityRange(sf_sc_identifier=idf,
                                                                allocation_pool_id = r2['allocation_pool_id'],
                                                                sf_port_id_begin = r2['sf_port_id_begin'],
                                                                sf_port_id_end = r1['sf_port_id_end'])
        context.session.add(sf_port_range)
        context.session.delete(r1)
        context.session.delete(r2)
    elif r1:
        r1['sf_port_id_begin'] = sf_port_id
    elif r2:
        r2['sf_port_id_end'] = sf_port_id
    else:
        sf_port_range =  models_sc.ServiceChainAvailabilityRange(sf_sc_identifier=idf,
                                                                allocation_pool_id = pool_id,
                                                                sf_port_id_begin = sf_port_id,
                                                                sf_port_id_end = sf_port_id)
        context.session.add(sf_port_range)
    _delete_sc_allocation(context, sf_port_id, service_id, idf)

def _recycle_sf_or_port(context, vm_port_id, service_id, identifier):
    alloc_qry = context.session.query(
            models_sc.ServiceChainAllocation).with_lockmode('update')
    if identifier in ['service_function_instance','service_traffic_classifier']:
        allocated = alloc_qry.filter_by(port_id=vm_port_id,sf_sc_id=service_id,sf_sc_identifier=identifier)
    else:
        allocated = alloc_qry.filter_by(sf_sc_id=service_id,sf_sc_identifier=identifier)

    if allocated:
        for allocate in allocated:
            LOG.debug(_("_recycle_port_id:allocation_pool_id=%s,sf_port_id=%sidentifier=%s",),allocate['allocation_pool_id'],
                      allocate['sf_port_id'],identifier)
            _recycle_sf_port_id(context, identifier, service_id,
                                allocate['sf_port_id'],allocate['allocation_pool_id'])
    else:
        raise SfPortNotFind

