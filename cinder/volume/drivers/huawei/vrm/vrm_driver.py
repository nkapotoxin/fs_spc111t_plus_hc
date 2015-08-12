# vim: tabstop=4 shiftwidth=4 softtabstop=4

"""
[VRM DRIVER] 

"""
import random
import json

from oslo.config import cfg
from cinder.volume.configuration import Configuration
from cinder import volume
from cinder import context as cinder_context
from cinder.openstack.common import log as logging
from cinder.volume import driver
from cinder import exception
from cinder.volume.drivers.huawei.vrm import exception as driver_exception
from cinder.openstack.common.gettextutils import _
from cinder.volume.drivers.huawei.vrm.conf import FC_DRIVER_CONF
from cinder.volume.drivers.huawei.vrm.vm_proxy import VmProxy
from cinder.volume.drivers.huawei.vrm.volume_proxy import VolumeProxy
from cinder.volume.drivers.huawei.vrm.volume_snapshot_proxy import VolumeSnapshotProxy
from cinder.volume.drivers.huawei.vrm.host_proxy import HostProxy
from cinder.volume.drivers.huawei.vrm.cluster_proxy import ClusterProxy
from cinder.volume.drivers.huawei.vrm.datastore_proxy import DatastoreProxy
from cinder.volume.drivers.huawei.vrm.http_client import VRMHTTPClient
from cinder.volume import utils as volume_utils


try:
    from eventlet import sleep
except ImportError:
    from time import sleep

backend_opts = [
    cfg.StrOpt('volume_driver',
               default='cinder.volume.drivers.huawei.vrm.vrm_driver.VRMDriver',
               help='Driver to use for volume creation'),
]

def metadata_to_dict(metadata):
    result = {}
    for item in metadata:
        if not item.get('deleted'):
            result[item['key']] = item['value']
    return result


LOG = logging.getLogger(__name__)
CONF = cfg.CONF

fc_plugin_conf = [
    cfg.StrOpt('vrm_config_file',
               default=None,
               help='vrm_config_file'),
    cfg.BoolOpt('vrm_thin_provision',
                default=False,
                help='Switch of thin provisioning support'),
    cfg.FloatOpt('vrm_over_ratio',
                 default=1.0,
                 help='Ratio of thin provisioning'),
    cfg.IntOpt('vrm_reserved_percentage',
               default=0,
               help='Reserved percentage of the backend volumes'),
    cfg.ListOpt('vrm_ds_name',
                default=[],
                help='vrm_ds_name'),
    cfg.ListOpt('current_list',
                default=[],
                help='current_list'),
    cfg.IntOpt('affine_rate',
               default=1,
               help='affine_rate'),
]



class VRMDriver(driver.VolumeDriver):
    VENDOR = 'Huawei'
    BACKEND = 'VRM'
    VERSION = 'v1.1'

    def __init__(self, *args, **kwargs):
        '''
        __init__

        :param args:
        :param kwargs:
        :return:
        '''
        super(VRMDriver, self).__init__(*args, **kwargs)
        LOG.debug(_("[VRM-CINDER] start VRMDriver __init__()"))
        self.context = None
        self.volume_api = volume.API()
        self.SHARED_HOSTS = []
        self.SHARED_DATASTORES = []
        self.SHARED_VOLUMES = []

        self.LAST_SHARED_HOSTS = self.SHARED_HOSTS
        self.LAST_SHARED_DATASTORES = self.SHARED_DATASTORES
        self.LAST_SHARED_VOLUMES = self.SHARED_VOLUMES
        self.left_periodrate = CONF.vrm_sm_periodrate

        if self.configuration:
            LOG.debug(_("[VRM-CINDER] append configuration"))
            self.configuration.append_config_values(fc_plugin_conf)
        else:
            LOG.debug(_("[VRM-CINDER] no configuration exception"))
            raise driver_exception.NoNeededData

        thin_provision = self.configuration.get('vrm_thin_provision')
        if thin_provision is None:
            self.thin_provision = False
        else:
            LOG.debug(_("[VRM-CINDER] thin_provision [%s]"), thin_provision)
            self.thin_provision = bool(thin_provision)

        over_ratio = self.configuration.get('vrm_over_ratio')
        if over_ratio is None:
            self.over_ratio = 1.0
        else:
            LOG.debug(_("[VRM-CINDER] super_ratio [%s]"), over_ratio)
            self.over_ratio = over_ratio

        reserved_percentage = self.configuration.get('vrm_reserved_percentage')
        if reserved_percentage is None:
            self.reserved_percentage = 0
        else:
            LOG.debug(_("[VRM-CINDER] reserved_percentage [%s]"), reserved_percentage)
            self.reserved_percentage = int(reserved_percentage)

        vrm_config_file = self.configuration.get('vrm_config_file')
        if vrm_config_file is None:
            LOG.debug(_("[VRM-CINDER] vrm_config_file is None"))
        else:
            LOG.debug(_("[VRM-CINDER] vrm_config_file is [%s]"), vrm_config_file)

        self.pool_list = self.configuration.get('vrm_ds_name')
        if not self.pool_list:
            LOG.error(_("[VRM-CINDER] vrm_ds_name is None exception"))
            raise driver_exception.NoNeededData
        self.pool_list = list(set(self.pool_list))

        self.current_list = self.configuration.get('current_list')
        self.affine_rate = self.configuration.get('affine_rate')

        self.volume_proxy = VolumeProxy()
        self.vm_proxy = VmProxy()
        self.volume_snapshot_proxy = VolumeSnapshotProxy()
        self.host_proxy = HostProxy()
        self.cluster_proxy = ClusterProxy()
        self.datastore_proxy = DatastoreProxy()
        self.vrmhttpclient = VRMHTTPClient()

        self.site_urn = None
        self.site_uri = None
        self.cluster_urn = None

        self.shared_hosts = []
        self.shared_datastores = []
        self.shared_volumes = []
        self.auth_token = None

        LOG.debug(_("[VRM-CINDER] end __init__()"))


    def _get_host_datastore_vol(self):
        '''
        get_host_datastore_vol

        :return:
        '''
        LOG.debug(_("[VRM-CINDER] start get_host_datastore_vol()"))
        self.shared_hosts = []
        self.shared_datastores = []
        self.shared_volumes = []

        self.shared_hosts = self.host_proxy.list_host()
        hosturns = [host['urn'] for host in self.shared_hosts]
        hosturns.sort()
        hosturns_set = set(hosturns)
        LOG.info(_("hosturns_set %s") % hosturns_set)

        datastores = self.datastore_proxy.list_datastore()
        sharetypes = [t.lower() for t in FC_DRIVER_CONF.vrm_ds_types]
        for datastore in datastores:
            storage_type = datastore['storageType'].lower()
            LOG.info(_("[VRMSMDriver] datastores [%s]"), json.dumps(datastore))
            ds_urn = datastore['urn']
            ds_name = datastore['name']
            if self.pool_list is not None:
                if ds_name in self.pool_list:
                    LOG.info(_("[VRM-CINDER] get the vrm_sm_datastore_name"))
                    self.shared_datastores.append(datastore)
                else:
                    LOG.info(_("vrm_sm_datastore_name unexists"))
                    continue

            if storage_type in sharetypes:
                hosts = datastore['hosts']
                hosts.sort()
                hosts_set = set(hosts)

                LOG.info(_("hosts_set %s") % hosts_set)
                if FC_DRIVER_CONF.vrm_ds_hosts_share:
                    if len(hosturns_set - hosts_set) == 0:
                        LOG.info(_("[VRM-CINDER] append ds share"))
                        self.shared_datastores.append(datastore)
                else:
                    if len(hosturns_set & hosts_set) > 0:
                        LOG.info(_("[VRM-CINDER] append ds"))
                        self.shared_datastores.append(datastore)

        if len(self.shared_datastores) <= 0:
            LOG.info(_("[VRM-CINDER] can not found any shared datastores "))
            raise driver_exception.NotFound()

        LOG.debug(_("[VRM-CINDER] end get_host_datastore_vol()"))
        return (self.shared_hosts, self.shared_datastores, self.shared_volumes)

    def _refresh_storage_info(self, refresh=False):
        '''
        _refresh_storage_info

        :param refresh:
        :return:
        '''
        LOG.debug(_("[BRM-DRIVER] start _refresh_storage_info(%s) "), refresh)
        if refresh == True:
            self.LAST_SHARED_HOSTS = self.SHARED_HOSTS
            self.LAST_SHARED_DATASTORES = self.SHARED_DATASTORES
            self.LAST_SHARED_VOLUMES = self.SHARED_VOLUMES

            self.SHARED_HOSTS, self.SHARED_DATASTORES, self.SHARED_VOLUMES = self._get_host_datastore_vol()
            self.left_periodrate = CONF.vrm_sm_periodrate
            LOG.info(_("[CINDER-BRM] refreshed shared hosts :[ %s ]"), self.SHARED_HOSTS)
            LOG.info(_("[CINDER-BRM] refreshed shared datastores :[ %s ]"), self.SHARED_DATASTORES)
        LOG.debug(_("[BRM-DRIVER] end _refresh_storage_info(%s) "), refresh)

    def do_setup(self, context):
        '''
        do_setup

        :param context:
        :return:
        '''
        LOG.debug(_("[BRM-DRIVER] start do_setup() "))
        self.context = context
        self.vrmhttpclient.init()
        self.site_urn = self.vrmhttpclient.get_siteurn()
        self._refresh_storage_info(True)
        clusters = self.cluster_proxy.list_cluster()
        self.cluster_urn = clusters[0].get('urn')
        LOG.debug(_("[CINDER-BRM] end do_setup"))

    def check_for_setup_error(self):
        '''
        check_for_setup_error

        :return:
        '''
        LOG.debug(_("[BRM-DRIVER] start check_for_setup_error() "))
        if len(self.SHARED_HOSTS) == 0 or len(self.SHARED_DATASTORES) == 0:
            LOG.info(_("[CINDER-BRM] check_for_setup_error, shared datasotre not found"))
            raise driver_exception.NoNeededData

    def _build_volume_stats(self):
        '''
        _build_volume_stats
        '''
        LOG.debug(_("[BRM-DRIVER] start _build_volume_stats() "))
        stats = {}
        stats["pools"] = []
        stats['driver_version'] = self.VERSION
        stats['storage_protocol'] = 'VRM'
        stats['vendor_name'] = self.VENDOR

        backend = self.configuration.get('volume_backend_name')
        if backend is None:
            stats['volume_backend_name'] = self.BACKEND
        else:
            stats['volume_backend_name'] = self.configuration.get('volume_backend_name')

        LOG.info(_("[CINDER-BRM] get volume stats finished:(%d)--%s"), self.left_periodrate, stats)

        return stats

    def _try_get_volume_stats(self, refresh=False):
        '''
        _try_get_volume_stats

        :param refresh:If 'refresh' is True, run the update first.
        :return:Return the current state of the volume service.
        '''
        LOG.debug(_("[BRM-DRIVER] start _try_get_volume_stats() "))
        if refresh:
            self.left_periodrate -= 1
            if self.left_periodrate <= 0:
                self._refresh_storage_info(refresh)

        free_capacity_gb = 0
        used_capacity_gb = 0
        total_capacity_gb = 0


        stats = self._build_volume_stats()
        ds_meta = {}
        ds_names = [ds['name'] for ds in self.SHARED_DATASTORES]
        for pool in self.pool_list:
            if pool not in ds_names:
                continue
            new_pool = {}
            ds_meta['ds_name'] = pool
            datastore = self._choose_datastore(ds_meta)
            if 'NORMAL' != datastore['status']:
                new_pool.update(dict(
                    pool_name=pool,
                    free_capacity_gb=0,
                    reserved_percentage=self.reserved_percentage,
                    total_capacity_gb=0,
                    provisioned_capacity_gb=0,
                    max_over_subscription_ratio=self.over_ratio,
                    affine_rate=1
                ))
                stats["pools"].append(new_pool)
                continue
                
            if self.current_list is not None and pool in self.current_list:
                new_pool.update(dict(
                    pool_name=pool,
                    free_capacity_gb=datastore['freeSizeGB'],
                    reserved_percentage=self.reserved_percentage,
                    total_capacity_gb=datastore['capacityGB'],
                    provisioned_capacity_gb=datastore['usedSizeGB'],
                    max_over_subscription_ratio=self.over_ratio,
                    affine_rate=self.affine_rate
                ))
            else:
                new_pool.update(dict(
                    pool_name=pool,
                    free_capacity_gb=datastore['freeSizeGB'],
                    reserved_percentage=self.reserved_percentage,
                    total_capacity_gb=datastore['capacityGB'],
                    provisioned_capacity_gb=datastore['usedSizeGB'],
                    max_over_subscription_ratio=self.over_ratio,
                    affine_rate=1
                ))
            if self.thin_provision is True:
                new_pool.update(dict(
                    thin_provisioning_support=True,
                    thick_provisioning_support=False
                ))
            else:
                new_pool.update(dict(
                    thin_provisioning_support=False,
                    thick_provisioning_support=True
                ))
            stats["pools"].append(new_pool)

        LOG.info(_("[CINDER-BRM] _try_get_volume_stats:(%d)--%s"), self.left_periodrate, stats)

        return stats

    def get_volume_stats(self, refresh=False):
        '''
        get_volume_stats

        :param refresh:If 'refresh' is True, run the update first.
        :return:Return the current state of the volume service.
        '''
        LOG.debug(_("[BRM-DRIVER] start get_volume_stats() "))
        try:
            stats = self._try_get_volume_stats(refresh)
        except Exception as ex:
            LOG.info(_("[CINDER-BRM] get volume stats Exception (%s)"), ex)
            stats = self._build_volume_stats()
        return stats


    def check_and_modify_thin(self, ds_urn, thin):
        '''
        [ DSWARE] /[LOCAL, SAN, LUN]
        :param ds_urn:
        :param thin:
        :return:
        '''
        LOG.info(_("[CINDER-BRM] start check_and_modify_thin (%s)"), ds_urn)
        for datastore in self.SHARED_DATASTORES:
            LOG.info(_("[CINDER-BRM] ds_urn (%s)"), ds_urn)
            LOG.info(_("[CINDER-BRM] datastore (%s)"), datastore['urn'])
            if datastore['urn'] == ds_urn:
                ds_type = str(datastore['storageType']).upper()
                LOG.info(_("[CINDER-BRM] ds_type (%s)"), ds_type)
                if ds_type in ['LOCAL', 'SAN', 'LUN']:
                    LOG.info(_("[CINDER-BRM] return False (%s)"), ds_urn)
                    return False
                if ds_type in [ 'DSWARE']:
                    LOG.info(_("[CINDER-BRM] return True (%s)"), ds_urn)
                    return True
        return thin


    def check_thin(self, datastore, thin):
        '''
        [ DSWARE] /[LOCAL, SAN, LUN]
        :param ds_urn:
        :param thin:
        :return:
        '''
        LOG.info(_("[CINDER-BRM] start check_thin (%s)"), datastore)
        ds_type = str(datastore['storageType']).upper()
        LOG.info(_("[CINDER-BRM] ds_type (%s)"), ds_type)
        if ds_type in ['LOCAL', 'SAN', 'LUN']:
            LOG.info(_("[CINDER-BRM] return False (%s)"), datastore)
            return False
        if ds_type in ['DSWARE']:
            LOG.info(_("[CINDER-BRM] return True (%s)"), datastore)
            return True
        return thin

    def _check_and_choice_datastore(self, ds_meta):
        '''
        _check_and_choice_datastore

        :param ds_meta:
        :return:
        '''
        LOG.debug(_("[BRM-DRIVER] start _check_and_choice_datastore() "))
        datastoreUrn = ds_meta['datastoreUrn']
        hypervisorIp = ds_meta['hypervisorIp']
        quantityGB = ds_meta['quantityGB']
        storageType = ds_meta['storageType']
        isThin = ds_meta['isThin']
        hypervisorUrn = None
        if hypervisorIp:
            for host in self.SHARED_HOSTS:
                if host['ip'].strip() == hypervisorIp.strip():
                    hypervisorUrn = host['urn']
                    break
            if hypervisorUrn is None:
                LOG.info(_("[CINDER-BRM] can not found hypervisorip=%s"), hypervisorIp)
                raise exception.HostNotFound(host=hypervisorIp)

        if datastoreUrn:
            for datastore in self.SHARED_DATASTORES:
                if datastore['urn'] == datastoreUrn:
                    this_storageType = datastore['storageType']
                    this_isThin = datastore['isThin']
                    this_freeSizeGB = int(datastore['freeSizeGB'])
                    this_hosts = datastore['hosts']

                    if this_storageType.lower() == storageType.lower() and str(this_isThin).lower() == str(
                            isThin).lower() and this_freeSizeGB > quantityGB:
                        if hypervisorUrn is None:
                            return datastore['urn']
                        elif hypervisorUrn in this_hosts:
                            return datastore['urn']

                    LOG.info(_("[CINDER-BRM] datastore=%s found,but not satisfied with [%s,%s,%d,%s]") % (
                        datastoreUrn, storageType, str(isThin), quantityGB, hypervisorIp))
                    raise driver_exception.NotFound()
            raise driver_exception.NotFound()
        ds_hosts = None
        ds_urn = None
        random.shuffle(self.SHARED_DATASTORES)
        for datastore in self.SHARED_DATASTORES:

            this_isThin = datastore['isThin']
            this_freeSizeGB = int(datastore['freeSizeGB'])
            ds_hosts = datastore['hosts']
            if this_freeSizeGB < quantityGB:
                continue
            if isThin is None:
                ds_urn = datastore['urn']
                break

            elif str(this_isThin).lower() == str(isThin).lower():
                ds_urn = datastore['urn']
                break

        if ds_urn is None:
            raise driver_exception.NotFound()
        random.shuffle(ds_hosts)
        host_urn = ds_hosts[0]
        return ds_urn, host_urn


    def _choose_datastore(self, ds_meta):
        '''
        _check_and_choice_datastore

        :param ds_meta:
        :return:
        '''
        LOG.debug(_("[BRM-DRIVER] start _choose_datastore() "))
        for datastore in self.SHARED_DATASTORES:
            if ds_meta['ds_name'] == datastore['name']:
                return datastore

        raise driver_exception.NotFound()

    def _vrm_pack_provider_location(self, volume_body):
        '''
        _vrm_pack_provider_location

        :param volume:
        :param volume_body:
        :return:
        '''
        LOG.debug(_("[BRM-DRIVER] start _vrm_pack_provider_location() "))
        fc_ip = FC_DRIVER_CONF.fc_ip

        provider_location = ""
        provider_location += ('addr=' + fc_ip + ':' + str(CONF.vrm_port) + ',')
        provider_location += ('uri=' + volume_body.get('uri') + ',')
        provider_location += ('urn=' + volume_body.get('urn') + ',')
        provider_location += ('datastoreUrn=' + volume_body.get('datastoreUrn') + ',')
        provider_location += ('isThin=' + str(volume_body.get('isThin')) + ',')
        provider_location += ('storageType=' + volume_body.get('storageType') + ',')
        provider_location += ('type=' + volume_body.get('type'))

        return provider_location

    def _vrm_unpack_provider_location(self, provider_location, key=None):
        '''
        _vrm_unpack_provider_location

        :param provider_location:
        :param key:
        :return:
        '''
        LOG.debug(_("[BRM-DRIVER] start _vrm_unpack_provider_location() "))
        kvalue = None
        kvs = {}
        if type(provider_location) is not type(None) and len(provider_location) > 0:
            items = provider_location.split(',')
            for item in items:
                (ki, eqi, vi) = item.partition('=')
                kvs[ki] = vi
                if key and key == ki:
                    kvalue = vi

        return kvalue, kvs


    def _vrm_get_volume_meta(self, id):
        '''
        _vrm_create_volume

        :param id:
        :return:
        '''
        LOG.debug(_("[BRM-DRIVER] start _vrm_get_volume_meta() "))
        model_update = {}
        metadata = {}

        if id:
            volume_body = self.volume_proxy.query_volume(id=id)
            if type(volume_body) is not type(None):
                model_update['provider_location'] = self._vrm_pack_provider_location(volume_body)
                urn = volume_body['urn']
                uri = volume_body['uri']
                metadata.update({'urn': urn})
                metadata.update({'uri': uri})
                volInfoUrl = volume_body.get('volInfoUrl', None)
                if volInfoUrl:
                    metadata.update({'quantityGB': volume_body['quantityGB']})
                    metadata.update({'volInfoUrl': volInfoUrl})

        return model_update, metadata

    def _vrm_delete_volume(self, volume):
        '''
        _vrm_delete_volume

        :param volume:
        :return:
        '''
        LOG.debug(_("[BRM-DRIVER] start _vrm_delete_volume() "))
        vol_metas = volume['volume_metadata']
        if type(vol_metas) is not type(None):
            for meta in vol_metas:
                LOG.debug(_("[BRM-DRIVER] volume_metadata is [%s:%s] "), meta.key, meta.value)
        provider_location = volume['provider_location']
        if provider_location is None or provider_location == '':
            LOG.error(_("[BRM-DRIVER]provider_location is null "))
            vol_meta = volume.get('volume_metadata')
            vol_meta_dict = metadata_to_dict(vol_meta)
            vol_uri = vol_meta_dict.get('uri')
            if vol_uri is not None:
                self.volume_proxy.delete_volume(volume_uri=vol_uri)
            return
        volume_uri, items = \
            self._vrm_unpack_provider_location(volume['provider_location'], 'uri')
        self.volume_proxy.delete_volume(volume_uri=volume_uri)


    def create_volume(self, volume):
        '''
        create_volume
        {
            "name":string,
            quantityGB:integer,
            datastoreUrn:string,
            "isThin":boolean,
            "type":string,
            indepDisk:boolean,
            persistentDisk:boolean
        }

        :param volume:
        :return:
        '''
        LOG.debug(_("[BRM-DRIVER] start create_volume() "))

        vol_meta = volume.get('volume_metadata')
        vol_meta_dict = metadata_to_dict(vol_meta)
        linked_clone = vol_meta_dict.get('linked_clone')
        if linked_clone is None:
            linked_clone = False
        elif str(linked_clone).lower() == 'true':
            linked_clone = True
        else:
            linked_clone = False

        if linked_clone:
            LOG.debug(_("[BRM-DRIVER] linked_clone volume. do nothing. "))
            return

        args_dict = {}

        args_dict['name'] = volume['name']
        args_dict['size'] = int(volume['size'])
        args_dict['uuid'] = volume['id']
        shareable = volume['shareable']
        if shareable and True == shareable:
            LOG.info(_("[CINDER-VRM] shareable"))
            args_dict['type'] = 'share'

        else:
            args_dict['type'] = 'normal'


        is_thin = FC_DRIVER_CONF.vrm_is_thin

        ds_meta = {}
        try:
            ds_meta['ds_name'] = volume.get('host').split('#')[1]
        except exception.CinderException as ex:
            LOG.info(
                _("[CINDER-BRM] host format exception, host is %s ") % volume.get('host'))
            raise ex

        datastore = self._choose_datastore(ds_meta)
        if datastore:
            LOG.info(_("[CINDER-VRM] datastore [%s],"), datastore)
            if str(datastore.get('storageType')).upper() in ['LUN']:
                LOG.info(_("[CINDER-VRM] rdm disk [%s]"), volume['id'])
                args_dict['size'] = int(datastore.get('capacityGB'))
                args_dict['independent'] = True

            args_dict['ds_urn'] = datastore.get('urn')
            is_thin = self.check_thin(datastore, is_thin)
            args_dict['is_thin'] = is_thin

            body = self.volume_proxy.create_volume(**args_dict)
            temp_str = body.get('urn')
            fc_vol_id = temp_str[temp_str.rfind(':') + 1:]
            LOG.info(_("[CINDER-VRM] fc_vol_id [%s] ") % fc_vol_id)
            model_update, metadata = self._vrm_get_volume_meta(id=fc_vol_id)
            context = cinder_context.get_admin_context()
            self.db.volume_metadata_update(context, volume['id'], metadata, False)
            return model_update
        else:
            raise exception.VolumeDriverException


    def _register_volume(self, volume):
        '''
        _register_volume

        :param volume:
        :return:
        '''
        LOG.debug(_("[BRM-DRIVER] start _register_volume() "))
        volume_metadata = volume['volume_metadata']
        volume_metadata_dict = metadata_to_dict(volume_metadata)
        model_update = {}

        volume_urn = volume_metadata_dict.get('volumeUrn')
        volume_id = volume_urn.split(':')[-1]
        volume_body = self.volume_proxy.get_volume(vol_id=volume_id)
        model_update['provider_location'] = self._vrm_pack_provider_location(volume_body)
        model_update['volume_urn'] = volume_body['urn']
        return model_update

    def delete_volume(self, volume):
        '''
        delete_volume

        :param volume:
        :return:
        '''
        LOG.debug(_("[BRM-DRIVER] start delete_volume() "))
        self._vrm_delete_volume(volume)

    def create_export(self, context, volume):
        '''
        create_export

        :param context:
        :param volume:
        :return:
        '''
        LOG.debug(_("[BRM-DRIVER] start create_export() "))


    def remove_export(self, context, volume):
        '''
        remove_export

        :param context:
        :param volume:
        :return:
        '''
        LOG.debug(_("[BRM-DRIVER] start remove_export() "))


    def ensure_export(self, context, volume):
        '''
        ensure_export

        :param context:
        :param volume:
        :return:
        '''
        LOG.debug(_("[BRM-DRIVER] start ensure_export() "))


    def check_for_export(self, context, volume_id):
        '''
        check_for_export

        :param context:
        :param volume_id:
        :return:
        '''
        LOG.debug(_("[BRM-DRIVER] start check_for_export() "))


    def create_snapshot(self, snapshot):
        '''
        create_snapshot

        :param snapshot:
        :return:
        '''
        LOG.debug(_("[BRM-DRIVER] start create_snapshot() "))
        model_update = {}
        volume = self.db.volume_get(self.context, snapshot['volume_id'])
        vol_meta = volume['volume_metadata']
        vol_meta_dict = metadata_to_dict(vol_meta)
        vol_urn = vol_meta_dict.get('urn')
        if type(vol_urn) is type(None):
            LOG.error(_("vol_urn  is null."))

        def volume_uri_to_number(uri):
            hi, si, ti = uri.rpartition('/')
            return ti

        snapshot_id = snapshot['id']
        snapshot_uuid = str(snapshot_id).replace('-', '')
        body = self.volume_snapshot_proxy.create_volumesnapshot(snapshot_uuid=snapshot_uuid, vol_urn=vol_urn)

        if body['urn'] is None:
            LOG.error(_("Trying to create snapshot failed, volume id is: %s"), snapshot['volume_id'])
            raise driver_exception.FusionComputeDriverException()

        return model_update

    def delete_snapshot(self, snapshot):
        '''
        delete_snapshot

        :param snapshot:
        :return:
        '''
        LOG.debug(_("[BRM-DRIVER] start delete_snapshot() "))
        model_update = {}
        snapshot_id = snapshot['id']
        snapshot_uuid = str(snapshot_id).replace('-', '')
        body = self.volume_snapshot_proxy.query_volumesnapshot(uuid=snapshot_uuid)
        if body == None:
            return model_update
        self.volume_snapshot_proxy.delete_volumesnapshot(id=snapshot_uuid)

        return model_update

    def create_volume_from_snapshot(self, volume, snapshot):
        '''
        create_volume_from_snapshot

        :param volume:
        :param snapshot:
        :return:
        '''
        LOG.debug(_("[BRM-DRIVER] start create_volume_from_snapshot()"))
        args_dict = {}

        vol_meta = volume.get('volume_metadata')
        vol_meta_dict = metadata_to_dict(vol_meta)
        linked_clone = vol_meta_dict.get('linked_clone')
        if linked_clone is None:
            linked_clone = False
        elif str(linked_clone).lower() == 'true':
            linked_clone = True
        else:
            linked_clone = False
        if linked_clone == True:
            LOG.warn(_("[BRM-DRIVER] linked_clone volume not support!!"))
            raise exception.CinderException

   
        full_clone = vol_meta_dict.get('full_clone')
        if full_clone is None:
            full_clone = '1'
        elif str(full_clone) == '0':
            full_clone = '0'
        else:
            full_clone = '1'
        args_dict['full_clone'] = full_clone

        model_update = {}
        snapshot_id = snapshot['id']
        # TODO
        os_vol_id = volume['id']
        shareable = volume['shareable']
        if shareable and True == shareable:
            LOG.info(_("[CINDER-VRM] shareable"))
            voltype = 'share'
        else:
            voltype = 'normal'
        snapshot_uuid = str(snapshot_id).replace('-', '')

        volume_size = int(volume.get('size'))
        snapshot_size = int(snapshot.get('volume_size'))
        LOG.info(_("[BRM-DRIVER] volume_size[%d] snapshot_size[%d]"), volume_size, snapshot_size)
        if volume_size != snapshot_size:
            LOG.debug(_("[BRM-DRIVER] volume_size != snapshot_size"))
            raise exception.CinderException


        args_dict['snapshot_uuid'] = snapshot_uuid
        args_dict['volume_name'] = volume['name']
        args_dict['volume_uuid'] = os_vol_id
        args_dict['type'] = voltype

        LOG.debug(_("[BRM-DRIVER] snapshot (%s) volume [%s]"), snapshot_id, os_vol_id)
        body = self.volume_snapshot_proxy.create_volume_from_snapshot(**args_dict)
        LOG.debug(_(json.dumps(body)))
        vol_urn = body['urn']
        fc_vol_id = vol_urn.split(':')[-1]

        model_update, metadata = self._vrm_get_volume_meta(id=fc_vol_id)
        context = cinder_context.get_admin_context()
        self.db.volume_metadata_update(context, os_vol_id, metadata, False)
        return model_update


    def create_cloned_volume(self, volume, src_volume):
        '''
        create_cloned_volume

        :param volume:
        :param src_volume:
        :return:
        '''
        LOG.debug(_("[BRM-DRIVER] start create_cloned_volume()"))
        name = ''
        uuid = ''
        name = volume['name']
        model_update = {}
        volume['is_thin'] = True
        LOG.debug(_("[BRM-DRIVER] start create_cloned_volume()"))
        model_update = self.create_volume(volume)
        src_volume_name = src_volume['name']
        dest_volume_size = volume['size']
        src_volume_size = src_volume['size']
        if dest_volume_size != src_volume_size:
            raise exception.InvalidParameterValue(err=_('valid volume size'))

        dest_volume_uri, items = self._vrm_unpack_provider_location(model_update['provider_location'], 'uri')
        dest_volume_urn, items = self._vrm_unpack_provider_location(model_update['provider_location'], 'urn')
        src_vol_meta = src_volume.get('volume_metadata')
        src_vol_meta_dict = metadata_to_dict(src_vol_meta)
        src_volume_uri = src_vol_meta_dict.get('uri')

        LOG.info(_("dest_volume_uri is %s, src_volume_uri is %s") % (dest_volume_uri, src_volume_uri))

        dest_volume_id = dest_volume_uri.split('/')[len(dest_volume_uri.split('/')) - 1]
        src_volume_id = src_volume_uri.split('/')[len(src_volume_uri.split('/')) - 1]
        LOG.info(_("src_volume_id is [%s] dest vol id [%s]"), src_volume_id, dest_volume_id)

        args_dict = {}
        args_dict['src_volume_id'] = src_volume_id
        args_dict['dest_volume_urn'] = dest_volume_urn

        try:
            self.volume_proxy.clone_volume(**args_dict)
        except exception.CinderException as ex:
            volume['provider_location'] = model_update['provider_location']
            LOG.info(
                _("[CINDER-BRM] clone_volume exception , delete (%s)") % model_update['provider_location'])
            self.delete_volume(volume)
            raise ex
        return model_update

    def clone_image(self, volume, image_location, image_id, image_meta):
        '''
        clone_image

        :param volume:
        :param image_location:
        :param image_id:
        :param image_meta:
        :return:
        '''
        LOG.debug(_("[BRM-DRIVER] start clone_image [%s]") % image_id)

        properties = image_meta.get('properties', None)
        if properties is None:
            return None, False
        elif 'template' != properties.get('__image_source_type', None):
            LOG.debug(_("[BRM-DRIVER] image_type is not template"))
            return None, False
        else:
            LOG.debug(_("[BRM-DRIVER] image_type is template"))

        image_type = 'template'

        context = cinder_context.get_admin_context()
        args_dict = {}
        vol_size = int(volume.get('size'))
        min_disk = image_meta.get('min_disk')
        if min_disk:
            min_disk = int(min_disk)
            if min_disk < 4 and vol_size != min_disk:
                msg = _("[BRM-DRIVER] image is smaller than 4G and volume must equal image ")
                LOG.error(msg)
                raise exception.ImageUnacceptable(image_id=image_id,reason=msg)

        args_dict['image_id'] = image_id
        os_vol_id = volume.get('id')
        args_dict['volume_id'] = os_vol_id
        args_dict['volume_size'] = vol_size


        vol_meta = volume.get('volume_metadata')
        vol_meta_dict = metadata_to_dict(vol_meta)
        linked_clone = vol_meta_dict.get('linked_clone')
        if linked_clone is None:
            linked_clone = False
        elif str(linked_clone).lower() == 'true':
            linked_clone = True
        else:
            linked_clone = False

        LOG.info(_('[BRM-DRIVER] image_meta [%s]' % image_meta))

        hw_image_location = properties.get('__image_location', None)
        if hw_image_location is None or hw_image_location == "":
            msg = _('[BRM-DRIVER] hw_image_location is null')
            LOG.error(msg)
            raise exception.ImageUnacceptable(image_id=image_id,reason=msg)

        args_dict['image_location'] = hw_image_location
        LOG.debug(_('[BRM-DRIVER] image_location is %s') % args_dict['image_location'])

        args_dict['image_type'] = image_type

        ds_meta = {}
        try:
            ds_meta['ds_name'] = volume.get('host').split('#')[1]
        except exception.CinderException as ex:
            LOG.info(
                _("[CINDER-BRM] host format exception, host is %s ") % volume.get('host'))
            raise ex

        datastore = self._choose_datastore(ds_meta)
        if not datastore:
            LOG.info(_("[CINDER-VRM] datastore [%s],"), datastore)
            raise exception.InvalidParameterValue(err=_('invalid datastore'))

        args_dict['ds_urn'] = datastore.get('urn')
        is_thin = FC_DRIVER_CONF.vrm_is_thin
        is_thin = self.check_thin(datastore, is_thin)
        args_dict['is_thin'] = is_thin

        args_dict['cluster_urn'] = self.cluster_urn
        LOG.debug(_("[BRM-DRIVER] cluster_urn [%s]") % self.cluster_urn)

        if args_dict.get('volume_sequence_num') is None:
            args_dict['volume_sequence_num'] = 1

        LOG.info(_("[BRM-DRIVER] %s image_type is  template ") % image_id)
        if linked_clone:
            urn = self.vm_proxy.create_linkclone_from_template(**args_dict)
        else:
            urn = self.vm_proxy.create_volume_from_template(**args_dict)

        temp_str = str(urn)
        fc_vol_id = temp_str[temp_str.rfind(':') + 1:]

        share = volume.get('shareable')
        LOG.info('[BRM-DRIVER] shareable [%s]', share)
        if str(share).lower() == 'true':
            try:
                self.volume_proxy.modify_volume(volume_id=fc_vol_id, type='share')
            except Exception as ex:
                LOG.error(_("modify volume to share is failed "))
                self.delete_volume(volume)
                raise ex

        model_update, metadata = self._vrm_get_volume_meta(fc_vol_id)
        self.db.volume_metadata_update(context, os_vol_id, metadata, False)
        return model_update, True


    def copy_image_to_volume(self, context, volume, image_service, image_id):

        '''
        clone_image

        :param volume:
        :param image_location:
        :param image_id:
        :param image_meta:
        :return:
        '''
        LOG.debug(_("[BRM-DRIVER] start copy_image_to_volume [%s]") % image_id)
        image_meta = image_service.show(context, image_id)
        args_dict = {}
        vol_size = int(volume.get('size'))
        min_disk = image_meta.get('min_disk')
        if min_disk:
            min_disk = int(min_disk)
            if min_disk < 4 and vol_size != min_disk:
                msg = _("[BRM-DRIVER] image is smaller than 4G and volume must equal image ")
                LOG.error(msg)
                raise exception.ImageUnacceptable(image_id=image_id, reason=msg)

        args_dict['image_id'] = image_id
        os_vol_id = volume.get('id')
        args_dict['volume_id'] = os_vol_id
        args_dict['volume_size'] = vol_size
        args_dict['is_thin'] = FC_DRIVER_CONF.vrm_is_thin

        vol_meta = volume.get('volume_metadata')
        vol_meta_dict = metadata_to_dict(vol_meta)
        linked_clone = vol_meta_dict.get('linked_clone')
        args_dict['volume_urn'] = vol_meta_dict.get('urn')
        if linked_clone is None:
            linked_clone = False
        elif str(linked_clone).lower() == 'true':
            linked_clone = True
        else:
            linked_clone = False

        LOG.info(_('[BRM-DRIVER] image_meta [%s]' % image_meta))

        properties = image_meta.get('properties', None)
        if properties is None or properties == "":
            image_type = 'glance'
        else:
            args_dict['volume_sequence_num'] = properties.get('__sequence_num')
            image_type = properties.get('__image_source_type', None)
            types = ['template', 'nfs', 'uds', 'glance']

            if image_type is not None and image_type not in types:
                msg = _('[BRM-DRIVER]  image type is not support ')
                LOG.error(msg)
                raise exception.ImageUnacceptable(image_id=image_id, reason=msg)

            if image_type is None:
                image_type = 'glance'

            if image_type != 'glance':
                hw_image_location = properties.get('__image_location', None)
                if hw_image_location is None or hw_image_location == "":
                    msg = _('[BRM-DRIVER] hw_image_location is null')
                    LOG.error(msg)
                    raise exception.ImageUnacceptable(image_id=image_id, reason=msg)

                args_dict['image_location'] = hw_image_location
                LOG.debug(_('[BRM-DRIVER] image_location is %s') % args_dict['image_location'])

        args_dict['image_type'] = image_type
        ds_meta = {}
        try:
            ds_meta['ds_name'] = volume.get('host').split('#')[1]
        except exception.CinderException as ex:
            LOG.info(
                _("[CINDER-BRM] host format exception, host is %s ") % volume.get('host'))
            raise ex

        datastore = self._choose_datastore(ds_meta)
        if not datastore:
            LOG.info(_("[CINDER-VRM] datastore [%s],"), datastore)
            raise exception.InvalidParameterValue(err=_('found no datastore'))

        args_dict['ds_urn'] = datastore.get('urn')
        is_thin = FC_DRIVER_CONF.vrm_is_thin
        is_thin = self.check_thin(datastore, is_thin)
        args_dict['is_thin'] = is_thin

        args_dict['cluster_urn'] = self.cluster_urn
        LOG.debug(_("[BRM-DRIVER] self.cluster_urn [%s]") % self.cluster_urn)

        args_dict['auth_token'] = context.auth_token
        LOG.info(_("[BRM-DRIVER] %s image_type is %s") % (image_id, image_type))

        if args_dict.get('volume_sequence_num') is None:
            args_dict['volume_sequence_num'] = 1

        if linked_clone:
            urn = self.vm_proxy.create_linkClone_from_extend(**args_dict)
        else:
            try:
                temp_str = str(vol_meta_dict.get('urn'))
                fc_vol_id = temp_str[temp_str.rfind(':') + 1:]
                self.volume_proxy.modify_volume(volume_id=fc_vol_id, type='normal')
            except Exception as ex:
                LOG.error(_("modify volume to normal is failed "))
                self.delete_volume(volume)
                raise ex
            urn = self.vm_proxy.create_volume_from_extend(**args_dict)

        temp_str = str(urn)
        fc_vol_id = temp_str[temp_str.rfind(':') + 1:]
        model_update, metadata = self._vrm_get_volume_meta(fc_vol_id)

        share = volume.get('shareable')
        LOG.info('[BRM-DRIVER] shareable [%s]', share)
        if str(share).lower() == 'true':
            try:
                self.volume_proxy.modify_volume(volume_id=fc_vol_id, type='share')
            except Exception as ex:
                LOG.error(_("modify volume to share is failed "))
                self.delete_volume(volume)
                raise ex

        self.db.volume_metadata_update(context, os_vol_id, metadata, False)


    def _generate_image_metadata(self, min_disk, location, volume_sequence_num, os_option, instance):
        """

        :param name: image name
        :param location: image location
        :param os_option: os type and version
        :param instance:
        :return:
        """
        if volume_sequence_num is None:
            LOG.debug(_("volume_sequence_num is None"))
            volume_sequence_num = 1
        metadata = {'__image_location': location or '',
                    '__image_source_type': FC_DRIVER_CONF.export_image_type,
                    '__sequence_num': volume_sequence_num}
        if os_option is not None:
            if os_option.get('__os_version') is not None:
                metadata['__os_version'] = os_option.get('__os_version')

            if os_option.get('__os_type') is not None:
                metadata['__os_type'] = os_option.get('__os_type')

        LOG.debug(_("image metadata is: %s"), json.dumps(metadata))
        return {'properties': metadata, 'min_disk': min_disk}

    def _generate_image_location(self, image_id):
        """
        generate image location: '172.17.1.30:/image/base/uuid/uuid.ovf'
        :param image_id:
        :return:
        """
        if FC_DRIVER_CONF.export_image_type == 'nfs':
            fc_image_path = FC_DRIVER_CONF.fc_image_path
            if fc_image_path:
                format = 'xml' if FC_DRIVER_CONF.export_version == 'v1.2' else 'ovf'
                return '%s/%s/%s.%s' % (fc_image_path, image_id, image_id, format)
            else:
                LOG.debug(_("fc_image_path is null"))
        elif FC_DRIVER_CONF.export_image_type == 'uds':
            if FC_DRIVER_CONF.uds_ip is not None and FC_DRIVER_CONF.uds_port is not None \
                    and FC_DRIVER_CONF.uds_bucket_name is not None:
                return '%s:%s:%s:%s' % (FC_DRIVER_CONF.uds_ip,
                                                FC_DRIVER_CONF.uds_port,
                                                FC_DRIVER_CONF.uds_bucket_name,
                                                image_id)
            else:
                LOG.debug(_("uds_ip: %s, uds_port: %s, uds_bucket_name: %s"), FC_DRIVER_CONF.uds_ip,
                          FC_DRIVER_CONF.uds_port, FC_DRIVER_CONF.uds_bucket_name)
        else:
            return None

    def copy_volume_to_image(self, context, volume, image_service, image_meta):
        '''
        copy_volume_to_image

        :param context:
        :param volume:
        :param image_service:
        :param image_meta:
        :return:
        '''
        LOG.debug(_("[BRM-DRIVER] start copy_volume_to_image() "))

        fc_image_path = FC_DRIVER_CONF.fc_image_path
        image_id = image_meta.get('id')
        if '/' in str(image_id):
            image_id = image_id.split('/')[-1]
        volume_id = volume.get('id')
        vol_size = int(volume.get('size'))
        vol_meta = volume.get('volume_metadata')
        vol_meta_dict = metadata_to_dict(vol_meta)

        vol_image_meta = None
        try:
            vol_image_meta = self.volume_api.get_volume_image_metadata(
                context, volume)
        except exception.CinderException as ex:
            LOG.error(_('[BRM-DRIVER] get_volume_image_metadata is error'))

        vol_image_meta_dic = None
        if vol_image_meta:
            vol_image_meta_dic = dict(vol_image_meta.iteritems())


        args_dict = {}
        args_dict['volume_id'] = volume_id
        args_dict['volume_size'] = vol_size
        args_dict['image_id'] = image_id
        args_dict['image_url'] = fc_image_path

        share = volume.get('shareable')
        LOG.info('[BRM-DRIVER] shareable [%s]', share)
        if str(share).lower() == 'false':
            args_dict['shareable'] = 'normal'
        else:
            args_dict['shareable'] = 'share'

        if vol_meta_dict.get('urn') is None:
            msg = _('[BRM-DRIVER] urn is null')
            LOG.error(msg)
            raise exception.InvalidVolumeMetadata(reason=msg)

        args_dict['volume_urn'] = str(vol_meta_dict.get('urn'))
        LOG.info(_("volume_urn is %s") % args_dict['volume_urn'])

        if self.SHARED_HOSTS is None or len(self.SHARED_HOSTS) == 0:
            msg = _('[BRM-DRIVER] SHARED_HOSTS is none')
            LOG.error(msg)
            raise exception.VolumeDriverException(message=msg)

        LOG.debug(_("[BRM-DRIVER] cluster_urn  [%s]") % self.cluster_urn)

        args_dict['cluster_urn'] = self.cluster_urn
        name = image_service.show(context, image_id).get('name')
        args_dict['image_type'] = FC_DRIVER_CONF.export_image_type
        args_dict['auth_token'] = context.auth_token
        try:
            volume_sequence_num = self.vm_proxy.export_volume_to_image(**args_dict)
        except Exception as ex:
            LOG.debug(_("[BRM-DRIVER] deletedelete image id:[%s]") % image_id)
            image_service.delete(context, image_id)
            raise ex
        location = self._generate_image_location(image_id)
        metadata = self._generate_image_metadata(vol_size, location, volume_sequence_num, vol_image_meta_dic, None)
        if 'glance' != args_dict.get('image_type'):
            image_service.update(context, image_id, {}, data='/home/vhd/G1-1.vhd')
        image_service.update(context, image_id, metadata, purge_props=False)
        LOG.info(_('image %s  create success') % name)

    def attach_volume(self, context, volume_id, instance_uuid,
                      host_name_sanitized, mountpoint):
        '''
        attach_volume

        :param context:
        :param volume_id:
        :param instance_uuid:
        :param host_name_sanitized:
        :param mountpoint:
        :return:
        '''
        LOG.info(_("[BRM-DRIVER] start attach_volume(%s)"), volume_id)


    def detach_volume(self, context, volume):
        '''
        detach_volume

        :param context:
        :param volume:
        :return:
        '''
        LOG.debug(_("[BRM-DRIVER] start detach_volume(%s) "), volume)


    def initialize_connection(self, volume, connector):
        '''
        initialize_connection

        :param volume:
        :param connector:
        :return:
        '''
        LOG.debug(_("[BRM-DRIVER] start initialize_connection() "))
        connection = {'data': {}}
        LOG.debug('volume: %s', volume)
        admin_context = cinder_context.get_admin_context()
        vol_meta = self.db.volume_metadata_get(admin_context, volume['id'])
        connection['vol_urn'] = vol_meta['urn']
        return connection

    def terminate_connection(self, volume, connector, **kwargs):
        '''
        terminate_connection

        :param volume:
        :param connector:
        :param force:
        :return:
        '''
        LOG.debug(_("[BRM-DRIVER] start terminate_connection() "))
        LOG.debug(_("[BRM-DRIVER] terminate_connection() [%s] [%s] "), volume, connector)

    def retype(self, context, volume, new_type, diff, host):
        '''
        retype

        :param context:
        :param volume:
        :param new_type:
        :param diff:
        :param host:
        :return:
        '''
        LOG.info(_("[BRM-DRIVER] start retype() "))
        LOG.info(_(" new volume type [%s]"), new_type)

        args_dict = {}
        ds_storage_type = ''
        is_thin = FC_DRIVER_CONF.vrm_is_thin
        if str(is_thin).lower() == 'true':
            args_dict['migrate_type'] = 1
        else:
            args_dict['migrate_type'] = 2
        shareable = volume['shareable']
        if True == shareable:
            LOG.info(_("[BRM-DRIVER] shareable"))
            #TODO:???

        extra_specs = new_type.get('extra_specs')
        if extra_specs is None:
            LOG.info(_("[BRM-DRIVER] extra_specs is None"))
            return True, None
        new_backend_name = extra_specs.get('volume_backend_name')
        if new_backend_name is None:
            LOG.info(_("[BRM-DRIVER] new_backend_name is None"))
            return True, None

        vol_meta = volume.get('volume_metadata')
        vol_meta_dict = metadata_to_dict(vol_meta)
        linked_clone = vol_meta_dict.get('linked_clone')
        if linked_clone is not None:
            if str(linked_clone).lower() == 'true':
                msg = (_('linked volume can not be retyped. '))
                LOG.error(msg)
                raise exception.InvalidInput(reason=msg)


        snapshots = self.db.snapshot_get_all_for_volume(context, volume.get('id'))
        if len(snapshots):
            msg = _("Volume still has %d dependent snapshots") % len(snapshots)
            raise exception.InvalidVolume(reason=msg)


        try:
            source_ds_name = volume.get('host').split('#')[1]
        except exception.CinderException as ex:
            LOG.info(
                _("[CINDER-BRM] host format exception, host is %s ") % volume.get('host'))
            raise ex

        LOG.info(_(" source_ds_name [%s]"), source_ds_name)


        try:
            new_ds_name = volume_utils.extract_host(host['host'], 'pool')
        except exception.CinderException as ex:
            LOG.info(
                _("[CINDER-BRM] host format exception, host is %s ") % volume.get('host'))
            raise ex
        
        LOG.info(_(" new_ds_name [%s]"), new_ds_name)
        
        if source_ds_name == new_ds_name:
            LOG.info(_("[CINDER-BRM] source ds_name == dest ds_name"))
            return True, None

        datastores = self.datastore_proxy.list_datastore()
        for datastore in datastores:
            ds_name = datastore.get('name')
            if ds_name is not None:
                LOG.info(_(" ds_name [%s]"), ds_name)
                if new_ds_name == ds_name:
                    args_dict['dest_ds_urn'] = datastore.get('urn')
                    ds_storage_type = datastore.get('storageType')
                    LOG.info(_(" new_ds_name [%s]"), new_ds_name)
                    break

        vol_meta = volume.get('volume_metadata')
        vol_meta_dict = metadata_to_dict(vol_meta)
        volume_urn = vol_meta_dict.get('urn')
        args_dict['volume_urn'] = volume_urn
        fc_vol_id = volume_urn[volume_urn.rfind(':') + 1:]
        volume_body = self.volume_proxy.query_volume(id=fc_vol_id)
        source_ds_urn = volume_body['datastoreUrn']

        args_dict['volume_id'] = fc_vol_id
        args_dict['speed'] = 30

        if None == args_dict.get('dest_ds_urn'):
            LOG.info(_("[BRM-DRIVER] no dest_ds_urn"))
            return False, None
        else:
            if source_ds_urn == args_dict['dest_ds_urn']:
                LOG.info(_("[BRM-DRIVER] same ds [%s]"), source_ds_urn)
                return True, None
            vm_body = self.vm_proxy.query_vm_volume(**args_dict)
            if None == vm_body:
                self.volume_proxy.migrate_volume(**args_dict)
            else:
                vm_urn = vm_body.get('urn')
                vm_id = vm_urn[-10:]
                args_dict['vm_id'] = vm_id
                self.vm_proxy.migrate_vm_volume(**args_dict)

        LOG.info(_("[BRM-DRIVER] retype return"))
        return True, None

    def manage_existing(self, volume, existing_ref):
        """Brings an existing backend storage object under Cinder management.

        existing_ref is passed straight through from the API request's
        manage_existing_ref value, and it is up to the driver how this should
        be interpreted.  It should be sufficient to identify a storage object
        that the driver should somehow associate with the newly-created cinder
        volume structure.
        """

        LOG.debug(_("[BRM-DRIVER] start manage_existing() "))
        # TODO judge if register vol:
        metadata = dict((item['key'], item['value']) for item in volume['volume_metadata'])
        volInfoUrl = metadata.get('volInfoUrl', None)
        if volInfoUrl is None:
            LOG.debug(_("manage_existing: volInfoUrl is None"))
            raise driver_exception.FusionComputeDriverException()

        name = volume['name']
        uuid = volume['id']
        shareable = volume['shareable']
        if True == shareable:
            voltype = 'share'
        else:
            voltype = 'normal'

        quantity_GB = int(volume['size'])

        args_dict = {}
        args_dict['name'] = name
        args_dict['quantityGB'] = quantity_GB
        args_dict['type'] = voltype
        args_dict['volInfoUrl'] = volInfoUrl
        args_dict['uuid'] = uuid

        args_dict['maxReadBytes'] = 0
        args_dict['maxWriteBytes'] = 0
        args_dict['maxReadRequest'] = 0
        args_dict['maxWriteRequest'] = 0
        body = self.volume_proxy.manage_existing(**args_dict)

        model_update = {}
        temp_str = str(body.get('urn'))
        fc_vol_id = temp_str[temp_str.rfind(':') + 1:]
        model_update, metadata = self._vrm_get_volume_meta(id=fc_vol_id)
        context = cinder_context.get_admin_context()
        self.db.volume_metadata_update(context, uuid, metadata, False)

        return model_update

    def manage_existing_get_size(self, volume, existing_ref):
        """Return size of volume to be managed by manage_existing.
        When calculating the size, round up to the next GB.
        """
        vol_size = 0
        for meta in volume['volume_metadata']:
            LOG.error("meta: %s" % str(meta))
            if meta.key == 'quantityGB':
                vol_size = int(meta.value)
                break

        volume['size'] = vol_size

        return vol_size

    def unmanage(self, volume):
        """Removes the specified volume from Cinder management.

        Does not delete the underlying backend storage object.

        For most drivers, this will not need to do anything.  However, some
        drivers might use this call as an opportunity to clean up any
        Cinder-specific configuration that they have associated with the
        backend storage object.

        :param volume:
        :return:
        """

        LOG.debug(_("[BRM-DRIVER] start unmanage() "))
        vol_metas = volume['volume_metadata']

        provider_location = volume['provider_location']
        if provider_location is None or provider_location == '':
            LOG.error(_("[BRM-DRIVER]provider_location is null "))
            return
        volume_uri, items = \
            self._vrm_unpack_provider_location(volume['provider_location'], 'uri')
        self.volume_proxy.unmanage(volume_uri=volume_uri)

    def migrate_volume(self, context, volume, host):
        '''

        :param context:
        :param volume:
        :param host:
        :return:
        '''
        LOG.debug(_("[BRM-DRIVER] start migrate_volume() "))

        raise NotImplementedError()

    def copy_volume_data(self, context, src_vol, dest_vol, remote=None):
        '''

        :param context:
        :param src_vol:
        :param dest_vol:
        :param remote:
        :return:
        '''
        msg = (_('copy_volume_data. '))
        LOG.error(msg)
        raise NotImplementedError()

    def extend_volume(self,volume,new_size):
        '''
        extend_volume

        :param volume:
        :param new_size:
        :return:
        '''
        LOG.debug(_("[BRM-DRIVER] start extend_volume() "))
        vol_metas = volume['volume_metadata']
        if type(vol_metas) is not type(None):
            for meta in vol_metas:
                LOG.debug(_("[BRM-DRIVER] volume_metadata is [%s:%s] "), meta.key, meta.value)

        vol_meta = volume.get('volume_metadata')
        vol_meta_dict = metadata_to_dict(vol_meta)
        vol_uri = vol_meta_dict.get('uri')

        if vol_uri is not None:
            self.volume_proxy.extend_volume(volume_uri=vol_uri,size=new_size*1024)
        else:
            raise exception.ExtendVolumeError


    def backup_volume(self, context, backup, backup_service):
        """Create a new backup from an existing volume.
        backup['status']
        backup['object_count']
        backup['_sa_instance_state']
        backup['user_id']
        backup['service']:q

        backup['availability_zone']
        backup['deleted']
        backup['created_at']
        backup['updated_at']
        backup['display_description']
        backup['project_id']
        backup['host']
        backup['container']
        backup['volume_id']
        backup['display_name']
        backup['fail_reason']
        backup['deleted_at']
        backup['service_metadata']
        backup['id']
        backup['size']
        -------- -------- -------- --------
        backup['backup_type']
        backup['volume_name']
        backup['snap_name']
        backup['snap_id']
        backup['snap_parent_name']
        backup['snap_last_name']
        backup['clone_volume_name']
        backup['storage_ip']
        backup['storage_pool_id']
        backup['volume_offset']
        backup['incremental']
        backup['is_close_volume']
        backup['is_bootable']
        backup['image_id']

        backup['volume_size']
        volume_file
        backup_metadata

backup db:CREATED_AT | UPDATED_AT | DELETED_AT | DELETED
| ID | VOLUME_ID | USER_ID | PROJECT_ID | HOST | AVAILABILITY_ZONE
| DISPLAY_NAME | DISPLAY_DESCRIPTION | CONTAINER | STATUS | FAIL_REASON
| SERVICE_METADATA | SERVICE | SIZE | OBJECT_COUNT


snapshot db: CREATED_AT|UPDATED_AT|DELETED_AT| DELETED |ID |VOLUME_ID|USER_ID
  |PROJECT_ID| STATUS  | PROGRESS | VOLUME_SIZE | SCHEDULED_AT | DISPLAY_NAME
  | DISPLAY_DESCRIPTION | PROVIDER_LOCATION | ENCRYPTION_KEY_ID | VOLUME_TYPE_ID | CGSNAPSHOT_ID

        """
        vol_second_os = self.db.volume_get(context, backup['volume_id'])

        LOG.debug(('Creating a new bbackup for volume %s.') % vol_second_os['name'])
        kwargs = {}
        volume_file = {}
        if vol_second_os.get('snapshot_id') != backup['container']:
            LOG.error(_("snapshot id is %s") % vol_second_os.get('snapshot_id'))
            LOG.error(_("backup container is %s") % backup['container'])
            raise exception.InvalidSnapshot(reason="snapshot id not equal backup container")
    
        vol_meta = vol_second_os.get('volume_metadata')
        vol_meta_dict = metadata_to_dict(vol_meta)
        volume_urn = vol_meta_dict.get('urn')
        fc_vol_id = volume_urn[volume_urn.rfind(':') + 1:]
        vol_second_fc = self.volume_proxy.query_volume(id=fc_vol_id)

        volume_file['storage_type'] = 0
        volume_file['volume_name'] = vol_second_fc['volNameOnDev']
        last_snap_id_os = vol_second_os['snapshot_id']
        last_snap_id_fc = str(vol_second_os['snapshot_id']).replace('-', '')
        last_snap_os = self.db.snapshot_get(context, last_snap_id_os)
        vol_first_id = last_snap_os['volume_id']
        volume_file['source_volume_id'] = vol_first_id
        
        ext_params = vol_second_fc.get('drExtParams')
        LOG.info(_("[VRM-CINDER] ext_params [%s]"), ext_params)
        ext_params_dic = json.loads(vol_second_fc.get('drExtParams'))
        LOG.info(_("[VRM-CINDER] ext_params [%s]"), ext_params_dic)
        volume_file['storage_ip'] = ext_params_dic['dsMgntIp']
        volume_file['storage_pool_id'] = ext_params_dic['dsResourceId']

        LOG.info(_("[VRM-CINDER] volume_file [%s]"), volume_file)
        backup_list = self.db.backup_get_by_volume_id(context, vol_first_id)
        
        last_backup = None
        if backup_list is not None:
            for back_tmp in backup_list:
                if back_tmp['status'] != "avaiable":
                    continue
                if last_backup is None:
                    last_backup = back_tmp
                else:
                    if last_backup['created_at'] < back_tmp['created_at']:
                        last_backup = back_tmp
            
        if last_backup is None:
            volume_file['backup_type'] = 0
            volume_file['parent_id'] = None
            volume_file['parent_snapshot_url'] = None
        else:
            LOG.debug(_("last_backup %s") % last_backup['id'])
            volume_file['backup_type'] = 1
            volume_file['parent_id'] = last_backup['id']
            
            if last_backup['service_metadata'] is None:
                raise exception.InvalidVolumeMetadata(reason="backup service_metadata is none")
            
            service_meta = last_backup['service_metadata']
            service_meta_dict = metadata_to_dict(service_meta)
            parent_snapshot_id_os = service_meta_dict.get('snap_id')
            parent_snapshot_id_fc = str(parent_snapshot_id_os).replace('-', '')
            volume_file['parent_snapshot_url'] = 'http://' + ext_params_dic['dsMgntIp'] \
                                      + '/' + ext_params_dic['dsResourceId']\
                                      + '/' + parent_snapshot_id_fc

        LOG.debug(_("vol_first_id is %s") % vol_first_id)
        vol_first_os = self.db.volume_get(context, vol_first_id)
        vol_first_meta = vol_first_os.get('volume_metadata')
        vol_first_meta_dict = metadata_to_dict(vol_first_meta)
        volume_first_urn = vol_first_meta_dict.get('urn')
        fc_first_vol_id = volume_first_urn[volume_urn.rfind(':') + 1:]
        LOG.debug(_("fc_first_vol_id is %s") % fc_first_vol_id)
        
        vol_source_fc = self.volume_proxy.query_volume(id=fc_first_vol_id)
        LOG.debug(_("vol_source_fc linkCloneParent is %s") % vol_source_fc['linkCloneParent'])
        if vol_source_fc['linkCloneParent'] is not None:
            volume_file['is_clone_volume'] = True
            try:
                vol_linked_fc = self.volume_proxy.query_volume(id=vol_source_fc['linkCloneParent'])
                linked_ext_params_dic = json.loads(vol_linked_fc.get('drExtParams'))
                volume_file['clone_volume_url'] = 'http://' + linked_ext_params_dic['dsMgntIp'] \
                                      + '/' + linked_ext_params_dic['dsResourceId']\
                                      + '/' + vol_source_fc['linkCloneParent']
            except:
                LOG.error(_("clone colume not exit")) 
                volume_file['clone_volume_url'] = None
        else:
            volume_file['is_clone_volume'] = False
            volume_file['clone_volume_url'] = None
            
        volume_file['snapshot_name'] = last_snap_os['name']
        volume_file['snapshot_id'] = last_snap_id_fc

        LOG.debug(_("[VRM-CINDER] volume_file [%s]"), volume_file)

        volume_file['volume_size'] = vol_second_os['size']
        LOG.debug(_("[VRM-CINDER] volume_file [%s]"), volume_file)

        volume_file['snapshot_url'] = 'http://' + ext_params_dic['dsMgntIp'] \
                                      + '/' + ext_params_dic['dsResourceId']\
                                      + '/' + last_snap_id_fc

        volume_file['bootable'] = False
        volume_file['image_id'] = None
        vol_image_meta = None
        try:
            vol_image_meta = self.volume_api.get_volume_image_metadata(context, vol_second_os)
            vol_image_meta_dic = None
            if vol_image_meta:
                vol_image_meta_dic = dict(vol_image_meta.iteritems())
                volume_file['image_id'] = vol_image_meta_dic.get('image_id')
                volume_file['bootable'] = True

        except exception.CinderException as ex:
            LOG.error(_('[BRM-DRIVER] get_volume_image_metadata is error [%s]'), ex)

        LOG.info(_("[VRM-CINDER] volume_file [%s]"), volume_file)

        try:
            backup_service.backup(backup, volume_file)

        finally:
            LOG.debug(('cleanup for volume %s.') % vol_second_os['name'])

    def restore_backup(self, context, backup, volume, backup_service):
        """Restore an existing backup to a new or existing volume."""

        LOG.debug(('restore_backup for volume %s.') % volume['name'])
        volume_file = {}

        vol_meta = volume.get('volume_metadata')
        vol_meta_dict = metadata_to_dict(vol_meta)
        volume_urn = vol_meta_dict.get('urn')
        fc_vol_id = volume_urn[volume_urn.rfind(':') + 1:]
        vol_second_fc = self.volume_proxy.query_volume(id=fc_vol_id)

        volume_file['restore_type'] = 0
        volume_file['storage_type'] = 0
        volume_file['volume_url'] = vol_second_fc['volInfoUrl']

        LOG.info(_("[VRM-CINDER] volume_file [%s]"), volume_file)

        ext_params = vol_second_fc.get('drExtParams')
        LOG.info(_("[VRM-CINDER] ext_params [%s]"), ext_params)
        ext_params_dic = json.loads(vol_second_fc.get('drExtParams'))
        LOG.info(_("[VRM-CINDER] ext_params [%s]"), ext_params_dic)
        volume_file['storage_ip'] = ext_params_dic['dsMgntIp']
        volume_file['storage_pool_id'] = ext_params_dic['dsResourceId']
        volume_file['volume_offset'] = True
        volume_file['volume_name'] = vol_second_fc['volNameOnDev']


        if vol_second_fc['linkCloneParent'] is not None:
            try:
                vol_linked_fc = self.volume_proxy.query_volume(id=vol_second_fc['linkCloneParent'])
                linked_ext_params_dic = json.loads(vol_linked_fc.get('drExtParams'))
                volume_file['clone_volume_url'] = 'http://' + linked_ext_params_dic['dsMgntIp'] \
                                      + '/' + linked_ext_params_dic['dsResourceId']\
                                      + '/' + vol_second_fc['linkCloneParent']
            except:
                LOG.error(_("clone colume not exit")) 
                volume_file['clone_volume_url'] = None
        else:
            volume_file['clone_volume_url'] = None

        volume_file['lastest_snapshot_url'] = None


        try:
            backup_service.restore(backup, volume['id'], volume_file)

        finally:
            LOG.debug(('cleanup for volume %s.') % volume['name'])


