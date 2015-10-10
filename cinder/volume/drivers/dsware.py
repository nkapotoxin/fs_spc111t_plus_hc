# vim: tabstop=4 shiftwidth=4 softtabstop=4
"""
Driver for Huawei Dsware.

"""

import time
import os
import re

from oslo.config import cfg

from cinder import exception
#from cinder import flags
from cinder.image import image_utils
from cinder.openstack.common import log as logging
from cinder import utils
from cinder.volume import driver
#from cinder.volume import iscsi
from cinder.volume.drivers import fspythonapi

from cinder.openstack.common.gettextutils import _

LOG = logging.getLogger(__name__)

volume_opts = [
    cfg.BoolOpt('dsware_isthin',
                default=False,
                help='default isthin flag value'),
    cfg.StrOpt('dsware_manager',
                default='',
                help='dsware_manager ip addr for this cinder-volume'),
    cfg.StrOpt('fusionstorageagent',
                default='',
                help='dsware_agent ip addr range.'),
]

#FLAGS = flags.FLAGS
FLAGS = cfg.CONF
FLAGS.register_opts(volume_opts)

# class DSWAREDriver(object)::


class DSWAREDriver(driver.VolumeDriver):
    VERSION = '1.0'

    DSWARE_VOLUME_CREATE_SUCCESS_STATUS = 0
    DSWARE_VOLUME_DUPLICATE_VOLUME = 6
    DSWARE_VOLUME_CREATING_STATUS = 7

    def __init__(self, *args, **kwargs):
        super(DSWAREDriver, self).__init__(*args, **kwargs)
        self.dsware_client = fspythonapi.FSPythonApi()

    def check_for_setup_error(self):
        #lrk: check config file here.
        if not os.path.exists(fspythonapi.fsc_conf_file):
            LOG.error("dsware config file: %s not exists!")
            raise

    def do_setup(self, context):
        self.context = context
        try:
            specs = {}
            specs['volume_backend_name']=self.configuration.volume_backend_name
            old_volume_type = {}
            try:
                old_volume_type = self.db.volume_type_get_by_name(self.context, "dsware")
            except exception.VolumeTypeNotFoundByName:
                pass
            if old_volume_type != {}:
                self.db.volume_type_extra_specs_update_or_create(self.context, 
                                                                 old_volume_type['id'], 
                                                                 specs)  
            else:
                self.db.volume_type_create(self.context, dict(name="dsware", 
                                                          extra_specs=specs))
        except exception.VolumeTypeExists:
            LOG.info("dsware volume-type exist in db.")
        else:
            LOG.info("dsware volume-type create successfully.") 
            
        #lrk: create fsc_conf_file here.
        conf_info = ["manage_ip=%s" % FLAGS.dsware_manager,
                     "\n",
                     "vbs_url=%s" % FLAGS.fusionstorageagent]
        try:
            os.makedirs(os.path.dirname(fspythonapi.fsc_conf_file))
        except Exception:
            pass
                
        with open(fspythonapi.fsc_conf_file, 'w') as f:
            f.writelines(conf_info)
               
        LOG.debug(_("DSWARE Driver do_setup finish."))

    def _get_dsware_manage_ip(self,volume):
        volume_metadata = volume['volume_metadata']
        if volume_metadata is not None:
            for metadata in volume_metadata:
                if metadata.key.lower() == 'manager_ip':
                    return metadata.value.lower()

            msg = _("DSWARE get manager ip failed!")
            raise exception.VolumeBackendAPIException(data=msg % locals())
        else:
            msg = _("DSWARE get manager ip failed,volume metadata is null!")
            raise exception.VolumeBackendAPIException(data=msg % locals())
            
    def _create_volume(self, volume_id, volume_size, isThin):
        pool_id = 0
        result = self.dsware_client.create_volume(
            volume_id, pool_id, volume_size, isThin)
        if result != 0:
            msg = _("DSWARE Create Volume failed! %(result)s")
            raise exception.VolumeBackendAPIException(data=msg % locals())

    def create_volume(self, volume):
        # Creates a volume in dsware
        LOG.debug(_("begin to create volume in dsware: %s") % volume['name'])
        volume_id = volume['name']
        volume_size = volume['size']
        is_thin = FLAGS.dsware_isthin
        volume_metadata = volume['volume_metadata']
        if volume_metadata is not None:
            for metadata in volume_metadata:
                if metadata.key.lower() == 'isthin' and metadata.value.lower() == 'true':
                    is_thin = True
                else:
                    is_thin = False
        # change GB to MB
        volume_size = volume_size * 1024
        self._create_volume(volume_id, volume_size, is_thin)

        dsw_manager_ip=self.dsware_client.get_manage_ip()
        meta_data = {}
        if volume_metadata is not None:
            for metadata in volume_metadata:
                meta_data.update({metadata.key:metadata.value})
        meta_data.update({"manager_ip" : dsw_manager_ip})
        return {"metadata":meta_data}

    def _create_volume_from_snap(self, volume_id, volume_size, snapshot_name):
        result = self.dsware_client.create_volume_from_snap(
            volume_id, volume_size, snapshot_name)
        if result != 0:
            msg = _("DSWARE:create volume from snap failed: %(result)s")
            raise exception.VolumeBackendAPIException(data=msg % locals())

    def create_volume_from_snapshot(self, volume, snapshot):
        # Creates a volume from snapshot
        volume_id = volume['name']
        volume_size = volume['size']
        snapshot_name = snapshot['name']
        volume_metadata = volume['volume_metadata']
        if volume_size < int(snapshot['volume_size']):
            msg = _("DSWARE:volume size can not be less than snapshot size")
            raise exception.VolumeBackendAPIException(data=msg % locals())

        volume_size = volume_size * 1024
        self._create_volume_from_snap(volume_id, volume_size, snapshot_name)

        dsw_manager_ip=self.dsware_client.get_manage_ip()
        meta_data = {}
        if volume_metadata is not None:
            for metadata in volume_metadata:
                meta_data.update({metadata.key:metadata.value})
        meta_data.update({"manager_ip" : dsw_manager_ip})
        return {"metadata":meta_data}

    def create_cloned_volume(self, volume, src_volume):
        '''
        dispatcher to dsware client create_volume_from_volume
        wait volume create finished
        '''
        volume_name = volume['name']
        volume_size = volume['size']
        src_volume_name = src_volume['name']
        src_volume_size = src_volume['size']
        src_volume_status = src_volume['status']
        volume_metadata = volume['volume_metadata']

        # FIXME(chenrui): check volume status
        if src_volume_status not in ['available','in-use']:
            msg = _('Cannot clone volume %(volume_name)s '
                    ' from src volume %(src_volume_name)s status %(src_volume_status)s')
            LOG.error(msg % locals())
            raise exception.VolumeBackendAPIException(data=msg % locals())

        if volume_size < src_volume_size:
            msg = _('Cannot clone volume %(volume_name)s of size %(volume_size)s'
                    ' from src volume %(src_volume_name)s of size %(src_volume_size)s')
            LOG.error(msg % locals())
            raise exception.VolumeBackendAPIException(data=msg % locals())

        volume_size = volume_size * 1024
        result = self.dsware_client.create_volume_from_volume(
            volume_name, volume_size, src_volume_name)
        if result:
            msg = _('Clone volume %(volume_name)s failed')
            raise exception.VolumeBackendAPIException(data=msg % locals())

        LOG.debug(_(
            'dsware_client.create_volume_from_volume, %(volume_name)s %(volume_size)s %(src_volume_name)s start') % locals())

        self._wait_for_create_cloned_volume_finish(volume_name)

        LOG.debug(_(
            'dsware_client.create_volume_from_volume, %(volume_name)s %(volume_size)s %(src_volume_name)s end') % locals())

        dsw_manager_ip=self.dsware_client.get_manage_ip()
        meta_data = {}
        if volume_metadata is not None:
            for metadata in volume_metadata:
                meta_data.update({metadata.key:metadata.value})
        meta_data.update({"manager_ip" : dsw_manager_ip})
        return {"metadata":meta_data}

    def _wait_for_create_cloned_volume_finish(self, new_volume_name):
        '''
        query new volume status until volume create success or fail
        '''
        count = 0
        while True:
            current_volume = self.dsware_client.query_volume(new_volume_name)

            if current_volume:
                status = current_volume['status']
                LOG.debug(
                    _('wait cloned volume, %(new_volume_name)s %(status)s') %
                    locals())

                if int(status) == self.DSWARE_VOLUME_CREATING_STATUS or int(
                        status) == self.DSWARE_VOLUME_DUPLICATE_VOLUME:
                    time.sleep(5)
                elif int(status) == self.DSWARE_VOLUME_CREATE_SUCCESS_STATUS:
                    break
                else:
                    msg = _('Clone volume %(new_volume_name)s failed')
                    LOG.error(msg % locals())
                    raise exception.VolumeBackendAPIException(
                        data=msg %
                        locals())
            # can't find volume
            else:
                LOG.warn(
                    _('can not find volume %(new_volume_name) from dsware') %
                    locals())
                count = count + 1
                if count == 10:
                    msg = _(
                        "DSWARE clone volume failed:volume can not find from dsware")
                    raise exception.VolumeBackendAPIException(
                        data=msg %
                        locals())
                time.sleep(5)

    def _analyse_output(self, out):
        if out is not None:
            analyse_result = {}
            out_temp = out.split('\n')
            for line in out_temp:
                if re.search('^ret_code=', line):
                    analyse_result['ret_code'] = line[9:]
                elif re.search('^ret_desc=', line):
                    analyse_result['ret_desc'] = line[9:]
                elif re.search('^dev_addr=', line):
                    analyse_result['dev_addr'] = line[9:]
            return analyse_result
        else:
            return None

    def _attach_volume(self, volume_name,dsw_manager_ip):
        cmd = ['vbs_cli', '-c', 'attachwithip', '-v', volume_name, '-i', dsw_manager_ip.replace('\n','') , '-p' , 0]
        out, err = self._execute(*cmd, run_as_root=True)
        analyse_result = self._analyse_output(out)
        LOG.debug(_("_attach_volume out is %s") % analyse_result)
        return analyse_result

    def _detach_volume(self, volume_name,dsw_manager_ip):
        cmd = ['vbs_cli', '-c', 'detachwithip', '-v', volume_name, '-i', dsw_manager_ip.replace('\n','') , '-p' , 0]
        out, err = self._execute(*cmd, run_as_root=True)
        analyse_result = self._analyse_output(out)
        LOG.debug(_("_detach_volume out is %s") % analyse_result)
        return analyse_result

    def _query_volume_attach(self, volume_name,dsw_manager_ip):
        cmd = ['vbs_cli', '-c', 'querydevwithip', '-v', volume_name, '-i', dsw_manager_ip.replace('\n','') , '-p' , 0]
        out, err = self._execute(*cmd, run_as_root=True)
        analyse_result = self._analyse_output(out)
        LOG.debug(_("_query_volume_attach out is %s") % analyse_result)
        return analyse_result

    def copy_image_to_volume(self, context, volume, image_service, image_id):
        # Copy image to volume
        # step1 attach volume to host
        LOG.debug(_("begin to copy image to volume"))
        dsw_manager_ip=self._get_dsware_manage_ip(volume)
        volume_attach_result = self._attach_volume(volume['name'],dsw_manager_ip)
        volume_attach_path = ''
        if volume_attach_result is not None and int(volume_attach_result['ret_code']) == 0:
            volume_attach_path = volume_attach_result['dev_addr']
            LOG.debug(_("volume_attach_path is %s") % volume_attach_path)
        if volume_attach_path == '':
            msg = _("host attach volume failed")
            raise exception.VolumeBackendAPIException(data=msg % locals())
            # step2 fetch the image from image_service and write it to the
            # volume.
        try:     
            image_utils.fetch_to_raw(context,
                                 image_service,
                                 image_id,
                                 volume_attach_path,
                                 self.configuration.volume_dd_blocksize)
        finally:  
            # step3 detach volume from host
            dsw_manager_ip=self._get_dsware_manage_ip(volume)
            volume_detach_result = self._detach_volume(volume['name'],dsw_manager_ip)
            if volume_detach_result is not None and int(volume_detach_result['ret_code']) != 0:
                msg = _(
                    "DSware detach volume from host failed: %(volume_detach_result['ret_desc'])s")
                raise exception.VolumeBackendAPIException(data=msg % locals())

    def copy_volume_to_image(self, context, volume, image_service, image_meta):
        # copy volume to image
        # step1 if volume was not attached,then attach it.

        dsw_manager_ip=self._get_dsware_manage_ip(volume)
        
        already_attached = True
        _attach_result = self._attach_volume(volume['name'],dsw_manager_ip)
        if _attach_result:
            retcode = _attach_result['ret_code']
            if int(retcode) == 50151401:
                already_attached = False
                result = self._query_volume_attach(volume['name'],dsw_manager_ip)
                if not result or int(result['ret_code']) != 0:
                    msg = "_query_volume_attach failed. result=%s" % result
                    raise exception.VolumeBackendAPIException(data=msg) 
                          
            elif int(retcode) == 0:
                result = _attach_result                
            else:
                msg = _(
                    "attach volume to host failed in copy volume to image: %s" % retcode)
                raise exception.VolumeBackendAPIException(data=msg)
            
            volume_attach_path = result['dev_addr']
            
        else:
            LOG.error("attach_volume failed.")
            raise exception.VolumeBackendAPIException(data=msg % locals())
        
        try:
            image_utils.upload_volume(context,
                                      image_service,
                                      image_meta,
                                      volume_attach_path)
        except Exception as e:
            LOG.error("upload_volume error, details: %s" % e)
            raise e        
        finally:
            if already_attached:
                self._detach_volume(volume['name'],dsw_manager_ip)
        
    def _get_volume(self, volume_name):
        result = self.dsware_client.query_volume(volume_name)
        LOG.debug(_("result['result'] is %s") % result['result'])
        if result['result'] == "50150005\n":
            LOG.debug(_("DSWARE get volume,volume is not exist."))
            return False
        elif result['result'] == 0:
            return True
        else:
            msg = _("DSWARE get volume failed!")
            raise exception.VolumeBackendAPIException(data=msg % locals())

    def _delete_volume(self, volume_name):
        # step1 detach volume from host before delete volume
        # self._detach_volume(volume_name,dsw_manager_ip)
        # step2 delete volume
        result = self.dsware_client.delete_volume(volume_name)
        LOG.debug(_("DSWARE delete volume,result is %s") % result)
        if result == '50150005\n':
            LOG.debug(_("DSWARE delete volume,volume is not exist."))
            return True
        elif result == '50151002\n':
            LOG.debug(_("DSWARE delete volume,volume is being deleted."))
            return True
        elif result == 0:
            return True
        else:
            msg = _("DSWARE delete volume failed:%(result)s")
            raise exception.VolumeBackendAPIException(data=msg % locals())

    def delete_volume(self, volume):
        # delete volume
        # step1 if volume is not exist,then return
        LOG.debug(_("begin to delete volume in DSWARE: %s") % volume['name'])
        if not self._get_volume(volume['name']):
            return True

        return self._delete_volume(volume['name'])

    def _get_snapshot(self, snapshot_name):
        snapshot_info = self.dsware_client.query_snap(snapshot_name)
        LOG.debug(_("_get_snapshot snapshot_info is : %s"), snapshot_info)
        if snapshot_info['result'] == "50150006\n":
            msg = _('Snapshot : %(snapshot_name)s not found')
            LOG.error(msg % locals())
            return False
        elif snapshot_info['result'] == 0:
            return True
        else:
            msg = _("DSWARE get snapshot failed!")
            raise exception.VolumeBackendAPIException(data=msg % locals())

    def _create_snapshot(self, snapshot_id, volume_id):
        LOG.debug(_("_create_snapshot %s to Dsware") % snapshot_id)
        smart_flag = 0
        res = self.dsware_client.create_snapshot(snapshot_id,
                                                 volume_id,
                                                 smart_flag)
        if res != 0:
            msg = _("DSWARE Create Snapshot failed! %(res)s")
            raise exception.VolumeBackendAPIException(data=msg % locals())

    def _delete_snapshot(self, snapshot_id):
        LOG.debug(_("_delete_snapshot %s to Dsware"), snapshot_id)
        res = self.dsware_client.delete_snapshot(snapshot_id)
        LOG.debug(_("_delete_snapshot res is : %s"), res)
        if res != 0:
            raise exception.SnapshotIsBusy(snapshot_name=snapshot_id)

    def create_snapshot(self, snapshot):
        vol_id = 'volume-%s' % snapshot['volume_id']
        snapshot_id = snapshot['name']
        if not self._get_volume(vol_id):
            msg = _('Create Snapshot volume : %(vol_id)s not found')
            LOG.error(msg % locals())
            raise exception.VolumeNotFound(volume_id=vol_id)
        else:
            self._create_snapshot(snapshot_id, vol_id)

    def delete_snapshot(self, snapshot):
        LOG.debug(_("delete_snapshot %s"), snapshot['name'])
        snapshot_id = snapshot['name']
        if not self._get_snapshot(snapshot_id):
            return
        else:
            self._delete_snapshot(snapshot_id)

    def _update_volume_status(self):
        status = {}
        status['volume_backend_name'] = self.configuration.volume_backend_name
        status['vendor_name'] = 'Open Source'
        status['driver_version'] = self.VERSION
        status['storage_protocol'] = 'dsware'

        status['total_capacity_gb'] = 0
        status['free_capacity_gb'] = 0
        status['reserved_percentage'] = self.configuration.reserved_percentage
        status['QoS_support'] = False
        pool_id = 0
        pool_info = self.dsware_client.query_pool_info(pool_id)
        result = pool_info['result']
        if result == 0:
            status['total_capacity_gb'] = float(pool_info['total_capacity'])/1024
            status['free_capacity_gb'] = (float(
                pool_info['total_capacity']) - float(pool_info['used_capacity']))/1024
            LOG.debug(_("total_capacity_gb is %s, free_capacity_gb is %s") % (
                status['total_capacity_gb'], status['free_capacity_gb']))
            self._stats = status
        else:
            self._stats = None

    def get_volume_stats(self, refresh=False):
        if refresh:
            self._update_volume_status()
        return self._stats

    def extend_volume(self, volume, new_size):
        # extend volume in dsware
		# two results:(1)extend successfully (2)any other results would be exception
        LOG.debug("begin to extend volume in dsware: %s" % volume['name'])
        volume_id = volume['name']
        if volume['size'] > new_size:
            msg = "DSWARE extend Volume failed! New size should be greater than old size!"
            raise exception.VolumeBackendAPIException(data = msg)
        # change GB to MB
        volume_size = new_size * 1024
        result = self.dsware_client.extend_volume(volume_id, volume_size)
        if result != 0:
            msg = "DSWARE extend Volume failed! %s"
            raise exception.VolumeBackendAPIException(data=msg % (result))
    


class DSWARELocalDriver(DSWAREDriver):
    """use Dsware local driver"""

    def __init__(self, *args, **kwargs):
        super(DSWARELocalDriver, self).__init__(*args, **kwargs)

    def initialize_connection(self, volume, connector):
        """update volume host, ensure volume to image ok"""
        LOG.debug(_("begin initialize_connection"))
        model_update = {}

        model_update['host'] = connector['host']

        #self.db.volume_update(self.context, volume['id'], model_update)

        properties = {}
        properties['volume_name'] = volume['name']
        properties['volume'] = volume
        properties['dsw_manager_ip'] = self._get_dsware_manage_ip(volume)

        LOG.debug(_("end initialize_connection %s") % properties)

        return {
            'driver_volume_type': 'dsware',
            'data': properties
        }

    def terminate_connection(self, volume, connector, force=False, **kwargs):
        pass

    def create_export(self, context, volume):
        pass

    def ensure_export(self, context, volume):
        pass

    def remove_export(self, context, volume):
        pass


