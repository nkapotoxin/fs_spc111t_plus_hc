#!/usr/bin/python
# coding=utf-8



"""
 Volume api for FusionStorage systems.
"""
import os
import re
from cinder.openstack.common import log as logging

import subprocess
import time
from cinder.openstack.common.gettextutils import _

LOG = logging.getLogger(__name__)
fsc_conf_file="/etc/cinder/volumes/fsc_conf"
fsc_cli="fsc_cli"
fsc_ip=[]
fsc_port='10519'
manage_ip="127.0.0.1"


volume_info = {
    'result': '',
    'vol_name':'',
    'father_name':'',
    'status':'',
    'vol_size':'',
    'real_size':'',
    'pool_id':'',
    'create_time':''}


snap_info = {
    'result': '',
    'snap_name':'',
    'father_name':'',
    'status':'',
    'snap_size':'',
    'real_size':'',
    'pool_id':'',
    'delete_priority':'',
    'create_time':''}


pool_info = {
    'result': '',
    'pool_id':'',
    'total_capacity':'',
    'used_capacity':'',
    'alloc_capacity':''}

class FSPythonApi(object):

    def __init__(self):
        LOG.debug(_("FSPythonApi init"))
        self.get_ip_port()
        

    def get_ip_port(self):
        LOG.debug(_("fsc_conf_file is %s") %fsc_conf_file)
        if os.path.exists(fsc_conf_file):
            try:
                fsc_file = open(fsc_conf_file, 'r')
                full_txt = fsc_file.readlines()
                LOG.debug(_("full_txt is %s") %full_txt)
                for line in full_txt:
                    if re.search('^vbs_url=', line):
                        tmp_vbs_url=line[8:]
                        return re.split(',', tmp_vbs_url)
            except Exception, e:
                LOG.debug(_("get fsc ip failed,error=%s")%(e))
            finally:
                fsc_file.close()
        else:
            LOG.debug(_("fsc conf file no exist,file_name=%s")%(fsc_conf_file))

    def get_manage_ip(self):
        LOG.debug(_("fsc_conf_file is %s") %fsc_conf_file)
        if os.path.exists(fsc_conf_file):
            try:
                fsc_file = open(fsc_conf_file, 'r')
                full_txt = fsc_file.readlines()
                for line in full_txt:
                    if re.search('^manage_ip=', line):
                        manage_ip=line[10:]
                        manage_ip = manage_ip.strip('\n')
                        return manage_ip
            except Exception, e:
                LOG.debug(_("get manage ip failed,error=%s")%(e))
            finally:
                fsc_file.close()
        else:
            LOG.debug(_("fsc conf file no exist,file_name=%s")%(fsc_conf_file))

    def get_dsw_manage_ip(self):
        return manage_ip

    def execute(self,cmd):

        result = None
        try:
            result = os.popen(cmd).readlines()
            LOG.debug(_("result is %s") %result)
            return result
        except Exception, e:
            print "execute cmd failed,error=%s"%(e)
            return None
        finally:
            pass

    def start_execute_cmd(self,cmd,type):

        fsc_ip = self.get_ip_port()
        manage_ip = self.get_manage_ip()
        ip_num = len(fsc_ip)

        LOG.debug(_("fsc_ip is %s") %fsc_ip)

        if ip_num <= 0:
            return None

        if ip_num > 3:
            ip_num = 3


        exec_result=''
        result=''
        if type:
            for ip in fsc_ip:
                cmd_args=''
                ip.replace('\n','')
                cmd_args ='sudo cinder-rootwrap /etc/cinder/rootwrap.conf ' + fsc_cli + ' '+ '--ip' + ' '+ ip.replace('\n','') + ' '+ '--manage_ip' + ' '+ manage_ip.replace('\n','') + ' '+ '--port' + ' '+ fsc_port + ' '+ cmd
                
                LOG.debug(_("DSWARE cmd_args is %s") %cmd_args)
            
                exec_result=self.execute(cmd_args)
                if exec_result:
                    for line in exec_result:
                        if re.search('^result=0', line): 
                            return exec_result
                        elif re.search('^result=50150007', line):
                            return 'result=0'
                        elif re.search('^result=50150008', line):
                            return 'result=0'
                        elif re.search('^result=50', line):
                            return exec_result
            return exec_result
        else:
            
            for ip in fsc_ip:
                cmd_args=''
                ip.replace('\n','')
                cmd_args = 'sudo cinder-rootwrap /etc/cinder/rootwrap.conf ' + fsc_cli + ' '+ '--ip' + ' '+ ip.replace('\n','') + ' '+ '--manage_ip' + ' '+ manage_ip.replace('\n','') + ' '+ '--port' + ' '+ fsc_port + ' '+ cmd

                LOG.debug(_("DSWARE cmd_args is %s") %cmd_args)
            
                exec_result=self.execute(cmd_args)
                if exec_result:
                    for line in exec_result:
                        if re.search('^result=', line): 
                            result=line
                            if re.search('^result=0', line):
                                return line
                            elif re.search('^result=50150007', line):
                                return 'result=0'
                            elif re.search('^result=50150008', line):
                                return 'result=0'
                            elif re.search('^result=50', line):
                                return line
            return result


    def create_volume(self,vol_name,pool_id,vol_size,thin_flag):
   
        cmd=''
        cmd = '--op create_vol' + ' ' + '--volume' + ' ' + vol_name + ' ' + '--pool' + ' ' + str(pool_id)  + ' ' + '--size' + ' ' + str(vol_size) + ' ' + '--thin' + ' ' + str(thin_flag)

        exec_result=self.start_execute_cmd(cmd,0)
        if exec_result:
            if re.search('^result=0', exec_result):
                return 0
            else:
                return  exec_result[7:]
        else:
            return 1

    def extend_volume(self, vol_name, new_vol_size):
        cmd = ''
        cmd = ('--op update_vol_size' + ' ' + '--volume') \
              + (' ' + vol_name + ' ' + '--size' + ' ' + str(new_vol_size))
        
        exec_result = self.start_execute_cmd(cmd, 0)
        if exec_result:
            if re.search('^result=0', exec_result):
                return 0
            else:
                return exec_result[7:]
        else:
            return 1

    def create_volume_from_snap(self,vol_name,vol_size,snap_name):
        cmd=''
        cmd = '--op create_vol_from_snap' + ' ' + '--volume' + ' ' + vol_name + ' ' + '--snap' + ' ' + snap_name  + ' ' + '--size' + ' ' + str(vol_size) 

        exec_result=self.start_execute_cmd(cmd,0)
        if exec_result:
            if re.search('^result=0', exec_result):
                return 0
            else:
                return  exec_result[7:]
        else:
            return 1


    def create_fullvol_from_snap(self,vol_name,snap_name):
        cmd=''
        cmd = '--op create_fullvol_from_snap' + ' ' + '--volume' + ' ' + vol_name + ' ' + '--snap' + ' ' + snap_name 

        exec_result=self.start_execute_cmd(cmd,0)
        if exec_result:
            if re.search('^result=0', exec_result):
                return 0
            else:
                return  exec_result[7:]
        else:
            return 1


    def create_volume_from_volume(self,vol_name,vol_size,src_vol_name):
        
        retcode=1
        tmp_snap_name=str(vol_name)+'_tmp_snap'

        retcode=self.create_snapshot(tmp_snap_name,src_vol_name,0)
        if 0 != retcode:
            return retcode


        retcode=self.create_volume(vol_name,0,vol_size,0)
        if 0 != retcode:
            self.delete_snapshot(tmp_snap_name)
            return retcode


        retcode=self.create_fullvol_from_snap(vol_name,tmp_snap_name)
        if 0 != retcode:
            self.delete_snapshot(tmp_snap_name)
            self.delete_volume(vol_name)
            return retcode

        return 0

    def create_clone_volume_from_volume(self,vol_name,vol_size,src_vol_name):
        
        retcode=1
        tmp_snap_name=str(src_vol_name)+'_DT_clnoe_snap'

        retcode=self.create_snapshot(tmp_snap_name,src_vol_name,0)

        retcode=self.create_volume_from_snap(vol_name,vol_size,tmp_snap_name)
        if 0 != retcode:
            return retcode

        return 0

    def volume_info_analyze(self,vol_info):
        
        local_volume_info=volume_info

        if not vol_info:
            local_volume_info['result']=1
            return local_volume_info

        local_volume_info['result']=0
        
        vol_info_list=[]
        vol_info_list=re.split(',', vol_info)
        for line in vol_info_list:
            line.replace('\n','')
            if re.search('^vol_name=', line):
                local_volume_info['vol_name']=line[9:] 
            elif re.search('^father_name=', line):
                local_volume_info['father_name']=line[12:] 
            elif re.search('^status=', line):
                local_volume_info['status']=line[7:] 
            elif re.search('^vol_size=', line):
                local_volume_info['vol_size']=line[9:] 
            elif re.search('^real_size=', line):
                local_volume_info['real_size']=line[10:] 
            elif re.search('^pool_id=', line):
                local_volume_info['pool_id']=line[8:] 
            elif re.search('^create_time=', line):
                local_volume_info['create_time']=line[12:] 
            else:
                print "analyze key is no exist,key=%s"%(str(line))
        return local_volume_info

    def query_volume(self,vol_name):
        
        tmp_volume_info=volume_info
        cmd=''
        cmd = '--op query_vol' + ' ' + '--volume' + ' ' + vol_name

        exec_result=self.start_execute_cmd(cmd,1)
        if exec_result:
            for line in exec_result:
                if re.search('^result=', line):
                    if not re.search('^result=0', line):
                        tmp_volume_info['result']=line[7:]
                        return tmp_volume_info
                    for line in exec_result:
                        if re.search('^vol_name='+vol_name, line):
                            tmp_volume_info=self.volume_info_analyze(line)
                            if str(0)==tmp_volume_info['status']:
                                tmp_snap_name=str(vol_name)+'_tmp_snap'
                                self.delete_snapshot(tmp_snap_name)
                            return tmp_volume_info

        tmp_volume_info['result']=1
        return tmp_volume_info


    def delete_volume(self,vol_name):
        cmd=''
        cmd = '--op del_vol' + ' ' + '--volume' + ' ' + vol_name

        exec_result=self.start_execute_cmd(cmd,0)
        if exec_result:
            if re.search('^result=0', exec_result):
                return 0
            else:
                return  exec_result[7:]
        else:
            return 1


    def create_snapshot(self,snap_name,vol_name,smart_flag):
        cmd=''
        cmd = '--op create_snap' + ' ' + '--volume' + ' ' + vol_name + ' ' + '--snap' + ' ' + snap_name  + ' ' + '--smart' + ' ' + str(smart_flag) 

        exec_result=self.start_execute_cmd(cmd,0)
        if exec_result:
            if re.search('^result=0', exec_result):
                return 0
            else:
                return  exec_result[7:]
        else:
            return 1

    def snap_info_analyze(self,info):
        
        local_snap_info=snap_info

        if not info:
            local_snap_info['result']=1
            return local_snap_info

        local_snap_info['result']=0
        
        snap_info_list=[]
        snap_info_list=re.split(',', info)
        for line in snap_info_list:
            line.replace('\n','')
            if re.search('^snap_name=', line):
                local_snap_info['snap_name']=line[10:] 
            elif re.search('^father_name=', line):
                local_snap_info['father_name']=line[12:] 
            elif re.search('^status=', line):
                local_snap_info['status']=line[7:] 
            elif re.search('^snap_size=', line):
                local_snap_info['snap_size']=line[10:] 
            elif re.search('^real_size=', line):
                local_snap_info['real_size']=line[10:] 
            elif re.search('^pool_id=', line):
                local_snap_info['pool_id']=line[8:]
            elif re.search('^delete_priority=', line):
                local_snap_info['delete_priority']=line[16:]
            elif re.search('^create_time=', line):
                local_snap_info['create_time']=line[12:] 
            else:
                print "analyze key is no exist,key=%s"%(str(line))

        return local_snap_info


    def query_snap(self,snap_name):
        
        tmp_snap_info=snap_info
        cmd=''
        cmd = '--op query_snap' + ' ' + '--snap' + ' ' + snap_name

        exec_result=self.start_execute_cmd(cmd,1)
        if exec_result:
            for line in exec_result:
                if re.search('^result=', line):
                    if not re.search('^result=0', line):
                        tmp_snap_info['result']=line[7:]
                        return tmp_snap_info
                    for line in exec_result:
                        if re.search('^snap_name='+snap_name, line):
                            tmp_snap_info=self.snap_info_analyze(line)
                            return tmp_snap_info

        tmp_snap_info['result']=1
        return tmp_snap_info


    def delete_snapshot(self,snap_name):
        cmd=''
        cmd = '--op del_snap' + ' ' + '--snap' + ' ' + snap_name

        exec_result=self.start_execute_cmd(cmd,0)
        if exec_result:
            if re.search('^result=0', exec_result):
                return 0
            else:
                return  exec_result[7:]
        else:
            return 1

    def pool_info_analyze(self,info):
        
        local_pool_info=pool_info

        if not info:
            local_pool_info['result']=1
            return local_pool_info

        local_pool_info['result']=0

        pool_info_list=[]
        pool_info_list=re.split(',', info)
        for line in pool_info_list:
            line.replace('\n','')
            if re.search('^pool_id=', line):
                local_pool_info['pool_id']=line[8:] 
            elif re.search('^total_capacity=', line):
                local_pool_info['total_capacity']=line[15:] 
            elif re.search('^used_capacity=', line):
                local_pool_info['used_capacity']=line[14:] 
            elif re.search('^alloc_capacity=', line):
                local_pool_info['alloc_capacity']=line[15:] 
            else:
                print "analyze key is no exist,key=%s"%(str(line))
        return local_pool_info


    def query_pool_info(self,pool_id):
        
        tmp_pool_info=pool_info
        cmd=''
        cmd = '--op query_pool_cap' + ' ' + '--pool' + ' ' + str(pool_id)
        LOG.debug(_("pool_id is %s") %pool_id)
        exec_result=self.start_execute_cmd(cmd,1)    
        if exec_result:
            for line in exec_result:
                if re.search('^result=', line):
                    if not re.search('^result=0', line):
                        tmp_pool_info['result']=line[7:]
                        return tmp_pool_info
                    for line in exec_result:
                        if re.search('^pool_id='+str(pool_id), line):
                            tmp_pool_info=self.pool_info_analyze(line)
                            return tmp_pool_info

        tmp_pool_info['result']=1
        return tmp_pool_info

def main():

    testAPI=FSPythonApi()


    recode=testAPI.create_volume('vol_1',0,1024,0)

    print "create volume result:%s"%(str(recode))
    
    time.sleep(2)

    recode=testAPI.extend_volume('vol_1',10240)

    print "extend volume result:%s"%(str(recode))

    recode=testAPI.create_snapshot('snap_1','vol_1',0)

    print "create snapshot result:%s"%(str(recode))
   
    time.sleep(2)

    recode=testAPI.create_volume_from_snap('vol_2',1024,'snap_1')

    print "create volume from snapshot result:%s"%(str(recode))

    time.sleep(5)

    recode=testAPI.create_volume_from_volume('vol_3',1024,'vol_2')
    print "create volume from volume result:%s"%(str(recode))

    time.sleep(5)

    vol_info=testAPI.query_volume('vol_3')
    if cmp('0',vol_info['result']):
        print "query volume info:"
        for key,value in vol_info.items():
            print key +"="+str(value)
    else:
        print "query volume result:%s"%(vol_info['result'])
    time.sleep(1)

    snap_info=testAPI.query_snap('snap_1')
    if cmp('0',snap_info['result']):
        print "query snap info:"
        for key,value in snap_info.items():
            print key +"="+str(value)
    else:
        print "query snap result:%s"%(snap_info['result'])
    time.sleep(1)

    recode=testAPI.delete_snapshot('snap_1')
    print "del snapshot result:%s"%(str(recode))

    time.sleep(1)

    recode=testAPI.delete_volume('vol_1')
    print "del volume vol_1 result:%s"%(str(recode))
    recode=testAPI.delete_volume('vol_2')
    print "del volume vol_2 result:%s"%(str(recode))
    recode=testAPI.delete_volume('vol_3')
    print "del volume vol_3 result:%s"%(str(recode))
    time.sleep(1)


    test_pool_info=testAPI.query_pool_info(0)
    if cmp('0',test_pool_info['result']):
        print "query pool info:"
        for key,value in test_pool_info.items():
            print key +"="+str(value)
    else:
        print "query pool result:%s"%(test_pool_info['result'])

if __name__ == "__main__":
    main()

