#!/bin/bash

agent_err_operation=103
dsware_agent_result="1"
dsware_agent_value="no"

PYTHON_SITE_PATH="`python -c \"from distutils.sysconfig import get_python_lib; print get_python_lib()\"`"
LOG_PATH="/var/log/dsware/agent_handle.log.0" 
fsa_ssl_passwd_file="${PYTHON_SITE_PATH}/cinder/volume/drivers/ssl/fsa_ssl_password" 

dsware_agent_error()
{
    echo "$(date +"[%Y-%m-%d %H:%M:%S]") [$0:${BASH_LINENO}] [${FUNCNAME[1]}] $@" >> $LOG_PATH 
}

function agent_error()
{
  dsware_agent_result=$agent_err_operation
  dsware_agent_value="Operation no exist"
}

function get_ssl_passwd()
{
    if [ 2 -ne $# ]
    then
        dsware_agent_error "parameter error, must input para openssl decode key"
        dsware_agent_result=1
        return 1
    fi
    if [ ! -f "$fsa_ssl_passwd_file" ]
    then
        dsware_agent_error "$fsa_ssl_passwd_file no exist"
        dsware_agent_result=1
        return 1
    fi
    iv_passwd="`cat $fsa_ssl_passwd_file`"
    iv_str=${iv_passwd:0:16}
    passwd=${iv_passwd:16}
    dsware_agent_value="`echo $passwd|openssl aes-256-cbc -d -K $2 -iv $iv_str -base64`"
    dsware_agent_result=0
    return 0
}

case $1 in
    get_ssl_passwd)
        get_ssl_passwd $@
        ;;            
    *)
        agent_error $@ 
        ;;
    
esac

echo "result=$dsware_agent_result;value=$dsware_agent_value;"

exit 0
