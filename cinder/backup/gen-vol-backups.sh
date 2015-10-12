#!/bin/bash

# list all enabled tenants
tenants=`keystone --os-tenant-name $OS_TENANT_NAME --os-password $OS_PASSWORD tenant-list|awk -F '|' '{if (match($4, "True"))print $3}'`
echo $tenants>>/tmp/vol-backup.log

# list all volumes of hybrid type
for tenant in $tenants
do
    cinder --os-tenant-name $tenant list >>/tmp/vol-backup.log 2>&1
    # skip all unauthorized tenants
    output=$?
    if (($output != 0))
        then continue
    fi
    volumes=`cinder --os-tenant-name $tenant list|awk -F '|' '{if ((match($3, "in-use")!=0 || match($3, "available")!=0) && match($6, "hybrid") && match($6, "az01")) print $2}'`
    echo $volumes >> /tmp/vol-backup.log
    for volume in $volumes
    do
        cinder --os-tenant-name $tenant backup-create $volume --name "`date`" --force True >>/tmp/vol-backup.log 2>&1
        #cinder --os-tenant-name $tenant backup-create $volume --name "`date`" >>/tmp/vol-backup.log 2>&1
    done
done
