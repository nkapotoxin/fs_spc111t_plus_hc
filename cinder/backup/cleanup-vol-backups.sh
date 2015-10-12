#!/bin/bash

# list all enabled tenants
days_to_cleanup=0
hours_to_cleanup=5
mins_to_cleanup=0

created_at_utc="true"

echo "start to cleanup backups at " `date` >>/tmp/cleanup-vol-backups.log
tenants=`keystone --os-tenant-name $OS_TENANT_NAME --os-password $OS_PASSWORD tenant-list|awk -F '|' '{if (match($4, "True"))print $3}'`
echo $tenants >>/tmp/cleanup-vol-backups.log
((secs_to_cleanup=$days_to_cleanup*2400*3600 + $hours_to_cleanup*3600 + $mins_to_cleanup*60))

# TODO: now backup list is tenant un related
for tenant in $tenants
do
    cinder --os-tenant-name $tenant list >>/tmp/cleanup-vol-backups.log 2>&1
    # skip all unauthorized tenants
    output=$?
    if (($output != 0))
        then continue
    fi
    bad_backups=`cinder --os-tenant-name $tenant backup-list|awk -F '|' '{if(match($4, "error")!=0 && match($4, "error_deleting")==0) print $2}'`

    for backup in $bad_backups
    do
        cinder --os-tenant-name $tenant backup-delete $backup >>/tmp/cleanup-vol-backups.log 2>&1
        echo "deleted error backup:" $backup >> /tmp/cleanup-vol-backups.log
    done

    avail_backups=`cinder --os-tenant-name $tenant backup-list|awk -F '|' '{if(match($4, "available")!=0) print $2}'`
    for backup in $avail_backups
    do
        # check if the backup out of date
        created=`cinder --os-tenant-name $tenant backup-show $backup|grep 'created_at'|cut -d '|' -f 3`
        year_mon_day=`echo $created|cut -d 'T' -f 1`
        hour_min_sec=`echo $created|cut -d 'T' -f 2|cut -d '.' -f 1`

        #fix created timestamp to be gnu standard
        fixed_created_at="$year_mon_day $hour_min_sec"

        created_secs=`date -d "$fixed_created_at" '+%s'`
        if [[ $created_at_utc =~ "true" ]]
        then
            ((created_secs=$created_secs + 3600*8))
        fi
        now_secs=`date '+%s'`

        if (($now_secs - $created_secs >= $secs_to_cleanup))
        then
            # check if the backup is of hybrid type
            #volume=`cinder --os-tenant-name $tenant backup-show $backup|grep 'volume_id'|cut -d '|' -f 3`
            #volume_type=`cinder --os-tenant-name $tenant show $volume|grep 'volume_type'|cut -d '|' -f 3`
            #volume_type=`echo $volume_type|sed 's/^ //g;s/ $//g'`
            #if [[ $volume_type =~ "hybrid" ]]
            #then
                cinder --os-tenant-name $tenant backup-delete $backup >>/tmp/cleanup-vol-backups.log 2>&1
                echo "now:" `date` ";deleted backup:" $backup ";created at:" $created >> /tmp/cleanup-vol-backups.log
            #fi
        fi
    done
done

