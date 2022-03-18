#!/bin/bash

# nagios script checks for failed raid device, run with sudo
# linux software raid /proc/mdstat
# thaobtp@vccloud.vn 2019-11-04

STATE_OK=0
STATE_WARNING=1
STATE_CRITICAL=2
STATE_UNKNOWN=3

PATH=/bin:/usr/bin:/sbin:/usr/sbin
export PATH

# Query all array
all_array=`mdadm --detail --scan | awk '{print $2}'`
all_devices=`mdadm --detail --scan | awk '{print $2}' | wc -l`
active_devices=0
declare -a inactive_devices
declare -a warning_devices

# Check faulty
if [ "$all_array" ]; then
    for i in $all_array;do
        state=`mdadm --detail $i | grep "State :" | awk '{print $3}'`
        if [ "$state" == "clean" ] || [ "$state" == "active" ];then
            active_devices=$((active_devices+1))
        elif [ "$state" == "inactive" ];then
            inactive_devices[${#inactive_devices[*]}]="$i"
        else
            warning_devices[${#warning_devices[*]}]="$i"
        fi
    done
    if [ "$all_devices" != 0 ];then
        if [ "$active_devices" == "$all_devices" ];then
            echo "OK: all devices is active"
            exit $STATE_OK
        elif [ "${#inactive_devices[@]}" -ne 0 ];then
            echo "CRITICAL: Following devices is failed:${inactive_devices[@]}"
            exit $STATE_CRITICAL
        else
            echo "WARNING: Following devices is sync or delayed: ${warning_devices[@]}"
            exit $STATE_WARNING
        fi
    else
        echo "UNKNOWN: can't show all devices"
        exit $STATE_UNKNOWN
    fi
else
    echo "UNKNOWN: mdadm don't work"
    exit $STATE_UNKNOWN
fi
