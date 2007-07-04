#!/bin/sh

ROOT=`pwd`
QS_UID=`id`
QS_UID_STR=`expr "$QS_UID" : 'uid=[0-9]*.\([a-z,A-Z,0-9,_]*\)'`
QS_UID=`id`
QS_GID=`expr "$QS_UID" : '.*gid=[0-9]*.\([a-z,A-Z,0-9,_]*\)'`
QS_UID=`id`
QS_UID=`expr "$QS_UID" : 'uid=\([0-9]*\)'`
QS_PORT_BASE=`expr ${QS_UID} - 1000`
QS_PORT_BASE=`expr $QS_PORT_BASE '*' 120`
QS_PORT_BASE=`expr $QS_PORT_BASE + 5000`


sed <conf/httpd.conf.tmpl >conf/httpd.conf \
    -e "s;##ROOT##;$ROOT;g" \
    -e "s;##USR##;$QS_UID_STR;g" \
    -e "s;##QS_PORT_BASE##;$QS_PORT_BASE;g"

if [ ! -d logs ]; then
    mkdir logs
fi


