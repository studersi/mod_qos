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
QS_PORT_BASE1=`expr $QS_PORT_BASE + 1`
QS_PORT_BASE2=`expr $QS_PORT_BASE + 2`
QS_PORT_BASE3=`expr $QS_PORT_BASE + 3`
QS_PORT_BASE5=`expr $QS_PORT_BASE + 5`
QS_PORT_BASE6=`expr $QS_PORT_BASE + 6`

echo "SET QS_PORT_BASE=$QS_PORT_BASE"   >  scripts/ports
echo "SET QS_PORT_BASE1=$QS_PORT_BASE1" >> scripts/ports
echo "SET QS_PORT_BASE2=$QS_PORT_BASE2" >> scripts/ports
echo "SET QS_PORT_BASE3=$QS_PORT_BASE3" >> scripts/ports
echo "SET QS_PORT_BASE5=$QS_PORT_BASE5" >> scripts/ports
echo "SET QS_PORT_BASE6=$QS_PORT_BASE6" >> scripts/ports

sed <conf/httpd.conf.tmpl >conf/httpd.conf \
    -e "s;##ROOT##;$ROOT;g" \
    -e "s;##USR##;$QS_UID_STR;g" \
    -e "s;##QS_PORT_BASE##;$QS_PORT_BASE;g" \
    -e "s;##QS_PORT_BASE1##;$QS_PORT_BASE1;g" \
    -e "s;##QS_PORT_BASE2##;$QS_PORT_BASE2;g" \
    -e "s;##QS_PORT_BASE3##;$QS_PORT_BASE3;g" \
    -e "s;##QS_PORT_BASE5##;$QS_PORT_BASE5;g" \
    -e "s;##QS_PORT_BASE6##;$QS_PORT_BASE6;g"

sed <appl_conf/httpd.conf.tmpl >appl_conf/httpd.conf \
    -e "s;##ROOT##;$ROOT;g" \
    -e "s;##USR##;$QS_UID_STR;g" \
    -e "s;##QS_PORT_BASE##;$QS_PORT_BASE;g" \
    -e "s;##QS_PORT_BASE1##;$QS_PORT_BASE1;g" \
    -e "s;##QS_PORT_BASE2##;$QS_PORT_BASE2;g" \
    -e "s;##QS_PORT_BASE5##;$QS_PORT_BASE5;g"

if [ ! -d logs ]; then
    mkdir logs
fi

if [ -f ../modsecurity/rules/modsecurity_crs_40_generic_attacks.conf ]; then
    MSID=0
    rm -f appl_conf/qos_deny_filter.conf
    for E in `grep "^SecRule " ../modsecurity/rules/modsecurity_crs_40_generic_attacks.conf | awk '{print $3}' | grep "\"$"`; do
	echo "QS_DenyRequestLine +MS${MSID} deny $E" >> appl_conf/qos_deny_filter.conf
	MSID=`expr $MSID + 1`
    done
fi
