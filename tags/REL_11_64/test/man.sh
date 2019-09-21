#!/bin/sh

PFX=[`basename $0`]

. ./ports

echo "$PFX download man page"
rm -f mod_qos.1
wget -q http://localhost:${QS_PORT_BASE}/man1/ -O mod_qos.1
sed -i mod_qos.1 -e 's:-:\\\-:g'
if [ `grep -c LocRequestLimit mod_qos.1` -eq 0 ]; then
    echo "FAILED to create module's man page"
    rm -f mod_qos.1
    exit 1
fi

echo "$PFX download header filter rules"
./ctl.sh stop 1>/dev/null
../httpd/httpd -d `pwd` -f conf/uc1.conf 2>/dev/null 1>/dev/null
sleep 2
rm -f headerfilterrules.txt
wget -q http://localhost:${QS_PORT_BASE}/headerfilter/ -O headerfilterrules.txt
if [ `grep -c QS_RequestHeaderFilter headerfilterrules.txt` -eq 0 ]; then
    echo "FAILED to create module's header filter rule list"
    rm -f headerfilterrules.txt
    exit 1
fi

exit 0

