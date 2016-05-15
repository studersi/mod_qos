#!/bin/sh

. ./ports
rm -f mod_qos.1
wget -q http://localhost:${QS_PORT_BASE}/man1/ -O mod_qos.1
sed -i mod_qos.1 -e 's:-:\\\-:g'
if [ `grep -c LocRequestLimit mod_qos.1` -eq 0 ]; then
    echo "FAILED to create module's man page"
    rm -f mod_qos.1
    exit 1
fi
exit 0

