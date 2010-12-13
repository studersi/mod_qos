#!/bin/sh
# -*-mode: ksh; ksh-indent: 2; -*-
#
# copies vip client information from URLIN to URLOUT
#

URLIN="http://127.0.0.1:5000/console"
URLOUT="http://127.0.0.1:5000/console"

rm -f export.txt
wget "${URLIN}?action=search&address=*" -O export.txt -o /dev/null

for E in `sed < export.txt -e "s: :#:g"`; do
  IP=`echo $E | awk -F':' '{print $1}'`
  if [ `echo $E | grep -c "vip=yes"` -eq 1 ]; then
    wget "${URLOUT}?action=setvip&address=$IP" -O /dev/null -o /dev/null
    echo "$IP\tsetvip"
  fi
done
