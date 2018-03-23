#!/bin/sh
#
# Copies vip client information from URLIN to URLOUT
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#

URLIN="http://127.0.0.1:5000/console"
URLOUT="http://127.0.0.1:5000/console"

# download the current status
rm -f export.txt
wget "${URLIN}?action=search&address=*" -O export.txt -o /dev/null

# upload the data
for E in `sed < export.txt -e "s: :#:g"`; do
  IP=`echo $E | awk -F'#' '{print $2}'`
  if [ `echo $E | grep -c "vip=yes"` -eq 1 ]; then
    wget "${URLOUT}?action=setvip&address=$IP" -O /dev/null -o /dev/null
    echo "$IP\tsetvip"
  fi
done

