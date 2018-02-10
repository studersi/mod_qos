#!/bin/sh
#
# Copies the vip information of the most recent (max. 20'000)
# clients from URLIN to URLOUT
#
# (requires mod_qos >= 11.37)
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#

URLIN="http://127.0.0.1:5000/console"
URLOUT="http://127.0.0.1:5000/console"
MAXCLIENT=20000

# download the current status
rm -f cc_export.txt
wget "${URLIN}?action=search&address=*" -O cc_export.txt -o /dev/null

cat cc_export.txt | grep "vip=yes" | awk '{print $NF "#" $2}' | sort -nr | head  -${MAXCLIENT} | awk -F'#' '{print $2}' > cc_clients.txt

# upload the data
for IP in `cat cc_clients.txt`; do
    wget "${URLOUT}?action=setvip&address=$IP" -O /dev/null -o /dev/null
    echo "$IP\tsetvip"
done

