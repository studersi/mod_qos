#!/bin/sh
#
# Example to propagate QS_ClientEventLimitCount events (client
# is blocked) to another (redundant/hot standby) server.
#
# Apache configuration: 
#
#  You may use qsexec to trigger external commands (this script)
#  when detecting a client (IP) event which shall be propagated.
#                       
#  ErrorLog  "|qsexec -e \'mod_qos.067.: access denied, QS_ClientEventLimitCount rule: event=(.*), max=([0-9]+), current=([0-9]+), age=0, c=(.*), id=\' -p \'sync.sh $1 $2 $3 $4\' |qsrotate -o logs/error_log"
#
#  You also need to enable the mod_qos console allowing this
#  script to update the client (IP) status within the Apache
#  server.
#
#  <Location /console>
#      SetHandler qos-console
#  </Location>
#
# Command line arguments:
#  $1 event name
#  $2 configured limitation
#  $3 current counter
#  $4 client IP
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#

cd `dirname $0`
. ./ports

consolelimit=`expr 999 + $2`
if [ $3 -gt $consolelimit ]; then
  # don't propagate events caused by the console
  exit 0
fi

wget -O - http://127.0.0.1:$QS_PORT_BASE6/console?action=limit\&address=$4\&event=$1 >/dev/null
