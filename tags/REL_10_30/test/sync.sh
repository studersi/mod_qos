#!/bin/sh
#
# Example to propagte QS_ClientEventLimitCount events (client
# is blocked) to another (redundant/hot standby) server.
#
# Usage: 
# ErrorLog  "|qsexec -e \'mod_qos.067.: access denied, QS_ClientEventLimitCount rule: event=(.*), max=[0-9]+, current=[0-9]+, c=(.*), id=\' -p \'sync.sh $1 $2\' |qsrotate -o logs/error_log"
#

cd `dirname $0`
. ./ports
wget -O - http://127.0.0.1:$QS_PORT_BASE6/console?action=limit\&address=$2\&event=$1 >/dev/null &
