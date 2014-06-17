#!/bin/sh
#
# Example to propagte QS_ClientEventLimitCount events (client
# is blocked) to another (redundant/hot standby) server.
#
# Sample usage/configuration:
# QS_ClientEventLimitCount  10 60  QS_Limit
# QS_ClientEventLimitCount  12 120 QS_LimitSP
# ErrorLog  "|qsexec -e \'mod_qos.067.: access denied, QS_ClientEventLimitCount rule: event=(.*), max=[0-9]+, current=[0-9]+, c=(.*), id=\' -p \'sync.sh $1 $2 $3\' |qsrotate -o logs/error_log"
#

cd `dirname $0`
. ./ports

if [ $1 = "QS_Limit" -a $2 != "10" ]; then
    # propagte status only once (when reaching the limit)
    exit 0
fi
if [ $1 = "QS_LimitSP" -a $2 != "12" ]; then
    # propagte status only once (when reaching the limit)
    exit 0
fi

wget -O - http://127.0.0.1:$QS_PORT_BASE6/console?action=limit\&address=$3\&event=$1 >/dev/null &
