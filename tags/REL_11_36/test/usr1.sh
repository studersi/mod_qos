#!/bin/sh
#
# ErrorLog "|##ROOT##/../util/src/qsexec -e \'child pid [0-9]+ exit signal\' -p ##ROOT##/usr1.sh | ##ROOT##/../util/src/qsrotate -o ##ROOT##/logs/error_log"
#

cmdDir=`dirname $0`
parentPid=`cat $cmdDir/logs/apache.pid`
kill -USR1 $parentPid

