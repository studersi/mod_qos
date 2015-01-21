#!/bin/sh

./sleep.sh 1>/dev/null
lines=`wc -l logs/access_log | awk '{print $1}'`
while [ 1 ]; do 
    ./sleep.sh 1>/dev/null
    linesnew=`wc -l logs/access_log | awk '{print $1}'`
    linesmin=`expr $linesnew - $lines`
    lines=$linesnew
    reqsec=`expr $linesmin / 60`
    qsld=`top -b -n 1 | grep qslog | awk '{print $(NF-3)}'`;
    echo "`date '+%H:%M:00'`;qslog;$qsld;req/sec;$reqsec"
done
