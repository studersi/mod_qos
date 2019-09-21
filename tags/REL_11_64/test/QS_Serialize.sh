#!/bin/sh

. ./ports

./ctl.sh stop 2>/dev/null 1>/dev/null
../httpd/httpd -d `pwd` -f conf/uc1.conf -D clientSerial 2>/dev/null 1>/dev/null

for counter in `seq 100`; do
    echo "GET /index.html?cl=${counter}&delayus=200000 HTTP/1.0\n" | telnet server1 $QS_PORT_BASE 2>/dev/null 1>/dev/null
done
sleep 30
last=`tail -1 logs/access_log`
if [ `echo $last | grep -c "cl=100&delayus"` -eq 0 ]; then
    echo "$last"
    echo "FAILED QS_ClientSerialize"
    exit 1
fi
secondlast=`tail -2 logs/access_log | head -1`
if [ `echo $secondlast | grep -c "cl=99&delayus"` -eq 0 ]; then
    echo "$secondlast"
    echo "FAILED QS_SrvSerialize"
    exit 1
fi

./ctl.sh stop 2>/dev/null 1>/dev/null
../httpd/httpd -d `pwd` -f conf/uc1.conf -D srvSerial 2>/dev/null 1>/dev/null
for counter in `seq 100`; do
    echo "GET /index.html?srv=${counter}&delayus=200000 HTTP/1.0\n" | telnet server1 $QS_PORT_BASE 2>/dev/null 1>/dev/null
done
sleep 30
last=`tail -1 logs/access_log`
if [ `echo $last | grep -c "srv=100&delayus"` -eq 0 ]; then
    echo "$last"
    echo "FAILED QS_SrvSerialize"
    exit 1
fi
secondlast=`tail -2 logs/access_log | head -1`
if [ `echo $secondlast | grep -c "srv=99&delayus"` -eq 0 ]; then
    echo "$secondlast"
    echo "FAILED QS_SrvSerialize"
    exit 1
fi

./ctl.sh stop 2>/dev/null 1>/dev/null
exit 0
