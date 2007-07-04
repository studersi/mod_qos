#!/bin/sh

QS_UID=`id`
QS_UID_STR=`expr "$QS_UID" : 'uid=[0-9]*.\([a-z,A-Z,0-9,_]*\)'`
QS_UID=`id`
QS_GID=`expr "$QS_UID" : '.*gid=[0-9]*.\([a-z,A-Z,0-9,_]*\)'`
QS_UID=`id`
QS_UID=`expr "$QS_UID" : 'uid=\([0-9]*\)'`
QS_PORT_BASE=`expr ${QS_UID} - 1000`
QS_PORT_BASE=`expr $QS_PORT_BASE '*' 120`
QS_PORT_BASE=`expr $QS_PORT_BASE + 5000`

./generate.sh

ERRORS=0

rm -f logs/access_log
echo "start `date` -----------------------------" >>  logs/error_log
./ctl.sh start

# -----------------------------------------------------------------
(echo "GET /test/index.html HTTP/1.0";  echo ""; echo "") | telnet localhost $QS_PORT_BASE 2>/dev/null 1>/dev/null
RON="1 2 3 4 5 6 7"
for E in $RON; do
(echo "GET /cgi/sleep.cgi HTTP/1.0";  echo ""; echo "") | telnet localhost $QS_PORT_BASE 2>/dev/null 1>/dev/null &
done

sleep 5
if [ `grep -c "GET /cgi/sleep.cgi HTTP/1.0\" 500" logs/access_log` -eq 0 ]; then
    ./ctl.sh stop
    echo "FAILED"
    exit 1
fi

./ctl.sh stop
echo "normal end"
exit 0
