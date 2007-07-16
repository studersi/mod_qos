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
echo "start server http://localhost:$QS_PORT_BASE/test/index.html"
echo "-- start `date` --" >>  logs/error_log
# -----------------------------------------------------------------
./ctl.sh start > /dev/null
(echo "GET /test/index.html HTTP/1.0";  echo ""; echo "") | telnet localhost $QS_PORT_BASE 2>/dev/null 1>/dev/null

# -----------------------------------------------------------------
echo "-- 7 requests to an url limited to max 5 concurrent requests" >>  logs/error_log
RON="1 2 3 4 5 6 7"
for E in $RON; do
(echo "GET /cgi/sleep.cgi HTTP/1.0";  echo ""; echo "") | telnet localhost $QS_PORT_BASE 2>/dev/null 1>/dev/null &
done
sleep 5
if [ `grep -c "GET /cgi/sleep.cgi HTTP/1.0\" 500" logs/access_log` -ne 2 ]; then
    ./ctl.sh stop
    echo "FAILED"
    exit 1
fi

# -----------------------------------------------------------------
echo "-- 7 requests with matching regex rule (overrides location rule)" >>  logs/error_log
RON="1 2 3 4 5 6 7"
for E in $RON; do
(echo "GET /cgi/image.gif HTTP/1.0";  echo ""; echo "") | telnet localhost $QS_PORT_BASE 2>/dev/null 1>/dev/null &
done
sleep 5
if [ `grep -c "GET /cgi/image.gif HTTP/1.0\" 500" logs/access_log` -ne 5 ]; then
    ./ctl.sh stop
    echo "FAILED"
    exit 1
fi

# -----------------------------------------------------------------
./ctl.sh stop > /dev/null
echo "normal end"
exit 0
