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
QS_PORT_BASE1=`expr $QS_PORT_BASE + 1`
QS_PORT_BASE2=`expr $QS_PORT_BASE + 2`

./generate.sh

ERRORS=0

rm -f logs/access_log
rm -f logs/error_log
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
    echo "FAILED 1"
    exit 1
fi

# -----------------------------------------------------------------
echo "-- 7 requests with matching regex rule max 2 (overrides location rule)" >>  logs/error_log
RON="1 2 3 4 5 6 7"
for E in $RON; do
(echo "GET /cgi/image.gif HTTP/1.0";  echo ""; echo "") | telnet localhost $QS_PORT_BASE 2>/dev/null 1>/dev/null &
done
sleep 5
if [ `grep -c "GET /cgi/image.gif HTTP/1.0\" 500" logs/access_log` -ne 5 ]; then
    ./ctl.sh stop
    echo "FAILED 2"
    exit 1
fi

# -----------------------------------------------------------------
rm -f cookie
echo "-- 1 request to an url limited to max 0 (only vip)" >>  logs/error_log
(echo "GET /no/index.html HTTP/1.0";  echo ""; echo "") | telnet localhost $QS_PORT_BASE 2>/dev/null 1>/dev/null &
echo "-- 1 request to an url limited to max 0 (only vip) - invalid key" >>  logs/error_log
curl -b MODQOS=eg3LcsEBcTAlxjE12JVz+Q/GqaT/PiZC88AOPK08ckQ= http://localhost:5960/no/index.html 2>/dev/null 1>/dev/null
echo "--> vip login" >> logs/error_log
curl -c cookie http://localhost:5960/login/vip.cgi 2>/dev/null 1>/dev/null
echo "--> vip access" >> logs/error_log
curl -b cookie http://localhost:5960/no/index.html 2>/dev/null 1>/dev/null
sleep 1
if [ `grep -c "GET /no/index.html HTTP/1.1\" 500.*curl.* D; .*" logs/access_log` -ne 1 ]; then
    ./ctl.sh stop
    echo "FAILED 3"
    exit 1
fi
if [ `grep -c "GET /login/vip.cgi HTTP/1.1\" 200.*curl.* V; .*" logs/access_log` -ne 1 ]; then
    ./ctl.sh stop
    echo "FAILED 4"
    exit 1
fi
if [ `grep -c "GET /no/index.html HTTP/1.1\" 200.*curl.* S; .*" logs/access_log` -ne 1 ]; then
    ./ctl.sh stop
    echo "FAILED 5"
    exit 1
fi
sleep 4
echo "--> vip timeout" >> logs/error_log
COOKIE=`cat cookie  | grep MODQOS | awk '{print $(NF)}'`
curl -b MODQOS=${COOKIE} http://localhost:5960/no/index.html 2>/dev/null 1>/dev/null
sleep 1
if [ `grep -c "GET /no/index.html HTTP/1.1\" 500.*curl.*D; .*" logs/access_log` -ne 2 ]; then
    ./ctl.sh stop
    echo "FAILED 6"
    exit 1
fi

echo "-- graceful restart" >>  logs/error_log
rm -f cookie
curl -c cookie http://localhost:5960/login/vip.cgi 2>/dev/null 1>/dev/null
curl -b cookie http://localhost:5960/no/index.html 2>/dev/null 1>/dev/null
sleep 1
./ctl.sh graceful > /dev/null
curl -b cookie http://localhost:5960/no/index.html 2>/dev/null 1>/dev/null
sleep 2
if [ `grep -c "GET /no/index.html HTTP/1.1\" 200.*curl.* S; .*" logs/access_log` -ne 3 ]; then
    ./ctl.sh stop
    echo "FAILED 6"
    exit 1
fi

echo "-- QS_VipRequest" >> logs/error_log
(echo "GET /no/index2.html HTTP/1.0";  echo "User-Agent: telnet"; echo "") | telnet localhost $QS_PORT_BASE 2>/dev/null 1>/dev/null &
(echo "GET /no/index.html HTTP/1.0";  echo "User-Agent: pass"; echo "") | telnet localhost $QS_PORT_BASE 2>/dev/null 1>/dev/null &
sleep 1
if [ `grep -c "GET /no/index2.html HTTP/1.0\" 200.*telnet.* S; .*" logs/access_log` -ne 1 ]; then
    ./ctl.sh stop
    echo "FAILED 7"
    exit 1
fi
if [ `grep -c "GET /no/index.html HTTP/1.0\" 200.*pass.* S; .*" logs/access_log` -ne 1 ]; then
    ./ctl.sh stop
    echo "FAILED 8"
    exit 1
fi

echo "-- QS_SrvMaxConn 40" >> logs/error_log
../test_tools/src/httest -s ./scripts/QS_SrvMaxConn_50.txt | grep -v Success
sleep 3
if [ `grep -c "access denied, rule: max=40" logs/error_log` -lt 10 ]; then
    ./ctl.sh stop
    echo "FAILED 9"
    exit 1
fi

# -----------------------------------------------------------------
echo "-- connection timeout" >>  logs/error_log
openssl s_client -connect server1:${QS_PORT_BASE2} >/dev/null 2>/dev/null
if [ `grep -c "connection timeout, rule: 3 sec inital timeout" logs/error_log` -lt 1 ]; then
    ./ctl.sh stop
    echo "FAILED 10"
    exit 1
fi

# -----------------------------------------------------------------
./ctl.sh stop > /dev/null
echo "normal end"
exit 0
