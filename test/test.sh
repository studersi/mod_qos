#!/bin/sh
#
# $Header: /home/cvs/m/mo/mod-qos/src/test/test.sh,v 2.8 2007-08-26 08:45:43 pbuchbinder Exp $
#

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
echo "-- 6 requests to an url limited to max 5 concurrent requests, QS_LocRequestLimit_5.txt" >>  logs/error_log
../test_tools/src/httest -s ./scripts/QS_LocRequestLimit_5.txt | grep -v Success
if [ $? -ne 0 ]; then
    ./ctl.sh stop
    echo "FAILED QS_LocRequestLimit_5.txt"
    exit 1
fi

# -----------------------------------------------------------------
echo "-- 3 requests with matching regex rule max 2 (overrides location rule), QS_LocRequestLimitMatch_2.txt" >>  logs/error_log
../test_tools/src/httest -s ./scripts/QS_LocRequestLimitMatch_2.txt | grep -v Success
if [ $? -ne 0 ]; then
    ./ctl.sh stop
    echo "FAILED QS_LocRequestLimitMatch_2.txt"
    exit 1
fi

# -----------------------------------------------------------------
echo "-- vip session, QS_VipHeaderName.txt" >>  logs/error_log
../test_tools/src/httest -s ./scripts/QS_VipHeaderName.txt | grep -v Success
if [ $? -ne 0 ]; then
    ./ctl.sh stop
    echo "FAILED QS_VipHeaderName.txt"
    exit 1
fi

# -----------------------------------------------------------------
echo "-- vip request, QS_VipRequest.txt" >>  logs/error_log
../test_tools/src/httest -s ./scripts/QS_VipRequest.txt | grep -v Success
if [ $? -ne 0 ]; then
    ./ctl.sh stop
    echo "FAILED QS_VipRequest.txt"
    exit 1
fi

# -----------------------------------------------------------------
echo "-- 50 connections, QS_SrvMaxConn 40" >> logs/error_log
../test_tools/src/httest -s ./scripts/QS_SrvMaxConn_50.txt | grep -v Success
if [ $? -ne 0 ]; then
    ./ctl.sh stop
    echo "FAILED QS_SrvMaxConn_50.txt"
    exit 1
fi
sleep 3
if [ `grep -c "access denied, rule: max=40" logs/error_log` -lt 10 ]; then
    ./ctl.sh stop
    echo "FAILED 10"
    exit 1
fi

# -----------------------------------------------------------------
echo "-- connection timeout" >>  logs/error_log
openssl s_client -connect server1:${QS_PORT_BASE2} >/dev/null 2>/dev/null
if [ `grep -c "connection timeout, rule: 3 sec inital timeout" logs/error_log` -lt 1 ]; then
    ./ctl.sh stop
    echo "FAILED 11"
    exit 1
fi

# -----------------------------------------------------------------
echo "-- dynamic keep alive, QS_KeepAliveTimeout" >>  logs/error_log
../test_tools/src/httest -s scripts/QS_KeepAliveTimeout.txt
if [ $? -ne 0 ]; then
    ./ctl.sh stop
    echo "FAILED QS_KeepAliveTimeout.txt"
    exit 1
fi

# -----------------------------------------------------------------
./ctl.sh stop > /dev/null
echo "normal end"
exit 0
