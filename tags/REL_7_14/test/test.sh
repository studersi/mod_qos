#!/bin/sh
#
# $Header: /home/cvs/m/mo/mod-qos/src/test/test.sh,v 2.70 2008-10-27 19:38:16 pbuchbinder Exp $
#
# mod_qos test cases, requires htt, see http://htt.sourceforge.net/
#
# See http://sourceforge.net/projects/mod-qos/ for further
# details about mod_qos.
#
# Copyright (C) 2007-2008 Pascal Buchbinder
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA 02110-1301, USA.
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
WARNINGS=0

sleep 1
IPCS=`ipcs | wc -l`

# delete the access log file since it is used to generate permit rules
rm -f logs/access1_log
rm -rf /var/tmp/qosc/server1
echo "start server http://localhost:$QS_PORT_BASE/test/index.html"
echo "-- start `date` --" >>  logs/error_log
# -----------------------------------------------------------------
./ctl.sh start -D real_ip > /dev/null
(echo "GET /test/index.html HTTP/1.0";  echo ""; echo "") | telnet localhost $QS_PORT_BASE 2>/dev/null 1>/dev/null

# -----------------------------------------------------------------
echo "-- client opens more than 10 connections, QS_SrvMaxConnPerIP_10.htt" >>  logs/error_log
./htt.sh -s ./scripts/QS_SrvMaxConnPerIP_10.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_QS_SrvMaxConnPerIP_10.htt"
fi
./ctl.sh stop > /dev/null
sleep 2
./ctl.sh start > /dev/null

# -----------------------------------------------------------------
echo "-- 6 requests to an url limited to max 5 concurrent requests, QS_LocRequestLimit_5.htt" >>  logs/error_log
./htt.sh -s ./scripts/QS_LocRequestLimit_5.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_LocRequestLimit_5.htt"
fi
./htt.sh -s ./scripts/QS_LocRequestLimit_DynamicErrorPage.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_LocRequestLimit_DynamicErrorPage.htt"
fi

# -----------------------------------------------------------------
echo "-- 3 requests with matching regex rule max 2 (overrides location rule), QS_LocRequestLimitMatch_2.htt" >>  logs/error_log
./htt.sh -s ./scripts/QS_LocRequestLimitMatch_2.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_LocRequestLimitMatch_2.htt"
fi
# one rule for multiple loctions
./htt.sh -s ./scripts/QS_LocRequestLimitMatch.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_LocRequestLimitMatch.htt"
fi
./htt.sh -s ./scripts/QS_LocRequestLimitMatch_3.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_LocRequestLimitMatch_3.htt"
fi

# -----------------------------------------------------------------
echo "-- conditional rule QS_CondLocRequestLimitMatch.htt" >>  logs/error_log
./htt.sh -s ./scripts/QS_CondLocRequestLimitMatch.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_CondLocRequestLimitMatch.htt"
fi

# -----------------------------------------------------------------
echo "-- vip session, QS_VipHeaderName.htt" >>  logs/error_log
./htt.sh -s ./scripts/QS_VipHeaderName.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_VipHeaderName.htt"
fi
./htt.sh -s ./scripts/QS_VipHeaderName2.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_VipHeaderName2.htt"
fi

# -----------------------------------------------------------------
echo "-- vip request, QS_VipRequest.htt" >>  logs/error_log
./htt.sh -s ./scripts/QS_VipRequest.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_VipRequest.htt"
fi

# -----------------------------------------------------------------
echo "-- vip request and graceful restart, QS_VipHeaderName_Graceful.htt" >>  logs/error_log
./htt.sh -s ./scripts/QS_VipHeaderName_Graceful.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_VipHeaderName_Graceful.htt"
fi

# -----------------------------------------------------------------
echo "-- graceful, QS_Graceful.htt" >> logs/error_log
./htt.sh -s ./scripts/QS_Graceful.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_Graceful.htt"
fi
./htt.sh -s ./scripts/QS_Graceful2.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_Graceful2.htt"
fi

# -----------------------------------------------------------------
echo "-- 50 connections, QS_SrvMaxConn 40" >> logs/error_log
./htt.sh -s ./scripts/QS_SrvMaxConn_50.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_SrvMaxConn_50.htt"
fi

# -----------------------------------------------------------------
echo "-- connection timeout, QS_SrvConnTimeout_body.htt" >>  logs/error_log
./htt.sh -s ./scripts/QS_SrvConnTimeout_body.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_SrvConnTimeout_body.htt"
fi

sleep 1
# -----------------------------------------------------------------
echo "-- disable keep alive, QS_SrvMaxConnClose_20.htt" >>  logs/error_log
./htt.sh -s ./scripts/QS_SrvMaxConnClose_20.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_SrvMaxConnClose_20.htt"
fi

# -----------------------------------------------------------------
echo "-- static filter, QS_DenyRequestLine.htt" >>  logs/error_log
./htt.sh -s ./scripts/QS_DenyRequestLine.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_DenyRequestLine.htt"
fi
./htt.sh -s ./scripts/QS_DenyEvent.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_DenyEvent.htt"
fi

# -----------------------------------------------------------------
echo "-- dynamic keep alive, QS_KeepAliveTimeout" >>  logs/error_log
./htt.sh -s ./scripts/QS_KeepAliveTimeout.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_KeepAliveTimeout.htt"
fi

# -----------------------------------------------------------------
echo "-- request/sec limit, QS_LocRequestPerSecLimit_5.htt" >>  logs/error_log
./htt.sh -s ./scripts/QS_LocRequestPerSecLimit_5.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_LocRequestPerSecLimit_5.htt"
fi
./htt.sh -s ./scripts/QS_LocRequestPerSecLimit_5t.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_LocRequestPerSecLimit_5t.htt"
fi

# -----------------------------------------------------------------
echo "-- kbytes/sec limit, QS_LocKBytesPerSecLimit.htt" >>  logs/error_log
./htt.sh -s ./scripts/QS_LocKBytesPerSecLimit.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_LocKBytesPerSecLimit.htt"
fi
./htt.sh -s ./scripts/QS_LocKBytesPerSecLimit_t.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_LocKBytesPerSecLimit_t.htt"
fi

# -----------------------------------------------------------------
echo "-- QS_EventRequestLimit.htt" >>  logs/error_log
./htt.sh -s ./scripts/QS_EventRequestLimit.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_EventRequestLimit.htt"
fi
echo "-- req/sec limit, QS_EventPerSecLimit0.htt" >>  logs/error_log
./htt.sh -s ./scripts/QS_EventPerSecLimit0.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_EventPerSecLimit0.htt"
fi
echo "-- req/sec limit, QS_EventPerSecLimit.htt" >>  logs/error_log
./htt.sh -s ./scripts/QS_EventPerSecLimit.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_EventPerSecLimit.htt"
fi
echo "-- req/sec limit, QS_EventPerSecLimit2.htt" >>  logs/error_log
./htt.sh -s ./scripts/QS_EventPerSecLimit2.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_EventPerSecLimit2.htt"
fi
echo "-- req/sec limit, QS_EventPerSecLimit3.htt" >>  logs/error_log
./htt.sh -s ./scripts/QS_EventPerSecLimit3.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_EventPerSecLimit3.htt"
fi
echo "-- req/sec limit, QS_EventPerSecLimit4.htt" >>  logs/error_log
./htt.sh -s ./scripts/QS_EventPerSecLimit4.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_EventPerSecLimit4.htt"
fi

# -----------------------------------------------------------------
echo "-- req/sec limit, QS_LocRequestPerSecLimitMatch.htt" >>  logs/error_log
./htt.sh -s ./scripts/QS_LocRequestPerSecLimitMatch.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_LocRequestPerSecLimitMatch.htt"
fi
./htt.sh -s ./scripts/QS_LocRequestPerSecLimitMatch_t.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_LocRequestPerSecLimitMatch_t.htt"
fi
sleep 1
# -----------------------------------------------------------------
echo "-- multiple requests in parallel, MultiRequest.htt" >>  logs/error_log
./htt.sh -s ./scripts/MultiRequest.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED MultiRequest.htt"
fi
sleep 1

# -----------------------------------------------------------------
cat logs/access1_log | awk '{print $7}' > logs/loc1.htt
../tools/filter/qsfilter2 -i logs/loc1.htt -v 0 -c appl_conf/qos_deny_filter.conf | grep QS_PermitUri > appl_conf/qos_permit_filter.conf
rm -f logs/loc1.htt
./ctl.sh stop > /dev/null
sleep 2
./ctl.sh start -D permit_filter > /dev/null
sleep 1
echo "-- permit filter QS_PermitUri.htt" >>  logs/error_log
echo "-- permit filter QS_PermitUri.htt" >>  logs/error1_log
./htt.sh -s ./scripts/QS_PermitUri.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_PermitUri.htt"
fi

echo "-- header filter, QS_HeaderFilter.htt" >>  logs/error_log
./htt.sh -s ./scripts/QS_HeaderFilter.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_HeaderFilter.htt"
fi

# -----------------------------------------------------------------
./ctl.sh stop > /dev/null
sleep 2
./ctl.sh start -D max_clients > /dev/null
echo "-- header filter, QS_SrvPreferNet.htt" >>  logs/error_log
./htt.sh scripts/Log.htt > /dev/null
QSTART=`grep -c "mod_qos(033)" logs/error_log`
echo "run ./scripts/QS_SrvPreferNet.htt"
./htt.sh -s ./scripts/QS_SrvPreferNet.htt 2>/dev/null 1>/dev/null
sleep 1
./htt.sh scripts/Log.htt > /dev/null
sleep 2
QFIRST=`grep -c "mod_qos(033)" logs/error_log`
./htt.sh -s ./scripts/QS_SrvPreferNet2.htt 2>/dev/null 1>/dev/null
sleep 1
./htt.sh scripts/Log.htt > /dev/null
sleep 2
QSECOND=`grep -c "mod_qos(033)" logs/error_log`
QDIFF1=`expr $QFIRST - $QSTART`
QDIFF2=`expr $QSECOND - $QFIRST`
echo "$QDIFF1 $QDIFF2"
if [ $QDIFF1 -lt $QDIFF2 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_SrvPreferNet.htt"
fi

### -----------------------------------------------------------------
##echo "-- mod_qos_control, QS_Control_Server.htt" >>  logs/error_log
##./htt.sh -s ./scripts/QS_Control_Server.htt
##if [ $? -ne 0 ]; then
##    ERRORS=`expr $ERRORS + 1`
##    echo "FAILED QS_Control_Server.htt"
##fi

# -----------------------------------------------------------------
./ctl.sh restart -D max_clients -D cc > /dev/null
echo "-- QS_ClientPrefer.htt" >>  logs/error_log
./htt.sh scripts/Log.htt > /dev/null
QSTART=`grep -c "mod_qos(063)" logs/error_log`
echo "run ./scripts/QS_ClientPrefer.htt"
./htt.sh -s ./scripts/QS_ClientPrefer.htt 2>/dev/null 1>/dev/null
sleep 1
./htt.sh scripts/Log.htt > /dev/null
sleep 1
QFIRST=`grep -c "mod_qos(063)" logs/error_log`
./htt.sh -s ./scripts/QS_ClientPrefer2.htt 2>/dev/null 1>/dev/null
sleep 1
./htt.sh scripts/Log.htt > /dev/null
sleep 1
QSECOND=`grep -c "mod_qos(063)" logs/error_log`
./htt.sh -s ./scripts/QS_ClientPrefer_IP.htt 2>/dev/null 1>/dev/null
sleep 1
./htt.sh scripts/Log.htt > /dev/null
sleep 1
QSTHIRD=`grep -c "mod_qos(063)" logs/error_log`
QDIFF1=`expr $QFIRST - $QSTART`
QDIFF2=`expr $QSECOND - $QFIRST`
QDIFF3=`expr $QSTHIRD - $QSECOND`
echo "$QDIFF1 $QDIFF2 $QDIFF3"
if [ $QDIFF1 -lt $QDIFF2 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_ClientPrefer.htt"
fi
if [ $QDIFF2 -lt $QDIFF3 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_ClientPrefer_IP.htt"
fi
QSTART=`grep -c "mod_qos(064)" logs/error_log`
./htt.sh -s ./scripts/QS_ClientPrefer_SP.htt
QFIRST=`grep -c "mod_qos(064)" logs/error_log`
QDIFF1=`expr $QFIRST - $QSTART`
echo "$QDIFF1"
if [ $QDIFF1 -eq 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_ClientPrefer_SP.htt"
fi

echo "-- QS_SetEnvResHeaders" >> logs/error_log
./htt.sh -s ./scripts/QS_SetEnvResHeaders.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_SetEnvResHeaders.htt"
fi
./ctl.sh restart -D real_ip -D cc > /dev/null
echo "-- QS_VipUser" >> logs/error_log
./htt.sh -s ./scripts/QS_VipUser.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_VipUser.htt"
fi

#./ctl.sh restart -D real_ip -D cc > /dev/null
#./htt.sh -s ./scripts/QS_VipIpUser.htt
#if [ $? -ne 0 ]; then
#    ERRORS=`expr $ERRORS + 1`
#    echo "FAILED QS_VipIpUser.htt"
#fi

# - real ip -------------------------------------------------------
./ctl.sh restart -D real_ip > /dev/null
echo "-- QS_ClientEventBlockCount.htt" >>  logs/error_log
./htt.sh -s ./scripts/QS_ClientEventBlockCount.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_ClientEventBlockCount.htt"
fi
sleep 3
echo "-- QS_ClientEventPerSecLimit.htt" >>  logs/error_log
./htt.sh -s ./scripts/QS_ClientEventPerSecLimit.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_ClientEventPerSecLimit.htt"
fi
./htt.sh -s ./scripts/QS_ClientEventPerSecLimit_t.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_ClientEventPerSecLimit_t.htt"
fi
./ctl.sh restart -D real_ip > /dev/null
echo "-- QS_ClientEventBlockCount_Status.htt" >>  logs/error_log
./htt.sh -s ./scripts/QS_ClientEventBlockCount_Status.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_ClientEventBlockCount_Status.htt"
fi
./ctl.sh graceful > /dev/null
./htt.sh -s ./scripts/QS_ClientEventBlockCount_Status_graceful.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_ClientEventBlockCount_Status_graceful.htt"
fi
./ctl.sh restart > /dev/null
echo "-- QS_ClientEventPerSecLimit.htt" >>  logs/error_log
./htt.sh -s ./scripts/QS_ClientEventPerSecLimit.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_ClientEventPerSecLimit.htt"
fi
./htt.sh -s ./scripts/QS_ClientEventPerSecLimit_t2.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_ClientEventPerSecLimit_t2.htt"
fi

./ctl.sh restart -D no_reqrate -D cc > /dev/null
./htt.sh -s ./scripts/QS_ClientPrefer_TMO.htt > /dev/null 2> /dev/null
./htt.sh -s ./scripts/QS_ClientPrefer_TMO2.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_ClientPrefer_TMO.htt"
fi

# - query/parp/path --------------------------------------------
./ctl.sh restart -D cc -D real_ip > /dev/null
PSCR="QS_SetEnvIfQuery.htt QS_SetEnvIfParp.htt QS_DenyQueryParp.htt QS_DenyPath.htt QS_DenyQuery.htt"
for E in $PSCR; do
    ./htt.sh -s ./scripts/${E}
    if [ $? -ne 0 ]; then
	ERRORS=`expr $ERRORS + 1`
	echo "FAILED $E"
    fi
done

# - DDoS -------------------------------------------------------
./htt.sh -s ./scripts/QS_SrvRequestRate_0.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_SrvRequestRate_0.htt"
fi
./htt.sh -s ./scripts/QS_SrvRequestRate_1.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_SrvRequestRate_1.htt"
fi
if [ `tail -1 logs/access_log | grep -c ' r; '` -eq 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_SrvRequestRate_1.htt (no lowrate)"
fi
./htt.sh -s ./scripts/QS_SrvRequestRate_2.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_SrvRequestRate_2.htt"
fi
if [ `tail -20 logs/error_log | grep -c "mod_qos(034)"` -ne 3 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_SrvRequestRate_0/1.htt"
fi
./htt.sh -s ./scripts/QS_SrvRequestRate_3.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_SrvRequestRate_3.htt"
fi
./ctl.sh restart > /dev/null
./htt.sh -s ./scripts/QS_SrvRequestRate_4.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_SrvRequestRate_4.htt"
fi
./htt.sh -s ./scripts/QS_SrvRequestRate_5.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_SrvRequestRate_5.htt"
fi

./htt.sh -s ./scripts/QS_SrvRequestRate_6.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_SrvRequestRate_6.htt"
fi
if [ `tail -17 logs/error_log | grep -c "QS_SrvMinDataRate rule (in)"` -eq 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_SrvRequestRate_6.htt (no error log entry)"
fi

./htt.sh -s ./scripts/QS_SrvResponseRate_0.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_SrvResponseRate_0.htt"
fi

./ctl.sh restart -D cc -D real_ip > /dev/null
./htt.sh -s ./scripts/QS_SetEnvResHeadersMatch.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_SetEnvResHeadersMatch.htt"
fi

# -----------------------------------------------------------------
./ctl.sh stop > /dev/null
sleep 2
for E in `strings ../httpd/modules/qos/.libs/mod_qos.so | grep "mod_qos(" | awk -F':' '{print $1}' | sort -u | grep -v "(00" | grep -v "(02" | grep -v "(051" | grep -v "(053" | grep -v "(062"`; do
    C=`grep -c $E logs/error_log`
    C1=`grep -c $E logs/error1_log`
    if [ $C -eq 0 -a $C1 -eq 0 ]; then
        WARNINGS=`expr $WARNINGS + 1`
	echo "WARNING: missing message $E $C $C1"
    fi
done

IPCS2=`ipcs | wc -l`
echo "ipcs: $IPCS $IPCS2"
if [ $IPCS -ne $IPCS2 ]; then
    echo "WARNING: ipcs count changed"
    WARNINGS=`expr $WARNINGS + 1`
fi


if [ $WARNINGS -ne 0 ]; then
    echo "ERROR: got $WARNINGS warnings"
fi

if [ $ERRORS -ne 0 ]; then
    echo "ERROR: end with $ERRORS errors"
    exit 1
fi

CFS=`find . -name "*core*"`
if [ "$CFS" != "" ]; then
    echo "ERROR: found core file"
    exit 1
fi

echo "normal end"
exit 0
