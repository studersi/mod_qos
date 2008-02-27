#!/bin/sh
#
# $Header: /home/cvs/m/mo/mod-qos/src/test/test.sh,v 2.34 2008-02-27 21:10:07 pbuchbinder Exp $
#
# mod_qos test cases, requires htt, see http://htt.sourceforge.net/
#
# See http://sourceforge.net/projects/mod-qos/ for further
# details about mod_qos.
#
# Copyright (C) 2007 Pascal Buchbinder
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
    ./ctl.sh stop
    echo "FAILED QS_QS_SrvMaxConnPerIP_10.htt"
    exit 1
fi
./ctl.sh stop > /dev/null
sleep 2
./ctl.sh start > /dev/null

# -----------------------------------------------------------------
echo "-- 6 requests to an url limited to max 5 concurrent requests, QS_LocRequestLimit_5.htt" >>  logs/error_log
./htt.sh -s ./scripts/QS_LocRequestLimit_5.htt
if [ $? -ne 0 ]; then
    ./ctl.sh stop
    echo "FAILED QS_LocRequestLimit_5.htt"
    exit 1
fi
./htt.sh -s ./scripts/QS_LocRequestLimit_DynamicErrorPage.htt
if [ $? -ne 0 ]; then
    ./ctl.sh stop
    echo "FAILED QS_LocRequestLimit_DynamicErrorPage.htt"
    exit 1
fi

# -----------------------------------------------------------------
echo "-- 3 requests with matching regex rule max 2 (overrides location rule), QS_LocRequestLimitMatch_2.htt" >>  logs/error_log
./htt.sh -s ./scripts/QS_LocRequestLimitMatch_2.htt
if [ $? -ne 0 ]; then
    ./ctl.sh stop
    echo "FAILED QS_LocRequestLimitMatch_2.htt"
    exit 1
fi
# one rule for multiple loctions
./htt.sh -s ./scripts/QS_LocRequestLimitMatch.htt
if [ $? -ne 0 ]; then
    ./ctl.sh stop
    echo "FAILED QS_LocRequestLimitMatch.htt"
    exit 1
fi
./htt.sh -s ./scripts/QS_LocRequestLimitMatch_3.htt
if [ $? -ne 0 ]; then
    ./ctl.sh stop
    echo "FAILED QS_LocRequestLimitMatch_3.htt"
    exit 1
fi

# -----------------------------------------------------------------
echo "-- vip session, QS_VipHeaderName.htt" >>  logs/error_log
./htt.sh -s ./scripts/QS_VipHeaderName.htt
if [ $? -ne 0 ]; then
    ./ctl.sh stop
    echo "FAILED QS_VipHeaderName.htt"
    exit 1
fi

# -----------------------------------------------------------------
echo "-- vip request, QS_VipRequest.htt" >>  logs/error_log
./htt.sh -s ./scripts/QS_VipRequest.htt
if [ $? -ne 0 ]; then
    ./ctl.sh stop
    echo "FAILED QS_VipRequest.htt"
    exit 1
fi

# -----------------------------------------------------------------
echo "-- vip request and graceful restart, QS_VipHeaderName_Graceful.htt" >>  logs/error_log
./htt.sh -s ./scripts/QS_VipHeaderName_Graceful.htt
if [ $? -ne 0 ]; then
    ./ctl.sh stop
    echo "FAILED QS_VipHeaderName_Graceful.htt"
    exit 1
fi

# -----------------------------------------------------------------
echo "-- graceful, QS_Graceful.htt" >> logs/error_log
./htt.sh -s ./scripts/QS_Graceful.htt
if [ $? -ne 0 ]; then
    ./ctl.sh stop
    echo "FAILED QS_Graceful.htt"
    exit 1
fi
./htt.sh -s ./scripts/QS_Graceful2.htt
if [ $? -ne 0 ]; then
    ./ctl.sh stop
    echo "FAILED QS_Graceful2.htt"
    exit 1
fi

# -----------------------------------------------------------------
echo "-- 50 connections, QS_SrvMaxConn 40" >> logs/error_log
./htt.sh -s ./scripts/QS_SrvMaxConn_50.htt
if [ $? -ne 0 ]; then
    ./ctl.sh stop
    echo "FAILED QS_SrvMaxConn_50.htt"
    exit 1
fi

# -----------------------------------------------------------------
echo "-- connection timeout, QS_SrvConnTimeout.htt" >>  logs/error_log
./htt.sh -s ./scripts/QS_SrvConnTimeout.htt
if [ $? -ne 0 ]; then
    ./ctl.sh stop
    echo "FAILED QS_SrvConnTimeout.htt"
    exit 1
fi
./htt.sh -s ./scripts/QS_SrvConnTimeout_body.htt
if [ $? -ne 0 ]; then
    ./ctl.sh stop
    echo "FAILED QS_SrvConnTimeout_body.htt"
    exit 1
fi

sleep 1
# -----------------------------------------------------------------
echo "-- disable keep alive, QS_SrvMaxConnClose_20.htt" >>  logs/error_log
./htt.sh -s ./scripts/QS_SrvMaxConnClose_20.htt
if [ $? -ne 0 ]; then
    ./ctl.sh stop
    echo "FAILED QS_SrvMaxConnClose_20.htt"
    exit 1
fi

# -----------------------------------------------------------------
echo "-- static filter, QS_DenyRequestLine.htt" >>  logs/error_log
./htt.sh -s ./scripts/QS_DenyRequestLine.htt
if [ $? -ne 0 ]; then
    ./ctl.sh stop
    echo "FAILED QS_DenyRequestLine.htt"
    exit 1
fi



# -----------------------------------------------------------------
echo "-- dynamic keep alive, QS_KeepAliveTimeout" >>  logs/error_log
./htt.sh -s ./scripts/QS_KeepAliveTimeout.htt
if [ $? -ne 0 ]; then
    ./ctl.sh stop
    echo "FAILED QS_KeepAliveTimeout.htt"
    exit 1
fi

# -----------------------------------------------------------------
echo "-- request/sec limit, QS_LocRequestPerSecLimit_5.htt" >>  logs/error_log
./htt.sh -s ./scripts/QS_LocRequestPerSecLimit_5.htt
if [ $? -ne 0 ]; then
    ./ctl.sh stop
    echo "FAILED QS_LocRequestPerSecLimit_5.htt"
    exit 1
fi
./htt.sh -s ./scripts/QS_LocRequestPerSecLimit_5t.htt
if [ $? -ne 0 ]; then
    ./ctl.sh stop
    echo "FAILED QS_LocRequestPerSecLimit_5t.htt"
    exit 1
fi

# -----------------------------------------------------------------
echo "-- kbytes/sec limit, QS_LocKBytesPerSecLimit.htt" >>  logs/error_log
./htt.sh -s ./scripts/QS_LocKBytesPerSecLimit.htt
if [ $? -ne 0 ]; then
    ./ctl.sh stop
    echo "FAILED QS_LocKBytesPerSecLimit.htt"
    exit 1
fi
./htt.sh -s ./scripts/QS_LocKBytesPerSecLimit_t.htt
if [ $? -ne 0 ]; then
    ./ctl.sh stop
    echo "FAILED QS_LocKBytesPerSecLimit_t.htt"
    exit 1
fi

# -----------------------------------------------------------------
echo "-- req/sec limit, QS_LocRequestPerSecLimitMatch.htt" >>  logs/error_log
./htt.sh -s ./scripts/QS_LocRequestPerSecLimitMatch.htt
if [ $? -ne 0 ]; then
    ./ctl.sh stop
    echo "FAILED QS_LocRequestPerSecLimitMatch.htt"
    exit 1
fi
./htt.sh -s ./scripts/QS_LocRequestPerSecLimitMatch_t.htt
if [ $? -ne 0 ]; then
    ./ctl.sh stop
    echo "FAILED QS_LocRequestPerSecLimitMatch_t.htt"
    exit 1
fi
sleep 1
# -----------------------------------------------------------------
echo "-- multiple requests in parallel, MultiRequest.htt" >>  logs/error_log
./htt.sh -s ./scripts/MultiRequest.htt
if [ $? -ne 0 ]; then
    ./ctl.sh stop
    echo "FAILED MultiRequest.htt"
    exit 1
fi

# -----------------------------------------------------------------
cat logs/access1_log | awk '{print $7}' > logs/loc1.htt
../tools/filter/qsfilter2 -i logs/loc1.htt -v 0 -c appl_conf/qos_deny_filter.conf | grep QS_PermitUri > appl_conf/qos_permit_filter.conf
rm -f logs/loc1.htt
./ctl.sh stop > /dev/null
sleep 2
./ctl.sh start -D permit_filter > /dev/null
echo "-- permit filter QS_PermitUri.htt" >>  logs/error_log
./htt.sh -s ./scripts/QS_PermitUri.htt
if [ $? -ne 0 ]; then
    ./ctl.sh stop
    echo "FAILED QS_PermitUri.htt"
    exit 1
fi


echo "-- header filter, QS_HeaderFilter.htt" >>  logs/error_log
./htt.sh -s ./scripts/QS_HeaderFilter.htt
if [ $? -ne 0 ]; then
    ./ctl.sh stop
    echo "FAILED QS_HeaderFilter.htt"
    exit 1
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
sleep 10
./htt.sh scripts/Log.htt > /dev/null
QFIRST=`grep -c "mod_qos(033)" logs/error_log`
./htt.sh -s ./scripts/QS_SrvPreferNet2.htt 2>/dev/null 1>/dev/null
sleep 10
./htt.sh scripts/Log.htt > /dev/null
QSECOND=`grep -c "mod_qos(033)" logs/error_log`
QDIFF1=`expr $QFIRST - $QSTART`
QDIFF2=`expr $QSECOND - $QFIRST`
echo "$QDIFF1 $QDIFF2"
if [ $QDIFF1 -lt $QDIFF2 ]; then
    ./ctl.sh stop
    echo "FAILED QS_SrvPreferNet.htt"
    exit 1
fi

# -----------------------------------------------------------------
echo "-- mod_qos_control, QS_Control_Server.htt" >>  logs/error_log
./htt.sh -s ./scripts/QS_Control_Server.htt
if [ $? -ne 0 ]; then
    ./ctl.sh stop
    echo "FAILED QS_Control_Server.htt"
    exit 1
fi

# -----------------------------------------------------------------
./ctl.sh stop > /dev/null
echo "normal end"
exit 0
