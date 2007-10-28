#!/bin/sh
#
# $Header: /home/cvs/m/mo/mod-qos/src/test/test.sh,v 2.25 2007-10-28 19:23:19 pbuchbinder Exp $
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

echo "start server http://localhost:$QS_PORT_BASE/test/index.html"
echo "-- start `date` --" >>  logs/error_log
# -----------------------------------------------------------------
./ctl.sh start -D real_ip > /dev/null
(echo "GET /test/index.html HTTP/1.0";  echo ""; echo "") | telnet localhost $QS_PORT_BASE 2>/dev/null 1>/dev/null

# -----------------------------------------------------------------
echo "-- client opens more than 10 connections, QS_SrvMaxConnPerIP_10.txt" >>  logs/error_log
./htt.sh -s ./scripts/QS_SrvMaxConnPerIP_10.txt
if [ $? -ne 0 ]; then
    ./ctl.sh stop
    echo "FAILED QS_QS_SrvMaxConnPerIP_10.txt"
    exit 1
fi
./ctl.sh stop > /dev/null
sleep 1
./ctl.sh start > /dev/null

# -----------------------------------------------------------------
echo "-- 6 requests to an url limited to max 5 concurrent requests, QS_LocRequestLimit_5.txt" >>  logs/error_log
./htt.sh -s ./scripts/QS_LocRequestLimit_5.txt
if [ $? -ne 0 ]; then
    ./ctl.sh stop
    echo "FAILED QS_LocRequestLimit_5.txt"
    exit 1
fi
./htt.sh -s ./scripts/QS_LocRequestLimit_DynamicErrorPage.txt
if [ $? -ne 0 ]; then
    ./ctl.sh stop
    echo "FAILED QS_LocRequestLimit_DynamicErrorPage.txt"
    exit 1
fi

# -----------------------------------------------------------------
echo "-- 3 requests with matching regex rule max 2 (overrides location rule), QS_LocRequestLimitMatch_2.txt" >>  logs/error_log
./htt.sh -s ./scripts/QS_LocRequestLimitMatch_2.txt
if [ $? -ne 0 ]; then
    ./ctl.sh stop
    echo "FAILED QS_LocRequestLimitMatch_2.txt"
    exit 1
fi

# -----------------------------------------------------------------
echo "-- vip session, QS_VipHeaderName.txt" >>  logs/error_log
./htt.sh -s ./scripts/QS_VipHeaderName.txt
if [ $? -ne 0 ]; then
    ./ctl.sh stop
    echo "FAILED QS_VipHeaderName.txt"
    exit 1
fi

# -----------------------------------------------------------------
echo "-- vip request, QS_VipRequest.txt" >>  logs/error_log
./htt.sh -s ./scripts/QS_VipRequest.txt
if [ $? -ne 0 ]; then
    ./ctl.sh stop
    echo "FAILED QS_VipRequest.txt"
    exit 1
fi

# -----------------------------------------------------------------
echo "-- vip request and graceful restart, QS_VipHeaderName_Graceful.txt" >>  logs/error_log
./htt.sh -s ./scripts/QS_VipHeaderName_Graceful.txt
if [ $? -ne 0 ]; then
    ./ctl.sh stop
    echo "FAILED QS_VipHeaderName_Graceful.txt"
    exit 1
fi

# -----------------------------------------------------------------
echo "-- graceful, QS_Graceful.txt" >> logs/error_log
./htt.sh -s ./scripts/QS_Graceful.txt
if [ $? -ne 0 ]; then
    ./ctl.sh stop
    echo "FAILED QS_Graceful.txt"
    exit 1
fi
./htt.sh -s ./scripts/QS_Graceful2.txt
if [ $? -ne 0 ]; then
    ./ctl.sh stop
    echo "FAILED QS_Graceful2.txt"
    exit 1
fi

# -----------------------------------------------------------------
echo "-- 50 connections, QS_SrvMaxConn 40" >> logs/error_log
./htt.sh -s ./scripts/QS_SrvMaxConn_50.txt
if [ $? -ne 0 ]; then
    ./ctl.sh stop
    echo "FAILED QS_SrvMaxConn_50.txt"
    exit 1
fi

# -----------------------------------------------------------------
echo "-- connection timeout, QS_SrvConnTimeout.txt" >>  logs/error_log
./htt.sh -s ./scripts/QS_SrvConnTimeout.txt
if [ $? -ne 0 ]; then
    ./ctl.sh stop
    echo "FAILED QS_SrvConnTimeout.txt"
    exit 1
fi

sleep 1
# -----------------------------------------------------------------
echo "-- disable keep alive, QS_SrvMaxConnClose_20.txt" >>  logs/error_log
./htt.sh -s ./scripts/QS_SrvMaxConnClose_20.txt
if [ $? -ne 0 ]; then
    ./ctl.sh stop
    echo "FAILED QS_SrvMaxConnClose_20.txt"
    exit 1
fi

# -----------------------------------------------------------------
echo "-- static filter, QS_DenyRequestLine.txt" >>  logs/error_log
./htt.sh -s ./scripts/QS_DenyRequestLine.txt
if [ $? -ne 0 ]; then
    ./ctl.sh stop
    echo "FAILED QS_DenyRequestLine.txt"
    exit 1
fi



# -----------------------------------------------------------------
echo "-- dynamic keep alive, QS_KeepAliveTimeout" >>  logs/error_log
./htt.sh -s ./scripts/QS_KeepAliveTimeout.txt
if [ $? -ne 0 ]; then
    ./ctl.sh stop
    echo "FAILED QS_KeepAliveTimeout.txt"
    exit 1
fi

# -----------------------------------------------------------------
echo "-- request/sec limit, QS_LocRequestPerSecLimit_5.txt" >>  logs/error_log
./htt.sh -s ./scripts/QS_LocRequestPerSecLimit_5.txt
if [ $? -ne 0 ]; then
    ./ctl.sh stop
    echo "FAILED QS_LocRequestPerSecLimit_5.txt"
    exit 1
fi
./htt.sh -s ./scripts/QS_LocRequestPerSecLimit_5t.txt
if [ $? -ne 0 ]; then
    ./ctl.sh stop
    echo "FAILED QS_LocRequestPerSecLimit_5t.txt"
    exit 1
fi

# -----------------------------------------------------------------
echo "-- kbytes/sec limit, QS_LocKBytesPerSecLimit.txt" >>  logs/error_log
./htt.sh -s ./scripts/QS_LocKBytesPerSecLimit.txt
if [ $? -ne 0 ]; then
    ./ctl.sh stop
    echo "FAILED QS_LocKBytesPerSecLimit.txt"
    exit 1
fi
./htt.sh -s ./scripts/QS_LocKBytesPerSecLimit_t.txt
if [ $? -ne 0 ]; then
    ./ctl.sh stop
    echo "FAILED QS_LocKBytesPerSecLimit_t.txt"
    exit 1
fi

# -----------------------------------------------------------------
echo "-- req/sec limit, QS_LocRequestPerSecLimitMatch.txt" >>  logs/error_log
./htt.sh -s ./scripts/QS_LocRequestPerSecLimitMatch.txt
if [ $? -ne 0 ]; then
    ./ctl.sh stop
    echo "FAILED QS_LocRequestPerSecLimitMatch.txt"
    exit 1
fi
./htt.sh -s ./scripts/QS_LocRequestPerSecLimitMatch_t.txt
if [ $? -ne 0 ]; then
    ./ctl.sh stop
    echo "FAILED QS_LocRequestPerSecLimitMatch_t.txt"
    exit 1
fi
sleep 1
# -----------------------------------------------------------------
echo "-- multiple requests in parallel, MultiRequest.txt" >>  logs/error_log
./htt.sh -s ./scripts/MultiRequest.txt
if [ $? -ne 0 ]; then
    ./ctl.sh stop
    echo "FAILED MultiRequest.txt"
    exit 1
fi

# -----------------------------------------------------------------
cat logs/access1_log | awk '{print $7}' > logs/loc1.txt
../tools/filter/qsfilter2 -i logs/loc1.txt -v 0 -c appl_conf/qos_deny_filter.conf | grep QS_PermitUri > appl_conf/qos_permit_filter.conf
rm -f logs/loc1.txt
./ctl.sh stop > /dev/null
./ctl.sh start -D permit_filter > /dev/null
echo "-- permit filter QS_PermitUri.txt" >>  logs/error_log
./htt.sh -s ./scripts/QS_PermitUri.txt
if [ $? -ne 0 ]; then
    ./ctl.sh stop
    echo "FAILED QS_PermitUri.txt"
    exit 1
fi


echo "-- header filter, QS_HeaderFilter.txt" >>  logs/error_log
./htt.sh -s ./scripts/QS_HeaderFilter.txt
if [ $? -ne 0 ]; then
    ./ctl.sh stop
    echo "FAILED QS_HeaderFilter.txt"
    exit 1
fi

# -----------------------------------------------------------------
./ctl.sh stop > /dev/null
echo "normal end"
exit 0
