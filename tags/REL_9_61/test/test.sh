#!/bin/sh
# -*-mode: ksh; ksh-indent: 2; -*-
#
# $Header: /home/cvs/m/mo/mod-qos/src/test/test.sh,v 2.162 2011-07-13 19:05:51 pbuchbinder Exp $
#
# mod_qos test cases, requires htt, see http://htt.sourceforge.net/
#
# See http://opensource.adnovum.ch/mod_qos/ for further
# details about mod_qos.
#
# Copyright (C) 2007-2011 Pascal Buchbinder
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

cd `dirname $0`

if [ `ps -ef | grep -v grep | grep -c "tee test.log"` -eq 0 ]; then
  $0 | tee test.log
  exit $?
fi

./generate.sh
. ./ports

ERRORS=0
WARNINGS=0

# delete the access log file since it is used to generate permit rules
./ctl.sh stop
sleep 1
IPCS=`ipcs | wc -l`
rm -f logs/*
rm -rf /var/tmp/qosc/server1
echo "start (`date '+%a %b %d %H:%M:%S %Y'`) server http://localhost:$QS_PORT_BASE/test/index.html"
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- start --" >>  logs/error_log
# -----------------------------------------------------------------
./ctl.sh start -D real_ip > /dev/null
(echo "GET /test/index.html HTTP/1.0";  echo ""; echo "") | telnet localhost $QS_PORT_BASE 2>/dev/null 1>/dev/null

# -----------------------------------------------------------------
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- client opens more than 10 connections, QS_SrvMaxConnPerIP_10.htt" >>  logs/error_log
./run.sh -se ./scripts/QS_SrvMaxConnPerIP_10.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_QS_SrvMaxConnPerIP_10.htt"
fi
./ctl.sh stop > /dev/null
sleep 2
./ctl.sh start > /dev/null

# -----------------------------------------------------------------
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- 6 requests to an url limited to max 5 concurrent requests, QS_LocRequestLimit_5.htt" >>  logs/error_log
./run.sh -s ./scripts/QS_LocRequestLimit_5.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_LocRequestLimit_5.htt"
fi
./run.sh -se ./scripts/QS_LocRequestLimit_DynamicErrorPage.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_LocRequestLimit_DynamicErrorPage.htt"
fi

# -----------------------------------------------------------------
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- 3 requests with matching regex rule max 2 (overrides location rule), QS_LocRequestLimitMatch_2.htt" >>  logs/error_log
./run.sh -se ./scripts/QS_LocRequestLimitMatch_2.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_LocRequestLimitMatch_2.htt"
fi
# one rule for multiple loctions
./run.sh -se ./scripts/QS_LocRequestLimitMatch.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_LocRequestLimitMatch.htt"
fi
./run.sh -se ./scripts/QS_LocRequestLimitMatch_3.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_LocRequestLimitMatch_3.htt"
fi

# -----------------------------------------------------------------
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- conditional rule QS_CondLocRequestLimitMatch.htt" >>  logs/error_log
./run.sh -se ./scripts/QS_CondLocRequestLimitMatch.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_CondLocRequestLimitMatch.htt"
fi

# -----------------------------------------------------------------
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- vip session, QS_VipHeaderName.htt" >>  logs/error_log
./run.sh -se ./scripts/QS_VipHeaderName.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_VipHeaderName.htt"
fi
./run.sh -se ./scripts/QS_VipHeaderName2.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_VipHeaderName2.htt"
fi
sleep 1

# -----------------------------------------------------------------
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- vip request, QS_VipRequest.htt" >>  logs/error_log
./run.sh -se ./scripts/QS_VipRequest.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_VipRequest.htt"
fi
sleep 1

# -----------------------------------------------------------------
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- vip request and graceful restart, QS_VipHeaderName_Graceful.htt" >>  logs/error_log
./run.sh -se ./scripts/QS_VipHeaderName_Graceful.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_VipHeaderName_Graceful.htt"
fi
sleep 1

# -----------------------------------------------------------------
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- graceful, QS_Graceful.htt" >> logs/error_log
./run.sh -se ./scripts/QS_Graceful.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_Graceful.htt"
fi
sleep 1

./run.sh -se ./scripts/QS_Graceful2.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_Graceful2.htt"
fi
sleep 1

# -----------------------------------------------------------------
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- 50 connections, QS_SrvMaxConn 40" >> logs/error_log
./run.sh -se ./scripts/QS_SrvMaxConn_50.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_SrvMaxConn_50.htt"
fi

# -----------------------------------------------------------------
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- connection timeout, QS_SrvConnTimeout_body.htt" >>  logs/error_log
./run.sh -se ./scripts/QS_SrvConnTimeout_body.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_SrvConnTimeout_body.htt"
fi

sleep 2
# -----------------------------------------------------------------
CLT="QS_SrvMaxConnClosePercent.htt QS_SrvMaxConnClose_20.htt"
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- disable keep alive, QS_SrvMaxConnClose*" >>  logs/error_log
for E in $CLR; do
    ./run.sh -se ./scripts/$E
    if [ $? -ne 0 ]; then
	ERRORS=`expr $ERRORS + 1`
	echo "FAILED $E"
    fi
done

# -----------------------------------------------------------------
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- static filter, QS_DenyRequestLine.htt" >>  logs/error_log
./run.sh -se ./scripts/QS_DenyRequestLine.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_DenyRequestLine.htt"
fi
./run.sh -se ./scripts/QS_DenyEvent.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_DenyEvent.htt"
fi

# -----------------------------------------------------------------
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- dynamic keep alive, QS_KeepAliveTimeout" >>  logs/error_log
./run.sh -se ./scripts/QS_KeepAliveTimeout.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_KeepAliveTimeout.htt"
fi
./run.sh -se ./scripts/QS_KeepAliveTimeout2.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_KeepAliveTimeout2.htt"
fi

# -----------------------------------------------------------------
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- request/sec limit, QS_LocRequestPerSecLimit_5.htt" >>  logs/error_log
./run.sh -se ./scripts/QS_LocRequestPerSecLimit_5.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_LocRequestPerSecLimit_5.htt"
fi
./run.sh -se ./scripts/QS_LocRequestPerSecLimit_5t.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_LocRequestPerSecLimit_5t.htt"
fi

# -----------------------------------------------------------------
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- kbytes/sec limit, QS_LocKBytesPerSecLimit.htt" >>  logs/error_log
./run.sh -se ./scripts/QS_LocKBytesPerSecLimit.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_LocKBytesPerSecLimit.htt"
fi
./run.sh -se ./scripts/QS_LocKBytesPerSecLimit_t.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_LocKBytesPerSecLimit_t.htt"
fi

# -----------------------------------------------------------------
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- QS_EventRequestLimit.htt" >>  logs/error_log
./run.sh -s ./scripts/QS_EventRequestLimit.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_EventRequestLimit.htt"
fi
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- QS_EventRequestLimit_vip.htt" >>  logs/error_log
./run.sh -s ./scripts/QS_EventRequestLimit_vip.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_EventRequestLimit_vip.htt"
fi
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- req/sec limit, QS_EventPerSecLimit0.htt" >>  logs/error_log
./run.sh -se ./scripts/QS_EventPerSecLimit0.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_EventPerSecLimit0.htt"
fi
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- req/sec limit, QS_EventPerSecLimit.htt" >>  logs/error_log
./run.sh -se ./scripts/QS_EventPerSecLimit.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_EventPerSecLimit.htt"
fi
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- req/sec limit, QS_EventPerSecLimit2.htt" >>  logs/error_log
./run.sh -se ./scripts/QS_EventPerSecLimit2.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_EventPerSecLimit2.htt"
fi
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- req/sec limit, QS_EventPerSecLimit3.htt" >>  logs/error_log
./run.sh -se ./scripts/QS_EventPerSecLimit3.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_EventPerSecLimit3.htt"
fi
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- req/sec limit, QS_EventPerSecLimit4.htt" >>  logs/error_log
./run.sh -se ./scripts/QS_EventPerSecLimit4.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_EventPerSecLimit4.htt"
fi

# -----------------------------------------------------------------
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- req/sec limit, QS_LocRequestPerSecLimitMatch.htt" >>  logs/error_log
./run.sh -se ./scripts/QS_LocRequestPerSecLimitMatch.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_LocRequestPerSecLimitMatch.htt"
fi
./run.sh -se ./scripts/QS_LocRequestPerSecLimitMatch_t.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_LocRequestPerSecLimitMatch_t.htt"
fi
sleep 1
# -----------------------------------------------------------------
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- multiple requests in parallel, MultiRequest.htt" >>  logs/error_log
./run.sh -se ./scripts/MultiRequest.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED MultiRequest.htt"
fi
sleep 1

./ctl.sh restart > /dev/null
sleep 1
./run.sh -se ./scripts/Graceful.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED Graceful.htt"
    sleep 2
fi
sleep 2

# -----------------------------------------------------------------
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- kbytes/sec limit, QS_EventKBytesPerSecLimit.htt" >>  logs/error_log
./run.sh -se ./scripts/QS_EventKBytesPerSecLimit.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_EventKBytesPerSecLimit.htt"
fi

# -----------------------------------------------------------------
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- permit filter QS_PermitUri.htt" >>  logs/error_log
echo "-- permit filter QS_PermitUri_pre.htt" >>  logs/error1_log
./run.sh -se ./scripts/QS_PermitUri_pre.htt
./bin/sleep 200
./ctl.sh stop > /dev/null
cat logs/access1_log | awk '{print $7}' > logs/loc1.htt
../util/src/qsfilter2 -i logs/loc1.htt -v 0 -c appl_conf/qos_deny_filter.conf | grep QS_PermitUri > appl_conf/qos_permit_filter.conf
./ctl.sh start -D permit_filter > /dev/null
./bin/sleep 200
echo "-- permit filter QS_PermitUri.htt" >>  logs/error1_log
./run.sh -se ./scripts/QS_PermitUri.htt
if [ $? -ne 0 ]; then
  ERRORS=`expr $ERRORS + 1`
  echo "FAILED QS_PermitUri.htt"
else
  rm -f logs/loc1.htt
fi

./run.sh -se ./scripts/QS_PermitUriAudit.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_PermitUriAudit.htt"
fi

echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- header filter, QS_HeaderFilter.htt" >>  logs/error_log
./run.sh -se ./scripts/QS_HeaderFilter.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_HeaderFilter.htt"
fi
# -----------------------------------------------------------------
./prefer.sh
EXT_ERR=$?
if [ $EXT_ERR -gt 0 ]; then
    echo "run again ..."
    ./prefer.sh
    EXT_ERR=$?
    if [ $EXT_ERR -eq 0 ]; then
	echo "                 OK"
    fi
fi
ERRORS=`expr $ERRORS + $EXT_ERR`

echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- QS_SetEnvResHeaders" >> logs/error_log
./run.sh -se ./scripts/QS_SetEnvResHeaders.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_SetEnvResHeaders.htt"
fi
./ctl.sh restart -D real_ip -D cc > /dev/null
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- QS_Graceful_cc.htt" >> logs/error_log
./run.sh -se ./scripts/QS_Graceful_cc.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_Graceful_cc.htt"
fi
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- QS_VipUser" >> logs/error_log
./run.sh -se ./scripts/QS_VipUser.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_VipUser.htt"
fi
./run.sh -se ./scripts/QS_VipCookie.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_VipCookie.htt"
fi

./ctl.sh restart -D real_ip -D cc > /dev/null
./run.sh -se ./scripts/QS_VipIpUser.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_VipIpUser.htt"
fi

./ctl.sh restart -D real_ip -D cc -D special-mod-qos-vip-ip > /dev/null
sleep 1
./run.sh -se ./scripts/QS_VipIpUser2.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_VipIpUser2.htt"
fi

# - real ip -------------------------------------------------------
./ctl.sh restart -D real_ip > /dev/null
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- QS_ClientEventBlockCount2.htt" >>  logs/error_log
./run.sh -se ./scripts/QS_ClientEventBlockCount2.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_ClientEventBlockCount2.htt"
fi

./ctl.sh restart -D real_ip > /dev/null
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- QS_ClientEventBlockCount.htt" >>  logs/error_log
./run.sh -se ./scripts/QS_ClientEventBlockCount.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_ClientEventBlockCount.htt"
fi
sleep 3
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- QS_ClientEventPerSecLimit.htt" >>  logs/error_log
./run.sh -se ./scripts/QS_ClientEventPerSecLimit.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_ClientEventPerSecLimit.htt"
fi
./run.sh -se ./scripts/QS_ClientEventPerSecLimit_t.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_ClientEventPerSecLimit_t.htt"
fi
./ctl.sh restart -D real_ip > /dev/null
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- QS_ClientEventBlockCount_Status_vip.htt" >>  logs/error_log
./run.sh -se ./scripts/QS_ClientEventBlockCount_Status_vip.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_ClientEventBlockCount_Status_vip.htt"
fi
./ctl.sh restart -D real_ip > /dev/null
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- QS_ClientEventBlockCount_Status.htt" >>  logs/error_log
./run.sh -se ./scripts/QS_ClientEventBlockCount_Status.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_ClientEventBlockCount_Status.htt"
fi
./ctl.sh graceful > /dev/null
./run.sh -se ./scripts/QS_ClientEventBlockCount_Status_graceful.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_ClientEventBlockCount_Status_graceful.htt"
fi
sleep 1

./ctl.sh restart > /dev/null
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- QS_ClientEventPerSecLimit.htt" >>  logs/error_log
./run.sh -se ./scripts/QS_ClientEventPerSecLimit.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_ClientEventPerSecLimit.htt"
fi
./run.sh -se ./scripts/QS_ClientEventPerSecLimit_t2.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_ClientEventPerSecLimit_t2.htt"
fi
./ctl.sh restart -D real_ip -D cc > /dev/null
./run.sh -se ./scripts/QS_ClientEventRequestLimit.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_ClientEventRequestLimit.htt"
fi

echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- QS_SrvMinDataRate.htt" >>  logs/error_log
./ctl.sh restart -D no_reqrate -D reqrate10 > /dev/null
./run.sh -se ./scripts/QS_SrvMinDataRate.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_SrvMinDataRate.htt"
fi

./ctl.sh restart -D no_reqrate -D cc > /dev/null
./run.sh -s ./scripts/QS_ClientPrefer_TMO.htt > /dev/null 2> /dev/null
./run.sh -se ./scripts/QS_ClientPrefer_TMO2.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_ClientPrefer_TMO.htt"
fi

# - query/parp/path --------------------------------------------
./ctl.sh restart -D cc -D real_ip > /dev/null
PSCR="QS_Delay.htt QS_SetEnvIfQuery.htt QS_SetEnvIfParp.htt QS_SetEnvIfBody.htt QS_SetEnvIfBody_support.htt QS_DenyQueryParp.htt QS_DenyQueryParpDeflate.htt QS_SetEnvIfParpDeflate.htt QS_SetEnvIfBodyDeflate.htt QS_DenyQueryParpHuge.htt QS_DenyQueryParpForm.htt QS_PermitUriParp.htt QS_PermitUriJSON.htt QS_DenyPath.htt QS_DenyQuery.htt QS_InvalidUrlEncoding.htt QS_DenyEnc.htt QS_LimitRequestBody.htt QS_DenyDecoding_uni.htt QS_ErrorPage.htt"
for E in $PSCR; do
    ./run.sh -s ./scripts/${E}
    if [ $? -ne 0 ]; then
	ERRORS=`expr $ERRORS + 1`
	echo "FAILED $E"
    fi
done
./htt.sh -se ./scripts/QS_UriParser.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_UriParser.htt"
fi
./run.sh -se ./scripts/Count.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED Count.htt"
fi

./ctl.sh restart -D real_ip > /dev/null
./run.sh -s ./scripts/QS_UnsetResHeader.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_UnsetResHeader.htt"
fi

# - DDoS -------------------------------------------------------
./ctl.sh restart -D BlockOnClose -D real_ip > /dev/null
./run.sh -s ./scripts/QS_SrvRequestRate_block.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_SrvRequestRate_block.htt"
fi

echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- QS_markslow.htt" >>  logs/error_log
./ctl.sh restart -D cc -D real_ip > /dev/null
./run.sh -s ./scripts/QS_markslow.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_markslow.htt"
fi

echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- QS_SrvRequestRate_0.htt" >>  logs/error_log
./run.sh -s ./scripts/QS_SrvRequestRate_0.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_SrvRequestRate_0.htt"
fi
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- QS_SrvRequestRate_1.htt" >>  logs/error_log
./run.sh -s ./scripts/QS_SrvRequestRate_1.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_SrvRequestRate_1.htt"
fi
if [ `tail -2 logs/access_log | grep -c ' r; '` -eq 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_SrvRequestRate_1.htt (no lowrate)"
    tail -2 logs/access_log
fi
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- QS_SrvRequestRate_2.htt" >>  logs/error_log
./run.sh -s ./scripts/QS_SrvRequestRate_2.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_SrvRequestRate_2.htt"
fi
NUM34=`tail -22 logs/error_log | grep -c "mod_qos(034)"`
if [ $NUM34 -ne 5 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_SrvRequestRate_0/1.htt ($NUM34 instaed of 5 log entries)"
    tail -22 logs/error_log | grep -c "mod_qos(034)"
fi
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- QS_SrvRequestRate_3.htt" >>  logs/error_log
./run.sh -s ./scripts/QS_SrvRequestRate_3.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_SrvRequestRate_3.htt"
fi

echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- QS_SrvRequestRate_vip.htt" >>  logs/error_log
./run.sh -s ./scripts/QS_SrvRequestRate_vip.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_SrvRequestRate_vip.htt"
fi

./ctl.sh restart > /dev/null
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- QS_SrvRequestRate_4.htt" >>  logs/error_log
./run.sh -s ./scripts/QS_SrvRequestRate_4.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_SrvRequestRate_4.htt"
fi
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- QS_SrvRequestRate_5.htt" >>  logs/error_log
./run.sh -s ./scripts/QS_SrvRequestRate_5.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_SrvRequestRate_5.htt"
fi
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- QS_SrvRequestRate_6.htt" >>  logs/error_log
./run.sh -s ./scripts/QS_SrvRequestRate_6.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_SrvRequestRate_6.htt"
fi
if [ `tail -17 logs/error_log | grep -c "QS_SrvMinDataRate rule (in)"` -eq 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_SrvRequestRate_6.htt (no error log entry)"
fi
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- QS_SrvRequestRate_7.htt" >>  logs/error_log
./run.sh -s ./scripts/QS_SrvRequestRate_7.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_SrvRequestRate_7.htt"
fi

echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- QS_SrvRequestRate_srv.htt" >>  logs/error_log
./run.sh -s ./scripts/QS_SrvRequestRate_srv.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_SrvRequestRate_srv.htt"
fi

echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- QS_SrvRequestRate_conn_off.htt" >>  logs/error_log
./run.sh -s ./scripts/QS_SrvRequestRate_conn_off.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_SrvRequestRate_conn_off.htt"
fi
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- QS_SrvRequestRate_conn_off2.htt" >>  logs/error_log
./run.sh -s ./scripts/QS_SrvRequestRate_conn_off2.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_SrvRequestRate_conn_off2.htt"
fi

echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- QS_SrvRequestRate_off.htt" >>  logs/error_log
./run.sh -s ./scripts/QS_SrvRequestRate_off.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_SrvRequestRate_off.htt"
fi

./run.sh -s ./scripts/QS_SrvResponseRate_0.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_SrvResponseRate_0.htt"
fi

#./ctl.sh restart -D QS_SrvMaxConn > /dev/null
./run.sh -s ./scripts/QS_SrvRequestRate.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_SrvRequestRate.htt"
fi

./ctl.sh restart -D cc -D real_ip > /dev/null
./run.sh -s ./scripts/QS_SetEnvResHeadersMatch.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_SetEnvResHeadersMatch.htt"
fi
./ctl.sh restart -D cc -D real_ip -D usertrack> /dev/null
./run.sh -s ./scripts/QS_SetEnvResBody.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_SetEnvResBody.htt"
fi
./run.sh -s ./scripts/QS_UserTrackingCookieName.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_UserTrackingCookieName.htt"
fi
./run.sh -s ./scripts/QS_UserTrackingCookieName2.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_UserTrackingCookieName2.htt"
fi

./ctl.sh restart -D cc -D real_ip > /dev/null
./run.sh -s ./scripts/QS_SetEnvIfStatus.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_SetEnvIfStatus.htt"
fi

./ctl.sh restart -D cc -D real_ip > /dev/null
./run.sh -s ./scripts/QS_ClientSerialize.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_ClientSerialize.htt"
fi

./ctl.sh restart -D cc -D real_ip > /dev/null
./run.sh -s ./scripts/console.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED console.htt"
fi

./ctl.sh restart -D cc -D real_ip -D usertrack_force> /dev/null
./run.sh -s ./scripts/QS_UserTrackingCookieNameForce.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_UserTrackingCookieNameForce.htt"
fi

# MaxRequestsPerChild&QS_SrvMinDataRate
./run.sh -s ./scripts/MaxRequestsPerChild.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED MaxRequestsPerChild.htt"
    tail -1 logs/error_log
fi
./run.sh -s ./scripts/MaxRequestsPerChild_test.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED MaxRequestsPerChild_test.htt"
fi

./ctl.sh restart -D COND_CONNECTIONS >/dev/null
./run.sh -s ./scripts/QS_SrvConn.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_SrvConn.htt"
fi

./ctl.sh restart -D MILESTONES >/dev/null
TEST="QS_MileStone.htt QS_MileStone2.htt QS_MileStone3.htt"
for E in $TEST; do 
    ./run.sh -s ./scripts/$E
    if [ $? -ne 0 ]; then
	ERRORS=`expr $ERRORS + 1`
	echo "FAILED $E"
    fi
done

./ctl.sh restart -D MILESTONES_LOG >/dev/null
TEST="QS_MileStone4.htt"
for E in $TEST; do 
    ./run.sh -s ./scripts/$E
    if [ $? -ne 0 ]; then
	ERRORS=`expr $ERRORS + 1`
	echo "FAILED $E"
    fi
done

./ctl.sh restart -D real_ip >/dev/null
echo "run (`date '+%a %b %d %H:%M:%S %Y'`) stack.sh \t\c"
./stack.sh
if [ $? -ne 0 ]; then
  ERRORS=`expr $ERRORS + 1`
  echo "FAILED stack.sh"
else
  echo "OK"
fi

./ctl.sh restart -D logonly >/dev/null
TEST="QS_LogOnly.htt QS_LogOnly2.htt"
for E in $TEST; do 
    ./run.sh -s ./scripts/$E
    if [ $? -ne 0 ]; then
	ERRORS=`expr $ERRORS + 1`
	echo "FAILED $E"
    fi
done

# tools -----------------------------------------------------------
./run.sh -s ./scripts/qstail.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED qstail.htt"
fi
./run.sh -s ./scripts/qslog.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED qslog.htt"
fi

# end -------------------------------------------------------------
./ctl.sh stop 2>/dev/null 1>/dev/null
sleep 1
IPCS2=`ipcs | wc -l`

./dos.sh
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED dos.sh (minimal DoS prevention test)"
fi

./qssign.sh
if [ $? -ne 0 ]; then
  ERRORS=`expr $ERRORS + 1`
  echo "FAILED qssign test failed"
fi

for E in `strings ../httpd/modules/qos/.libs/mod_qos.so | grep "mod_qos(" | awk -F':' '{print $1}' | sort -u | grep -v "(00" | grep -v "(02" | grep -v "(051" | grep -v "(053" | grep -v "(062" | grep -v "(066" | grep -v "(068" | grep -v "(071"`; do
    C=`grep -c $E logs/error_log`
    C1=`grep -c $E logs/error1_log`
    if [ $C -eq 0 -a $C1 -eq 0 ]; then
        WARNINGS=`expr $WARNINGS + 1`
	echo "WARNING: missing message $E $C $C1"
    fi
done

../tools/filter/filter2.sh
if [ $? -ne 0 ]; then
  ERRORS=`expr $ERRORS + 1`
  echo "FAILED qsfilter2 test failed"
fi

grep \\$\\$\\$ ../httpd_src/modules/qos/*.c
if [ $? -ne 1 ]; then
  WARNINGS=`expr $WARNINGS + 1`
  echo "WARNING: found pattern '\$\$\$'"
fi
grep \\$\\$\\$ ../util/src/*.c
if [ $? -ne 1 ]; then
  WARNINGS=`expr $WARNINGS + 1`
  echo "WARNING: found pattern '\$\$\$'"
fi

LINES=`grep fprintf ../httpd_src/modules/qos/mod_qos.c | grep -v "NOT FOR PRODUCTIVE USE" | grep -v "requires OpenSSL, compile Apache using" | wc -l | awk '{print $1}'`
if [ $LINES != "0" ]; then
  WARNINGS=`expr $WARNINGS + 1`
  echo "WARNING: found pattern 'fprintf'"
fi

if [ `grep -c "exit signal" logs/error_log` -gt 0 ]; then
  WARNINGS=`expr $WARNINGS + 1`
  echo "WARNING: found 'exit signal' message"
fi

echo "ipcs: $IPCS $IPCS2"
if [ $IPCS -ne $IPCS2 ]; then
    echo "WARNING: ipcs count changed"
    WARNINGS=`expr $WARNINGS + 1`
fi

../tools/stat.sh
if [ $? -ne 0 ]; then
  ERRORS=`expr $ERRORS + 1`
  echo "FAILED qspng test failed"
fi

echo "end (`date '+%a %b %d %H:%M:%S %Y'`)"

if [ $WARNINGS -ne 0 ]; then
    echo "ERROR: got $WARNINGS warnings and $ERRORS errors"
    exit 1
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
