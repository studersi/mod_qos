#!/bin/sh
# -*-mode: ksh; ksh-indent: 2; -*-
#
# $Header$
#
# mod_qos test cases, requires htt, see http://htt.sourceforge.net/
#
# See http://mod-qos.sourceforge.net/ for further
# details about mod_qos.
#

cd `dirname $0`

if [ `ps -ef | grep -v grep | grep -c "tee test.log"` -eq 0 ]; then
  $0 2>&1 | tee test.log
  exit $?
fi

ulimit -c unlimited
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
    echo "FAILED QS_SrvMaxConnPerIP_10.htt"
fi
./ctl.sh restart -D real_ip -D SrvMaxConnPerIPConnections > /dev/null
./run.sh -se ./scripts/QS_SrvMaxConnPerIP_10_idle.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_SrvMaxConnPerIP_10_idle.htt"
fi
./ctl.sh restart -D real_ip -D excludelocal > /dev/null
./run.sh -se ./scripts/QS_SrvMaxConnExclude.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_SrvMaxConnExclude.htt"
fi
./ctl.sh restart -D real_ip -D excludelocalglobal > /dev/null
./run.sh -se ./scripts/QS_SrvMaxConnExclude2.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_SrvMaxConnExclude2.htt"
fi
sleep 2
./ctl.sh restart > /dev/null

# -----------------------------------------------------------------
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- QS_SetEnvIfResBody.htt" >>  logs/error_log
./run.sh -se ./scripts/QS_SetEnvIfResBody.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_SetEnvIfResBody.htt"
fi

# -----------------------------------------------------------------
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- 6 requests to an url limited to max 5 concurrent requests, QS_LocRequestLimit_5.htt" >>  logs/error_log
QSLOCREQS="QS_LocRequestLimit_5.htt QS_LocRequestLimit_6.htt QS_LocRequestLimit_7.htt"
for QSLOCREQ in $QSLOCREQS; do
  ./run.sh -s ./scripts/${QSLOCREQ}
  if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED $QSLOCREQ"
  fi
done
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
./run.sh -se ./scripts/qslogdirective.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED qslogdirective.htt"
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
sleep 10

# -----------------------------------------------------------------
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- vip request, QS_VipRequest.htt" >>  logs/error_log
./run.sh -se ./scripts/QS_VipRequest.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_VipRequest.htt"
fi
sleep 10

# -----------------------------------------------------------------
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- vip request and graceful restart, QS_VipHeaderName_Graceful.htt" >>  logs/error_log
./run.sh -se ./scripts/QS_VipHeaderName_Graceful.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_VipHeaderName_Graceful.htt"
fi
sleep 1
./run.sh -se scripts/graceful_sem.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED graceful_sem.htt"
fi
./ctl.sh restart > /dev/null
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
sleep 10

# -----------------------------------------------------------------
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- 50 connections, QS_SrvMaxConn 40" >> logs/error_log
./run.sh -se ./scripts/QS_SrvMaxConn_50.htt
sleep 1
./run.sh -se ./scripts/QS_SrvMaxConn_50.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_SrvMaxConn_50.htt"
fi
sleep 10

# -----------------------------------------------------------------
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- connection timeout, QS_SrvConnTimeout_body.htt" >>  logs/error_log
./run.sh -se ./scripts/QS_SrvConnTimeout_body.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_SrvConnTimeout_body.htt"
fi

sleep 10
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
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- request/sec limit + concurrent req limit, QS_CombinedReqSec.htt" >>  logs/error_log
./run.sh -se ./scripts/QS_CombinedReqSec.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_CombinedReqSec.htt"
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
sleep 10

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
./ctl.sh restart > /dev/null
sleep 60 # lets the server close sockets
./run.sh -se ./scripts/QS_LocKBytesPerSecLimit_var.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_LocKBytesPerSecLimit_var.htt"
fi
./run.sh -se ./scripts/QS_LocKBytesPerSecLimitMatch.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_LocKBytesPerSecLimitMatch.htt"
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
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- req/sec limit, QS_EventLimitCount.htt" >>  logs/error_log
./run.sh -se ./scripts/QS_EventLimitCount.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_EventLimitCount.htt"
fi
sleep 10

# -----------------------------------------------------------------
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- req/sec limit, QS_LocRequestPerSecLimitMatch.htt" >>  logs/error_log
#./ctl.sh restart > /dev/null
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
sleep 10

# -----------------------------------------------------------------
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- multiple requests in parallel, MultiRequest.htt" >>  logs/error_log
./run.sh -se ./scripts/MultiRequest.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED MultiRequest.htt"
fi

./ctl.sh restart -D ignore404 > /dev/null
sleep 60
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- req/sec limit, QS_EventPerSecLimit404.htt" >>  logs/error_log
./run.sh -se ./scripts/QS_EventPerSecLimit404.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_EventPerSecLimit404.htt"
fi
sleep 5
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- concurrent req limit, QS_LocRequestLimit404.htt" >>  logs/error_log
./run.sh -se ./scripts/QS_LocRequestLimit404.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_LocRequestLimit404.htt"
fi
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- concurrent req limit, QS_EventRequestLimit404.htt" >>  logs/error_log
./run.sh -se ./scripts/QS_EventRequestLimit404.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_EventRequestLimit404.htt"
fi

# requires httest 2.4.9
export ENV_HTTEST=/usr/local/bin/httest-2.4.9
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- concurrent req limit, websocket_QS_LocRequestLimit.htt" >>  logs/error_log
./run.sh -se ./scripts/websocket_QS_LocRequestLimit.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED websocket_QS_LocRequestLimit.htt"
fi
unset ENV_HTTEST

./ctl.sh  restart -D ignore404 -D cont > /dev/null
sleep 90 # lets the server close sockets
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- concurrent req, MaxRequestsPerChild, QS_EventRequestLimitMaxReq.htt" >>  logs/error_log
./run.sh -se ./scripts/QS_EventRequestLimitMaxReq.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_EventRequestLimitMaxReq.htt"
fi
sleep 30

./ctl.sh restart > /dev/null
sleep 1
./run.sh -se ./scripts/Graceful.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED Graceful.htt"
    sleep 2
fi
sleep 10

# -----------------------------------------------------------------
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- kbytes/sec limit, QS_EventKBytesPerSecLimit.htt" >>  logs/error_log
./run.sh -se ./scripts/QS_EventKBytesPerSecLimit.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_EventKBytesPerSecLimit.htt"
fi
sleep 10

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
./ctl.sh restart -D permit_filter -D logonly > /dev/null
./run.sh -se ./scripts/QS_HeaderFilter2.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_HeaderFilter2.htt"
fi


# -----------------------------------------------------------------
./prefer.sh
EXT_ERR=$?
if [ $EXT_ERR -gt 0 ]; then
    echo "WARNING run again ..."
    WARNINGS=`expr $WARNINGS + 1`
    ./prefer.sh
    EXT_ERR=$?
    if [ $EXT_ERR -eq 0 ]; then
	echo "                 OK"
    else
      echo ""
      echo "FAILED prefer.sh"
    fi
fi
ERRORS=`expr $ERRORS + $EXT_ERR`

# -----------------------------------------------------------------
export ENV_HTTEST=/usr/local/bin/httest-2.4.9
./prefer2.sh
EXT_ERR=$?
ERRORS=`expr $ERRORS + $EXT_ERR`
sleep 1
unset ENV_HTTEST

# -----------------------------------------------------------------
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

./ctl.sh  restart -D BlockOnAbort -D real_ip > /dev/null
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- QS_ClientEventBlockCount BrokenConnection.htt" >>  logs/error_log
./run.sh -se ./scripts/BrokenConnection.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED BrokenConnection.htt"
fi

./ctl.sh  restart -D BlockNullConn -D real_ip > /dev/null
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- QS_ClientEventBlockCount NullConnection.htt" >>  logs/error_log
./run.sh -se ./scripts/NullConnection.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED NullConnection.htt"
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
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- QS_ClientEventBlockCount_Rep.htt" >>  logs/error_log
./run.sh -se ./scripts/QS_ClientEventBlockCount_Rep.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_ClientEventBlockCount_Rep.htt"
fi

./ctl.sh restart -D real_ip > /dev/null
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- QS_ClientEventBlockCount.htt" >>  logs/error_log
./run.sh -se ./scripts/QS_ClientEventBlockCount.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_ClientEventBlockCount.htt"
fi

./ctl.sh restart -D real_ip -D v6 > /dev/null
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- QS_ClientEventBlockCount_v6.htt" >>  logs/error_log
./run.sh -se ./scripts/QS_ClientEventBlockCount_v6.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_ClientEventBlockCount_v6.htt"
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
./ctl.sh restart -D real_ip -D ip_not_blocked >/dev/null
./run.sh -se ./scripts/QS_ClientEventBlockCount_StatusAllow.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_ClientEventBlockCount_StatusAllow.htt"
fi
sleep 10

./ctl.sh restart -D shorttimeout > /dev/null
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- QS_TimeoutS.htt" >>  logs/error_log
./run.sh -se ./scripts/QS_TimeoutS.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_TimeoutS.htt"
fi
./ctl.sh restart > /dev/null
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- QS_Timeout.htt" >>  logs/error_log
./run.sh -se ./scripts/QS_Timeout.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_Timeout.htt"
fi

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

sleep 60

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

./ctl.sh restart -D forwardproxy > /dev/null
./run.sh -se ./scripts/ForwardProxy.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED ForwardPorxy.htt"
fi

# - query/parp/path --------------------------------------------
./ctl.sh restart -D cc -D real_ip > /dev/null
PSCR="QS_Delay.htt QS_SetEnvIfQuery.htt QS_SetEnvIfParp.htt QS_SetEnvIfBody.htt QS_SetEnvIfBody_plus.htt QS_SetEnvIfBody_support.htt QS_DenyQueryParp.htt QS_DenyQueryParpDeflate.htt QS_SetEnvIfParpDeflate.htt QS_SetEnvIfBodyDeflate.htt QS_DenyQueryParpHuge.htt QS_DenyQueryParpForm.htt QS_PermitUriParp.htt QS_PermitUriJSON.htt QS_DenyPath.htt QS_DenyQuery.htt QS_InvalidUrlEncoding.htt QS_DenyEnc.htt QS_LimitRequestBody.htt QS_DenyDecoding_uni.htt QS_ErrorPage.htt MultiMatch.htt InternalRedirect.htt Yoda.htt"
for E in $PSCR; do
    ./run.sh -s ./scripts/${E}
    if [ $? -ne 0 ]; then
	ERRORS=`expr $ERRORS + 1`
	echo "FAILED $E"
    fi
done
#./htt.sh -se ./scripts/QS_UriParser.htt
#if [ $? -ne 0 ]; then
#    ERRORS=`expr $ERRORS + 1`
#    echo "FAILED QS_UriParser.htt"
#fi
./run.sh -se ./scripts/Count.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED Count.htt"
fi

#./ctl.sh restart -D real_ip -D autoerrorpage > /dev/null
#./run.sh -se ./scripts/QS_ErrorPage2.htt
#if [ $? -ne 0 ]; then
#    ERRORS=`expr $ERRORS + 1`
#    echo "FAILED QS_ErrorPage2.htt"
#fi

./ctl.sh restart -D ErrorResponse503 > /dev/null
./run.sh -se ./scripts/QS_ErrorResponseCode.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_ErrorResponseCode.htt"
fi

echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- QS_SetReqHeader" >>  logs/error_log
./run.sh -s ./scripts/QS_SetReqHeader.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_SetReqHeader.htt"
fi

echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- QS_UnsetResHeader (QS_ClientEventLimitCount)" >>  logs/error_log
./ctl.sh restart -D real_ip > /dev/null
./run.sh -s ./scripts/QS_UnsetResHeader.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_UnsetResHeader.htt"
fi
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- QS_ClientEventLimitCount" >>  logs/error_log
./ctl.sh restart -D real_ip -D X-Forwarded-For > /dev/null
./run.sh -s ./scripts/QS_ClientEventLimitCount.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_ClientEventLimitCount.htt"
fi
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- QS_ClientEventLimitCount2" >>  logs/error_log
./ctl.sh restart -D real_ip > /dev/null
./run.sh -s ./scripts/QS_ClientEventLimitCount2.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_ClientEventLimitCount2.htt"
fi
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- QS_CondClientEventLimitCount" >>  logs/error_log
./ctl.sh restart -D real_ip -D CondClientLimit > /dev/null
./run.sh -s ./scripts/QS_CondClientEventLimitCount.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_CondClientEventLimitCount.htt"
fi
sleep 20

# - DDoS -------------------------------------------------------
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

./htt.sh -s ./scripts/QS_SrvResponseRate_0.htt
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
sleep 10

./ctl.sh restart -D BlockOnClose -D real_ip > /dev/null
./run.sh -s ./scripts/QS_SrvRequestRate_block.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_SrvRequestRate_block.htt"
fi

./ctl.sh restart -D cc -D real_ip > /dev/null
./run.sh -s ./scripts/QS_SetEnvResHeadersMatch.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_SetEnvResHeadersMatch.htt"
fi
sleep 60
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
./ctl.sh restart -D cc -D real_ip -D C404 > /dev/null
./run.sh -s ./scripts/QS_SetEnvIfStatus2.htt
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

./ctl.sh restart -D cc -D real_ip -D usertrack_force -D cont > /dev/null
./run.sh -s ./scripts/QS_UserTrackingCookieNameForce.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_UserTrackingCookieNameForce.htt"
fi

sleep 60
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

GEO="QS_ClientGeoIPPriv.htt QS_ClientGeoIPPriv2.htt QS_ClientGeoIPPriv3.htt QS_AllConn.htt QS_ClientGeoIPVar.htt QS_Country_Redirect.htt QS_ClientGeoIPPrivLogOnly.htt"
for G in $GEO; do
  ./run.sh -s ./scripts/$G
  if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED $G"
  fi
done

# tests which automatically restart the server
TEST="mod_cache.htt"
for E in $TEST; do 
    ./run.sh -s ./scripts/$E
    if [ $? -ne 0 ]; then
	ERRORS=`expr $ERRORS + 1`
	echo "FAILED $E"
    fi
done

./ctl.sh restart -D MILESTONES >/dev/null
TEST="QS_MileStone.htt QS_MileStone2.htt QS_MileStone3.htt"
for E in $TEST; do 
    ./run.sh -s ./scripts/$E
    if [ $? -ne 0 ]; then
	ERRORS=`expr $ERRORS + 1`
	echo "FAILED $E"
    fi
done

./man.sh
if [ $? -ne 0 ]; then
  echo "WARNING, no man page available"
  WARNINGS=`expr $WARNINGS + 1`
fi  

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
sleep 10
# fill up the whole store with 50'000 entries ...
./run.sh -s ./scripts/stack.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED stack.htt"
fi
echo "run (`date '+%a %b %d %H:%M:%S %Y'`) stack.sh \t\c"
./stack.sh
if [ $? -ne 0 ]; then
  ERRORS=`expr $ERRORS + 1`
  echo "FAILED stack.sh"
else
  echo "OK"
fi
sleep 10
./run.sh -s ./scripts/stack.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED stack.htt"
fi

./ctl.sh stop >/dev/null
sleep 10
./ctl.sh restart -D logonly -D real_ip >/dev/null
sleep 1
TEST="QS_LogOnly.htt QS_LogOnly1.htt QS_LogOnly1a.htt QS_LogOnly1b.htt QS_LogOnly2.htt QS_LogOnly3.htt QS_LogOnly4.htt QS_LogOnly5.htt QS_LogOnly6.htt QS_LogOnly7.htt QS_LogOnly8.htt QS_LogOnly9.htt"
for E in $TEST; do 
    ./run.sh -s ./scripts/$E
    if [ $? -ne 0 ]; then
	ERRORS=`expr $ERRORS + 1`
	echo "FAILED $E"
    fi
    sleep 3
done

# tools -----------------------------------------------------------
./run.sh -s ./scripts/qstail.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED qstail.htt"
fi

./qslog.sh test all
RC=$?
if [ $RC -ne 0 ]; then
  ERRORS=`expr $ERRORS + $RC`
  echo "FAILED qslog.sh test all"
fi

./qsgeo.sh
if [ $? -ne 0 ]; then
  ERRORS=`expr $ERRORS + 1`
  echo "FAILED qsgeo.sh"
fi
./qslogger.sh
if [ $? -ne 0 ]; then
  ERRORS=`expr $ERRORS + 1`
  echo "FAILED qslogger.sh"
fi
./qshead.sh
if [ $? -ne 0 ]; then
  ERRORS=`expr $ERRORS + 1`
fi

# end -------------------------------------------------------------
./ctl.sh stop 2>/dev/null 1>/dev/null
sleep 1
IPCS2=`ipcs | wc -l`

# logs ------------------------------------------------------------
./qssign.sh
if [ $? -ne 0 ]; then
  ERRORS=`expr $ERRORS + 1`
  echo "FAILED qssign test failed"
fi

./qsrotate.sh
if [ $? -ne 0 ]; then
  ERRORS=`expr $ERRORS + 1`
fi

# some simple configurations --------------------------------------
usscripts="dos.sh uc1.sh QS_Serialize.sh ucn.sh"
for E in $usscripts; do
  sleep 60
  echo "> $E"
  ./$E
  URC=$?
  if [ $URC -ne 0 ]; then
    ERRORS=`expr $ERRORS + $URC`
    echo "FAILED $E"
  fi
  echo "< $E"
done

# tools -----------------------------------------------------------
echo "- qsgrep"
LOCH=`../util/src/qsgrep -e 'mod_qos\(031\).*, c=([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})' -o 'ip=$1' logs/error_log | egrep -c "^ip=127.0.0.1$"`
if [ $LOCH -lt 1 ]; then
  ERRORS=`expr $ERRORS + 1`
  echo "FAILED qsgrep"
fi
# qsgrep -e "([0-9.: ]+) isi3web    NProxyOp   [0-9a-zA-Z.-]+ .* sCF=([0-9,<>A-Z]*) .* dTF=([0-9,,<>A-Z]*) .* sCB=([0-9,<>A-Z]*) .* dTr1B=([0-9,<>A-Z]*) .* cR=([0-9]+) .* Event=([0-9,<>A-Z]*) .* trID=([0-9a-zA-Z.-]*)" -o '$1 $2 $3 $4 $5 $6 $7 $8' na.log > short.log
# cat short.log | qslog -p -f  ....St.a.E -o stat.log


echo "- qsexec"
PAT=`./genlog.sh | ../util/src/qsexec -e 'mod_qos\(031\).*, c=([0-9.]*)' -t 5:10 'printf $1'`
if [ "$PAT" != "127.0.0.1127.0.0.1127.0.0.2" ]; then
  ERRORS=`expr $ERRORS + 1`
  echo "FAILED qsexec test 1 failed ($PAT)"
fi
PAT=`./genlog.sh | ../util/src/qsexec -e 'mod_qos\(031\).*, c=([0-9.]*)' -t 5:3 'printf $1'`
if [ "$PAT" != "127.0.0.2" ]; then
  ERRORS=`expr $ERRORS + 1`
  echo "FAILED qsexec test 2 failed ($PAT)"
fi
PAT=`./genlog.sh -c | ../util/src/qsexec -e 'mod_qos\(031\).*, c=([0-9.]*)' -t 3:2 -c 'mod_qos\(000\).* c=([0-9.]*)' 'printf "clear $1"' 'printf "event $1"'`
if [ "$PAT" != "event 127.0.0.2event 127.0.0.2clear 127.0.0.2" ]; then
  ERRORS=`expr $ERRORS + 1`
  echo "FAILED qsexec test 2 failed ($PAT)"
fi

../tools/filter/filter2.sh
if [ $? -ne 0 ]; then
  ERRORS=`expr $ERRORS + 1`
  echo "FAILED qsfilter2 test failed"
fi

../tools/stat.sh
if [ $? -ne 0 ]; then
  ERRORS=`expr $ERRORS + 1`
  echo "FAILED qspng test failed"
fi

./qsdt.sh
if [ $? -ne 0 ]; then
  ERRORS=`expr $ERRORS + 1`
  echo "FAILED qsdt test failed"
fi

# log messages
eLogs=`ls logs/error*_log*`
for E in `strings ../httpd/modules/qos/.libs/mod_qos.so | grep "mod_qos(" | awk -F':' '{print $1}' | sort -u | grep -v "(00" | grep -v "mod_qos()" | grep -v "(02" | grep -v "(051" | grep -v "(045" | grep -v "(053" | grep -v "(036" | grep -v "(035" | grep -v "(037" | grep -v "(038" | grep -v "(062" | grep -v "(166" | grep -v "(167" | grep -v "(071" | grep -v "(080" | grep -v "(081" | grep -v "(082" | grep -v "(083" | grep -v 'mod_qos(%03d)'`; do
    CO=0
    for L in $eLogs; do
	C=`grep -c $E $L`
	CO=`expr $CO + $C`
    done
    if [ $CO -eq 0 ]; then
	WARNINGS=`expr $WARNINGS + 1`
	echo "WARNING: missing message $E"
    fi
done
for L in $eLogs; do
    if [ `grep -c "mod_qos(08" $L` -gt 0 ]; then
	ERRORS=`expr $ERRORS + 1`
	echo "FAILED found mod_qos(08x) messages in $L"
    fi
done

# code / open issues and tasks ------------------------------------
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

for L in $eLogs; do
    if [ `grep -c "exit signal" $L` -gt 0 ]; then
	WARNINGS=`expr $WARNINGS + 1`
	echo "WARNING: found 'exit signal' message in $L"
    fi
done

echo "ipcs: $IPCS $IPCS2"
if [ $IPCS -ne $IPCS2 ]; then
    echo "WARNING: ipcs count changed ($IPCS -> $IPCS2)"
    WARNINGS=`expr $WARNINGS + 1`
fi

CFS=`find . -name "*core*"`
if [ -n "$CFS" ]; then
  ERRORS=`expr $ERRORS + 1`
  echo "FAILED found core file"
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

echo "normal end"
exit 0
