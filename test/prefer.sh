#!/bin/sh

ERRORS=0

./ctl.sh restart -D max_clients -D cc > /dev/null
sleep 1
# fist run: no vip clients
echo "[`date '+%a %b %d %H:%M:%S %Y'`] [notice] -- QS_ClientPrefer.htt" >>  logs/error_log
./run.sh scripts/Log.htt 1> /dev/null 2>/dev/null
QSTART=`grep -c "mod_qos(066)" logs/error_log`
echo "run (`date '+%a %b %d %H:%M:%S %Y'`) ./scripts/QS_ClientPrefer.htt"
./run.sh -s ./scripts/QS_ClientPrefer.htt 2>/dev/null 1>/dev/null
sleep 1
./run.sh scripts/Log.htt > /dev/null 2>/dev/null
sleep 1
# some clients are marked to be vip
# second run: some clients are vip and their connections are not dropped (so less messages in log)
QFIRST=`grep -c "mod_qos(066)" logs/error_log`
echo "run (`date '+%a %b %d %H:%M:%S %Y'`) ./scripts/QS_ClientPrefer2.htt"
./run.sh -s ./scripts/QS_ClientPrefer2.htt 2>/dev/null 1>/dev/null
sleep 1
./run.sh scripts/Log.htt > /dev/null 2>/dev/null
sleep 1
# again: mark clients (IP only) as VIP
# third run: a higher percentage of clients are vip
QSECOND=`grep -c "mod_qos(066)" logs/error_log`
echo "run (`date '+%a %b %d %H:%M:%S %Y'`) ./scripts/QS_ClientPrefer_IP.htt"
./run.sh -s ./scripts/QS_ClientPrefer_IP.htt 2>/dev/null 1>/dev/null
sleep 1
./run.sh scripts/Log.htt > /dev/null 2>/dev/null
sleep 1
QSTHIRD=`grep -c "mod_qos(066)" logs/error_log`
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
    echo "FAILED QS_ClientPrefer_IP.htt ($QDIFF2 $QDIFF3)"
fi
# mark some cliens to have lower priority:
./htt.sh -se ./scripts/QS_ClientPrefer_SP_pre.htt 2>/dev/null 1>/dev/null
QSTART=`grep -c "mod_qos(066)" logs/error_log`
# forth run: some clients are marked having lower priority
./htt.sh -se ./scripts/QS_ClientPrefer_SP.htt 2>/dev/null 1>/dev/null
QFIRST=`grep -c "mod_qos(066)" logs/error_log`
QDIFF1=`expr $QFIRST - $QSTART`
echo "$QDIFF1"
if [ $QDIFF1 -eq 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_ClientPrefer_SP.htt ($QSTART $QFIRST $QDIFF1)"
fi

./ctl.sh restart -D cc > /dev/null
sleep 1
./htt.sh -se ./scripts/ClientBehavior.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED ClientBehavior.htt"
fi
./run.sh -se ./scripts/ClientBehavior_static.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED ClientBehavior_static.htt"
fi

exit $ERRORS
