#!/bin/sh

ERRORS=0

./ctl.sh restart -D max_clients -D cc > /dev/null
echo "-- QS_ClientPrefer.htt" >>  logs/error_log
./run.sh scripts/Log.htt > /dev/null
QSTART=`grep -c "mod_qos(063)" logs/error_log`
echo "run ./scripts/QS_ClientPrefer.htt"
./run.sh -s ./scripts/QS_ClientPrefer.htt 2>/dev/null 1>/dev/null
sleep 1
./run.sh scripts/Log.htt > /dev/null
sleep 1
QFIRST=`grep -c "mod_qos(063)" logs/error_log`
./run.sh -s ./scripts/QS_ClientPrefer2.htt 2>/dev/null 1>/dev/null
sleep 1
./run.sh scripts/Log.htt > /dev/null
sleep 1
QSECOND=`grep -c "mod_qos(063)" logs/error_log`
./run.sh -s ./scripts/QS_ClientPrefer_IP.htt 2>/dev/null 1>/dev/null
sleep 1
./run.sh scripts/Log.htt > /dev/null
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
./htt.sh -se ./scripts/QS_ClientPrefer_SP.htt
QFIRST=`grep -c "mod_qos(064)" logs/error_log`
QDIFF1=`expr $QFIRST - $QSTART`
echo "$QDIFF1"
if [ $QDIFF1 -eq 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED QS_ClientPrefer_SP.htt"
fi

./ctl.sh restart -D cc > /dev/null
./htt.sh -se ./scripts/ClientBehavior.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED ClientBehavior.htt"
fi

exit $ERRORS
