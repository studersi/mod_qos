#!/bin/sh
# $Id$

cd `dirname $0`
PFX=[`basename $0`]
LOGFILE=`pwd`/qsrotate.log
ERROR=0

# log of application is rotated every 10 minutes, uses gzip and 4 generations
# we keep 4 generations (and we assume somebody has run all tests before)
# qsrotate -o <access1_log> -z -g 4 -s 600 -f -b 536870912"
FNR=`ls -l logs/| grep -c "access1_log.*gz"`
if [ $FNR -ne 4 ]; then
    echo "$PFX FAILED, access1_log, wrong number of file generations $FNR instead of 4"
    ERROR=1
fi

d1k="d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k d1k"

# rotates every 2MB, (no compression, 10 generation limit)
# generates 3MB data (1.5 files)
rm -f ${LOGFILE}*
for E in `seq 3072`; do echo "$d1k"; done | ../util/src/qsrotate -b 2097152 -o ${LOGFILE}
sleep 1
ROT2MB=`ls -l ${LOGFILE}* | egrep '209.... [a-zA-Z]+ .*qsrotate\.log\.[0-9]+' | wc -l`
if [ "$ROT2MB" -ne 1 ]; then
    echo "$PFX FAILED, rotate -b, expected 1 (is $ROT2MB)"
    ERROR=1
fi
if [ "`ls -l ${LOGFILE}* | wc -l`" -ne 2 ]; then
    echo "$PFX FAILED, rotate -b, total files"
    ERROR=1
fi

# 3 generations 
rm -f ${LOGFILE}*
for E in `seq 204800`; do echo "$d1k"; done | ../util/src/qsrotate -b 2097152 -g 3 -o ${LOGFILE}
if [ "`ls -l ${LOGFILE}* | wc -l`" -ne 4 ]; then
    echo "$PFX FAILED, rotate -g, files"
    ERROR=1
fi
#   1920000 Sep 11 07:24 qsrotate.log
#   2098176 Sep 11 07:24 qsrotate.log.20140911072447
#   2098176 Sep 11 07:24 qsrotate.log.20140911072448
#   2098176 Sep 11 07:24 qsrotate.log.20140911072449
sleep 1
for LINE in `seq 3`; do
    LSIZE=`ls -l qsrotate.log.20* | tail -$LINE | head -1 | awk '{print $5}'`
    if [ $LSIZE -gt 2199999 ]; then
	echo "$PFX FAILED, rotate -b, $LINE => $LSIZE"
	ERROR=1
    fi
done
# write again data (server restart)
for E in `seq 2099`; do echo "$d1k"; done | ../util/src/qsrotate -b 2097152 -g 3 -o ${LOGFILE}
sleep 1
for LINE in `seq 3`; do
    LSIZE=`ls -l qsrotate.log.20* | tail -$LINE | head -1 | awk '{print $5}'`
    if [ $LSIZE -gt 2199999 ]; then
	echo "$PFX FAILED, rotate -b, $LINE => $LSIZE (2)"
	ERROR=1
    fi
done

# 4 SIGUST1
rm -f usr1.log*
for E in `seq 3`; do date +'%s'; sleep 1; done | ../util/src/qsrotate -o usr1.log &
qpid=`ps -ef | grep usr1.log | grep qsrotate | awk '{print $2}'`
sleep 1
kill -USR1 $qpid
sleep 1
if [ `ls -l usr1.log* | wc -l` -ne 2 ]; then
    echo "$PFX FAILED, USR1"
    ls -l usr1.log*
    ERROR=1
fi
last=`tail -1 usr1.log.2*`
next=`echo $last+1|bc`
if [ "`head -1 usr1.log`" != "$next" ]; then
    echo "$PFX FAILED, USR1 $next"
    ls -l usr1.log*
    ERROR=1
fi
rm -f usr1.log*

# line-by-line processing (incl. time stamp)
rm -f d.log
echo "msgA\nmsgB\nmsgC" |  ../util/src/qsrotate -d -o d.log
if [ `egrep -c "^20..\-..\-.. ..:..:.. msgA$" d.log` -ne 1 ]; then
    echo "$PFX FAILED, -d line 1"
    cat d.log
    ERROR=1
fi
if [ `egrep -c "^20..\-..\-.. ..:..:.. msgB$" d.log` -ne 1 ]; then
    echo "$PFX FAILED, -d line 2"
    cat d.log
    ERROR=1
fi
if [ `egrep -c "^20..\-..\-.. ..:..:.. msgC$" d.log` -ne 1 ]; then
    echo "$PFX FAILED, -d line 3"
    cat d.log
    ERROR=1
fi
if [ `wc -l d.log | awk '{print $1}'` -ne 3 ]; then
    echo "$PFX FAILED, -d number of lines"
    cat d.log
    ERROR=1
fi
rm d.log

if [ $ERROR -ne 0 ]; then
    exit 1
fi
rm -f ${LOGFILE}*
echo "$PFX normal end"
exit 0

