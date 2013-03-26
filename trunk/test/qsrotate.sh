#!/bin/sh
# $Id: qsrotate.sh,v 2.2 2013-03-26 19:35:46 pbuchbinder Exp $

cd `dirname $0`
PFX=[`basename $0`]
LOGFILE=`pwd`/qsrotate.log
ERROR=0

# log of application is rotated every 10 minutes, uses gzip and 4 generations
# we keep 4 generations
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
ROT2MB=`ls -l ${LOGFILE}* | egrep '209.... [a-zA-Z]+ .*qsrotate\.log\.[0-9]+' | wc -l`
if [ "$ROT2MB" -ne 1 ]; then
    echo "$PFX FAILED, rotate -b, expected 1 (is $ROT2MB"
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

if [ $ERROR -ne 0 ]; then
    exit 1
fi
echo "$PFX normal end"
exit 0

