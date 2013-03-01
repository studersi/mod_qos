#!/bin/sh

cd `dirname $0`
PFX=[`basename $0`]

# log of application is rotated every 10 minutes
# we keep 4 generations
FNR=`ls -l logs/| grep -c "access1_log.*gz"`
if [ $FNR -ne 4 ]; then
    echo "$PFX FAILED, wrong number of file generations $FNR instead of 4"
    exit 1
fi


exit 0

