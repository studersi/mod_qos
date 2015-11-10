#!/bin/sh

S=${1:-60}
SEC=`date '+%S'`
SEC=`expr $S - $SEC`
if [ $SEC -lt 0 ]; then
  S=`expr $S + 60`
  SEC=`date '+%S'`
  SEC=`expr $S - $SEC`
fi
echo "sleep $SEC seconds ..."
sleep $SEC

