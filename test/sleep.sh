#!/bin/sh

S=${1:-60}
SEC=`date '+%S'`
SEC=`expr $S - $SEC`
echo "sleep $SEC seconds ..."
sleep $SEC

