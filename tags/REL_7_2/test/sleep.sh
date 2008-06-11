#!/bin/sh

SEC=`date '+%S'`
SEC=`expr 60 - $SEC`
echo "sleep $SEC seconds ..."
sleep $SEC

