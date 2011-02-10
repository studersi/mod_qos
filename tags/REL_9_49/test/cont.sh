#!/bin/sh

./ctl.sh stop
sleep 2
IPCS=`ipcs | wc -l`
sleep 2
./ctl.sh restart -D cc -D cont

for E in `seq 100`; do
    ./htt.sh -T -s scripts/QS_Load_loc.htt
done

./ctl.sh stop
sleep 2
echo "------------------------------"
echo "- $IPCS"
echo "------------------------------"
IPCS=`ipcs | wc -l`
echo "- $IPCS"
echo "------------------------------"
