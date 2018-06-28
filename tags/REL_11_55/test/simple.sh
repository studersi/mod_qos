#!/bin/bash
# -*-mode: ksh; ksh-indent: 2; -*-

./ctl.sh stop
sleep 1
set -e
set -u
echo "QOS Apache"
ulimit -c unlimited
../httpd/httpd -d `pwd` -f conf/simple.conf
sleep 1

for E in `seq 100`; do
  ./run.sh -s scripts/simple.htt
done
time ./run.sh -s scripts/simple.htt
sleep 1
./run.sh -s scripts/simple_verify.htt

./ctl.sh stop
sleep 1
echo "Apache"
../httpd/httpd -d `pwd` -f conf/simple.conf -D no_qos
sleep 1

time ./run.sh -s scripts/simple.htt

./ctl.sh stop
echo "normal end"