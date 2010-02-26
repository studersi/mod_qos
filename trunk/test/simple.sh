#!/bin/sh
# -*-mode: ksh; ksh-indent: 2; -*-

./ctl.sh stop
sleep 1
set -e
set -u
echo "QOS Apache"
ulimit -c unlimited
../httpd/httpd -d `pwd` -f conf/simple.conf
#../httpd/httpd -d `pwd` -f appl_conf/httpd.conf
sleep 1

./run.sh scripts/simple.htt

./ctl.sh stop
sleep 1
echo "Apache"
../httpd/httpd -d `pwd` -f conf/simple.conf -D no_qos
#../httpd/httpd -d `pwd` -f appl_conf/httpd.conf
sleep 1


./ctl.sh stop
echo "normal end"