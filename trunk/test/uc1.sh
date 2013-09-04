#!/bin/bash
# -*-mode: ksh; ksh-indent: 2; -*-
#
# execute tests using config for single use cases (only one feature enabled)
#

./ctl.sh stop 2>/dev/null 1>/dev/null
set -e
set -u
ulimit -c unlimited

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1a 2>/dev/null 1>/dev/null
sleep 2
./run.sh -s scripts/UC1_QS_LocRequestLimitMatch.htt
./ctl.sh stop 2>/dev/null 1>/dev/null

../httpd/httpd -d `pwd` -f conf/uc1.conf -D uc1b 2>/dev/null 1>/dev/null
sleep 2
./run.sh -s scripts/UC1_QS_ClientEventLimitCount.htt
./ctl.sh stop 2>/dev/null 1>/dev/null

exit 0
