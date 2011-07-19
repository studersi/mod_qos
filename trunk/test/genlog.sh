#!/bin/sh
# -*-mode: ksh; ksh-indent: 2; -*-

if [ "$1" = "-c" ]; then
  count=0
  while [ $count -lt 7 ]; do
    count=`expr $count + 1`
    ./bin/sleep 500
    echo "[`date '+%a %b %d %H:%M:%S %Y'`] [error] mod_qos(031): access denied, QS_SrvMaxConnPerIP rule: max=10, concurrent connections=11, c=127.0.0.2"
  done
  count=0
  while [ $count -lt 7 ]; do
    count=`expr $count + 1`
    ./bin/sleep 500
    echo "[`date '+%a %b %d %H:%M:%S %Y'`] [error] mod_qos(031): access denied, QS_SrvMaxConnPerIP rule: max=10, concurrent connections=11, c=127.0.0.2"
    echo "[`date '+%a %b %d %H:%M:%S %Y'`] [info] mod_qos(000): access granted, c=127.0.0.2"
  done
else
  count=0
  while [ $count -lt 10 ]; do
    count=`expr $count + 1`
    sleep 1
    echo "[`date '+%a %b %d %H:%M:%S %Y'`] [error] mod_qos(031): access denied, QS_SrvMaxConnPerIP rule: max=10, concurrent connections=11, c=127.0.0.1"
  done
  
  count=0
  while [ $count -lt 7 ]; do
    count=`expr $count + 1`
    ./bin/sleep 500
    echo "[`date '+%a %b %d %H:%M:%S %Y'`] [error] mod_qos(031): access denied, QS_SrvMaxConnPerIP rule: max=10, concurrent connections=11, c=127.0.0.2"
  done
fi


