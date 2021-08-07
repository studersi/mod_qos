#!/bin/sh
cd `dirname $0`
mem=0
rsz=0
if [ ! -f logs/apache.pid ]; then
  exit 1
fi
p=`cat logs/apache.pid`
pidl=""
for E in `ps -ef | grep httpd | grep $p | awk '{print $2}' | grep -v $p`; do
  m=`ps -o vsz -p $E | tail -1`
  r=`ps -o rsz -p $E | tail -1`
  mem=`expr $mem + $m`
  rsz=`expr $rsz + $r`
  pidl="${E},${pidl}"
done
lines=`wc -l logs/access_log | awk '{print $1}'`
echo "`date`;vsz;$mem;rsz;$rsz;lines;$lines;pid;$pidl"

