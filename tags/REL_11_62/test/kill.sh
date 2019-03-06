#!/bin/sh
p=`cat logs/apache.pid`
for E in `ps -ef | grep httpd | grep $p | awk '{print $2}' | grep -v $p`; do
  echo $E
  kill -11 $E
done

