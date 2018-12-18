#!/bin/sh
# -*-mode: ksh; ksh-indent: 2; -*-


DATA=`./b64 -e "123"`
if [ "$DATA" != "MTIz" ]; then
  echo "error 1"
  exit 1
fi
DATA=`printf '123' | ./b64 -e`
if [ "$DATA" != "MTIz" ]; then
  echo "error 2"
  exit 1
fi
DATA=`printf '123\n' | ./b64 -e`
if [ "$DATA" != "MTIzCg==" ]; then
  echo "error 3"
  exit 1
fi
DATA=`printf '123\n' | ./b64 -e | ./b64 -d | ./b64 -he`
if [ "$DATA" != "\x31\x32\x33\x0a" ]; then
  echo "error 4"
  exit 1
fi
DATA=`./b64 -e "123" | ./b64 -d`
if [ "$DATA" != "123" ]; then
  echo "error 5"
  exit 1
fi
DATA=`./b64 -he "123"`
if [ "$DATA" != "\x31\x32\x33" ]; then
  echo "error 6"
  exit 1
fi
DATA=`./b64 -he "123" | ./b64 -hd`
if [ "$DATA" != "123" ]; then
  echo "error 7"
  exit 1
fi

echo "normal end"
exit 0
