#!/bin/sh
# -*-mode: ksh; ksh-indent: 2; -*-
#

echo "- good:"
cat logs/access_log | ../tools/filter/qssign -s 1234567890 > logs/signed_access_log
cat logs/signed_access_log | ../tools/filter/qssign -s 1234567890 -v
if [ $? -ne 0 ]; then
  echo "ERROR: verification failed"
  exit 1
fi

echo "- invalid signature:"
sed <logs/signed_access_log >logs/signed_access_log.1 -e "s:000000000005#:000000000003#:g"
cat logs/signed_access_log.1 | ../tools/filter/qssign -s 1234567890 -v
if [ $? -eq 0 ]; then
  echo "ERROR: verification failed"
  exit 1
fi

echo "-invalid sequence (missing line):"
grep -v "000000000003#" logs/signed_access_log > logs/signed_access_log.1
cat logs/signed_access_log.1 | ../tools/filter/qssign -s 1234567890 -v
if [ $? -eq 0 ]; then
  echo "ERROR: verification failed"
  exit 1
fi

echo "normal end"
exit 0
