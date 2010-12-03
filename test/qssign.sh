#!/bin/sh
# -*-mode: ksh; ksh-indent: 2; -*-
#

echo "- sign"
cat logs/access_log | ../util/src/qssign -s 1234567890 > logs/signed_access_log

echo "- good"
cat logs/signed_access_log | ../util/src/qssign -s 1234567890 -v
if [ $? -ne 0 ]; then
  echo "ERROR: verification failed (1)"
  exit 1
fi

echo "- good (from prg)"
cat logs/signed_access_log | ../util/src/qssign -S "echo 1234567890" -v
if [ $? -ne 0 ]; then
  echo "ERROR: verification failed (2)"
  exit 1
fi

echo "- wrong passphrase (from prg)"
OUT=`cat logs/signed_access_log | ../util/src/qssign -S "echo 123467890" -v 2>&1`
if [ $? -eq 0 ]; then
  echo "ERROR: verification failed (3) ($OUT)"
  exit 1
fi
if [ `echo $OUT | grep -c "invalid signature"` -eq 0 ]; then
  echo "ERROR: verification failed (4)"
  exit 1
fi

echo "- wrong passphrase"
OUT=`cat logs/signed_access_log | ../util/src/qssign -s abc -v 2>&1`
if [ $? -eq 0 ]; then
  echo "ERROR: verification failed (5)"
  exit 1
fi
if [ `echo $OUT | grep -c "invalid signature"` -eq 0 ]; then
  echo "ERROR: verification failed (6)"
  exit 1
fi

echo "- invalid signature"
sed <logs/signed_access_log >logs/signed_access_log.1 -e "s:000000000005#:000000000003#:g"
OUT=`cat logs/signed_access_log.1 | ../util/src/qssign -s 1234567890 -v 2>&1`
if [ $? -eq 0 ]; then
  echo "ERROR: verification failed (7)"
  exit 1
fi
if [ `echo $OUT | grep -c "invalid signature"` -eq 0 ]; then
  echo "ERROR: verification failed (8)"
  exit 1
fi

echo "- invalid sequence (missing line)"
grep -v "000000000003#" logs/signed_access_log > logs/signed_access_log.1
OUT=`cat logs/signed_access_log.1 | ../util/src/qssign -s 1234567890 -v 2>&1`
if [ $? -eq 0 ]; then
  echo "ERROR: verification failed (9)"
  exit 1
fi
if [ `echo $OUT | grep -c "wrong sequence"` -eq 0 ]; then
  echo "ERROR: verification failed (10)"
  exit 1
fi

echo "normal end"
exit 0
