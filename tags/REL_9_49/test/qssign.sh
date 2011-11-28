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

## --------------------
## tomcat, catalina
#Jun 4, 2008 9:21:22 AM org.apache.catalina.startup.HostConfig deployWAR
#
## log4j (one of many, many possible formats)
#2010-04-14 20:18:37,464 | INFO  | org.hibernate.cfg.Configuration         ::getConfigurationInputStream:1081  Configuration resource: /hibernate.cfg.xml
#
## linux: postfix, auth, ...
#Dec  5 07:01:02 titan postfix/cleanup[5524]: AFEF8E6AC6: message-id=<20101205060102.79228E6AB2@server>
#Dec  5 07:15:03 localhost CRON[5556]: pam_unix(cron:session): session closed for user root
echo "=============================================="
echo "Dec  6 04:00:06 localhost kernel: kjournald starting.  Commit interval 5 seconds" | ../util/src/qssign -s 1234567890 -e
#
##
echo "=============================================="
echo "2010 12 04 20:46:45.118 dispatch   IWWWauthCo 07148.4046314384 3-ERROR :  AuthsessClient_1_0::execute: no valid" | ../util/src/qssign -s 1234567890 -e

echo "=============================================="
echo "[Mon Dec 06 21:29:07 2010] [notice] Apache/2.2.17 (Unix) mod_ssl/2.2.17 OpenSSL/0.9.8k" | ../util/src/qssign -s 1234567890 -e

echo "=============================================="
echo "127.0.0.1 - - [06/Dec/2010:21:26:57 +0100] \"GET /qos/favicon.ico HTTP/1.1\" 200 1150" | ../util/src/qssign -s 1234567890 -e


echo "- end"
head -4 logs/access_log | ../util/src/qssign -s 1234567890 -e > logs/signed_access_log.1
OUT=`cat logs/signed_access_log.1 | ../util/src/qssign -s 1234567890 -e -v`
if [ $? -ne 0 ]; then
  echo "ERROR: verification failed (11)"
  exit 1
fi
if [ -n "$OUT" ]; then
  echo "ERROR: verification failed (12) [$OUT}"
  exit 1
fi
tail -4 logs/access_log | ../util/src/qssign -s 1234567890 -e >> logs/signed_access_log.1
OUT=`cat logs/signed_access_log.1 | ../util/src/qssign -s 1234567890 -e -v`
if [ $? -ne 0 ]; then
  echo "ERROR: verification failed (13)"
  exit 1
fi
if [ -n "$OUT" ]; then
  echo "ERROR: verification failed (14) [$OUT]"
  exit 1
fi
COUNT=`wc -l logs/signed_access_log.1 | awk '{print $1}'`
echo "- end (missing last line nr $COUNT)"
COUNT=`expr $COUNT - 1`
OUT=`head -${COUNT} logs/signed_access_log.1 | ../util/src/qssign -s 1234567890 -e -v 2>&1`
if [ `echo $OUT | grep -c "NOTICE: no end marker seen"` -eq 0 ]; then
  echo "ERROR: verification failed (15) [$OUT]"
  exit 1
fi
echo "- end (new seq, no end)"
head -4 logs/access_log | ../util/src/qssign -s 1234567890 -e | head -3 > logs/signed_access_log.1
head -4 logs/access_log | ../util/src/qssign -s 1234567890 -e >> logs/signed_access_log.1
OUT=`cat logs/signed_access_log.1 | ../util/src/qssign -s 1234567890 -e -v 2>&1`
if [ $? -eq 0 ]; then
  echo "ERROR: verification failed (16)"
  exit 1
fi
if [ `echo $OUT | grep -c "wrong sequence, server restart"` -eq 0 ]; then
  echo "ERROR: verification failed (17) [$OUT]"
  exit 1
fi
echo "- end (wrong beginning)"
head -4 logs/access_log | ../util/src/qssign -s 1234567890 -e | tail -3 > logs/signed_access_log.1
OUT=`cat logs/signed_access_log.1 | ../util/src/qssign -s 1234567890 -e -v 2>&1`
if [ `echo $OUT | grep -c "log starts with sequence"` -eq 0 ]; then
  echo "ERROR: verification failed (18) [$OUT]"
  exit 1
fi

echo "normal end"
exit 0