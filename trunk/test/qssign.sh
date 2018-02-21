#!/bin/sh
# -*-mode: ksh; ksh-indent: 2; -*-
#

cd `dirname $0`
cwd=`pwd`
PFX=[`basename $0`]

if [ `echo "INFO 123\nINFO abc\nDEBUG def\nINFO ghi" | ../util/src/qssign -s 123 -f "DEBUG" | grep -c "INFO ghi 000000000003#"` -ne 1 ]; then
    echo "ERROR: filter failed"
    exit 1
fi

echo "$PFX - log4j"
cd ../tools/log4j-qssign/1.2/
rm -f signed.log
mvn test 1>/dev/null
cd $cwd
cat ../tools/log4j-qssign/1.2/signed.log | ../util/src/qssign -s 12345 -v
if [ $? -ne 0 ]; then
  echo "$PFX ERROR: verification failed (0)(valid)"
  exit 1
else
  echo "$PFX OK"
fi
# modify second line
ts=`cat ../tools/log4j-qssign/1.2/signed.log | head -2 | tail -1 | awk '{print $2}'`
sed -i ../tools/log4j-qssign/1.2/signed.log -e "s/${ts}/xx_xx_xx/g"
cat ../tools/log4j-qssign/1.2/signed.log | ../util/src/qssign -s 12345 -v 2>/dev/null
if [ $? -ne 1 ]; then
  echo "$PFX ERROR: verification failed (0)(tempered)"
  exit 1
else
  echo "$PFX OK"
fi

echo "$PFX - sign"
cat logs/access_log | ../util/src/qssign -s 1234567890 > logs/signed_access_log

echo "$PFX - good"
cat logs/signed_access_log | ../util/src/qssign -s 1234567890 -v
if [ $? -ne 0 ]; then
  echo "$PFX ERROR: verification failed (1)"
  exit 1
fi

echo "$PFX - good (from prg)"
cat logs/signed_access_log | ../util/src/qssign -S "echo 1234567890" -v
if [ $? -ne 0 ]; then
  echo "$PFX ERROR: verification failed (2)"
  exit 1
fi

echo "$PFX - wrong passphrase (from prg)"
OUT=`cat logs/signed_access_log | ../util/src/qssign -S "echo 123467890" -v 2>&1`
if [ $? -eq 0 ]; then
  echo "$PFX ERROR: verification failed (3) ($OUT)"
  exit 1
fi
if [ `echo $OUT | grep -c "invalid signature"` -eq 0 ]; then
  echo "$PFX ERROR: verification failed (4)"
  exit 1
fi

echo "$PFX - wrong passphrase"
OUT=`cat logs/signed_access_log | ../util/src/qssign -s abc -v 2>&1`
if [ $? -eq 0 ]; then
  echo "$PFX ERROR: verification failed (5)"
  exit 1
fi
if [ `echo $OUT | grep -c "invalid signature"` -eq 0 ]; then
  echo "$PFX ERROR: verification failed (6)"
  exit 1
fi

echo "$PFX - invalid signature"
sed <logs/signed_access_log >logs/signed_access_log.1 -e "s:000000000005#:000000000003#:g"
OUT=`cat logs/signed_access_log.1 | ../util/src/qssign -s 1234567890 -v 2>&1`
if [ $? -eq 0 ]; then
  echo "$PFX ERROR: verification failed (7)"
  exit 1
fi
if [ `echo $OUT | grep -c "invalid signature"` -eq 0 ]; then
  echo "$PFX ERROR: verification failed (8)"
  exit 1
fi

echo "$PFX - invalid sequence (missing line)"
grep -v "000000000003#" logs/signed_access_log > logs/signed_access_log.1
OUT=`cat logs/signed_access_log.1 | ../util/src/qssign -s 1234567890 -v 2>&1`
if [ $? -eq 0 ]; then
  echo "$PFX ERROR: verification failed (9)"
  exit 1
fi
if [ `echo $OUT | grep -c "wrong sequence"` -eq 0 ]; then
  echo "$PFX ERROR: verification failed (10)"
  exit 1
fi

## --------------------
## tomcat, catalina
#Jun 4, 2008 9:21:22 AM org.apache.catalina.startup.HostConfig deployWAR
#
## log4j (some of many, many possible formats)
echo "=============================================="
echo "2010-04-14 20:18:37,464 | INFO  | org.hibernate.cfg         ::getInputStream:1081  resource: /hibernate.cfg.xml" | ../util/src/qssign -s 1234567890 -e | tee qssignend.log
if [ `grep -c "000 | INFO  | qssign" qssignend.log` -ne 2 ]; then
  echo "$PFX ERROR: invalid format a"
  exit 1
fi
echo "=============================================="
echo "2011-08-30 07:27:22,738 INFO  loginId='test'" | ../util/src/qssign -s 1234567890 -e | tee qssignend.log
if [ `grep -c "000 \| INFO  qssign" qssignend.log` -ne 2 ]; then
  echo "$PFX ERROR: invalid format b"
  exit 1
fi
echo "=============================================="
echo "2011-09-01 07:37:17,275 main            org.apache.catalina.startup.Catalina     INFO  Server startup in 5770 ms" | ../util/src/qssign -s 1234567890 -e | tee qssignend.log
if [ `grep -c "000 qssign          end" qssignend.log` -ne 1 ]; then
  echo "$PFX ERROR: invalid format c"
  exit 1
fi
echo "=============================================="
echo "2011-08-30 07:27:22,738 anything..." | ../util/src/qssign -s 1234567890 -e | tee qssignend.log
if [ `grep -c "000 INFO  qssign" qssignend.log` -ne 2 ]; then
  echo "$PFX ERROR: invalid format d"
  exit 1
fi
#
## linux: postfix, auth, ...
#Dec  5 07:01:02 titan postfix/cleanup[5524]: AFEF8E6AC6: message-id=<20101205060102.79228E6AB2@server>
#Dec  5 07:15:03 localhost CRON[5556]: pam_unix(cron:session): session closed for user root
echo "=============================================="
echo "Dec  6 04:00:06 localhost kernel: kjournald starting.  Commit interval 5 seconds" | ../util/src/qssign -s 1234567890 -e | tee qssignend.log
if [ `grep -c "qssign: qssign" qssignend.log` -ne 2 ]; then
  echo "$PFX ERROR: invalid format e"
  exit 1
fi
#
##
echo "=============================================="
echo "2010 12 04 20:46:45.118 dispatch   IWWWauthCo 07148.4046314384 3-ERROR :  AuthsessClient_1_0::execute: no valid" | ../util/src/qssign -s 1234567890 -e | tee qssignend.log
if [ `grep -c "000 qssign     end" qssignend.log` -ne 1 ]; then
  echo "$PFX ERROR: invalid format"
  exit 1
fi

echo "=============================================="
echo "[Mon Dec 06 21:29:07 2010] [notice] Apache/2.2.17 (Unix) mod_ssl/2.2.17 OpenSSL/0.9.8k" | ../util/src/qssign -s 1234567890 -e | tee qssignend.log
if [ `grep -c "\[notice\] qssign" qssignend.log` -ne 2 ]; then
  echo "$PFX ERROR: invalid format"
  exit 1
fi

echo "=============================================="
echo "127.0.0.1 - - [06/Dec/2010:21:26:57 +0100] \"GET /qos/favicon.ico HTTP/1.1\" 200 1150" | ../util/src/qssign -s 1234567890 -e | tee qssignend.log

echo "=============================================="
echo "127.0.0.1 - - [31/Oct/2013:21:41:21 +0100] \"GET /auth/index.html HTTP/1.1\" 401 194 \"-\" \"Mozilla/5.0 1\"" | ../util/src/qssign -s 1234567890 -e | tee qssignend.log

echo "=============================================="
echo "2013/11/07 17:44:07 [error] 4640#0: *55 auth_token_module(014): request not authorized: invalid signature, client: 127.0.0.1, server: localhost, request: \"GET /app/index.html?req=1 HTTP/1.1\", host: \"127.0.0.1:8204\"" | ../util/src/qssign -s 1234567890 -e -a sha256 | tee qssignend.log
if [ `grep -c "0#0: qssign" qssignend.log` -ne 2 ]; then
  echo "$PFX ERROR: invalid format"
  exit 1
fi
echo "$PFX algorithm... OK:"
cat qssignend.log | ../util/src/qssign -s 1234567890 -v -a sha256
if [ $? -ne 0 ]; then
    echo "$PFX ERROR: validation failed (sha256)"
    exit 1
fi
echo "$PFX -"
echo "$PFX algorithm... expect error:"
cat qssignend.log | ../util/src/qssign -s 1234567890 -v -a sha1
if [ $? -eq 0 ]; then
    echo "$PFX ERROR: validation success (sha256)"
    exit 1
fi

echo "$PFX - end"
head -4 logs/access_log | ../util/src/qssign -s 1234567890 -e > logs/signed_access_log.1
OUT=`cat logs/signed_access_log.1 | ../util/src/qssign -s 1234567890 -e -v`
if [ $? -ne 0 ]; then
  echo "$PFX ERROR: verification failed (11)"
  exit 1
fi
if [ -n "$OUT" ]; then
  echo "$PFX ERROR: verification failed (12) [$OUT}"
  exit 1
fi
tail -4 logs/access_log | ../util/src/qssign -s 1234567890 -e >> logs/signed_access_log.1
OUT=`cat logs/signed_access_log.1 | ../util/src/qssign -s 1234567890 -e -v`
if [ $? -ne 0 ]; then
  echo "$PFX ERROR: verification failed (13)"
  exit 1
fi
if [ -n "$OUT" ]; then
  echo "$PFX ERROR: verification failed (14) [$OUT]"
  exit 1
fi
COUNT=`wc -l logs/signed_access_log.1 | awk '{print $1}'`
echo "$PFX - end (missing last line nr $COUNT)"
COUNT=`expr $COUNT - 1`
OUT=`head -${COUNT} logs/signed_access_log.1 | ../util/src/qssign -s 1234567890 -e -v 2>&1`
if [ `echo $OUT | grep -c "NOTICE: no end marker seen"` -eq 0 ]; then
  echo "$PFX ERROR: verification failed (15) [$OUT]"
  exit 1
fi
echo "$PFX - end (new seq, no end)"
head -4 logs/access_log | ../util/src/qssign -s 1234567890 -e | head -3 > logs/signed_access_log.1
head -4 logs/access_log | ../util/src/qssign -s 1234567890  >> logs/signed_access_log.1
OUT=`cat logs/signed_access_log.1 |  ../util/src/qssign -s 1234567890 -e -v 2>&1`
if [ $? -eq 0 ]; then
  echo "$PFX ERROR: verification failed (16)"
  exit 1
fi
if [ `echo $OUT | grep -c "wrong sequence, server restart"` -eq 0 ]; then
  echo "$PFX ERROR: verification failed (17) [$OUT]"
  exit 1
fi
echo "$PFX - end (wrong beginning)"
head -4 logs/access_log | ../util/src/qssign -s 1234567890 -e | tail -3 > logs/signed_access_log.1
OUT=`cat logs/signed_access_log.1 | ../util/src/qssign -s 1234567890 -e -v 2>&1`
if [ `echo $OUT | grep -c "log starts with sequence"` -eq 0 ]; then
  echo "$PFX ERROR: verification failed (18) [$OUT]"
  exit 1
fi

echo "$PFX - sigusr1"
cat qssign_sigusr1.log | ../util/src/qssign -s password -v -e
if [ $? -ne 0 ]; then
  echo "$PFX ERROR: sigusr1 (two processes running)"
  exit 1
fi


rm qssignend.log
echo "$PFX normal end"
exit 0
