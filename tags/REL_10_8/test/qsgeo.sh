#!/bin/sh
# -*-mode: ksh; ksh-indent: 2; -*-


cat >geo.log <<EOF
195.112.173.221 - - [07/Feb/2012:19:25:33 +0100] "GET /cgi/sleep.cgi?s=4 HTTP/1.1" 200 5 "-" 4 5 - 5 id=TzFsnX8AAQEAACL4ApQAAAAA - - - 0 - 1 a=1 #8952
139.152.12.123 - - [07/Feb/2012:19:25:33 +0100] "GET /cgi/sleep.cgi?s=4 HTTP/1.1" 200 5 "-" 4 4 - 4 id=TzFsnX8AAQEAACL4ApYAAAAB - - - 0 - 3 a=3 #8952
62.184.102.22 - - [07/Feb/2012:19:25:33 +0100] "GET /cgi/sleep.cgi?s=4 HTTP/1.1" 200 5 "-" 4 3 - 3 id=TzFsnX8AAQEAACL4ApUAAAAD - - - 0 - 2 a=2 #8952
EOF

cat geo.log | ../util/src/qsgeo -d conf/GeoIPCountryWhois.csv > geo.log.c

if [ `grep -c "195.112.173.221 BR -" geo.log.c` -ne 1 ]; then
  echo "FAILED - Brazil"
  exit 1
fi
if [ `grep -c "139.152.12.123 JP -" geo.log.c` -ne 1 ]; then
  echo "FAILED - Japan"
  exit 1
fi
if [ `grep -c "62.184.102.22 FR -" geo.log.c` -ne 1 ]; then
  echo "FAILED - France"
  exit 1
fi

rm geo.log
rm geo.log.c
exit 0
