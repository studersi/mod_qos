#!/bin/sh
# -*-mode: ksh; ksh-indent: 2; -*-

PFX=[`basename $0`]

echo "$PFX start"

# ----------------------------------------------------------------------
# "normal" (%h %l %u %t \"%r\" %>s ...) apache access log
# ----------------------------------------------------------------------
cat >geo.log <<EOF
195.112.173.221 - - [07/Feb/2012:19:25:33 +0100] "GET /cgi/sleep.cgi?s=4 HTTP/1.1" 200 5 "-" 4 5 - 5 id=TzFsnX8AAQEAACL4ApQAAAAA - - - 0 - 1 a=1 #8952
139.152.12.123 - - [07/Feb/2012:19:25:33 +0100] "GET /cgi/sleep.cgi?s=4 HTTP/1.1" 200 5 "-" 4 4 - 4 id=TzFsnX8AAQEAACL4ApYAAAAB - - - 0 - 3 a=3 #8952
62.184.102.22 - - [07/Feb/2012:19:25:33 +0100] "GET /cgi/sleep.cgi?s=4&ip=62.184.102.22 HTTP/1.1" 200 5 "-" 4 3 - 3 id=TzFsnX8AAQEAACL4ApUAAAAD - - - 0 - 2 a=2 #8952
EOF

cat geo.log | ../util/src/qsgeo -d conf/GeoIPCountryWhois.csv > geo.log.c

if [ `grep -c "^195.112.173.221 BR - - \[07" geo.log.c` -ne 1 ]; then
  echo "FAILED - Brazil, apache log"
  exit 1
fi
if [ `grep -c "139.152.12.123 JP -" geo.log.c` -ne 1 ]; then
  echo "FAILED - Japan, apache log"
  exit 1
fi
if [ `grep -c "62.184.102.22 FR - - \[07/Feb/2012:19:25:33 +0100\] \"GET /cgi/sleep.cgi?s=4&ip=62.184.102.22 HTTP/1.1" geo.log.c` -ne 1 ]; then
  echo "FAILED - France, apache log"
  exit 1
fi

# ----------------------------------------------------------------------
# qslog -pc log file
# ----------------------------------------------------------------------
cat >geo.log <<EOF
195.112.173.221;req;4;errors;0;duration;180;bytes;4000;1xx;0;2xx;4;3xx;0;4xx;0;5xx;0;304;0;av;0;avms;52;<1s;4;1s;0;2s;0;3s;0;4s;0;5s;0;>5s;0;ci;0;html;2;css/js;0;img;1;other;1;A01;2;A02;1;X02;1;
blabla
kkkkkkkkkkkkkkkkkkkkkkkk222222139.152.12.123;req;1
139.152.12.123;req;1;errors;0;duration;1;bytes;2000;1xx;0;2xx;1;3xx;0;4xx;0;5xx;0;304;0;av;0;avms;152;<1s;1;1s;0;2s;0;3s;0;4s;0;5s;0;>5s;0;ci;40;html;1;css/js;0;img;0;other;0;A01;1;
EOF

cat geo.log | ../util/src/qsgeo -d conf/GeoIPCountryWhois.csv > geo.log.c

if [ `grep -c "^195.112.173.221;BR;req;4" geo.log.c` -ne 1 ]; then
  echo "FAILED - Brazil, qslog -pc"
  exit 1
fi

if [ `grep -c "^139.152.12.123;JP;req;1;errors;0;duration;1" geo.log.c` -ne 1 ]; then
  echo "FAILED - Japan, qslog -pc"
  exit 1
fi

if [ `grep -c "blabla" geo.log.c` -ne 1 ]; then
  echo "FAILED - blabla, qslog -pc"
  exit 1
fi

if [ `grep -c "kkkkkkkkkkkkkkkkkkkkkkkk222222139.152.12.123;req;1" geo.log.c` -ne 1 ]; then
  echo "FAILED - invalid format, qslog -pc"
  exit 1
fi

../util/src/qsgeo -d conf/GeoIPCountryWhois_raw.csv -l > geo.log.c
if [ `grep -c '"192.168.0.0","192.168.255.255","3232235520","3232301055","PV","private network"' geo.log.c` -ne 1 ]; then
  echo "FAILED - missing private network, qslog -l"
  exit 1
fi
if [ `diff conf/GeoIPCountryWhois_raw.csv geo.log.c | wc -l` -ne 8 ]; then
  echo "FAILED - wrong number of injected lines, qslog -l"
  exit 1
fi

../util/src/qsgeo -d conf/DB1.csv -l > geo.log.c
if [ `grep -c '"192.168.0.0","192.168.255.255","3232235520","3232301055","PV","private network"' geo.log.c` -ne 1 ]; then
  echo "FAILED - missing private network, qslog -l, DB1"
  exit 1
fi
if [ `grep -c '"217.244.61.160","217.244.61.191","3656662432","3656662463","AT","Austria"' geo.log.c` -ne 1 ]; then
  echo "FAILED - missing enriched entry, qslog -l, DB1"
  exit 1
fi

# cleanup
rm geo.log
rm geo.log.c
echo "$PFX OK"
exit 0
