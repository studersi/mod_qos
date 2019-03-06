#!/bin/sh
# -*-mode: ksh; ksh-indent: 2; -*-

cd `dirname $0`
PFX=[`basename $0`]

VERSION=`grep "char g_revision" httpd_src/modules/qos/mod_qos.c | awk '{print $6}' | awk -F'"' '{print $2}'`
DOC_V=`head -1 doc/CHANGES.txt | grep Version | awk '{print $2}'`
if [ "$VERSION" != "$DOC_V" ]; then
    echo "FAILED, version missmatch"
    exit 1
fi

A_V=`./httpd/httpd -v | grep "Server version" | awk -F'/' '{print $2}' | awk -F'.' '{print $1 "." $2}'`
if [ "$A_V" != "2.2" ]; then
    echo "FAILED, need Apache 2.2 binary to read log messages"
    exit 1
fi
strings ./httpd/modules/qos/.libs/mod_qos.so | grep "mod_qos("\
    | sort -u | sort -n |\
    grep -v -e "mod_qos()" \
	 -e "mod_qos(000)" \
	 -e "e;mod_qos(%" \
	 -e "no valid IP header found (@prr)" > doc/MESSAGES.txt

if [ `grep -c '0\.00' doc/index.html` -ne 3 ]; then
    echo "$PFX ERROR, unexected number of version pattern 0.00"
    exit 1
fi
sed <doc/index.html >doc/dist/index.html \
    -e "s:Penetration of the web server by attackers (DoS):<a href='dos.html'>Penetration of the web server by attackers (DoS)</a>:g" \
    -e "s:defend against SSL DoS attacks:<a href='dos.html#NullConnection'>defend against SSL DoS attacks</a>:g" \
    -e "s/0\.00/${VERSION}/g" \
    -e "s:DIST START -->::g" \
    -e "s:<!-- DIST END::g"

