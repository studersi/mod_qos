#!/bin/sh
# -*-mode: ksh; ksh-indent: 2; -*-

cd `dirname $0`

VERSION=`grep "char g_revision" httpd_src/modules/qos/mod_qos.c | awk '{print $6}' | awk -F'"' '{print $2}'`

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

sed <doc/index.html >doc/dist/index.html \
    -e "s:Penetration of the web server by attackers (DoS):<a href='dos.html'>Penetration of the web server by attackers (DoS)</a>:g" \
    -e "s:defend against SSL DoS attacks:<a href='dos.html#NullConnection'>defend against SSL DoS attacks</a>:g" \
    -e "s/0\.00/${VERSION}/g" \
    -e "s:DIST START -->::g" \
    -e "s:<!-- DIST END::g"

