#!/bin/sh
# -*-mode: ksh; ksh-indent: 2; -*-

cd `dirname $0`

VERSION=`grep "char g_revision" httpd_src/modules/qos/mod_qos.c | awk '{print $6}' | awk -F'"' '{print $2}'`

A_V=`./httpd/httpd -v | grep "Server version" | awk -F'/' '{print $2}' | awk -F'.' '{print $1 "." $2}'`
if [ "$A_V" != "2.2" ]; then
    echo "FAILED, need Apache 2.2 binary to read log messages"
    exit 1
fi
strings ./httpd/modules/qos/.libs/mod_qos.so | grep "mod_qos(" | sort -u | sort -n | grep -v -e "mod_qos()" -e "mod_qos(000)" > doc/MESSAGES.txt

sed <doc/index.html >doc/dist/index.html \
    -e "s:(DoS):(<a href='dos.html'>DoS</a>):g" \
    -e "s/0\.00/${VERSION}/g" \
    -e "s:BUILD START -->::g" \
    -e "s:<!-- BUILD END::g"

