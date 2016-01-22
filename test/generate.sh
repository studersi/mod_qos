#!/bin/sh
# -*-mode: ksh; ksh-indent: 2; -*-
#
# $Header: /home/cvs/m/mo/mod-qos/src/test/generate.sh,v 2.39 2016-01-22 16:40:00 pbuchbinder Exp $
#
# Simple start/stop script (for test purposes only).
#
# See http://opensource.adnovum.ch/mod_qos/ for further
# details about mod_qos.
#
# Copyright (C) 2007-2015 Pascal Buchbinder
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA 02110-1301, USA.
#

PFX=[`basename $0`]
cd `dirname $0`

ROOT=`pwd`
QS_UID=`id`
QS_UID_STR=`expr "$QS_UID" : 'uid=[0-9]*.\([a-z,A-Z,0-9,_]*\)'`
QS_UID=`id`
QS_GID=`expr "$QS_UID" : '.*gid=[0-9]*.\([a-z,A-Z,0-9,_]*\)'`
QS_UID=`id`
QS_UID=`expr "$QS_UID" : 'uid=\([0-9]*\)'`
#QS_PORT_BASE=`expr ${QS_UID} - 1000`
QS_PORT_BASE=`expr ${QS_UID} \% 1000`
#QS_PORT_BASE=`expr $QS_PORT_BASE '*' 120`
QS_PORT_BASE=`expr $QS_PORT_BASE + 5000`
QS_PORT_BASE1=`expr $QS_PORT_BASE + 1`
QS_PORT_BASE2=`expr $QS_PORT_BASE + 2`
QS_PORT_BASE3=`expr $QS_PORT_BASE + 3`
QS_PORT_BASE5=`expr $QS_PORT_BASE + 5`
QS_PORT_BASE6=`expr $QS_PORT_BASE + 6`
QS_PORT_BASE8=`expr $QS_PORT_BASE + 8`
QS_PORT_BASE9=`expr $QS_PORT_BASE + 9`
QS_PORT_BASE10=`expr $QS_PORT_BASE + 10`
QS_PORT_BASE11=`expr $QS_PORT_BASE + 11`

echo "SET QS_PORT_BASE=$QS_PORT_BASE"   >  scripts/ports
echo "SET QS_PORT_BASE1=$QS_PORT_BASE1" >> scripts/ports
echo "SET QS_PORT_BASE2=$QS_PORT_BASE2" >> scripts/ports
echo "SET QS_PORT_BASE3=$QS_PORT_BASE3" >> scripts/ports
echo "SET QS_PORT_BASE5=$QS_PORT_BASE5" >> scripts/ports
echo "SET QS_PORT_BASE6=$QS_PORT_BASE6" >> scripts/ports
echo "SET QS_PORT_BASE8=$QS_PORT_BASE8" >> scripts/ports
echo "SET QS_PORT_BASE9=$QS_PORT_BASE9" >> scripts/ports
echo "SET QS_PORT_BASE10=$QS_PORT_BASE10" >> scripts/ports
echo "SET QS_PORT_BASE11=$QS_PORT_BASE11" >> scripts/ports
echo "SET QS_HOME=`pwd`" >> scripts/ports
echo "SET QS_HOME_ENC=`pwd | sed s:/:%2F:g`" >> scripts/ports

echo "QS_PORT_BASE=$QS_PORT_BASE"   >  ports
echo "export QS_PORT_BASE"          >> ports
echo "QS_PORT_BASE1=$QS_PORT_BASE1" >> ports
echo "export QS_PORT_BASE1"         >> ports
echo "QS_PORT_BASE2=$QS_PORT_BASE2" >> ports
echo "export QS_PORT_BASE2"         >> ports
echo "QS_PORT_BASE6=$QS_PORT_BASE6" >> ports
echo "export QS_PORT_BASE6"         >> ports

if [ ! -r libexec/mod_parp.so ]; then
    mkdir -p libexec
    if [ -r ../../parp/httpd/modules/parp/.libs/mod_parp.so ]; then
	echo "$PFX link mod_parp"
	cd libexec
	ln -s ${ROOT}/../../../parp/httpd/modules/parp/.libs/mod_parp.so .
	cd ..
    else
	echo "$PFX mod_parp is missing"
    fi
fi
if [ ! -r libexec/mod_setenvifplus.so ]; then
    mkdir -p libexec
    if [ -r ../../setenvifplus/httpd/modules/metadataplus/.libs/mod_setenvifplus.so ]; then
	echo "$PFX link mod_setenvifplus"
	cd libexec
	ln -s ${ROOT}/../../setenvifplus/httpd/modules/metadataplus/.libs/mod_setenvifplus.so
	cd ..
    else
	echo "$PFX mod_setenvifplus is missing"
    fi
fi

# image.iso   ~1MB
# dvd.iso    ~10MB
# dvd2.iso  ~100MB
# dvd3.iso  ~500MB
# guide.pdf  ~20MB
if [ ! -f htdocs/image.iso ]; then
  for E in `seq 12500`; do
    echo "TEXT TEXT TEXT TEXT TEXT TEXT TEXT TEXT TEXT TEXT TEXT TEXT TEXT TEXT TEXT TEXT " >> htdocs/image.iso
  done
  cp htdocs/image.iso htdocs/demo/c/image.iso
  cp htdocs/image.iso htdocs/bbb/image.iso
  rm -f htdocs/dvd.iso
  for E in `seq 10`; do
    cat htdocs/image.iso >> htdocs/dvd.iso
  done
  cp htdocs/dvd.iso htdocs/movie.mpeg
  rm -f htdocs/dvd2.iso
  for E in `seq 10`; do
    cat htdocs/dvd.iso >> htdocs/dvd2.iso
  done
  rm -f htdocs/dvd3.iso
  for E in `seq 5`; do
    cat htdocs/dvd2.iso >> htdocs/dvd3.iso
  done
  cp htdocs/dvd.iso htdocs/guide01.pdf
  cat htdocs/dvd.iso >> htdocs/guide01.pdf
  mkdir -p htdocs/images
  cp htdocs/demo/a/_*.jpg htdocs/images/
fi

CONFFILES="conf/httpd.conf conf/demo.conf conf/simple.conf conf/dos.conf conf/qos_viewer.conf appl_conf/httpd.conf conf/uc1.conf conf/ucn.conf"
for E in $CONFFILES; do
    sed <$E.tmpl >$E \
	-e "s;##ROOT##;$ROOT;g" \
	-e "s;##USR##;$QS_UID_STR;g" \
	-e "s;##QS_PORT_BASE##;$QS_PORT_BASE;g" \
	-e "s;##QS_PORT_BASE1##;$QS_PORT_BASE1;g" \
	-e "s;##QS_PORT_BASE2##;$QS_PORT_BASE2;g" \
	-e "s;##QS_PORT_BASE3##;$QS_PORT_BASE3;g" \
	-e "s;##QS_PORT_BASE5##;$QS_PORT_BASE5;g" \
	-e "s;##QS_PORT_BASE6##;$QS_PORT_BASE6;g" \
	-e "s;##QS_PORT_BASE8##;$QS_PORT_BASE8;g" \
	-e "s;##QS_PORT_BASE9##;$QS_PORT_BASE9;g" \
	-e "s;##QS_PORT_BASE10##;$QS_PORT_BASE10;g" \
	-e "s;##QS_PORT_BASE11##;$QS_PORT_BASE11;g"
done

echo "" > conf/json.conf

if [ ! -d logs ]; then
    mkdir logs
fi

if [ -f ../3thrdparty/modsecurity/rules/modsecurity_crs_40_generic_attacks.conf ]; then
    MSID=0
    rm -f appl_conf/qos_deny_filter.conf
    for E in `grep "^SecRule " ../3thrdparty/modsecurity/rules/modsecurity_crs_40_generic_attacks.conf | awk '{print $3}' | grep "\"$"`; do
	echo "QS_DenyRequestLine +MS${MSID} deny $E" >> appl_conf/qos_deny_filter.conf
	MSID=`expr $MSID + 1`
    done
fi

cd libexec
rm -f mod_websocket.so
rm -f mod_websocket_echo.so
rm -f mod_websocket_mirror.so
ln -s ../../mod-websocket/.libs/mod_websocket.so .
ln -s ../../mod-websocket/.libs/mod_websocket_echo.so .
ln -s ../../mod-websocket/.libs/mod_websocket_mirror.so .
cd ..

cd ./bin
cc -o sleep sleep.c
