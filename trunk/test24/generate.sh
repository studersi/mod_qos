#!/bin/sh
# -*-mode: ksh; ksh-indent: 2; -*-
#
# $Header: /home/cvs/m/mo/mod-qos/src/test24/generate.sh,v 1.12 2016-03-16 21:49:29 pbuchbinder Exp $
#
# Simple start/stop script (for test purposes only).
#
# See http://opensource.adnovum.ch/mod_qos/ for further
# details about mod_qos.
#
# Copyright (C) 2007-2016 Pascal Buchbinder
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

DIRECTORIES="logs scripts htdocs conf"
for E in $DIRECTORIES; do
  mkdir -p $E
done

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

echo "SET QS_PORT_BASE=$QS_PORT_BASE"   >  scripts/ports
echo "SET QS_PORT_BASE1=$QS_PORT_BASE1" >> scripts/ports
echo "SET QS_PORT_BASE2=$QS_PORT_BASE2" >> scripts/ports
echo "SET QS_PORT_BASE3=$QS_PORT_BASE3" >> scripts/ports
echo "SET QS_PORT_BASE5=$QS_PORT_BASE5" >> scripts/ports
echo "SET QS_PORT_BASE6=$QS_PORT_BASE6" >> scripts/ports
echo "SET QS_PORT_BASE8=$QS_PORT_BASE8" >> scripts/ports
echo "SET QS_PORT_BASE9=$QS_PORT_BASE9" >> scripts/ports
echo "SET QS_PORT_BASE10=$QS_PORT_BASE10" >> scripts/ports
echo "SET QS_HOME=`pwd`" >> scripts/ports
echo "SET QS_HOME_ENC=`pwd | sed s:/:%2F:g`" >> scripts/ports

echo "QS_PORT_BASE=$QS_PORT_BASE"   >  ports
echo "export QS_PORT_BASE"          >> ports
echo "QS_PORT_BASE1=$QS_PORT_BASE1" >> ports
echo "export QS_PORT_BASE1"         >> ports
echo "QS_PORT_BASE2=$QS_PORT_BASE2" >> ports
echo "export QS_PORT_BASE1"         >> ports

if [ ! -x bin/curl ]; then
    if [ -x ../../curl-*/src/curl ]; then
	cd bin
	ln -s ../../../curl-*/src/curl .
	cd ..
    else
	echo "ERROR, could not find curl binary"
    fi
fi
if [ ! -f htdocs/image.iso -o ]; then
  for E in `seq 12500`; do
    echo "TEXT TEXT TEXT TEXT TEXT TEXT TEXT TEXT TEXT TEXT TEXT TEXT TEXT TEXT TEXT TEXT " >> htdocs/image.iso
  done
  rm -f htdocs/dvd.iso
  for E in `seq 10`; do
    cat htdocs/image.iso >> htdocs/dvd.iso
  done
  rm -f htdocs/dvd2.iso
  for E in `seq 10`; do
    cat htdocs/dvd.iso >> htdocs/dvd2.iso
  done
  echo "END OF dvd2.iso" >> htdocs/dvd2.iso
  echo "END OF dvd.iso" >> htdocs/dvd.iso
fi

mkdir -p htdocs/limitbs
mkdir -p htdocs/ratelimit
mkdir -p htdocs/images
cp ../doc/images/*.* htdocs/images
cp htdocs/image.iso htdocs/limitbs/image.iso
cp htdocs/image.iso htdocs/ratelimit/image.iso
if [ ! -d htdocs/demo ]; then
    cd htdocs
    ln -s ../../test/htdocs/demo/
    cd ..
fi
CONFFILES="conf/httpd.conf conf/demo.conf conf/ucn.conf"
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
	-e "s;##QS_PORT_BASE10##;$QS_PORT_BASE10;g"
done

if [ ! -x run.sh ]; then
  ln -s ../test/run.sh .
fi

if [ ! -d bin ]; then
  mkdir bin
  cd bin
  ln -s ../../test/bin/h* .
  ln -s ../../test/bin/s* .
  ln -s ../../test/sleep.sh .
  cd ..
fi
