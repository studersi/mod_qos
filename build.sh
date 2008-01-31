#!/bin/sh
# -*-mode: ksh; ksh-indent: 2; -*-
#
# $Header: /home/cvs/m/mo/mod-qos/src/build.sh,v 2.20 2008-01-31 20:12:03 pbuchbinder Exp $
#
# Simple build script using apache and libpng tar.gz from the 3thrdparty directory
#
# See http://sourceforge.net/projects/mod-qos/ for further
# details about mod_qos.
#
# Copyright (C) 2007-2008 Pascal Buchbinder
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

TOP=`pwd`

#APACHE_VER=2.0.59
APACHE_VER=2.2.4

echo "build Apache $APACHE_VER"
if [ ! -d httpd-${APACHE_VER} ]; then
  gzip -c -d $TOP/3thrdparty/httpd-${APACHE_VER}.tar.gz | tar xf -
fi
rm -f httpd
ln -s httpd-${APACHE_VER} httpd

#PNG=1.2.5
#if [ ! -d libpng-${PNG} ]; then
#  gzip -c -d ./3thrdparty/libpng-${PNG}.tar.gz | tar xf -
#fi
#rm -f libpng
#ln -s libpng-${PNG} libpng
#cd libpng
#./configure --disable-shared
#make
#cd ..

rm -rf httpd/modules/qos
mkdir -p httpd/modules/qos
ln -s `pwd`/httpd_src/modules/qos/mod_qos.c httpd/modules/qos
ln -s `pwd`/httpd_src/modules/qos/mod_qos_control.c httpd/modules/qos
ln -s `pwd`/httpd_src/modules/qos/config.m4 httpd/modules/qos
ln -s `pwd`/httpd_src/modules/qos/Makefile.in httpd/modules/qos

if [ "$1" = "release" ]; then
  echo "release binary"
  CFLAGS="-DDEFAULT_SERVER_LIMIT=512 -DDEFAULT_THREAD_LIMIT=256"
  export CFLAGS 
else
  CFLAGS="-DDEFAULT_SERVER_LIMIT=512 -DDEFAULT_THREAD_LIMIT=256 -DQS_INTERNAL_TEST -g"
  export CFLAGS 
fi

cd httpd
./buildconf
./configure --with-mpm=worker --enable-so --enable-qos=shared --enable-qos-control=shared --enable-proxy=shared --enable-ssl --enable-status=shared --enable-info=shared --enable-static-support --enable-unique-id
make
strip modules/qos/.libs/mod_qos.so
if [ $? -ne 0 ]; then
  echo "ERROR"
  exit 1
fi
strip modules/qos/.libs/mod_qos_control.so
if [ $? -ne 0 ]; then
  echo "ERROR"
  exit 1
fi
cd ..

cd tools
make
cd ..
cd tools/filter
make
cd ../..

if [ -f ./3thrdparty/modsecurity-apache_2.1.1.tar.gz ]; then
  tar xfz ./3thrdparty/modsecurity-apache_2.1.1.tar.gz modsecurity-apache_2.1.1/rules/modsecurity_crs_40_generic_attacks.conf
  ln -s modsecurity-apache_2.1.1 modsecurity
fi

echo "END"
