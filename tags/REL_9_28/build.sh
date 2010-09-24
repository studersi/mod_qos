#!/bin/sh
# -*-mode: ksh; ksh-indent: 2; -*-
#
# $Header: /home/cvs/m/mo/mod-qos/src/build.sh,v 2.39 2010-08-17 19:04:00 pbuchbinder Exp $
#
# Simple build script using Apache tar.gz from the 3thrdparty directory
#
# See http://sourceforge.net/projects/mod-qos/ for further
# details about mod_qos.
#
# Copyright (C) 2007-2010 Pascal Buchbinder
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
APACHE_VER=2.2.16

echo "build Apache $APACHE_VER"
if [ ! -d httpd-${APACHE_VER} ]; then
  gzip -c -d $TOP/3thrdparty/httpd-${APACHE_VER}.tar.gz | tar xf -
fi
rm -f httpd
ln -s httpd-${APACHE_VER} httpd

PNG=1.4.2
if [ -f ./3thrdparty/libpng-${PNG}.tar.gz ]; then
  if [ ! -d libpng-${PNG} ]; then
    gzip -c -d ./3thrdparty/libpng-${PNG}.tar.gz | tar xf -
  fi
  rm -f libpng
  ln -s libpng-${PNG} libpng
  cd libpng
  ./configure --disable-shared
  make
  cd ..
fi

rm -rf httpd/modules/qos
mkdir -p httpd/modules/qos
ln -s `pwd`/httpd_src/modules/qos/mod_qos.c httpd/modules/qos
ln -s `pwd`/httpd_src/modules/qos/mod_qos.h httpd/modules/qos
ln -s `pwd`/httpd_src/modules/qos/config.m4 httpd/modules/qos
ln -s `pwd`/httpd_src/modules/qos/Makefile.in httpd/modules/qos

ADDMOD=""
if [ "$1" = "release" ]; then
  echo "release binary"
  CFLAGS="-DDEFAULT_SERVER_LIMIT=512 -DDEFAULT_THREAD_LIMIT=256 -DQS_REQ_RATE_TM=10 -DI_INSIST_ON_EXTRA_CYCLES_FOR_CLF_COMPLIANCE"
  export CFLAGS 
else
  CFLAGS="-DDEFAULT_SERVER_LIMIT=512 -DDEFAULT_THREAD_LIMIT=256 -DQS_INTERNAL_TEST -g -Wall"
  export CFLAGS 
  ADDMOD="--prefix=/var/tmp/apache"
fi

LDFLAGS=""
export LDFLAGS
LD_LIBRARY_PATH=""
export LD_LIBRARY_PATH
LTCFLAGS=""
export LTCFLAGS

cd httpd
./buildconf
if [ $? -ne 0 ]; then
  echo "ERROR"
  exit 1
fi

#./configure --enable-so --enable-qos=shared --enable-proxy=shared --enable-ssl --enable-status=shared --enable-info=shared --enable-static-support --enable-unique-id --enable-dumpio=shared --enable-deflate $ADDMOD
./configure --with-mpm=worker --enable-so --enable-qos=shared --enable-proxy=shared --enable-ssl --enable-status=shared --enable-info=shared --enable-static-support --enable-unique-id --enable-dumpio=shared --enable-deflate $ADDMOD
if [ $? -ne 0 ]; then
  echo "ERROR"
  exit 1
fi

# patch ...
sed <build/rules.mk > build/rules.mk.2 \
 -e "s;LINK     = \$(LIBTOOL) --mode=link \$(CC) \$(ALL_CFLAGS)  \$(LT_LDFLAGS);LINK     = \$(LIBTOOL) --mode=link \$(CC) \$(ALL_CFLAGS) -static \$(LT_LDFLAGS);g"
mv build/rules.mk.2 build/rules.mk

make
if [ $? -ne 0 ]; then
  echo "ERROR"
  exit 1
fi

if [ "$1" = "release" ]; then
  strip modules/qos/.libs/mod_qos.so
  if [ $? -ne 0 ]; then
    echo "ERROR"
    exit 1
  fi
fi
cd ..

cd util
./buildconf.sh
./configure
make
cd ..

echo "END"
