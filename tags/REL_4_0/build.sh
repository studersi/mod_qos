#!/bin/sh
#
# $Header: /home/cvs/m/mo/mod-qos/src/build.sh,v 2.10 2007-09-07 22:08:07 pbuchbinder Exp $
#
# Simple build script using apache tar.gz from the 3thrdparty directory
#
# See http://sourceforge.net/projects/mod-qos/ for further
# details about mod_qos.
#
# Copyright (C) 2007 Pascal Buchbinder
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
APACHE_VER=2.2.6

echo "build Apache $APACHE_VER"
if [ ! -d httpd-${APACHE_VER} ]; then
    gzip -c -d $TOP/3thrdparty/httpd-${APACHE_VER}.tar.gz | tar xf -
fi
rm -f httpd
ln -s httpd-${APACHE_VER} httpd

rm -rf httpd/modules/qos
mkdir -p httpd/modules/qos
ln -s `pwd`/httpd_src/modules/qos/mod_qos.c httpd/modules/qos
ln -s `pwd`/httpd_src/modules/qos/config.m4 httpd/modules/qos
ln -s `pwd`/httpd_src/modules/qos/Makefile.in httpd/modules/qos

CFLAGS="-DDEFAULT_SERVER_LIMIT=512 -DDEFAULT_THREAD_LIMIT=256 -DQS_SIM_IP -g"
export CFLAGS 

cd httpd
./buildconf
#./configure --enable-so --enable-qos=shared --enable-proxy=shared --enable-ssl --enable-status=shared
./configure --with-mpm=worker --enable-so --enable-qos=shared --enable-proxy=shared --enable-ssl --enable-status=shared
make
strip modules/qos/.libs/mod_qos.so
cd ..

cd tools
make
cd ..

echo "END"
