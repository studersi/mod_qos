#!/bin/sh
#
# $Header: /home/cvs/m/mo/mod-qos/src/build.sh,v 2.3 2007-07-31 19:57:18 pbuchbinder Exp $
#
# Simple build script using apache tar.gz from the 3thrdparty directory
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

rm -rf httpd/modules/qos
mkdir -p httpd/modules/qos
ln -s `pwd`/httpd_src/modules/qos/mod_qos.c httpd/modules/qos
ln -s `pwd`/httpd_src/modules/qos/config.m4 httpd/modules/qos
ln -s `pwd`/httpd_src/modules/qos/Makefile.in httpd/modules/qos

CFLAGS="-DDEFAULT_SERVER_LIMIT=512 -DDEFAULT_THREAD_LIMIT=256 -g"
export CFLAGS 

cd httpd
./buildconf
./configure --with-mpm=worker --enable-so --enable-qos=shared --enable-proxy=shared --enable-ssl
make
strip modules/qos/.libs/mod_qos.so
cd ..

cd tools
make
cd ..

echo "END"
