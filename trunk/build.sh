#!/bin/sh
#
# $Header: /home/cvs/m/mo/mod-qos/src/build.sh,v 1.1 2007-05-20 12:52:50 pbuchbinder Exp $
#
# Simple build script using apache tar.gz from the 3thrdparty directory
#

TOP=`pwd`

APACHE_VER=2.0.59
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

cd httpd
./buildconf
./configure --enable-so --enable-qos=shared
make
cd ..
echo "END"

