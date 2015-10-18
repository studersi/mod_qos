#!/bin/sh
# -*-mode: ksh; ksh-indent: 2; -*-
#
# $Header: /home/cvs/m/mo/mod-qos/src/build24.sh,v 1.13 2015-10-18 15:13:00 pbuchbinder Exp $
#
# Simple Apache 2.4 build script.
#

TOP=`pwd`

APACHE_VER=2.4.17
MPM=event
#MPM=worker

echo "build Apache $APACHE_VER"
if [ -d httpd-${APACHE_VER}-${MPM} ]; then
    rm -rf httpd-${APACHE_VER}-${MPM}
fi
gzip -c -d $TOP/3thrdparty/httpd-${APACHE_VER}.tar.gz | tar xf -
rm -f httpd
mv httpd-${APACHE_VER} httpd-${APACHE_VER}-${MPM}
ln -s httpd-${APACHE_VER}-${MPM} httpd

if [ ! -d ../apr ]; then
    cd ..
    svn co http://svn.apache.org/repos/asf/apr/apr/trunk apr
    cd apr
    ./buildconf
    ./configure
    make
    cd $TOP
fi

rm -rf httpd/modules/qos
mkdir -p httpd/modules/qos
ln -s `pwd`/httpd_src/modules/qos/mod_qos.c httpd/modules/qos
ln -s `pwd`/httpd_src/modules/qos/mod_qos.h httpd/modules/qos
ln -s `pwd`/httpd_src/modules/qos/config.m4 httpd/modules/qos
ln -s `pwd`/httpd_src/modules/qos/Makefile.in httpd/modules/qos
rm -rf httpd/modules/qtest
mkdir -p httpd/modules/qtest
ln -s `pwd`/httpd_src/modules/qtest/mod_qtest.c httpd/modules/qtest
ln -s `pwd`/httpd_src/modules/qtest/config.m4 httpd/modules/qtest
ln -s `pwd`/httpd_src/modules/qtest/Makefile.in httpd/modules/qtest

CFLAGS="-DDEFAULT_SERVER_LIMIT=512 -DDEFAULT_THREAD_LIMIT=256 -DQS_INTERNAL_TEST -g -Wall"
export CFLAGS

cd httpd

./configure --with-apr=`pwd`/../../apr --with-mpm=${MPM} --enable-modules=all --enable-mods-static=all --with-module=qos:qos
#./configure --with-apr=`pwd`/../../apr --with-mpm=${MPM} --enable-modules=all --enable-mods-static=all --with-module=qos:qos --enable-http2 --with-nghttp2=$TOP/../nghttp2-1.3.4/

if [ $? -ne 0 ]; then
  echo "ERROR"
  exit 1
fi

make
if [ $? -ne 0 ]; then
  echo "ERROR"
  exit 1
fi
cd ..

echo "END"
