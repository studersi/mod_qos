#!/bin/sh
# -*-mode: ksh; ksh-indent: 2; -*-
#
# $Header$
#
# Simple Apache 2.4 build script.
#

TOP=`pwd`

APACHE_VER=2.4.50
#MPM=event
MPM=worker
#MPM=prefork

echo "build Apache $APACHE_VER"
if [ -d httpd-${APACHE_VER}-${MPM} ]; then
    rm -rf httpd-${APACHE_VER}-${MPM}
fi
gzip -c -d $TOP/3thrdparty/httpd-${APACHE_VER}.tar.gz | tar xf -
rm -f httpd
rm -rf httpd-${APACHE_VER}-${MPM}
mv httpd-${APACHE_VER} httpd-${APACHE_VER}-${MPM}
ln -s httpd-${APACHE_VER}-${MPM} httpd

cd httpd/srclib
gzip -c -d $TOP/3thrdparty/apr-1.7.0.tar.gz | tar xf -
mv apr-1.7.0 apr
gzip -c -d $TOP/3thrdparty/apr-util-1.6.1.tar.gz | tar xf -
mv apr-util-1.6.1 apr-util
cd ../..

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

CFLAGS="-DDEFAULT_SERVER_LIMIT=512 -DDEFAULT_THREAD_LIMIT=256 -DQS_INTERNAL_TEST -g -Wall -O0"
export CFLAGS

cd httpd

prefix=$TOP/install
mkdir -p $prefix
#./configure --prefix=$prefix --with-apr=`pwd`/../../apr --with-mpm=${MPM} --enable-modules=all --enable-mods-static=all --with-module=qos:qos --enable-http2 --with-nghttp2=${TOP}/../nghttp2-1.10.0/ --with-ssl=${TOP}/../../openssl/
./configure --prefix=$prefix --with-included-apr --with-mpm=${MPM} --enable-modules=all --enable-mods-static=all --with-module=qos:qos --enable-http2

if [ $? -ne 0 ]; then
  echo "ERROR"
  exit 1
fi

make
if [ $? -ne 0 ]; then
  echo "ERROR"
  exit 1
fi
make install
cd ..

cp ../setenvifplus/httpd_src/modules/metadataplus/mod_setenvifplus.c install/modules
./install/bin/apxs -c ./install/modules/mod_setenvifplus.c

cp ../parp/httpd_src/modules/parp/mod_parp.c install/modules
cp ../parp/httpd_src/modules/parp/mod_parp.h install/modules
./install/bin/apxs -c ./install/modules/mod_parp.c

cp httpd_src/modules/qtest/mod_qtest.c install/modules
./install/bin/apxs -DQOS_TEST_MOD -c ./install/modules/mod_qtest.c

echo "END"
