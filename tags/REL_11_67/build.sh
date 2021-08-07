#!/bin/sh
# -*-mode: ksh; ksh-indent: 2; -*-
#
# $Header$
#
# Simple build script using Apache tar.gz from the 3thrdparty directory
#
# See http://mod-qos.sourceforge.net/ for further
# details about mod_qos.
#

TOP=`pwd`

#APACHE_VER=2.0.59
APACHE_VER=2.2.34
MPM=worker
#MPM=prefork
#MPM=event

echo "build Apache $APACHE_VER ($MPM)"

rm -f httpd
rm -rf httpd-${APACHE_VER}-${MPM}
rm -rf httpd-${APACHE_VER}

gzip -c -d $TOP/3thrdparty/httpd-${APACHE_VER}.tar.gz | tar xf -
#    echo "apply security patches"
#    for E in `(cd 3thrdparty/patch22/; find . -name "*patch")`; do
#	srcFile=`echo $E | sed "s/.patch//"`
#	patch httpd-${APACHE_VER}/$srcFile  3thrdparty/patch22/$E 
#    done

mv httpd-${APACHE_VER} httpd-${APACHE_VER}-${MPM}
ln -s httpd-${APACHE_VER}-${MPM} httpd

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
mkdir -p httpd/modules/qtest
ln -s `pwd`/httpd_src/modules/qtest/mod_qtest.c httpd/modules/qtest
ln -s `pwd`/httpd_src/modules/qtest/config.m4 httpd/modules/qtest
ln -s `pwd`/httpd_src/modules/qtest/Makefile.in httpd/modules/qtest

ADDMOD=""
if [ "$1" = "release" ]; then
  echo "release binary"
  CFLAGS="-DDEFAULT_SERVER_LIMIT=512 -DDEFAULT_THREAD_LIMIT=256 -DQS_REQ_RATE_TM=10 -DI_INSIST_ON_EXTRA_CYCLES_FOR_CLF_COMPLIANCE"
  export CFLAGS 
  ADDMOD="--prefix=/var/tmp/apache"
else
  CFLAGS="-DDEFAULT_SERVER_LIMIT=512 -DDEFAULT_THREAD_LIMIT=256 -DQS_INTERNAL_TEST -g -Wall -DI_INSIST_ON_EXTRA_CYCLES_FOR_CLF_COMPLIANCE -DQOS_TEST_MOD"
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

#if [ `echo $APACHE_VER | awk '{print substr($0, 1, 3)}'` = "2.2" ]; then
  ./configure --with-mpm=${MPM} --enable-so --enable-qos=shared --enable-qtest=shared --enable-proxy=shared --enable-cache=shared --enable-mem_cache=shared --enable-ssl --enable-status=shared --enable-info=shared --enable-static-support --enable-unique-id=shared --enable-logio=shared --enable-dumpio=shared --enable-logio=shared --enable-deflate --enable-reqtimeout=shared --enable-rewrite=shared $ADDMOD
  RC=$?
#else
#  ./configure --with-mpm=${MPM} --enable-so --enable-qos=shared --enable-qtest=shared --enable-proxy=shared --enable-ssl --enable-status=shared --enable-info=shared --enable-static-support --enable-unique-id=shared --enable-logio=shared --enable-dumpio=shared --enable-deflate $ADDMOD
#  RC=$?
#fi
if [ $RC -ne 0 ]; then
  echo "ERROR"
  exit 1
fi

# patch (static linking) ...
sed <build/rules.mk > build/rules.mk.2 \
 -e "s;LINK     = \$(LIBTOOL) --mode=link \$(CC) \$(ALL_CFLAGS)  \$(LT_LDFLAGS);LINK     = \$(LIBTOOL) --mode=link \$(CC) \$(ALL_CFLAGS) -static \$(LT_LDFLAGS);g"
mv build/rules.mk.2 build/rules.mk

#cd modules/ssl
#perl ssl_engine_dh.c
#cd ../..

make
if [ $? -ne 0 ]; then
  echo "ERROR"
  exit 1
fi
make install

if [ "$1" = "release" ]; then
  strip modules/qos/.libs/mod_qos.so
  if [ $? -ne 0 ]; then
    echo "ERROR"
    exit 1
  fi
fi
cd ..

mkdir -p mod-websocket
cd mod-websocket
tar xfz ../3thrdparty/apache-websocket.tgz
rm -f mod_websocket_mirror.c
ln -s ../3thrdparty/mod_websocket_mirror.c .
/var/tmp/apache/bin/apxs -c mod_websocket.c
/var/tmp/apache/bin/apxs -c mod_websocket_echo.c
/var/tmp/apache/bin/apxs -c mod_websocket_mirror.c
cd ..

cd util
./buildconf.sh
./configure
make
cd ..

echo "END"

