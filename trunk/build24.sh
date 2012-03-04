#!/bin/sh
# -*-mode: ksh; ksh-indent: 2; -*-
#
# $Header: /home/cvs/m/mo/mod-qos/src/build24.sh,v 1.1 2012-03-04 22:06:10 pbuchbinder Exp $
#
# Simple build script using Apache 2.4
#


TOP=`pwd`

APACHE_VER=2.4.1

echo "build Apache $APACHE_VER"
if [ ! -d httpd-${APACHE_VER} ]; then
  gzip -c -d $TOP/3thrdparty/httpd-${APACHE_VER}.tar.gz | tar xf -
fi
rm -f httpd
mv httpd-${APACHE_VER} httpd-${APACHE_VER}
ln -s httpd-${APACHE_VER} httpd

#cd ..
#svn co http://svn.apache.org/repos/asf/apr/apr/trunk apr
#cd apr
#./configure
#make
#cd $TOP

cd httpd

./configure --with-apr=`pwd`/../../apr
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
