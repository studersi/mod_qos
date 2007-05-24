#!/bin/sh
#
# $Header: /home/cvs/m/mo/mod-qos/src/package.sh,v 1.2 2007-05-24 20:15:40 pbuchbinder Exp $
#
# Script to build file release
#
# ./doc
# contains the index.html/readme about mod_qos
# ./apache
# contains the source code
#

TOP=`pwd`
VERSION=`grep mod_qos.c,v httpd_src/modules/qos/mod_qos.c | awk '{print $8}'`
echo "build version $VERSION"

rm -rf mod_qos-${VERSION}*
mkdir -p mod_qos-${VERSION}/doc
mkdir -p mod_qos-${VERSION}/apache2

echo "install documentation"
cp doc/README.TXT mod_qos-${VERSION}
cp doc/index.html mod_qos-${VERSION}/doc
cp doc/mod_qos_s.gif mod_qos-${VERSION}/doc

echo "install source"
cp httpd_src/modules/qos/mod_qos.c mod_qos-${VERSION}/apache2
cp httpd_src/modules/qos/config.m4 mod_qos-${VERSION}/apache2
cp httpd_src/modules/qos/Makefile.in mod_qos-${VERSION}/apache2

echo "package"
tar cf mod_qos-${VERSION}.tar mod_qos-${VERSION}
gzip mod_qos-${VERSION}.tar
rm -r mod_qos-${VERSION}

echo "END"
