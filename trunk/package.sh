#!/bin/sh
#
# $Header: /home/cvs/m/mo/mod-qos/src/package.sh,v 2.12 2007-12-18 19:58:44 pbuchbinder Exp $
#
# Script to build file release
#
# ./doc
# contains the index.html/readme about mod_qos
# ./apache
# contains the source code
# ./tools
# supplemental code
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
VERSION=`grep mod_qos.c,v httpd_src/modules/qos/mod_qos.c | awk '{print $8}'`
echo "build mod_dos version $VERSION distribution package"

TAGV=`echo $VERSION | awk -F'.' '{print "REL_" $1 "_" $2}'`
echo "check release tag $TAGV ..."
if [ "`cvs -q diff -r $TAGV 2>&1`" = "" ]; then
    echo ok
else
    echo "FAILED"
    exit 1
fi
if [ `grep -c "Version $VERSION" doc/CHANGES.txt` -eq 0 ]; then
    echo "CHANGES.txt check FAILED"
    exit 1
fi

rm -rf mod_qos-${VERSION}*
mkdir -p mod_qos-${VERSION}/doc
mkdir -p mod_qos-${VERSION}/apache2
mkdir -p mod_qos-${VERSION}/tools
mkdir -p mod_qos-${VERSION}/tools/qsfilter

echo "install documentation"
cp doc/README.TXT mod_qos-${VERSION}
cp doc/LICENSE.txt mod_qos-${VERSION}/doc
cp doc/CHANGES.txt mod_qos-${VERSION}/doc
sed <doc/index.html >mod_qos-${VERSION}/doc/index.html -e "s/4.15/${VERSION}/g"
cp doc/mod_qos_s.gif mod_qos-${VERSION}/doc
cp doc/favicon.ico mod_qos-${VERSION}/doc

echo "install source"
cp httpd_src/modules/qos/mod_qos.c mod_qos-${VERSION}/apache2
cp httpd_src/modules/qos/config.m4 mod_qos-${VERSION}/apache2
cp httpd_src/modules/qos/Makefile.in mod_qos-${VERSION}/apache2

echo "tools"
cp tools/qs_util.h mod_qos-${VERSION}/tools
cp tools/qs_util.c mod_qos-${VERSION}/tools
cp tools/qslog.c mod_qos-${VERSION}/tools
cp tools/qscheck.c mod_qos-${VERSION}/tools
cp tools/Makefile mod_qos-${VERSION}/tools
cp tools/filter/qsfilter2.c mod_qos-${VERSION}/tools/qsfilter
cp tools/filter/Makefile mod_qos-${VERSION}/tools/qsfilter

echo "package: mod_qos-${VERSION}-src.tar.gz"
tar cf mod_qos-${VERSION}-src.tar --owner root --group bin mod_qos-${VERSION}
gzip mod_qos-${VERSION}-src.tar
rm -r mod_qos-${VERSION}

echo "END"
