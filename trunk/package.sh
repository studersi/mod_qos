#!/bin/sh
# -*-mode: ksh; ksh-indent: 2; -*-
#
# $Header: /home/cvs/m/mo/mod-qos/src/package.sh,v 2.46 2013-01-03 19:41:13 pbuchbinder Exp $
#
# Script to build file release
#
# ./doc
# contains the index.html/readme about mod_qos
# ./apache2
# contains the source code
# ./tools
# supplemental code
#
# See http://opensource.adnovum.ch/mod_qos/ for further
# details about mod_qos.
#
# Copyright (C) 2007-2013 Pascal Buchbinder
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

cd `dirname $0`
TOP=`pwd`
VERSION=`grep "char g_revision" httpd_src/modules/qos/mod_qos.c | awk '{print $6}' | awk -F'"' '{print $2}'`
F_VERSION=`grep "char man_version" util/src/qs_util.h | awk '{print $6}' | awk -F'"' '{print $2}'`
echo "build mod_dos version $VERSION distribution package"
if [ "$VERSION" != "$F_VERSION" ]; then
  echo "FAILED, wrong version!"
  echo " mod_qos: $VERSION"
  exit 1
fi

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
grep \\$\\$\\$ ./httpd_src/modules/qos/*.c
if [ $? -ne 1 ]; then
  WARNINGS=`expr $WARNINGS + 1`
  echo "WARNING: found pattern '\$\$\$' in module"
  exit 1
fi
grep FIXME ./httpd_src/modules/qos/*.c
if [ $? -ne 1 ]; then
  WARNINGS=`expr $WARNINGS + 1`
  echo "WARNING: found pattern 'FIXME' in module"
  exit 1
fi
grep \\$\\$\\$ ./util/src/*.c
if [ $? -ne 1 ]; then
  WARNINGS=`expr $WARNINGS + 1`
  echo "WARNING: found pattern '\$\$\$' in utility"
  exit 1
fi
grep FIXME ./util/src/*.c
if [ $? -ne 1 ]; then
  WARNINGS=`expr $WARNINGS + 1`
  echo "WARNING: found pattern 'FIXME' in utility"
  exit 1
fi

set -e
set -u

echo "update man pages"
./man.sh 1>/dev/null

rm -rf mod_qos-${VERSION}*
mkdir -p mod_qos-${VERSION}/doc
mkdir -p mod_qos-${VERSION}/apache2
mkdir -p mod_qos-${VERSION}/tools/src
mkdir -p mod_qos-${VERSION}/tools/man1
mkdir -p doc/tmp

echo "install documentation"
cp doc/README.TXT mod_qos-${VERSION}
cp doc/LICENSE.txt mod_qos-${VERSION}/doc
cp doc/CHANGES.txt mod_qos-${VERSION}/doc
sed <doc/index.html >mod_qos-${VERSION}/doc/index.html \
 -e "s/0\.00/${VERSION}/g"
sed <mod_qos-${VERSION}/doc/index.html >doc/tmp/index.html \
 -e "s:BUILD START -->::g" \
 -e "s:<!-- BUILD END::g"
cp doc/mod_qos_s.gif mod_qos-${VERSION}/doc/
cp doc/mod_qos_seq.gif mod_qos-${VERSION}/doc/
cp doc/nevis.gif mod_qos-${VERSION}/doc/
cp doc/favicon.ico mod_qos-${VERSION}/doc/
cp doc/*.1.html mod_qos-${VERSION}/doc/
cp doc/qsfilter2_process.gif mod_qos-${VERSION}/doc/

echo "install source"
cp httpd_src/modules/qos/mod_qos.c mod_qos-${VERSION}/apache2
grep -v qos_control httpd_src/modules/qos/config.m4 > mod_qos-${VERSION}/apache2/config.m4
cp httpd_src/modules/qos/Makefile.in mod_qos-${VERSION}/apache2

echo "tools"
DES=mod_qos-${VERSION}/tools
cp util/Makefile.in ${DES}/
cp util/src/Makefile.in ${DES}/src/
cp util/Makefile.am ${DES}/
cp util/src/Makefile.am ${DES}/src/
cp util/configure ${DES}/
cp util/configure.ac ${DES}/
cp util/config.h.in ${DES}/
cp util/install-sh ${DES}/
cp util/missing ${DES}/
cp util/depcomp ${DES}/
cp util/src/*.c ${DES}/src/
cp util/src/*.h ${DES}/src/
cp util/man1/*.1 ${DES}/man1/

## standard distribution
#echo "std package: mod_qos-${VERSION}-src.tar.gz"
#tar cf mod_qos-${VERSION}-src.tar --owner root --group bin mod_qos-${VERSION}
#gzip mod_qos-${VERSION}-src.tar

# extended distribution
echo "package: mod_qos-${VERSION}.tar.gz"
cp httpd_src/modules/qos/mod_qos.h mod_qos-${VERSION}/apache2
tar cf mod_qos-${VERSION}.tar --owner root --group bin mod_qos-${VERSION}
gzip mod_qos-${VERSION}.tar
rm -r mod_qos-${VERSION}

echo "normal end"
