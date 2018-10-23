#!/bin/sh
# -*-mode: ksh; ksh-indent: 2; -*-
#
# $Header$
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
# See http://mod-qos.sourceforge.net/ for further
# details about mod_qos.
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
SREV=`svn ls -v ^/tags | grep ${TAGV}/ | awk '{print $1}'`
echo "revision: $SREV"
if [ -z "$SREV" ]; then
    echo "FAILED - revision does not exist"
fi
if [ -z "`svn diff -r $SREV 2>&1`" ]; then
  echo ok
else
  echo "FAILED - open changes"
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
if [ $? -ne 0 ]; then
    echo "WARNING: failed to create man pages"
    exit 1
fi
rm -rf mod_qos-${VERSION}*
mkdir -p mod_qos-${VERSION}/doc/images
mkdir -p mod_qos-${VERSION}/apache2
mkdir -p mod_qos-${VERSION}/tools/src
mkdir -p mod_qos-${VERSION}/tools/man1

echo "install documentation"
./docs.sh
cp doc/README.TXT mod_qos-${VERSION}
cp doc/LICENSE.txt mod_qos-${VERSION}/doc
cp doc/CHANGES.txt mod_qos-${VERSION}/doc
cp doc/glossary.html mod_qos-${VERSION}/doc
sed <doc/index.html >mod_qos-${VERSION}/doc/index.html \
 -e "s/0\.00/${VERSION}/g"
cp doc/images/mod_qos.gif mod_qos-${VERSION}/doc/images/
cp doc/images/directive_seq.gif mod_qos-${VERSION}/doc/images/
cp doc/images/ClientPrefer.png mod_qos-${VERSION}/doc/images/
cp doc/images/SrvMinDataRate.png mod_qos-${VERSION}/doc/images/
cp doc/images/LimitCount.png mod_qos-${VERSION}/doc/images/
cp doc/images/LimitCountExample.png mod_qos-${VERSION}/doc/images/
cp doc/images/ClosedLoop.png mod_qos-${VERSION}/doc/images/
cp doc/images/Serialization.png mod_qos-${VERSION}/doc/images/
cp doc/images/Events.png mod_qos-${VERSION}/doc/images/
cp doc/images/Rule.png mod_qos-${VERSION}/doc/images/
cp doc/images/QS_ClientEventBlockCount.png mod_qos-${VERSION}/doc/images/
cp doc/images/qslog_spreadsheet_example.png mod_qos-${VERSION}/doc/images/
cp doc/images/qsloc.png mod_qos-${VERSION}/doc/images/
cp doc/images/qslogFormat.png mod_qos-${VERSION}/doc/images/
cp doc/images/qsloc1.png mod_qos-${VERSION}/doc/images/
cp doc/images/qsloc2.png mod_qos-${VERSION}/doc/images/
cp doc/images/qsloc3.png mod_qos-${VERSION}/doc/images/
cp doc/images/UserTracking.png mod_qos-${VERSION}/doc/images/
cp doc/images/download.jpg mod_qos-${VERSION}/doc/images/
cp doc/favicon.ico mod_qos-${VERSION}/doc/
cp doc/*.1.html mod_qos-${VERSION}/doc/
cp doc/qsfilter2_process.gif mod_qos-${VERSION}/doc/
echo "mod_qos version $VERSION" > mod_qos-${VERSION}/doc/MESSAGES.txt
cat doc/MESSAGES.txt >> mod_qos-${VERSION}/doc/MESSAGES.txt
cp doc/images/link.png mod_qos-${VERSION}/doc/images/link.png

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
if [ -f test/mod_qos.1 ]; then
    cp test/mod_qos.1 ${DES}/man1/
else
    echo "FAILED, module's man page is missing"
    exit 1
fi
if [ -f test/headerfilterrules.txt ]; then
    if [ `grep -c "mod_qos $VERSION" test/headerfilterrules.txt` -eq 0 ]; then
	echo "version check for headerfilterrules FAILED"
	exit 1
    fi
    cp test/headerfilterrules.txt mod_qos-${VERSION}/doc
    cp test/headerfilterrules.txt doc/
else
    echo "FAILED, header filter rule list is missing"
    exit 1
fi

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
