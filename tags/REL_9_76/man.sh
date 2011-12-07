#!/bin/sh
# -*-mode: ksh; ksh-indent: 2; -*-
#
# $Header: /home/cvs/m/mo/mod-qos/src/man.sh,v 2.3 2011-11-30 19:25:20 pbuchbinder Exp $
#

set -e
set -u

PATH=/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

cd util/src
rm -rf ../man1
mkdir -p ../man1
make clean 1>/dev/null
make 2>/dev/null 1>/dev/null

tools="qsexec qsfilter2 qsgrep qslog qspng qsrotate qssign qstail"

for t in $tools; do
  echo "./$t --man"
  ./$t --man > ../man1/${t}.1
  man2html -r ../man1/${t}.1 | grep -v "Content-type: text/html" | \
   grep -v "cgi-bin/man/man2html" | \
   grep -v "using the manual pages" | \
   grep -v "Time: " | \
   sed -e "s:../man1/::g" \
       -e "s:../index.html:index.html#utilities:g" \
       -e "s:This document was created by:<img align=\"right\" border=\"0\" src=\"nevis.gif\"/>:g" \
   > ../../doc/${t}.1.html
done

# insert process image
sed -i "s:<H2>DESCRIPTION</H2>:<H2>DESCRIPTION</H2><p><img src=\"qsfilter2_process.gif\" alt=\"overview\"></p>:g" ../../doc/qsfilter2.1.html
