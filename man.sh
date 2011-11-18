#!/bin/sh
# -*-mode: ksh; ksh-indent: 2; -*-
#
# $Header: /home/cvs/m/mo/mod-qos/src/man.sh,v 2.2 2011-11-18 20:51:18 pbuchbinder Exp $
#

set -e
set -u

cd util/src
rm -rf ../man1
mkdir -p ../man1
make clean 1>/dev/null
make 2>/dev/null 1>/dev/null
tools="qsexec qsfilter2 qsgrep qslog qspng qsrotate qssign qstail"
for t in $tools; do
  echo "./$t --man"
  ./$t --man > ../man1/${t}.1
done

