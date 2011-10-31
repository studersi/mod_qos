#!/bin/sh
# -*-mode: ksh; ksh-indent: 2; -*-
#
# $Header: /home/cvs/m/mo/mod-qos/src/man.sh,v 2.1 2011-10-31 20:50:18 pbuchbinder Exp $
#

set -e
set -x

cd util/src
rm -rf ../man1
mkdir -p ../man1
make clean
make
tools="qsexec qsfilter2 qsgrep qslog qspng qsrotate qssign qstail"
for t in $tools; do
    ./$t --man > ../man1/${t}.1
done

