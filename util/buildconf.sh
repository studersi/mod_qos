#!/bin/bash

cd `dirname $0`

# input:
# Makefile.am src/Makefile.am
# autoscan has created configure.ac

echo "create aclocal.m4"
aclocal

echo "create config.h.in"
autoheader

echo "create Makefile.in"
automake -ac

echo "create configure"
autoconf

# test
#DES=../_u
#rm -rf $DES
#mkdir -p ${DES}/src
#cp Makefile.in ${DES}/
#cp src/Makefile.in ${DES}/src/
#cp Makefile.am ${DES}/
#cp src/Makefile.am ${DES}/src/
#cp configure ${DES}/
#cp configure.ac ${DES}/
#cp config.h.in ${DES}/
#cp install-sh ${DES}/
#cp missing ${DES}/
#cp depcomp ${DES}/
#cp src/*.c ${DES}/src/
#cp src/*.h ${DES}/src/
#cd $DES
#./configure
#make
