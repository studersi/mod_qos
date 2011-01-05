#!/bin/bash

cd `dirname $0`
if [ ! -f ltmain.sh ]; then
    if [ -f /usr/share/libtool/config/ltmain.sh ]; then
	ln -s /usr/share/libtool/config/ltmain.sh .
    fi
fi

echo aclocal
aclocal
echo autoconf
autoconf
echo autoheader
autoheader
echo automake -i -f -a
automake -i -f -a
