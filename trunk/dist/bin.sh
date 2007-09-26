#!/bin/sh

if [ "$1" = "" ]; then
    echo "Usage: `basename $0` <version dir>"
    exit 1
fi
if [ ! -d $1 ]; then
    echo "directory does not exist"
    exit 1
fi

rm -f mod_qos-${1}-bin.tar.gz

cd $1
for E in `find . -name "*.so"`; do
    if [ `strings $E | grep -c "mod_qos TEST"` -ne 0 ]; then
	echo "ERROR, test binary detected: $E"
	exit 1
    fi
    if [ `strings $E | grep -c "QS_EnableInternalIPSimulation"` -ne 0 ]; then
	echo "ERROR, test binary detected: $E"
	exit 1
    fi
done
tar cvf ../mod_qos-${1}-bin.tar --owner root --group bin .
gzip ../mod_qos-${1}-bin.tar

