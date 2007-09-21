#!/bin/sh

rm -f mod_qos_bin.tar.gz

cd $1
tar cvf ../mod_qos-${1}-bin.tar --owner root --group bin .
gzip ../mod_qos-${1}-bin.tar

