#!/bin/sh

echo "/app/this/cont?n=1&v=2" >> access_log
echo "/app/this/cont?v=1&n=2" >> access_log
echo "/app/this/sep?v=1&n=2" >> access_log
echo "/app/this/sep?v&n=1" >> access_log
echo "/app/this/sep?v=&n=1" >> access_log
echo "/app/this/sep?v=a&n=1" >> access_log
echo "/app/this/sep?n=1" >> access_log
echo "/app/this/sep?n=1&" >> access_log

./qsfilter2 -i access_log -m $@

rm access_log
