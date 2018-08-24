#!/bin/sh

if [ `./duration duration.log '^[0-9_:.,-]+[_ -]([0-9:]+)[.,]([0-9]{3}) ([a-z0-9]+) [A-Z]+ Received HTTPRequest' '^[0-9_:.,-]+[_ -]([0-9:]+)[.,]([0-9]{3}) ([a-z0-9]+) [A-Z]+ .*Received response' | grep -c -e 138 -e 61238 -e 48311 -e 13989` -ne 4 ]; then
    echo "FAILED"
    exit 1
fi
echo "OK"
exit 0
