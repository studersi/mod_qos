#!/bin/sh

echo "/aaa/index.do" > access_log
echo "/aaa/image/1.jpg" >> access_log
echo "/aaa/view?page=1" >> access_log
echo "/aaa/edit?document=1" >> access_log
echo "/aaa/edit?image=1.jpg" >> access_log

../../util/src/qsfilter2 -i access_log $@

rm access_log
