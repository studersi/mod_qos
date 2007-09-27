#!/bin/sh


echo -e "/webapp/test\n/webapp/mo^\"'re?name=value\n/webapp/sp;v1.1%20?show_all" | ./qsfilter $@

