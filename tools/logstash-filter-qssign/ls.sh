#!/bin/sh

find . -type f | grep -v -e CVS -e "~" -e ls.sh -e "#" | awk '{print substr($0,3)}'
