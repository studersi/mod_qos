#!/bin/sh

find . -type f | grep -v -e CVS -e "~" -e ls.sh -e "#" -e install.sh | awk '{print substr($0,3)}'
