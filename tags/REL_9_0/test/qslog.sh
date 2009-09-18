#!/bin/sh
#
# $Id: qslog.sh,v 2.1 2009-07-31 21:49:48 pbuchbinder Exp $
#
# used by qslog.htt

case "$1" in
    count)
      LINES=`cat qs.log* | wc -l`
      FILES=`ls -1 qs.log* | wc -l`
      echo "$LINES $FILES"
    ;;
    run)
      ./htt.sh scripts/_qslog.htt 2>&1 | ../tools/qsrotate -o qs.log -s 5
    ;;
    *)
      echo "Usage: `basename $0` run|count"
      exit 1
    ;;
esac

exit 0
