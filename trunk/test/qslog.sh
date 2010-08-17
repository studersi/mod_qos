#!/bin/sh
#
# $Id: qslog.sh,v 2.3 2010-08-17 19:04:00 pbuchbinder Exp $
#
# used by qslog.htt

case "$1" in
    count)
      LINES=`cat qs.log* | wc -l`
      FILES=`ls -1 qs.log* | wc -l`
      echo "$LINES $FILES"
    ;;
    run)
      ./run.sh scripts/_qslog.htt 2>&1 | ../util/src/qsrotate -o qs.log -s 5
    ;;
    *)
      echo "Usage: `basename $0` run|count"
      exit 1
    ;;
esac

exit 0
