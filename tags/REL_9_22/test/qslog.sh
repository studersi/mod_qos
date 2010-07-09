#!/bin/sh
#
# $Id: qslog.sh,v 2.2 2010-06-23 18:54:16 pbuchbinder Exp $
#
# used by qslog.htt

case "$1" in
    count)
      LINES=`cat qs.log* | wc -l`
      FILES=`ls -1 qs.log* | wc -l`
      echo "$LINES $FILES"
    ;;
    run)
      ./run.sh scripts/_qslog.htt 2>&1 | ../tools/qsrotate -o qs.log -s 5
    ;;
    *)
      echo "Usage: `basename $0` run|count"
      exit 1
    ;;
esac

exit 0
