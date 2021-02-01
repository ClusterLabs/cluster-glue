#!/bin/sh
TAG=${1:-HEAD}
if test -d .git &&
	D=$( git describe --abbrev=12 --long --tags --match glue-\* $TAG )
then
	if [ "$TAG" = "HEAD" ]; then
		LATEST_DIRTY_TS=$(git diff --name-only $TAG | xargs -r stat -c %Y | sort -nr | head -n1)
		if test -n "$LATEST_DIRTY_TS" ; then
			LATEST_DIRTY_YMDHMS=$(date "+%Y%m%d%H%M%S" -d @$LATEST_DIRTY_TS)
			D=$D+$LATEST_DIRTY_YMDHMS
		fi
	fi
	echo "${D#glue-}"
elif test -s .tarball-version; then
	head -n1 .tarball-version
else
	echo "unknown"
	exit 1
fi
