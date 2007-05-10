#!/bin/bash

 # Copyright (C) 2007 Dejan Muhamedagic <dmuhamedagic@suse.de>
 # 
 # This program is free software; you can redistribute it and/or
 # modify it under the terms of the GNU General Public
 # License as published by the Free Software Foundation; either
 # version 2.1 of the License, or (at your option) any later version.
 # 
 # This software is distributed in the hope that it will be useful,
 # but WITHOUT ANY WARRANTY; without even the implied warranty of
 # MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 # General Public License for more details.
 # 
 # You should have received a copy of the GNU General Public
 # License along with this library; if not, write to the Free Software
 # Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 #

if [ `id -u` != 0 ]; then
	echo "sorry, but i talk to root only"
	exit 2
fi
if [ "`dirname $0`" != . ]; then
	echo "you have to run me from the directory where i live"
	exit 2
fi

TESTDIR=${TESTDIR:-testcases}
TESTSET=$TESTDIR/basicset
OUTDIR=${OUTDIR:-output}
LRMD_OUTF="$OUTDIR/lrmd.out"
LRMD_LOGF="$OUTDIR/lrmd.log"
LRMD_DEBUGF="$OUTDIR/lrmd.debug"
OUTF="$OUTDIR/regression.out"
LRMADMIN="../admin/lrmadmin"
LRMD_OPTS="-r -vvv"
DIFF_OPTS="--ignore-all-space -U 1"
common_filter=$TESTDIR/common.filter
common_exclf=$TESTDIR/common.excl
export OUTDIR TESTDIR LRMADMIN
rm -f $LRMD_LOGF $LRMD_DEBUGF

abspath() {
	echo $1 | grep -qs "^/" &&
		echo $1 ||
		echo `pwd`/$1
}

# make lrmd log to our files only
HA_logfile=`abspath $LRMD_LOGF`
HA_debugfile=`abspath $LRMD_DEBUGF`
HA_use_logd=no
HA_logfacility=""
export HA_logfile HA_debugfile HA_use_logd HA_logfacility

exec >$OUTF 2>&1
. /etc/ha.d/shellfuncs
mkdir -p $OUTDIR

start_lrmd() {
	echo "starting lrmd" >/dev/tty
	$HA_BIN/lrmd -s 2>/dev/null
	if [ $? -eq 3 ]; then
		$HA_BIN/lrmd $LRMD_OPTS >$LRMD_OUTF 2>&1 &
		sleep 1
		$HA_BIN/lrmd -s 2>/dev/null
	else
		echo "lrmd already running; can't proceed" >/dev/tty
		return 2
	fi
}
stop_lrmd() {
	echo "stopping lrmd" >/dev/tty
	$HA_BIN/lrmd -k
}
cp_ra() {
	if [ ! -e /usr/lib/ocf/resource.d/heartbeat/lrmregtest ]; then
		cp -p lrmregtest /usr/lib/ocf/resource.d/heartbeat
		lrmregtest_ocf=1
	fi
	if [ ! -e /etc/init.d/Dummy-lsb ]; then
		cp -p Dummy-lsb /etc/init.d
		Dummy_lsb=1
	fi
}
rm_ra() {
	[ "$lrmregtest_ocf" ] &&
		rm -f /usr/lib/ocf/resource.d/heartbeat/lrmregtest
	[ "$Dummy_lsb" ] && rm -f /etc/init.d/Dummy-lsb
}

cp_ra
start_lrmd || exit $?
trap "stop_lrmd; rm_ra" EXIT

[ "$1" = prepare ] && { prepare=1; shift 1;}

setenvironment() {
	filterf=$TESTDIR/$testcase.filter
	exclf=$TESTDIR/$testcase.excl
	expf=$TESTDIR/$testcase.exp
	outf=$OUTDIR/$testcase.out
	difff=$OUTDIR/$testcase.diff
}

filter_output() {
	{ [ -x $common_filter ] && $common_filter || cat;} |
	{ [ -f $common_exclf ] && egrep -vf $common_exclf || cat;} |
	{ [ -x $filterf ] && $filterf || cat;} |
	{ [ -f $exclf ] && egrep -vf $exclf || cat;}
}

dumpcase() {
	cat<<EOF
----------
testcase $testcase failed
output is in $outf
diff (from $difff):
`cat $difff`
----------
EOF
}

runtestcase() {
	setenvironment
	echo -n "$testcase" >/dev/tty
	./evaltest.sh < $TESTDIR/$testcase > $outf 2>&1

	filter_output < $outf |
	if [ "$prepare" ]; then
		echo " saving to expect file" >/dev/tty
		cat > $expf
	else
		echo -n " checking..." >/dev/tty
		diff $DIFF_OPTS $expf - > $difff
		if [ $? -ne 0 ]; then
			echo " FAIL" >/dev/tty
			dumpcase
			return 1
		else
			echo " PASS" >/dev/tty
			rm -f $outf $difff
		fi
	fi
}

if [ "$1" -a -f "$TESTDIR/$1" ]; then
	testcase=$1
	runtestcase
else
	echo "$1" | grep -q "^set:" &&
		TESTSET=$TESTDIR/`echo $1 | sed 's/set://'`
	while read testcase; do
		runtestcase
	done < $TESTSET
fi

if test -s $OUTF; then
	echo "seems like some tests failed or else something not expected"
	echo "check $OUTF and diff files in $OUTDIR"
	echo "in case you wonder what lrmd was doing, read $LRMD_LOGF and $LRMD_DEBUGF"
	exit 1
else
	rm -f $OUTF $LRMD_OUTF
fi >/dev/tty
