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
OUTF="$OUTDIR/regression.out"
LRMADMIN="../admin/lrmadmin"
LRMD_OPTS="-r -vvv"
DIFF_OPTS="--ignore-all-space -U 1"
export OUTDIR TESTDIR LRMADMIN DIFF_OPTS

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
cp_Dummylsb() {
	if [ ! -e /etc/init.d/Dummy-lsb ]; then
		cp -p Dummy-lsb /etc/init.d
		Dummylsb=1
	fi
}
rm_Dummylsb() {
	if [ "$Dummylsb" ]; then
		rm -f /etc/init.d/Dummy-lsb
	fi
}

cp_Dummylsb
start_lrmd || exit $?
trap "stop_lrmd; rm_Dummylsb" EXIT

[ "$1" = prepare ] && { export prepare=1; shift 1;}

if [ "$1" -a -f "$TESTDIR/$1" ]; then
	./evaltest.sh $1
else
	echo "$1" | grep -q "^set:" &&
		TESTSET=$TESTDIR/`echo $1 | sed 's/set://'`
	while read testcase; do
		./evaltest.sh $testcase
	done < $TESTSET
fi

if test -s $OUTF; then
	echo "seems like some tests failed or else something not expected"
	echo "check $OUTF and diff files in $OUTDIR"
	exit 1
else
	rm -f $OUTF $LRMD_OUTF
fi >/dev/tty
