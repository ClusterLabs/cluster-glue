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

setenvironment() {
	common_filter=$TESTDIR/common.filter
	common_exclf=$TESTDIR/common.excl
	filterf=$TESTDIR/$testcase.filter
	exclf=$TESTDIR/$testcase.excl
	expf=$TESTDIR/$testcase.exp
	outf=$OUTDIR/$testcase.out
	difff=$OUTDIR/$testcase.diff
}

testcase=$1
test -f $TESTDIR/$testcase || {
	echo "no such testcase: $TESTDIR/$testcase; please fix me"
	exit 2
}
setenvironment

. ./defaults
. ./lrmadmin-interface
. ./descriptions

echo -n "$testcase" >/dev/tty

resetvars() {
	unset rsc type class provider timeout interval targetrc args
	unset extcheck
}
specopt() {
	case "$cmd" in
		"%setenv")
			echo ".SETENV $rest"
			eval $rest
		;;
		"%extcheck")
			echo ".EXTCHECK $rest"
			extcheck="$rest"
			set $extcheck
			[ -x "$1" ] || extcheck="$TESTDIR/$extcheck"
		;;
	esac
}
dotest() {
	echo -n "." >/dev/tty
	eval $rest
	describe_$cmd
	lrm_$cmd |
		{ [ "$extcheck" ] && $extcheck || cat;}
}

#
# run the tests
#
while read cmd rest; do
	case "$cmd" in
		"#"*) : a comment ;;
		"%stop") break ;;
		"%"*) specopt ;;
		*) dotest; resetvars ;;
	esac
done < $TESTDIR/$testcase > $outf 2>&1

filter_output() {
	{ [ -x $common_filter ] && $common_filter || cat;} |
	{ [ -x $common_exclf ] && egrep -vf $common_exclf || cat;} |
	{ [ -x $filterf ] && $filterf || cat;} |
	{ [ -f $exclf ] && egrep -vf $exclf || cat;}
}

if [ "$prepare" ]; then
	#
	# prepare the expect file and exit
	#
	echo " saving to expect file" >/dev/tty
	filter_output < $outf > $expf
	exit
fi

#
# check the output
#
echo -n " checking..." >/dev/tty
filter_output < $outf |
	diff $DIFF_OPTS - $expf > $difff

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

#
# report if necessary
#
if [ $? -ne 0 ]; then
	echo " FAIL" >/dev/tty
	dumpcase
	exit 1
fi

echo " done" >/dev/tty
rm -f $outf $difff
