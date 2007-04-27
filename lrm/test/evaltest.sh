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

#
# special operations squad
#
specopt_setenv() {
	eval $rest
}
specopt_sleep() {
	#sleep $rest
	# the while loop below is the same
	# but we give user some feedback on what's happening
	while [ "$rest" -gt 0 ]; do
		sleep 1
		echo -n "+" >/dev/tty
		rest=$((rest-1))
	done
}
specopt_extcheck() {
	extcheck="$rest"
	set $extcheck
	[ -x "$1" ] ||  # a program in the PATH
		extcheck="$TESTDIR/$extcheck"  # or our script
}
specopt_bg() {
	if [ "$bgprocs_num" -eq 0 ]; then
		bgprocs_num=${rest:-1}
	else
		echo ".BG bad usage: more tests yet to be backgrounded"
	fi
}
specopt() {
	cmd=`echo $cmd | sed 's/%//'`  # strip leading '%'
	echo ".`echo $cmd | tr [a-z] [A-Z]` $rest"  # show what we got
	specopt_$cmd  # do what they asked for
}

#
# wait for background processes to finish
# and print their output
# NB: We wait for processes in a FIFO order
#     The order in which they finish does not matter
#
waitforbgprocs() {
	while [ "$bgprocs" ]; do
		set $bgprocs
		proc=$1  # get the first one
		pid=`echo $proc | sed 's/.*://'`
		testline=`echo $proc | sed 's/:.*//'`

		while kill -0 $pid 2>/dev/null; do
			sleep 1
		done
		wait $pid # capture the exit code

		echo ".BG test line $testline finished (exit code: $?):"
		echo "==========test:$testline start output=========="
		cat $outf-$testline
		echo "==========test:$testline   end output=========="
		rm -f $outf-$testline

		shift 1  # remove the first one from the list
		bgprocs="$@"
	done
}

dotest() {
	echo -n "." >/dev/tty
	eval $rest  # set parameters
	describe_$cmd  # show what we are about to do
	lrm_$cmd |  # and execute the command
		{ [ "$extcheck" ] && $extcheck || cat;}
}

#
# run the tests
#
bgprocs_num=0
line=1
{
while read cmd rest; do
	case "$cmd" in
		"") : empty ;;
		"#"*) : a comment ;;
		"%stop") break ;;
		"%"*) specopt ;;
		*)
			if [ "$bgprocs_num" -gt 0 ]; then
				echo .BG test line $line runs in background
				dotest $line > $outf-$line 2>&1 &
				bgprocs="$bgprocs $line:$!"
				bgprocs_num=$((bgprocs_num-1))
			else
				dotest $line
			fi
			resetvars  # unset all variables
		;;
	esac
	line=$((line+1))
done < $TESTDIR/$testcase
waitforbgprocs
} > $outf 2>&1

filter_output() {
	{ [ -x $common_filter ] && $common_filter || cat;} |
	{ [ -f $common_exclf ] && egrep -vf $common_exclf || cat;} |
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
# check the output
#
echo -n " checking..." >/dev/tty
filter_output < $outf |
	diff $DIFF_OPTS - $expf > $difff

#
# report if necessary
#
if [ $? -ne 0 ]; then
	echo " FAIL" >/dev/tty
	dumpcase
	exit 1
fi

echo " PASS" >/dev/tty
rm -f $outf $difff
