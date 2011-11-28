#!/bin/sh

 # Copyright (C) 2007 Dejan Muhamedagic <dejan@suse.de>
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

: ${TESTDIR:=testcases}
: ${LRMADMIN:=../admin/lrmadmin}
test -x $LRMADMIN || LRMADMIN=lrmadmin
: ${OCF_ROOT:=/usr/lib/ocf}

. ./defaults
. ./lrmadmin-interface
. ./descriptions

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
		echo -n "+" >&3
		rest=$(($rest-1))
	done
}
specopt_extcheck() {
	extcheck="$rest"
	set $extcheck
	which "$1" >/dev/null 2>&1 ||  # a program in the PATH
		extcheck="$TESTDIR/$extcheck"  # or our script
}
specopt_repeat() {
	repeat_limit=$rest
}
specopt_bg() {
	if [ "$job_cnt" -gt "$bgprocs_num" ]; then
		bgprocs_num=${rest:-1}
		job_cnt=1
	else
		echo ".BG bad usage: more tests yet to be backgrounded"
	fi
}
specopt_bgrepeat() { # common
	specopt_bg
	specopt_repeat
}
specopt_wait() { # common
	waitforbgprocs
}
specopt_shell() { # run command with shell
	echo "$rest" | sh -s |  # and execute the command
		{ [ "$extcheck" ] && $extcheck || cat;}
}
specopt() {
	cmd=`echo $cmd | sed 's/%//'`  # strip leading '%'
	echo ".`echo $cmd | tr '[a-z]' '[A-Z]'` $rest"  # show what we got
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
		shift 1  # remove it from the list
		bgprocs="$@"
		IFS=":"
		set $proc  # split into lineno,pid
		testline=$1 jobnum=$2 pid=$3
		unset IFS

		while kill -0 $pid 2>/dev/null; do
			sleep 1
		done
		wait $pid # capture the exit code

		echo ".BG test line $testline/job $jobnum finished (exit code: $?):"
		echo "==========test:$testline:$jobnum start output=========="
		cat $OUTDIR/bg$$-$testline-$jobnum
		echo "==========test:$testline:$jobnum   end output=========="
		rm -f $OUTDIR/bg$$-$testline-$jobnum
	done
}

#
# substitute variables in the test line
#
substvars() {
	sed "
	s/%t/$test_cnt/g
	s/%l/$line/g
	s/%j/$job_cnt/g
	s/%i/$repeat_cnt/g
	"
}

dotest() {
	echo -n "." >&3
	test_cnt=$(($test_cnt+1))
	describe_$cmd  # show what we are about to do
	lrm_$cmd |  # and execute the command
		{ [ "$extcheck" ] && $extcheck || cat;}
}
runonetest() {
	eval `echo $rest | substvars`  # set parameters
	if [ "$job_cnt" -le "$bgprocs_num" ]; then
		echo .BG test line $line/job $job_cnt runs in background
		dotest > $OUTDIR/bg$$-$line-$job_cnt 2>&1 &
		bgprocs="$bgprocs $line:$job_cnt:$!"
		job_cnt=$(($job_cnt+1))
	else
		dotest
	fi
}
runtest() {
	while [ $repeat_cnt -le $repeat_limit ]; do
		runonetest
		resetvars  # unset all variables
		repeat_cnt=$(($repeat_cnt+1))
	done
	repeat_limit=1 repeat_cnt=1
}

#
# run the tests
#
bgprocs_num=0 job_cnt=1
repeat_limit=1 repeat_cnt=1
line=1
test_cnt=1

while read cmd rest; do
	case "$cmd" in
		"") : empty ;;
		"#"*) : a comment ;;
		"%stop") break ;;
		"%"*) specopt ;;
		*) runtest ;;
	esac
	line=$(($line+1))
done
waitforbgprocs
