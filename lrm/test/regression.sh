#!/bin/bash

 # Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
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

 

verbose=$1
io_dir=.
diff_opts="--ignore-all-space -U -1 -u"
failed=.regression.failed
# zero out the error log
> $failed

function do_test {

    base=$1;
    name=$2;
    output=$io_dir/${base}.out
    expected=$io_dir/${base}.exp


    if [ "$create_mode" != "true" -a ! -f $expected ]; then
	echo "Test $name	($base)...	Error ($expected)";
#	return;
    fi

    ./$base > $output

    if [ ! -s $output ]; then
	echo "Test $name	($base)...	Error ($output)";
	rm $output
	return;
    fi

    if [ "$create_mode" = "true" ]; then
	cp "$output" "$expected"
    fi

    diff $diff_opts -q $expected $output >/dev/null
    rc=$?

    if [ "$rc" = 0 ]; then
	echo "Test $name	($base)...	Passed";
    elif [ "$rc" = 1 ]; then
	echo "Test $name	($base)...	* Failed";
	diff $diff_opts $expected $output 2>/dev/null >> $failed
    else
	echo "Test $name	($base)...	Error (diff: $rc)";
	echo "==== Raw results for test ($base) ====" >> $failed
	cat $output 2>/dev/null >> $failed
    fi
    
    rm $output
}

create_mode="false"

#the returns of ra_info will be different based on your computer.
#so if you want to run it, you need run in create_mode="true" first
do_test ra_info 			"get ra info"

#following tests need the IP 192.168.58.4 can be added
#e.g. run "ifconfig eth0 add 192.168.58.3" first
do_test add_del_rsc 			"add/del resource"
do_test simple_ops			"test simple ops"
do_test test_target_rc			"test normal target rc"
do_test test_target_rc_everytime	"test target_rc==EVERYTIME"
do_test test_target_rc_changed		"test target_rc==CHANGED and interval>0"

#following test needs the IP 3ffe:ffff:0:f101::3 can be added
#e.g. run "/sbin/ip -6 addr add 3ffe:ffff:0:f101::2/64 dev eth0" first
#because IPaddr executes too fast so it is hard to test get_cur_state()
#so I used IPv6addr to test it
do_test	apitest			        "test get_cur_state() and stop_op()"
