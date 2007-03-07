#!/bin/bash
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
#
#

no_logs=0
exit_on_error=1
num_servers=10
num_clients=10
client_time=2

total_failed=0

server_loop_cnt=0
while [ $server_loop_cnt != $num_servers ]; do
	echo "############ DEBUG: Starting sver iter $server_loop_cnt"
	if [ $no_logs = 1 ]; then
	    ./ipctransientserver > /dev/null 2>&1 &
	else
	    ./ipctransientserver &
	fi
	server_pid=$!

	sleep 5    

	iter_failed=0
	client_loop_cnt=0
	while [ $client_loop_cnt != $num_clients ]; do
	sleep 5    
	    echo "############ DEBUG: Starting client iter $client_loop_cnt"
	    if [ $no_logs = 1 ]; then
		./ipctransientclient > /dev/null 2>&1 &
	    else
		./ipctransientclient &
	    fi
	    client_pid=$!
	    sleep $client_time
		if [ $exit_on_error = 1 ];then
			kill -0 $client_pid > /dev/null 2>&1 
		else
			kill -9 $client_pid > /dev/null 2>&1
		fi
	    rc=$?
	    if [ $rc = 0 ]; then
			echo "############ ERROR: Iter $client_loop_cnt failed to recieve all messages"
			let iter_failed=$iter_failed+1
			if [ $exit_on_error = 1 ];then
				echo "terminating after first error..."
				exit 0
			fi
	    else
			echo "############ INFO: Iter $client_loop_cnt passed"
	    fi
	    
	    let client_loop_cnt=$client_loop_cnt+1;
	done
	let server_loop_cnt=server_loop_cnt+1;
	let total_failed=$iter_failed+$total_failed
	kill -9 $server_pid > /dev/null 2>&1 
	rc=$?
	if [ $rc = 0 ]; then
	    echo "############ ERROR: Server was already dead"
	fi
done


if [ $total_failed = 0 ]; then
    echo "INFO: All tests passed"
else
    echo "ERROR: $total_failed tests failed"
fi
