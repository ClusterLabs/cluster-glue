#!/bin/sh

# Description:  Simulation script compliant to LSB init script standard
# Author:       Sun Jiang Dong
#               Support: linux-ha-dev@lists.tummy.com
# License:      GNU Lesser General Public License (LGPL)
# Copyright:    (C) 2004 International Business Machines, Inc.

# *** Brief specification for LSB init script as below *** 
# Mandatory supported commands
# start	  start the service
# stop	  stop the service
# restart stop and restart the service if the service is already running, otherwise start the service
# reload  cause the configuration of the service to be reloaded without actually stopping and restarting the service
# force-reload  cause the configuration to be reloaded if the service supports this, otherwise restart the service

# Return values
# status  print the current status of the service
# 0	  program is running or service is OK
# 1	  program is dead and /var/run pid file exists
# 2	  program is dead and /var/lock lock file exists
# 3	  program is stopped
# 4	  program or service status is unknown
# 5-99	  reserved for future LSB use

# This is a test scripts compliant to lsb init script standard

PIDFILE=/tmp/.daemon_testlsb_script_pid
function test_current_status()
{
	if [ -f $PIDFILE ]; then
	    daemon_id=`cat $PIDFILE`
	    ps -p $daemon_id > /dev/null
	    if [ $?==0 ]; then
		# "The service is already running"
		return 1
	    else
# "The service is dead and its pid file exist"
		    return -1
	    fi
	else
		return 0
			fi
}

function close()
{
	if [ -f $PIDFILE ]; then
		daemon_id=`cat $PIDFILE`
	    kill -9 $daemon_id
	    /bin/rm -f $PIDFILE
	fi
}

case $1 in
  start)
	test_current_status
	case $? in
	    1)
		echo "The service is already running"
		exit 0
		;;
	    -1)
		echo "The service is dead and its pid file exist"
		;;
	esac

	echo "starting the service ..."

	./daemon_for_lsb.sh &
	sleep 2
	echo "the service started successfully"
        ;;

  stop)
	test_current_status
	case $? in
	    0)
		echo "The service is not running before"
		exit 0
		;;
	    -1)
		echo "The service is already dead and its pid file exist"
		/bin/rm -f $PIDFILE
		exit 0
		;;
	esac

	echo "stopping the service ..."
	close
	sleep 1
	exit 0
	;;

  restart)
	test_current_status
	case $? in
	    0)
		echo "The service is not running before"
		;;
	    -1)
		echo "The service is already dead and its pid file exist"
		/bin/rm -f $PIDFILE
		exit 0
		;;
	    1)
		close
		;;
	esac
	echo "restarting the service ..."
	./daemon_for_lsb.sh &
	sleep 2
	exit 0
	;;

  reload)
	test_current_status
	case $? in
	    0)
		echo "The service is not running before"
		exit 3
		;;
	    -1)
		echo "The service is already dead and its pid file exist"
		/bin/rm -f $PIDFILE
		exit 1
		;;
	esac
	echo "reloading the service ..."
	sleep 1
	echo "reloaded the service"
	exit 0

	;;

  force-reload)
	test_current_status
	case $? in
	    0)
		echo "The service is not running before"
		;;
	    -1)
		echo "The service is already dead and its pid file exist"
		/bin/rm -f $PIDFILE
		;;
	    1)
		close
		;;
	esac

	echo "force-reloading the service ..."
	./daemon_for_lsb.sh &
	sleep 2
	echo "force-reloaded the service"
	exit 0
	;;

  *)
	echo "don't recognized command-option" $@
	;;
esac

exit 0
