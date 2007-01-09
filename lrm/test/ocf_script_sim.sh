#!/bin/sh

# Description:  Simulation script compliant to OCF script standard
# Author:       Sun Jiang Dong
#               Support: linux-ha-dev@lists.tummy.com
# License:      GNU Lesser General Public License (LGPL)
# Copyright:    (C) 2004 International Business Machines, Inc.

# *** Below is the brief specificaion of OCF script ***
# Supported commands
# start	    mandatory, start the service.
# stop	    mandatory, stop the service.
# monitor   mandatory, checks and returns the current status of the resource instance.
# meta-data mandatory, returns the resource agent meta data via stdout.
# recover   optional, a special case of the "start" action, this should try to recover a resource locally.
# reload    optional, cause the configuration of the service to be reloaded without actually stopping and restarting the service
# validate-all optional, validate the instance parameters provided.

# Return value
# status  print the current status of the service
# 0	No error, action succeeded completely
# 1 	generic or unspecified error (current practice)
#	The "monitor" operation shall return this for a crashed, hung or
#	otherwise non-functional resource.
# 2 	invalid or excess argument(s)
#	Likely error code for validate-all, if the instance parameters
#	do not validate. Any other action is free to also return this
#	exit status code for this case.
# 3 	unimplemented feature (for example, "reload")
# 4 	user had insufficient privilege
# 5 	program is not installed
# 6 	program is not configured
# 7 	program is not running
#	Note: This is not the error code to be returned by a successful
#	"stop" operation. A successful "stop" operation shall return 0.
#	The "monitor" action shall return this value only for a 
#	_cleanly_ stopped resource. If in doubt, it should return 1.
#
# 8-99 	  reserved for future LSB use
# 100-149 reserved for distribution use
# 150-199 reserved for application use
# 200-254 reserved

# Environment variables    Meaning
# OCF_RA_VERSION_MAJOR
# OCF_RA_VERSION_MINOR
# OCF_ROOT
# OCF_RESOURCE_INSTANCE    The name of the resource instance.
# OCF_RESOURCE_TYPE        The name of the resource type being operated on.

function check_api_version()
{
	if [ $OCF_RA_VERSION_MAJOR==1 ] && [ $OCF_RA_VERSION_MINO==0 ]; then
	    return 0
        else
	    return -1
	fi
}

PIDFILE=/tmp/.idaemon_testocf_script_pid
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

  monitor)
	test_current_status
	case $? in
	    1)
		echo "The service is running"
		exit 0
		;;
	    -1)
		echo "The service is dead and its pid file exist"
		exit 6
		;;
	    0)
		echo "The service is not running"
		exit 6
	esac
	;;

  meta-data)
	echo "Meta data Meta data Meta data Meta data Meta data Meta data"
	;;

  reload|recover)
	# unimplemented feature
	exit 3
	;;

  validate-all)
	sleep 1
	set | grep OCF_
	exit 0
	;;

  *)
	echo "don't recognized command-option" $@
	exit 3
	;;
esac

exit 0
