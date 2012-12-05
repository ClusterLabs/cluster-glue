#!/bin/sh
#
#
# 	ha_log.sh for stonith external plugins
#	(equivalent to ocf_log in ocf-shellfuncs in resource-agents)
#
# Copyright (c) 2004 SUSE LINUX AG, Lars Marowsky-Brée
#                    All Rights Reserved.
#
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
# 

# Build version: @GLUE_BUILD_VERSION@

PROG=`basename $0`

: ${HA_DATEFMT=+"%b %d %T"}
: ${HA_LOGD=yes}
: ${HA_LOGTAG=""}
: ${HA_LOGFACILITY=daemon}
: ${HA_LOGFILE=""}
: ${HA_DEBUGLOG=""}
: ${HA_debug="0"}

hadate() {
  date "+$HA_DATEFMT"
}

level_pres() {
	case "$1" in
		crit)	echo "CRIT";;
		err|error)	echo "ERROR";;
		warn|warning)	echo "WARN";;
		notice)	echo "notice";;
		info)	echo "info";;
		debug)	echo "debug";;
		*)
			ha_log err "$PROG: unrecognized loglevel: $1"
			exit 1
		;;
	esac
}

set_logtag() {
	# add parent pid to the logtag
	if [ "$HA_LOGTAG" ]; then
		if [ -n "$CRM_meta_st_device_id" ]; then
			HA_LOGTAG="$HA_LOGTAG($CRM_meta_st_device_id)[$PPID]"
		else
			HA_LOGTAG="$HA_LOGTAG[$PPID]"
		fi
	fi
}

ha_log() {
	loglevel=$1
	shift
	prn_level=`level_pres $loglevel`
	msg="$prn_level: $@"

	if [ "x$HA_debug" = "x0" -a "x$loglevel" = xdebug ] ; then
		return 0
	fi

	set_logtag

	# if we're connected to a tty, then output to stderr
	if tty >/dev/null; then
		if [ "$HA_LOGTAG" ]; then
			echo "$HA_LOGTAG: $msg"
		else
			echo "$msg"
		fi >&2
		return 0
	fi

	[ "x$HA_LOGD" = "xyes" ] &&
		cat<<EOF | ha_logger -t "$HA_LOGTAG" && return 0
$msg
EOF

	if [ -n "$HA_LOGFACILITY" -a "$HA_LOGFACILITY" != none ]; then
		logger -t "$HA_LOGTAG" -p $HA_LOGFACILITY.$loglevel "$msg"
	fi	
	dest=${HA_LOGFILE:-$HA_DEBUGLOG}
	if [ -n "$dest" ]; then
		msg="$prn_level: `hadate` $@"
		echo "$HA_LOGTAG:	$msg" >> $dest
	fi
}

if [ $# -lt 2 ]; then
	ha_log err "$PROG: not enough arguments [$#]"
	exit 1
fi

loglevel="$1"
shift 1
msg="$*"

ha_log "$loglevel" "$msg"
