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

#
# figure out the cluster type, depending on the process list
# and existence of configuration files
#
get_cluster_type() {
	if ps -ef | egrep -qs '[a]isexec|[c]orosync' ||
			[ -f /etc/ais/openais.conf -a ! -f "$HA_CF" ] ||
			[ -f /etc/corosync/corosync.conf -a ! -f "$HA_CF" ]
	then
		debug "this is OpenAIS cluster stack"
		echo "openais"
	else
		debug "this is Heartbeat cluster stack"
		echo "heartbeat"
	fi
}
#
# find out which membership tool is installed
#
echo_membership_tool() {
	membership_tools="ccm_tool crm_node"
	for f in $membership_tools; do
		which $f 2>/dev/null && break
	done
}
#
# find nodes for this cluster
#
getnodes() {
	# 1. set by user?
	if [ "$USER_NODES" ]; then
		echo $USER_NODES
	# 2. running crm
	elif iscrmrunning; then
		debug "querying CRM for nodes"
		get_crm_nodes
	# 3. hostcache
	elif [ -f $HA_VARLIB/hostcache ]; then
		debug "reading nodes from $HA_VARLIB/hostcache"
		awk '{print $1}' $HA_VARLIB/hostcache
	# 4. ha.cf
	elif [ "$CLUSTER_TYPE" = heartbeat ]; then
		debug "reading nodes from ha.cf"
		getcfvar node
	fi
}

logd_getcfvar() {
	sed 's/#.*//' < $LOGD_CF |
		grep -w "^$1" |
		sed 's/^[^[:space:]]*[[:space:]]*//'
}
get_logd_logvars() {
	# unless logfacility is set to none, heartbeat/ha_logd are
	# going to log through syslog
	HA_LOGFACILITY=`logd_getcfvar logfacility`
	[ "" = "$HA_LOGFACILITY" ] && HA_LOGFACILITY=$DEFAULT_HA_LOGFACILITY
	[ none = "$HA_LOGFACILITY" ] && HA_LOGFACILITY=""
	HA_LOGFILE=`logd_getcfvar logfile`
	HA_DEBUGFILE=`logd_getcfvar debugfile`
}
findlogdcf() {
	for f in \
		`test -x $HA_BIN/ha_logd &&
			which strings > /dev/null 2>&1 &&
			strings $HA_BIN/ha_logd | grep 'logd\.cf'` \
		`for d; do echo $d/logd.cf $d/ha_logd.cf; done`
	do
		if [ -f "$f" ]; then
			echo $f
			debug "found logd.cf at $f"
			return 0
		fi
	done
	debug "no logd.cf"
	return 1
}
#
# logging
#
syslogmsg() {
	severity=$1
	shift 1
	logtag=""
	[ "$HA_LOGTAG" ] && logtag="-t $HA_LOGTAG"
	logger -p ${HA_LOGFACILITY:-$DEFAULT_HA_LOGFACILITY}.$severity $logtag $*
}

#
# find log destination
#
findmsg() {
	# this is tricky, we try a few directories
	syslogdirs="/var/log /var/logs /var/syslog /var/adm /var/log/ha /var/log/cluster"
	favourites="ha-*"
	mark=$1
	log=""
	for d in $syslogdirs; do
		[ -d $d ] || continue
		log=`grep -l -e "$mark" $d/$favourites` && break
		log=`grep -l -e "$mark" $d/*` && break
	done 2>/dev/null
	[ "$log" ] &&
		ls -t $log | tr '\n' ' '
	[ "$log" ] &&
		debug "found HA log at `ls -t $log | tr '\n' ' '`" ||
		debug "no HA log found in $syslogdirs"
}

#
# print a segment of a log file
#
str2time() {
	perl -e "\$time='$*';" -e '
	eval "use Date::Parse";
	if (!$@) {
		print str2time($time);
	} else {
		eval "use Date::Manip";
		if (!$@) {
			print UnixDate(ParseDateString($time), "%s");
		}
	}
	'
}
getstamp_syslog() {
	awk '{print $1,$2,$3}'
}
getstamp_legacy() {
	awk '{print $2}' | sed 's/_/ /'
}
linetime() {
	l=`tail -n +$2 $1 | head -1 | $getstampproc`
	str2time "$l"
}
find_getstampproc() {
	t=0 l="" func=""
	trycnt=10
	while [ $trycnt -gt 0 ] && read l; do
		t=$(str2time `echo $l | getstamp_syslog`)
		if [ "$t" ]; then
			func="getstamp_syslog"
			debug "the log file is in the syslog format"
			break
		fi
		t=$(str2time `echo $l | getstamp_legacy`)
		if [ "$t" ]; then
			func="getstamp_legacy"
			debug "the log file is in the legacy format (please consider switching to syslog format)"
			break
		fi
		trycnt=$(($trycnt-1))
	done
	echo $func
}
findln_by_time() {
	local logf=$1
	local tm=$2
	local first=1
	local last=`wc -l < $logf`
	while [ $first -le $last ]; do
		mid=$((($last+$first)/2))
		trycnt=10
		while [ $trycnt -gt 0 ]; do
			tmid=`linetime $logf $mid`
			[ "$tmid" ] && break
			warning "cannot extract time: $logf:$mid; will try the next one"
			trycnt=$(($trycnt-1))
			# shift the whole first-last segment
			first=$(($first-1))
			last=$(($last-1))
			mid=$((($last+$first)/2))
		done
		if [ -z "$tmid" ]; then
			warning "giving up on log..."
			return
		fi
		if [ $tmid -gt $tm ]; then
			last=$(($mid-1))
		elif [ $tmid -lt $tm ]; then
			first=$(($mid+1))
		else
			break
		fi
	done
	echo $mid
}

dumplog() {
	local logf=$1
	local from_line=$2
	local to_line=$3
	[ "$from_line" ] ||
		return
	tail -n +$from_line $logf |
		if [ "$to_line" ]; then
			head -$(($to_line-$from_line+1))
		else
			cat
		fi
}

#
# find files newer than a and older than b
#
isnumber() {
	echo "$*" | grep -qs '^[0-9][0-9]*$'
}
touchfile() {
	t=`mktemp` &&
	perl -e "\$file=\"$t\"; \$tm=$1;" -e 'utime $tm, $tm, $file;' &&
	echo $t
}
find_files_clean() {
	[ -z "$to_stamp" ] || rm -f "$to_stamp"
	to_stamp=""
	[ -z "$from_stamp" ] || rm -f "$from_stamp"
	from_stamp=""
}
find_files() {
	dirs=$1
	from_time=$2
	to_time=$3
	isnumber "$from_time" && [ "$from_time" -gt 0 ] || {
		warning "sorry, can't find files based on time if you don't supply time"
		return
	}
	trap find_files_clean 0
	if ! from_stamp=`touchfile $from_time`; then
		warning "sorry, can't create temporary file for find_files"
		return
	fi
	findexp="-newer $from_stamp"
	if isnumber "$to_time" && [ "$to_time" -gt 0 ]; then
		if ! to_stamp=`touchfile $to_time`; then
			warning "sorry, can't create temporary file for" \
				"find_files"
			find_files_clean
			return
		fi
		findexp="$findexp ! -newer $to_stamp"
	fi
	find $dirs -type f $findexp
	find_files_clean
	trap "" 0
}

#
# check permissions of files/dirs
#
pl_checkperms() {
perl -e '
# check permissions and ownership
# uid and gid are numeric
# everything must match exactly
# no error checking! (file should exist, etc)
($filename, $perms, $in_uid, $in_gid) = @ARGV;
($mode,$uid,$gid) = (stat($filename))[2,4,5];
$p=sprintf("%04o", $mode & 07777);
$p ne $perms and exit(1);
$uid ne $in_uid and exit(1);
$gid ne $in_gid and exit(1);
' $*
}
num_id() {
	getent $1 $2 | awk -F: '{print $3}'
}
chk_id() {
	[ "$2" ] && return 0
	echo "$1: id not found"
	return 1
}
check_perms() {
	essential_files |
	while read type f p uid gid; do
		[ -$type $f ] || {
			echo "$f wrong type or doesn't exist"
			continue
		}
		n_uid=`num_id passwd $uid`
		chk_id "$uid" "$n_uid" || continue
		n_gid=`num_id group $gid`
		chk_id "$gid" "$n_gid" || continue
		pl_checkperms $f $p $n_uid $n_gid || {
			echo "wrong permissions or ownership for $f:"
			ls -ld $f
		}
	done
}

#
# coredumps
#
findbinary() {
	random_binary=`which cat 2>/dev/null` # suppose we are lucky
	binary=`gdb $random_binary $1 < /dev/null 2>/dev/null |
		grep 'Core was generated' | awk '{print $5}' |
		sed "s/^.//;s/[.':]*$//"`
	if [ x = x"$binary" ]; then
		debug "could not detect the program name for core $1 from the gdb output; will try with file(1)"
		binary=$(file $1 | awk '/from/{
			for( i=1; i<=NF; i++ )
				if( $i == "from" ) {
					print $(i+1)
					break
				}
			}')
		binary=`echo $binary | tr -d "'"`
		binary=$(echo $binary | tr -d '`')
		if [ "$binary" ]; then
			binary=`which $binary 2>/dev/null`
		fi
	fi
	if [ x = x"$binary" ]; then
		warning "could not find the program path for core $1"
		return
	fi
	fullpath=`which $binary 2>/dev/null`
	if [ x = x"$fullpath" ]; then
		if [ -x $HA_BIN/$binary ]; then
			echo $HA_BIN/$binary
			debug "found the program at $HA_BIN/$binary for core $1"
		else
			warning "could not find the program path for core $1"
		fi
	else
		echo $fullpath
		debug "found the program at $fullpath for core $1"
	fi
}
getbt() {
	which gdb > /dev/null 2>&1 || {
		warning "please install gdb to get backtraces"
		return
	}
	for corefile; do
		absbinpath=`findbinary $corefile`
		[ x = x"$absbinpath" ] && continue
		echo "====================== start backtrace ======================"
		ls -l $corefile
		gdb -batch -n -quiet -ex ${BT_OPTS:-"thread apply all bt full"} -ex quit \
			$absbinpath $corefile 2>/dev/null
		echo "======================= end backtrace ======================="
	done
}

#
# heartbeat configuration/status
#
iscrmrunning() {
	ps -ef | grep -qs [c]rmd || return 1
	#crmadmin -D >/dev/null 2>&1 &
	crm_mon -1 >/dev/null 2>&1 &
	pid=$!
	maxwait=10
	while kill -0 $pid 2>/dev/null && [ $maxwait -gt 0 ]; do
		sleep 1
		maxwait=$(($maxwait-1))
	done
	if kill -0 $pid 2>/dev/null; then
		kill $pid
		false
	else
		wait $pid
	fi
}
dumpstate() {
	crm_mon -1 | grep -v '^Last upd' > $1/$CRM_MON_F
	cibadmin -Ql > $1/$CIB_F
	`echo_membership_tool` $MEMBERSHIP_TOOL_OPTS -p > $1/$MEMBERSHIP_F 2>&1
}
getconfig() {
	[ -f "$CONF" ] &&
		cp -p $CONF $1/
	[ -f "$LOGD_CF" ] &&
		cp -p $LOGD_CF $1/
	if iscrmrunning; then
		dumpstate $1
		touch $1/RUNNING
	else
		cp -p $HA_VARLIB/crm/$CIB_F $1/ 2>/dev/null
		touch $1/STOPPED
	fi
	[ "$HOSTCACHE" ] &&
		cp -p $HA_VARLIB/hostcache $1/$HOSTCACHE 2>/dev/null
	[ "$HB_UUID_F" ] &&
		crm_uuid -r > $1/$HB_UUID_F 2>&1
	[ -f "$1/$CIB_F" ] &&
		crm_verify -V -x $1/$CIB_F >$1/$CRM_VERIFY_F 2>&1
	[ -f "$1/$CIB_F" ] && which crm >/dev/null 2>&1 &&
		CIB_file=$1/$CIB_F crm configure show >$1/$CIB_TXT_F 2>&1

}
get_crm_nodes() {
	cibadmin -Ql -o nodes |
	awk '
	/type="normal"/ {
		for( i=1; i<=NF; i++ )
			if( $i~/^uname=/ ) {
				sub("uname=.","",$i);
				sub("\".*","",$i);
				print $i;
				next;
			}
	}
	'
}

#
# remove values of sensitive attributes
#
# this is not proper xml parsing, but it will work under the
# circumstances
is_sensitive_xml() {
	epatt=""
	for patt in $SANITIZE; do
		epatt="$epatt|$patt"
	done
	epatt="`echo $epatt|sed 's/.//'`"
	egrep -qs "name=\"$epatt\""
}
test_sensitive_one() {
	file=$1
	compress=""
	echo $file | grep -qs 'gz$' && compress=gzip
	echo $file | grep -qs 'bz2$' && compress=bzip2
	if [ "$compress" ]; then
		decompress="$compress -dc"
	else
		compress=cat
		decompress=cat
	fi
	$decompress < $file | is_sensitive_xml
}
sanitize_xml_attrs() {
	sed $(
	for patt in $SANITIZE; do
		echo "-e /name=\"$patt\"/s/value=\"[^\"]*\"/value=\"****\"/"
	done
	)
}
sanitize_hacf() {
	awk '
	$1=="stonith_host"{ for( i=5; i<=NF; i++ ) $i="****"; }
	{print}
	'
}
sanitize_one_clean() {
	[ -z "$tmp" ] || rm -f "$tmp"
	tmp=""
	[ -z "$ref" ] || rm -f "$ref"
	ref=""
}
sanitize_one() {
	file=$1
	compress=""
	echo $file | grep -qs 'gz$' && compress=gzip
	echo $file | grep -qs 'bz2$' && compress=bzip2
	if [ "$compress" ]; then
		decompress="$compress -dc"
	else
		compress=cat
		decompress=cat
	fi
	trap sanitize_one_clean 0
	tmp=`mktemp`
	ref=`mktemp`
	if [ -z "$tmp" -o -z "$ref" ]; then
		sanitize_one_clean
		fatal "cannot create temporary files"
	fi
	touch -r $file $ref  # save the mtime
	if [ "`basename $file`" = ha.cf ]; then
		sanitize_hacf
	else
		$decompress | sanitize_xml_attrs | $compress
	fi < $file > $tmp
	mv $tmp $file
	# note: cleaning $tmp up is still needed even after it's renamed
	# because its temp directory is still there.

	touch -r $ref $file
	sanitize_one_clean
	trap "" 0
}

#
# keep the user posted
#
fatal() {
	echo "`uname -n`: ERROR: $*" >&2
	exit 1
}
warning() {
	echo "`uname -n`: WARN: $*" >&2
}
info() {
	echo "`uname -n`: INFO: $*" >&2
}
debug() {
	[ "$VERBOSITY" ] && [ $VERBOSITY -gt 0 ] &&
	echo "`uname -n`: DEBUG: $*" >&2
}
pickfirst() {
	for x; do
		which $x >/dev/null 2>&1 && {
			echo $x
			return 0
		}
	done
	return 1
}

#
# get some system info
#
distro() {
	which lsb_release >/dev/null 2>&1 && {
		lsb_release -d
		debug "using lsb_release for distribution info"
		return
	}
	relf=`ls /etc/debian_version 2>/dev/null` ||
	relf=`ls /etc/slackware-version 2>/dev/null` ||
	relf=`ls -d /etc/*-release 2>/dev/null` && {
		for f in $relf; do
			test -f $f && {
				echo "`ls $f` `cat $f`"
				debug "found $relf distribution release file"
				return
			}
		done
	}
	warning "no lsb_release, no /etc/*-release, no /etc/debian_version: no distro information"
}

pkg_ver() {
	if which dpkg >/dev/null 2>&1 ; then
			pkg_mgr="deb"
	elif which rpm >/dev/null 2>&1 ; then
			pkg_mgr="rpm"
	elif which pkg_info >/dev/null 2>&1 ; then 
			pkg_mgr="pkg_info"
	elif which pkginfo >/dev/null 2>&1 ; then 
			pkg_mgr="pkginfo"
	else
			echo "Unknown package manager!"
			return
	fi
	debug "the package manager is $pkg_mgr"

	# for Linux .deb based systems
	for pkg ; do
		case $pkg_mgr in
		deb)
			if dpkg-query -f '${Name} ${Version}' -W $pkg 2>/dev/null ; then
				debsums -s $pkg 2>/dev/null
			fi
			;;
		rpm)
			if rpm -q --qf '%{name} %{version}-%{release} - %{distribution} %{arch}\n' $pkg ; then
				rpm --verify $pkg
			fi
			;;
		pkg_info)
			pkg_info | grep $pkg
			;;
		pkginfo)
			pkginfo | awk '{print $3}'  # format?
			;;
		esac
	done
}

crm_info() {
	$HA_BIN/crmd version 2>&1
}
