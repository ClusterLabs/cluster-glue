dnl
dnl autoconf for Pacemaker
dnl
dnl License: GNU General Public License (GPL)

dnl ===============================================
dnl Bootstrap 
dnl ===============================================
AC_PREREQ(2.53)

dnl Suggested structure:
dnl     information on the package
dnl     checks for programs
dnl     checks for libraries
dnl     checks for header files
dnl     checks for types
dnl     checks for structures
dnl     checks for compiler characteristics
dnl     checks for library functions
dnl     checks for system services

AC_INIT(cluster-glue, 1.0.12, linux-ha-dev@lists.linux-ha.org)

FEATURES=""
HB_PKG=heartbeat

AC_CONFIG_AUX_DIR(.)
AC_CANONICAL_HOST

dnl Where #defines go (e.g. `AC_CHECK_HEADERS' below)
dnl
dnl Internal header: include/config.h
dnl   - Contains ALL defines
dnl   - include/config.h.in is generated automatically by autoheader
dnl   - NOT to be included in any header files except lha_internal.h
dnl     (which is also not to be included in any other header files)
dnl
dnl External header: include/crm_config.h
dnl   - Contains a subset of defines checked here
dnl   - Manually edit include/crm_config.h.in to have configure include
dnl     new defines
dnl   - Should not include HAVE_* defines
dnl   - Safe to include anywhere
AM_CONFIG_HEADER(include/config.h include/glue_config.h)
ALL_LINGUAS="en fr"

AC_ARG_WITH(version,
    [  --with-version=version   Override package version (if you're a packager needing to pretend) ],
    [ PACKAGE_VERSION="$withval" ])

AC_ARG_WITH(pkg-name,
    [  --with-pkg-name=name     Override package name (if you're a packager needing to pretend) ],
    [ PACKAGE_NAME="$withval" ])

PKG_PROG_PKG_CONFIG
AC_ARG_WITH([systemdsystemunitdir],
     [AS_HELP_STRING([--with-systemdsystemunitdir=DIR], [Directory for systemd service files])],,
     [with_systemdsystemunitdir=auto])
AS_IF([test "x$with_systemdsystemunitdir" = "xyes" -o "x$with_systemdsystemunitdir" = "xauto"], [
     def_systemdsystemunitdir=$($PKG_CONFIG --variable=systemdsystemunitdir systemd)

     AS_IF([test "x$def_systemdsystemunitdir" = "x"],
         [AS_IF([test "x$with_systemdsystemunitdir" = "xyes"],
                [AC_MSG_ERROR([systemd support requested but pkg-config unable to query systemd package])])
          with_systemdsystemunitdir=no],
         [with_systemdsystemunitdir="$def_systemdsystemunitdir"])])
AS_IF([test "x$with_systemdsystemunitdir" != "xno"],
      [AC_SUBST([systemdsystemunitdir], [$with_systemdsystemunitdir])])
AM_CONDITIONAL([HAVE_SYSTEMD], [test "x$with_systemdsystemunitdir" != "xno"])

AM_INIT_AUTOMAKE($PACKAGE_NAME, $PACKAGE_VERSION)
AC_DEFINE_UNQUOTED(GLUE_VERSION, "$PACKAGE_VERSION", Current version of the glue library)

CC_IN_CONFIGURE=yes
export CC_IN_CONFIGURE

LDD=ldd

dnl ========================================================================
dnl Compiler characteristics
dnl ========================================================================

AC_PROG_CC dnl Can force other with environment variable "CC".
AM_PROG_CC_C_O
AC_PROG_CC_STDC

AC_LIBTOOL_DLOPEN               dnl Enable dlopen support...
AC_LIBLTDL_CONVENIENCE          dnl make libltdl a convenience lib
AC_PROG_LIBTOOL

AC_C_STRINGIZE
AC_TYPE_SIZE_T
AC_CHECK_SIZEOF(char)
AC_CHECK_SIZEOF(short)
AC_CHECK_SIZEOF(int)
AC_CHECK_SIZEOF(long)
AC_CHECK_SIZEOF(long long)
AC_CHECK_SIZEOF(clock_t, [], [#include <sys/times.h>])
AC_STRUCT_TIMEZONE

dnl ===============================================
dnl Helpers 
dnl ===============================================
cc_supports_flag() {
         local CFLAGS="$@"
         AC_MSG_CHECKING(whether $CC supports "$@")
         AC_COMPILE_IFELSE([AC_LANG_SOURCE(int main(){return 0;})] ,[RC=0; AC_MSG_RESULT(yes)],[RC=1; AC_MSG_RESULT(no)])
         return $RC
}

dnl ===============================================
dnl Configure Options
dnl ===============================================

dnl Some systems, like Solaris require a custom package name
AC_ARG_WITH(pkgname,
    [  --with-pkgname=name     name for pkg (typically for Solaris) ],
    [ PKGNAME="$withval" ],
    [ PKGNAME="LXHAhb" ],
  )
AC_SUBST(PKGNAME)

AC_ARG_ENABLE([ansi],
[  --enable-ansi force GCC to compile to ANSI/ANSI standard for older compilers.
     [default=yes]])

AC_ARG_ENABLE([fatal-warnings],
[  --enable-fatal-warnings very pedantic and fatal warnings for gcc
     [default=yes]])

AC_ARG_ENABLE([pretty],
[  --enable-pretty 
     Pretty-print compiler output unless there is an error
     [default=no]])

AC_ARG_ENABLE([quiet],
[  --enable-quiet 
     Supress make output unless there is an error
     [default=no]])

AC_ARG_ENABLE([thread-safe],
[  --enable-thread-safe Enable some client libraries to be thread safe.
     [default=no]])

AC_ARG_ENABLE([bundled-ltdl],
[  --enable-bundled-ltdl  Configure, build and install the standalone ltdl library bundled with ${PACKAGE} [default=no]]) 
LTDL_LIBS=""

AC_ARG_ENABLE([upstart],
AS_HELP_STRING([--enable-upstart],
               [Enable Upstart support in lrmd. [default=no]]))

INITDIR=""
AC_ARG_WITH(initdir,
    [  --with-initdir=DIR      directory for init (rc) scripts [${INITDIR}]],
    [ INITDIR="$withval" ])

OCF_ROOT_DIR="/usr/lib/ocf"
AC_ARG_WITH(ocf-root,
    [  --with-ocf-root=DIR      directory for OCF scripts [${OCF_ROOT_DIR}]],
    [ if test x"$withval" = xprefix; then OCF_ROOT_DIR=${prefix}; else
	 OCF_ROOT_DIR="$withval"; fi ])

AC_ARG_WITH(
  daemon-group,
    [  --with-daemon-group=GROUP_NAME
                          Group to run our programs as. [default=haclient]  ],
    [ GLUE_DAEMON_GROUP="$withval" ],
    [ GLUE_DAEMON_GROUP="haclient" ],
  )

AC_ARG_WITH(
  daemon-user,
    [  --with-daemon-user=USER_NAME
                          User to run privileged non-root things as. [default=hacluster]  ],
    [ GLUE_DAEMON_USER="$withval" ],
    [ GLUE_DAEMON_USER="hacluster" ],
  )


AC_ARG_WITH(
  rundir,
    [ --with-rundir=DIR
			directory to store state information [default=localstatedir/run] ],
    [ GLUE_STATE_DIR="$withval" ],
    [ GLUE_STATE_DIR="${localstatedir}/run" ],
  )

dnl ===============================================
dnl General Processing
dnl ===============================================

AC_SUBST(HB_PKG)

INIT_EXT=""
echo Our Host OS: $host_os/$host

if test "X$OCF_ROOT_DIR" = X; then
  OCF_ROOT_DIR="/usr/lib/ocf"
fi

AC_MSG_NOTICE(Sanitizing prefix: ${prefix})
case $prefix in
  NONE)	prefix=/usr;;
esac

AC_MSG_NOTICE(Sanitizing exec_prefix: ${exec_prefix})
case $exec_prefix in
  dnl For consistency with Heartbeat, map NONE->$prefix
  NONE)	  exec_prefix=$prefix;;
  prefix) exec_prefix=$prefix;;
esac

AC_MSG_NOTICE(Sanitizing INITDIR: ${INITDIR})
case $INITDIR in
  prefix) INITDIR=$prefix;;
  "")
    AC_MSG_CHECKING(which init (rc) directory to use)
      for initdir in /etc/init.d /etc/rc.d/init.d /sbin/init.d	\
	   /usr/local/etc/rc.d /etc/rc.d
      do
        if
          test -d $initdir
        then
          INITDIR=$initdir
          break
        fi
      done
      AC_MSG_RESULT($INITDIR);;
esac
AC_SUBST(INITDIR)

AC_MSG_NOTICE(Sanitizing libdir: ${libdir})
case $libdir in
  dnl For consistency with Heartbeat, map NONE->$prefix
  *prefix*|NONE)
    AC_MSG_CHECKING(which lib directory to use)
    for aDir in lib64 lib
    do
      trydir="${exec_prefix}/${aDir}"
      if
        test -d ${trydir}
      then
        libdir=${trydir}
        break
      fi
    done
    AC_MSG_RESULT($libdir);
    ;;
esac

DLOPEN_FORCE_FLAGS=""
AC_SUBST(DLOPEN_FORCE_FLAGS)


dnl Expand autoconf variables so that we dont end up with '${prefix}' 
dnl in #defines and python scripts
dnl NOTE: Autoconf deliberately leaves them unexpanded to allow
dnl    make exec_prefix=/foo install
dnl No longer being able to do this seems like no great loss to me...

eval prefix="`eval echo ${prefix}`"
eval exec_prefix="`eval echo ${exec_prefix}`"
eval bindir="`eval echo ${bindir}`"
eval sbindir="`eval echo ${sbindir}`"
eval libexecdir="`eval echo ${libexecdir}`"
eval datadir="`eval echo ${datadir}`"
eval sysconfdir="`eval echo ${sysconfdir}`"
eval sharedstatedir="`eval echo ${sharedstatedir}`"
eval localstatedir="`eval echo ${localstatedir}`"
eval libdir="`eval echo ${libdir}`"
eval includedir="`eval echo ${includedir}`"
eval oldincludedir="`eval echo ${oldincludedir}`"
eval infodir="`eval echo ${infodir}`"
eval mandir="`eval echo ${mandir}`"

dnl docdir is a recent addition to autotools
eval docdir="`eval echo ${docdir}`"
if test "x$docdir" = "x"; then
   docdir="`eval echo ${datadir}/doc`"
fi
AC_SUBST(docdir)

AC_MSG_CHECKING(for the location of the lock directory)
for HA_VARLOCKDIR in ${localstatedir}/lock ${localstatedir}/spool/lock ${localstatedir}/spool/locks ${localstatedir}/lock
do
  if
    test -d "$HA_VARLOCKDIR"
  then
    AC_MSG_RESULT($HA_VARLOCKDIR)
    break
  fi
done

AC_SUBST(HA_VARLOCKDIR)
AC_DEFINE_UNQUOTED(HA_VARLOCKDIR,"$HA_VARLOCKDIR", System lock directory)

dnl Home-grown variables
eval INITDIR="${INITDIR}"

for j in prefix exec_prefix bindir sbindir libexecdir datadir sysconfdir \
    sharedstatedir localstatedir libdir includedir oldincludedir infodir \
    mandir INITDIR docdir HA_VARLOCKDIR
do 
  dirname=`eval echo '${'${j}'}'`
  if
    test ! -d "$dirname"
  then
    AC_MSG_WARN([$j directory ($dirname) does not exist!])
  fi
done

dnl This OS-based decision-making is poor autotools practice;
dnl feature-based mechanisms are strongly preferred.
dnl
dnl So keep this section to a bare minimum; regard as a "necessary evil". 

ON_LINUX=0
REBOOT_OPTIONS="-f"
POWEROFF_OPTIONS="-f"

case "$host_os" in
*bsd*)		LIBS="-L/usr/local/lib"
		CPPFLAGS="$CPPFLAGS -I/usr/local/include"
		INIT_EXT=".sh"
		;;
*solaris*)
		REBOOT_OPTIONS="-n"
		POWEROFF_OPTIONS="-n"
		;;
*linux*)	
		ON_LINUX=1
		REBOOT_OPTIONS="-nf"
		POWEROFF_OPTIONS="-nf"
		AC_DEFINE_UNQUOTED(ON_LINUX, $ON_LINUX, Compiling for Linux platform)
 		;;
darwin*)	
		AC_DEFINE_UNQUOTED(ON_DARWIN, 1, Compiling for Darwin platform)
  		LIBS="$LIBS -L${prefix}/lib"
  		CFLAGS="$CFLAGS -I${prefix}/include"
		;;
esac

AM_CONDITIONAL(ON_LINUX, test $ON_LINUX = 1)

dnl Eventually remove this 
dnl CFLAGS="$CFLAGS -I${prefix}/include/heartbeat"

AC_SUBST(INIT_EXT)
AC_DEFINE_UNQUOTED(HA_LOG_FACILITY, LOG_DAEMON, Default logging facility)

AC_MSG_NOTICE(Host CPU: $host_cpu)

case "$host_cpu" in
  ppc64|powerpc64)
    case $CFLAGS in
     *powerpc64*)			;;
     *)	if test "$GCC" = yes; then
	  CFLAGS="$CFLAGS -m64"
	fi				;;
    esac
esac

AC_MSG_CHECKING(which format is needed to print uint64_t)
case "$host_cpu" in
  s390x)U64T="%lu";;
  *64*) U64T="%lu";;
  *)    U64T="%llu";;
esac
AC_MSG_RESULT($U64T)
AC_DEFINE_UNQUOTED(U64T, "$U64T", Correct printf format for logging uint64_t)

dnl Variables needed for substitution
AC_DEFINE_UNQUOTED(GLUE_DAEMON_USER,"$GLUE_DAEMON_USER", User to run daemons as)
AC_SUBST(GLUE_DAEMON_USER)

AC_DEFINE_UNQUOTED(GLUE_DAEMON_GROUP,"$GLUE_DAEMON_GROUP", Group to run daemons as)
AC_SUBST(GLUE_DAEMON_GROUP)

dnl Eventually move out of the heartbeat dir tree and create symlinks when needed
GLUE_DAEMON_DIR=$libdir/heartbeat
AC_DEFINE_UNQUOTED(GLUE_DAEMON_DIR,"$GLUE_DAEMON_DIR", Location for daemons)
AC_SUBST(GLUE_DAEMON_DIR)

GLUE_STATE_DIR=${localstatedir}/run
AC_DEFINE_UNQUOTED(GLUE_STATE_DIR,"$GLUE_STATE_DIR", Where to keep state files and sockets)
AC_SUBST(GLUE_STATE_DIR)

GLUE_SHARED_DIR=${datadir}/"$PACKAGE_NAME"
AC_DEFINE_UNQUOTED(GLUE_SHARED_DIR,"$GLUE_SHARED_DIR", Location for scripts)
AC_SUBST(GLUE_SHARED_DIR)

AC_DEFINE_UNQUOTED(HA_VARRUNDIR,"$GLUE_STATE_DIR", Where Heartbeat keeps state files and sockets - old name)
AC_SUBST(HA_VARRUNDIR)

HA_VARLIBHBDIR=${localstatedir}/lib/heartbeat
AC_DEFINE_UNQUOTED(HA_VARLIBHBDIR,"$HA_VARLIBHBDIR", Whatever this used to mean)
AC_SUBST(HA_VARLIBHBDIR)
AC_DEFINE_UNQUOTED(HA_VARLIBDIR,"$HA_VARLIBHBDIR", Whatever this used to mean)
AC_SUBST(HA_VARLIBDIR)

AC_DEFINE_UNQUOTED(OCF_ROOT_DIR,"$OCF_ROOT_DIR", OCF root directory - specified by the OCF standard)
AC_SUBST(OCF_ROOT_DIR)

OCF_RA_DIR="${OCF_ROOT_DIR}/resource.d/"
AC_DEFINE_UNQUOTED(OCF_RA_DIR,"$OCF_RA_DIR", Location for OCF RAs)
AC_SUBST(OCF_RA_DIR)

HA_LOGDAEMON_IPC="${localstatedir}/lib/heartbeat/log_daemon"
AC_DEFINE_UNQUOTED(HA_LOGDAEMON_IPC, "$HA_LOGDAEMON_IPC", Logging Daemon IPC socket name)
AC_SUBST(HA_LOGDAEMON_IPC)

HA_URLBASE="http://linux-ha.org/wiki/"
AC_DEFINE_UNQUOTED(HA_URLBASE, "$HA_URLBASE", Web site base URL)
AC_SUBST(HA_URLBASE)

HA_COREDIR="${localstatedir}/lib/heartbeat/cores"
AC_DEFINE_UNQUOTED(HA_COREDIR,"$HA_COREDIR", top directory of area to drop core files in)
AC_SUBST(HA_COREDIR)

LRM_VARLIBDIR="${localstatedir}/lib/heartbeat/lrm"
AC_DEFINE_UNQUOTED(LRM_VARLIBDIR,"$LRM_VARLIBDIR", LRM directory)
AC_SUBST(LRM_VARLIBDIR)

LRM_CIBSECRETS="${localstatedir}/lib/heartbeat/lrm/secrets"
AC_DEFINE_UNQUOTED(LRM_CIBSECRETS,"$LRM_CIBSECRETS", CIB secrets location)
AC_SUBST(LRM_CIBSECRETS)

AC_DEFINE_UNQUOTED(PILS_BASE_PLUGINDIR,"$libdir/heartbeat/plugins", Default plugin search path)
AC_DEFINE_UNQUOTED(HA_PLUGIN_DIR,"$libdir/heartbeat/plugins", Where to find plugins)
AC_DEFINE_UNQUOTED(LRM_PLUGIN_DIR,"$libdir/heartbeat/plugins/RAExec", Where to find LRM plugins)

AC_DEFINE_UNQUOTED(LSB_RA_DIR,"$INITDIR", Location for LSB RAs)
LSB_RA_DIR=$INITDIR
AC_SUBST(LSB_RA_DIR)

AC_DEFINE_UNQUOTED(HA_SYSCONFDIR, "$sysconfdir", Location of system configuration files)

HA_HBCONF_DIR=${sysconfdir}/ha.d/
AC_DEFINE_UNQUOTED(HA_HBCONF_DIR,"$HA_HBCONF_DIR", Location for v1 Heartbeat configuration)
AC_SUBST(HA_HBCONF_DIR)

HB_RA_DIR=${sysconfdir}/ha.d/resource.d/
AC_DEFINE_UNQUOTED(HB_RA_DIR,"$HB_RA_DIR", Location for v1 Heartbeat RAs)
AC_SUBST(HB_RA_DIR)

stonith_plugindir="${libdir}/stonith/plugins"
stonith_ext_plugindir="${stonith_plugindir}/external"
stonith_rhcs_plugindir="${stonith_plugindir}/rhcs"
AC_DEFINE_UNQUOTED(ST_TEXTDOMAIN, "stonith", Stonith plugin domain) 
AC_DEFINE_UNQUOTED(STONITH_MODULES, "$stonith_plugindir", Location of stonith plugins)
AC_DEFINE_UNQUOTED(STONITH_EXT_PLUGINDIR, "$stonith_ext_plugindir", Location of non-plugin stonith scripts)
AC_DEFINE_UNQUOTED(STONITH_RHCS_PLUGINDIR, "$stonith_rhcs_plugindir", Location of RHCS fence scripts)
AC_SUBST(stonith_plugindir)
AC_SUBST(stonith_ext_plugindir)
AC_SUBST(stonith_rhcs_plugindir)

dnl Old names for new things
AC_DEFINE_UNQUOTED(HA_CCMUSER,   "$GLUE_DAEMON_USER",  User to run daemons as) 
AC_DEFINE_UNQUOTED(HA_APIGROUP,  "$GLUE_DAEMON_GROUP", Group to run daemons as)
AC_DEFINE_UNQUOTED(HA_LIBHBDIR,  "$GLUE_DAEMON_DIR",   Location for daemons)

LRM_DIR=lrm
AC_SUBST(LRM_DIR)

AC_PATH_PROGS(HG, hg false)
AC_MSG_CHECKING(build version)
GLUE_BUILD_VERSION=unknown
if test -f $srcdir/.hg_archival.txt; then
   GLUE_BUILD_VERSION=`cat $srcdir/.hg_archival.txt | awk '/node:/ { print $2 }'`
elif test -x $HG -a -d .hg; then
   GLUE_BUILD_VERSION=`$HG id -itb`
   if test $? != 0; then
       GLUE_BUILD_VERSION=unknown
   fi
fi

AC_DEFINE_UNQUOTED(GLUE_BUILD_VERSION, "$GLUE_BUILD_VERSION", Build version)
AC_MSG_RESULT($GLUE_BUILD_VERSION)
AC_SUBST(GLUE_BUILD_VERSION)

dnl check byte order
AC_MSG_CHECKING(for byteorder)
AC_C_BIGENDIAN(
[AC_MSG_RESULT(big-endian); AC_DEFINE(CONFIG_BIG_ENDIAN, 1, [big-endian])],
[AC_MSG_RESULT(little-endian); AC_DEFINE(CONFIG_LITTLE_ENDIAN, 1, [little-endian])],
)


dnl ===============================================
dnl Program Paths
dnl ===============================================

PATH="$PATH:/sbin:/usr/sbin:/usr/local/sbin:/usr/local/bin"
export PATH


dnl Replacing AC_PROG_LIBTOOL with AC_CHECK_PROG because LIBTOOL
dnl was NOT being expanded all the time thus causing things to fail.
AC_CHECK_PROGS(LIBTOOL, glibtool libtool libtool15 libtool13)

AM_PATH_PYTHON
AC_CHECK_PROGS(MAKE, gmake make)
AC_PATH_PROGS(HTML2TXT, lynx w3m)
AC_PATH_PROGS(HELP2MAN, help2man)
AC_PATH_PROGS(POD2MAN, pod2man, pod2man)
AC_PATH_PROGS(SSH, ssh, /usr/bin/ssh)
AC_PATH_PROGS(SCP, scp, /usr/bin/scp)
AC_PATH_PROGS(HG, hg, /bin/false)
AC_PATH_PROGS(TAR, tar)
AC_PATH_PROGS(MD5, md5)
AC_PATH_PROGS(RPM, rpm)
AC_PATH_PROGS(TEST, test)
AC_PATH_PROGS(PING, ping, /bin/ping)
AC_PATH_PROGS(IFCONFIG, ifconfig, /sbin/ifconfig)
AC_PATH_PROGS(MAILCMD, mailx mail)
AC_PATH_PROGS(EGREP, egrep)
AC_PATH_PROGS(PKGCONFIG, pkg-config)
AC_PATH_PROGS(XML2CONFIG, xml2-config)

AC_ARG_ENABLE([doc],
 AS_HELP_STRING([--enable-doc], [build documentation (default is yes)]),
 [], [enable_doc=yes])
if test "x$enable_doc" != "xno"; then
       AC_PATH_PROGS(XSLTPROC, xsltproc)
       if test "x$XSLTPROC" = "x"; then
           AC_MSG_WARN([xsltproc not installed, unable to (re-)build manual pages])
       fi
       AC_PATH_PROGS(ASCIIDOC, asciidoc)
       if test "x$ASCIIDOC" = "x"; then
           AC_MSG_WARN([asciidoc not installed, unable to (re-)build manual pages])
       fi
fi
AM_CONDITIONAL(BUILD_DOC, test "x$XSLTPROC" != "x" )

AC_PATH_PROGS(VALGRIND_BIN, valgrind, /usr/bin/valgrind)
AC_DEFINE_UNQUOTED(VALGRIND_BIN, "$VALGRIND_BIN", Valgrind command)

AC_SUBST(MAILCMD)
AC_SUBST(EGREP)
AC_SUBST(SHELL)
AC_SUBST(PING)
AC_SUBST(TEST)
AC_SUBST(RPM)
AC_SUBST(XSLTPROC)

AC_MSG_CHECKING(ifconfig option to list interfaces)
for IFCONFIG_A_OPT in  "-A" "-a" ""
do
  $IFCONFIG $IFCONFIG_A_OPT > /dev/null 2>&1
  if
    test "$?" = 0
  then
    AC_DEFINE_UNQUOTED(IFCONFIG_A_OPT, "$IFCONFIG_A_OPT", option for ifconfig command)
    AC_MSG_RESULT($IFCONFIG_A_OPT)
    break
  fi
done

AC_SUBST(IFCONFIG_A_OPT)

if test x"${LIBTOOL}" = x""; then
   AC_MSG_ERROR(You need (g)libtool installed in order to build ${PACKAGE})
fi
if test x"${MAKE}" = x""; then
   AC_MSG_ERROR(You need (g)make installed in order to build ${PACKAGE})
fi

AM_CONDITIONAL(BUILD_HELP, test x"${HELP2MAN}" != x"")
if test x"${HELP2MAN}" != x""; then
   FEATURES="$FEATURES manpages"
fi

dnl ===============================================
dnl Libraries
dnl ===============================================
AC_CHECK_LIB(socket, socket)			
AC_CHECK_LIB(c, dlopen)				dnl if dlopen is in libc...
AC_CHECK_LIB(dl, dlopen)			dnl for Linux
AC_CHECK_LIB(rt, sched_getscheduler)            dnl for Tru64
AC_CHECK_LIB(gnugetopt, getopt_long)		dnl if available
AC_CHECK_LIB(uuid, uuid_parse)			dnl e2fsprogs
AC_CHECK_LIB(uuid, uuid_create)			dnl ossp
AC_CHECK_LIB(posix4, sched_getscheduler)

if test x"${PKGCONFIG}" = x""; then
   AC_MSG_ERROR(You need pkgconfig installed in order to build ${PACKAGE})
fi

dnl
dnl     On many systems libcrypto is needed when linking against libsnmp.
dnl     Check to see if it exists, and if so use it.
dnl
AC_CHECK_LIB(crypto, CRYPTO_free, CRYPTOLIB="-lcrypto",)
AC_SUBST(CRYPTOLIB)

if test "x${enable_thread_safe}" = "xyes"; then
        GPKGNAME="gthread-2.0"
else
        GPKGNAME="glib-2.0"
fi

if 
   $PKGCONFIG --exists $GPKGNAME
then
	GLIBCONFIG="$PKGCONFIG $GPKGNAME"
else
	set -x
        echo PKG_CONFIG_PATH=$PKG_CONFIG_PATH
	$PKGCONFIG --exists $GPKGNAME; echo $?
	$PKGCONFIG --cflags $GPKGNAME; echo $?
	$PKGCONFIG $GPKGNAME; echo $?
	set +x
        
	AC_MSG_ERROR(You need glib2-devel installed in order to build ${PACKAGE})
fi
AC_MSG_RESULT(using $GLIBCONFIG)

#
#	Where is dlopen?
#
if test "$ac_cv_lib_c_dlopen" = yes; then
	LIBADD_DL=""
elif test "$ac_cv_lib_dl_dlopen" = yes; then
	LIBADD_DL=-ldl
else
        LIBADD_DL=${lt_cv_dlopen_libs}
fi
dnl
dnl Check for location of gettext
dnl
dnl On at least Solaris 2.x, where it is in libc, specifying lintl causes
dnl grief. Ensure minimal result, not the sum of all possibilities.
dnl And do libc first.
dnl Known examples:
dnl    c:      Linux, Solaris 2.6+
dnl    intl:   BSD, AIX

AC_CHECK_LIB(c, gettext)
if test x$ac_cv_lib_c_gettext != xyes; then
   AC_CHECK_LIB(intl, gettext)
fi

if test x$ac_cv_lib_c_gettext != xyes -a x$ac_cv_lib_intl_gettext != xyes; then
   AC_MSG_ERROR(You need gettext installed in order to build ${PACKAGE})
fi

if test "X$GLIBCONFIG" != X; then
	AC_MSG_CHECKING(for special glib includes: )
	GLIBHEAD=`$GLIBCONFIG --cflags`
	AC_MSG_RESULT($GLIBHEAD)
	CPPFLAGS="$CPPFLAGS $GLIBHEAD"

	AC_MSG_CHECKING(for glib library flags)
	GLIBLIB=`$GLIBCONFIG --libs`
	AC_MSG_RESULT($GLIBLIB)
	LIBS="$LIBS $GLIBLIB"
fi

dnl ========================================================================
dnl Headers
dnl ========================================================================

AC_HEADER_STDC
AC_CHECK_HEADERS(arpa/inet.h)
AC_CHECK_HEADERS(asm/types.h)
AC_CHECK_HEADERS(assert.h)
AC_CHECK_HEADERS(auth-client.h)
AC_CHECK_HEADERS(ctype.h)
AC_CHECK_HEADERS(dirent.h)
AC_CHECK_HEADERS(errno.h)
AC_CHECK_HEADERS(fcntl.h)
AC_CHECK_HEADERS(getopt.h)
AC_CHECK_HEADERS(glib.h)
AC_CHECK_HEADERS(grp.h)
AC_CHECK_HEADERS(limits.h)
AC_CHECK_HEADERS(linux/errqueue.h,,,
	[#ifdef HAVE_LINUX_TYPES_H
	 # include <linux/types.h>
	 #endif
	])
AC_CHECK_HEADERS(malloc.h)
AC_CHECK_HEADERS(netdb.h)
AC_CHECK_HEADERS(netinet/in.h)
AC_CHECK_HEADERS(netinet/ip.h)
AC_CHECK_HEADERS(pthread.h)
AC_CHECK_HEADERS(pwd.h)
AC_CHECK_HEADERS(sgtty.h)
AC_CHECK_HEADERS(signal.h)
AC_CHECK_HEADERS(stdarg.h)
AC_CHECK_HEADERS(stddef.h)
AC_CHECK_HEADERS(stdio.h)
AC_CHECK_HEADERS(stdlib.h)
AC_CHECK_HEADERS(string.h)
AC_CHECK_HEADERS(strings.h)
AC_CHECK_HEADERS(sys/dir.h)
AC_CHECK_HEADERS(sys/ioctl.h)
AC_CHECK_HEADERS(sys/param.h)
AC_CHECK_HEADERS(sys/poll.h)
AC_CHECK_HEADERS(sys/reboot.h)
AC_CHECK_HEADERS(sys/resource.h)
AC_CHECK_HEADERS(sys/select.h)
AC_CHECK_HEADERS(sys/socket.h)
AC_CHECK_HEADERS(sys/sockio.h)
AC_CHECK_HEADERS(sys/stat.h)
AC_CHECK_HEADERS(sys/time.h)
AC_CHECK_HEADERS(sys/timeb.h)
AC_CHECK_HEADERS(sys/types.h)
AC_CHECK_HEADERS(sys/uio.h)
AC_CHECK_HEADERS(sys/un.h)
AC_CHECK_HEADERS(sys/utsname.h)
AC_CHECK_HEADERS(sys/wait.h)
AC_CHECK_HEADERS(time.h)
AC_CHECK_HEADERS(unistd.h)
AC_CHECK_HEADERS(winsock.h)
AC_CHECK_HEADERS(sys/termios.h)
AC_CHECK_HEADERS(termios.h)

dnl These headers need prerequisits before the tests will pass 
dnl AC_CHECK_HEADERS(net/if.h)
dnl AC_CHECK_HEADERS(netinet/icmp6.h)
dnl AC_CHECK_HEADERS(netinet/ip6.h)
dnl AC_CHECK_HEADERS(netinet/ip_icmp.h)

AC_MSG_CHECKING(for special libxml2 includes)
if test "x$XML2CONFIG" = "x"; then
   AC_MSG_ERROR(libxml2 config not found)
else
   XML2HEAD="`$XML2CONFIG --cflags`"
   AC_MSG_RESULT($XML2HEAD)
   AC_CHECK_LIB(xml2, xmlReadMemory)
fi

CPPFLAGS="$CPPFLAGS $XML2HEAD"

AC_CHECK_HEADERS(libxml/xpath.h)
if test "$ac_cv_header_libxml_xpath_h" != "yes"; then
   AC_MSG_ERROR(The libxml developement headers were not found)
fi

dnl Check syslog.h for 'facilitynames' table
dnl
AC_CACHE_CHECK([for facilitynames in syslog.h],ac_cv_HAVE_SYSLOG_FACILITYNAMES,[
AC_TRY_COMPILE([
#define SYSLOG_NAMES
#include <stdlib.h>
#include <syslog.h>
],
[ void *fnames; fnames = facilitynames; ],
ac_cv_HAVE_SYSLOG_FACILITYNAMES=yes,ac_cv_HAVE_SYSLOG_FACILITYNAMES=no,ac_cv_HAVE_SYSLOG_FACILITYNAMES=cross)])
if test x"$ac_cv_HAVE_SYSLOG_FACILITYNAMES" = x"yes"; then
    AC_DEFINE(HAVE_SYSLOG_FACILITYNAMES,1,[ ])
fi

dnl Check for POSIX signals
dnl
AC_CACHE_CHECK([have POSIX signals],ac_cv_HAVE_POSIX_SIGNALS,[
AC_TRY_COMPILE([
#include <signal.h>
],
[ struct sigaction act, oact; sigaction(0, &act, &oact); return 0;],
ac_cv_HAVE_POSIX_SIGNALS=yes,ac_cv_HAVE_POSIX_SIGNALS=no,ac_cv_HAVE_POSIX_SIGNALS=cross)])
if test x"$ac_cv_HAVE_POSIX_SIGNALS" = x"yes"; then
    AC_DEFINE(HAVE_POSIX_SIGNALS,1,[ ])
fi

dnl 'reboot()' system call: one argument (e.g. Linux) or two (e.g. Solaris)?
dnl
AC_CACHE_CHECK([number of arguments in reboot system call],
  ac_cv_REBOOT_ARGS,[
    AC_TRY_COMPILE(
      [#include <sys/reboot.h>],
      [(void)reboot(0);],
      ac_cv_REBOOT_ARGS=1,
      [AC_TRY_COMPILE(
        [#include <sys/reboot.h>],
        [(void)reboot(0,(void *)0);],
        ac_cv_REBOOT_ARGS=2,
        ac_cv_REBOOT_ARGS=0
      )],
      ac_cv_REBOOT_ARGS=0
    )
  ]
)
dnl Argument count of 0 suggests no known 'reboot()' call.
if test "$ac_cv_REBOOT_ARGS" -ge "1"; then
  AC_DEFINE_UNQUOTED(REBOOT_ARGS,$ac_cv_REBOOT_ARGS,[number of arguments for reboot system call])
fi

AC_PATH_PROGS(REBOOT, reboot, /sbin/reboot)
AC_SUBST(REBOOT)
AC_SUBST(REBOOT_OPTIONS)
AC_DEFINE_UNQUOTED(REBOOT, "$REBOOT", path to the reboot command)
AC_DEFINE_UNQUOTED(REBOOT_OPTIONS, "$REBOOT_OPTIONS", reboot options)

AC_PATH_PROGS(POWEROFF_CMD, poweroff, /sbin/poweroff)
AC_SUBST(POWEROFF_CMD)
AC_SUBST(POWEROFF_OPTIONS)
AC_DEFINE_UNQUOTED(POWEROFF_CMD, "$POWEROFF_CMD", path to the poweroff command)
AC_DEFINE_UNQUOTED(POWEROFF_OPTIONS, "$POWEROFF_OPTIONS", poweroff options)

dnl Sockets are our preferred and supported comms mechanism.  But the
dnl implementation needs to be able to convey credentials: some don't.
dnl So on a few OSes, credentials-carrying streams might be a better choice.
dnl
dnl Solaris releases up to and including "9" fall into this category
dnl (its sockets don't carry credentials; streams do).
dnl
dnl At Solaris 10, "getpeerucred()" is available, for both sockets and
dnl streams, so it should probably use (preferred) socket mechanism.

AC_CHECK_HEADERS(stropts.h)	dnl streams available (fallback option)

AC_CHECK_HEADERS(ucred.h)	dnl e.g. Solaris 10 decl. of "getpeerucred()"
AC_CHECK_FUNCS(getpeerucred)

dnl ************************************************************************
dnl checks for headers needed by clplumbing On BSD
AC_CHECK_HEADERS(sys/syslimits.h)
if test "$ac_cv_header_sys_param_h" = no; then
	AC_CHECK_HEADERS(sys/ucred.h)
else
	AC_CHECK_HEADERS(sys/ucred.h,[],[],[#include <sys/param.h>])
fi

dnl ************************************************************************
dnl checks for headers needed by clplumbing On Solaris
AC_CHECK_HEADERS(sys/cred.h xti.h)

dnl ************************************************************************
dnl checks for headers needed by clplumbing On FreeBSD/Solaris
AC_CHECK_HEADERS(sys/filio.h)

dnl ========================================================================
dnl Structures
dnl ========================================================================

AC_CHECK_MEMBERS([struct tm.tm_gmtoff],,,[[#include <time.h>]])
AC_CHECK_TYPES([nfds_t],,,[[#include <poll.h>]])

AC_MSG_CHECKING(if clock_t is long enough)
if test $ac_cv_sizeof_clock_t -ge 8; then
  AC_MSG_RESULT(yes)
  AC_DEFINE(CLOCK_T_IS_LONG_ENOUGH, 1, [Set if CLOCK_T is adequate by itself for the "indefinite future" (>= 100 years)])
else
  AC_MSG_RESULT(no)
fi

dnl ========================================================================
dnl Functions
dnl ========================================================================

AC_CHECK_FUNCS(g_log_set_default_handler)
AC_CHECK_FUNCS(getopt, AC_DEFINE(HAVE_DECL_GETOPT,  1, [Have getopt function]))
AC_CHECK_FUNCS(getpeereid)

dnl **********************************************************************
dnl Check for various argv[] replacing functions on various OSs
dnl
dnl Borrowed from Proftpd
dnl Proftpd is Licenced under the terms of the GNU General Public Licence
dnl and is available from http://www.proftpd.org/
dnl

AC_CHECK_FUNCS(setproctitle)
AC_CHECK_HEADERS(libutil.h)
AC_CHECK_LIB(util, setproctitle,
        [AC_DEFINE(HAVE_SETPROCTITLE,1,[ ])
                ac_cv_func_setproctitle="yes" ; LIBS="$LIBS -lutil"])

if test "$ac_cv_func_setproctitle" = "yes"; then
  pf_argv_set="PF_ARGV_NONE"
fi

if test "$pf_argv_set" = ""; then
  AC_CHECK_HEADERS(sys/pstat.h)
  if test "$ac_cv_header_pstat_h" = "yes"; then
    AC_CHECK_FUNCS(pstat)

    if test "$ac_cv_func_pstat" = "yes"; then
        pf_argv_set="PF_ARGV_PSTAT"
    else
        pf_argv_set="PF_ARGV_WRITEABLE"
    fi
  fi

  if test "$pf_argv_set" = ""; then
    AC_EGREP_HEADER([#define.*PS_STRINGS.*],sys/exec.h,
                        have_psstrings="yes",have_psstrings="no")
    if test "$have_psstrings" = "yes"; then
        pf_argv_set="PF_ARGV_PSSTRINGS"
    fi
  fi

  if test "$pf_argv_set" = ""; then
    AC_CACHE_CHECK(whether __progname and __progname_full are available,
                    pf_cv_var_progname,
                    AC_TRY_LINK([extern char *__progname, *__progname_full;],
                        [__progname = "foo"; __progname_full = "foo bar";],
                        pf_cv_var_progname="yes", pf_cv_var_progname="no"))

    if test "$pf_cv_var_progname" = "yes"; then
        AC_DEFINE(HAVE___PROGNAME,1,[ ])
    fi

    AC_CACHE_CHECK(which argv replacement method to use,
                    pf_cv_argv_type,
                    AC_EGREP_CPP(yes,[
#if defined(__GNU_HURD__)
  yes
#endif
  ],pf_cv_argv_type="new", pf_cv_argv_type="writeable"))

    if test "$pf_cv_argv_type" = "new"; then
        pf_argv_set="PF_ARGV_NEW"
    fi

    if test "$pf_argv_set" = ""; then
        pf_argv_set="PF_ARGV_WRITEABLE"
    fi
  fi
fi
AC_DEFINE_UNQUOTED(PF_ARGV_TYPE, $pf_argv_set,
        mechanism to pretty-print ps output: setproctitle-equivalent)

dnl End of tests borrowed from Proftpd

dnl ========================================================================
dnl   ltdl
dnl ========================================================================

AC_CHECK_LIB(ltdl, lt_dlopen, [LTDL_foo=1])
if test "x${enable_bundled_ltdl}" = "xyes"; then
   if test $ac_cv_lib_ltdl_lt_dlopen = yes; then
      AC_MSG_NOTICE([Disabling usage of installed ltdl])
   fi
   ac_cv_lib_ltdl_lt_dlopen=no
fi

LIBLTDL_DIR=""
if test $ac_cv_lib_ltdl_lt_dlopen != yes ; then
   AC_MSG_NOTICE([Installing local ltdl])
   LIBLTDL_DIR=libltdl
   ( cd $srcdir ; $TAR -xvf libltdl.tar )
   if test "$?" -ne 0; then
     AC_MSG_ERROR([$TAR of libltdl.tar in $srcdir failed])
   fi
   AC_CONFIG_SUBDIRS(libltdl)
else
   LIBS="$LIBS -lltdl"
   AC_MSG_NOTICE([Using installed ltdl])
   INCLTDL=""
   LIBLTDL=""
fi

AC_SUBST(INCLTDL)
AC_SUBST(LIBLTDL)
AC_SUBST(LIBLTDL_DIR)

dnl ========================================================================
dnl   libnet
dnl ========================================================================

AC_ARG_ENABLE([libnet],
 [  --enable-libnet 	Use libnet for ARP based funcationality, [default=try]], 
 [], [enable_libnet=try])

libnet=""
libnet_version="none"
LIBNETLIBS=""
LIBNETDEFINES=""

AC_MSG_CHECKING(if libnet is required)
libnet_fatal=$enable_libnet
case $enable_libnet in
     no) ;;
     yes|libnet10|libnet11|10|11) libnet_fatal=yes;;
     try)
	case $host_os in
	     *Linux*|*linux*) libnet_fatal=no;;
	     *) libnet_fatal=yes;; dnl legacy behavior
	esac
	;;
     *) libnet_fatal=yes; enable_libnet=try;;
esac
AC_MSG_RESULT($libnet_fatal)

if test "x$enable_libnet" != "xno"; then
   AC_PATH_PROGS(LIBNETCONFIG, libnet-config)

   AC_CHECK_LIB(nsl, t_open)			dnl -lnsl
   AC_CHECK_LIB(socket, socket)			dnl -lsocket
   AC_CHECK_LIB(net, libnet_get_hwaddr, LIBNETLIBS=" -lnet", [])
 fi
 
AC_MSG_CHECKING(for libnet)
if test "x$LIBNETLIBS" != "x" -o "x$enable_libnet" = "xlibnet11"; then
      LIBNETDEFINES=""
      if test "$ac_cv_lib_nsl_t_open" = yes; then
         LIBNETLIBS="-lnsl $LIBNETLIBS"
      fi
      if test "$ac_cv_lib_socket_socket" = yes; then
         LIBNETLIBS="-lsocket $LIBNETLIBS"
      fi

      libnet=net
      libnet_version="libnet1.1"
fi

if test "x$enable_libnet" = "xtry" -o "x$enable_libnet" = "xlibnet10"; then
   if test "x$LIBNETLIBS" = x -a "x${LIBNETCONFIG}" != "x" ; then
      LIBNETDEFINES="`$LIBNETCONFIG --defines` `$LIBNETCONFIG --cflags`";
      LIBNETLIBS="`$LIBNETCONFIG --libs`";
      libnet_version="libnet1.0 (old)"
      case $LIBNETLIBS in
        *-l*)	libnet=`echo $LIBNETLIBS | sed 's%.*-l%%'`;;
        *)	libnet_version=none;;
      esac

      CPPFLAGS="$CPPFLAGS $LIBNETDEFINES"

      AC_CHECK_HEADERS(libnet.h)
      if test "$ac_cv_header_libnet_h" = no; then
	libnet_version=none
      fi
   fi
fi
AC_MSG_RESULT(found $libnet_version)

if test "$libnet_version" = none; then
   LIBNETLIBS=""
   LIBNETDEFINES=""
   if test $libnet_fatal = yes; then
        AC_MSG_ERROR(libnet not found)
   fi

else
   AC_CHECK_LIB($libnet,libnet_init,
      [new_libnet=yes; AC_DEFINE(HAVE_LIBNET_1_1_API, 1, Libnet 1.1 API)],
      [new_libnet=no; AC_DEFINE(HAVE_LIBNET_1_0_API, 1, Libnet 1.0 API)],$LIBNETLIBS)
fi

dnl ************************************************************************
dnl * Check for netinet/icmp6.h to enable the IPv6addr resource agent
AC_CHECK_HEADERS(netinet/icmp6.h,[],[],[#include <sys/types.h>])
AM_CONDITIONAL(USE_IPV6ADDR, test "$ac_cv_header_netinet_icmp6_h" = yes -a "$new_libnet" = yes )


dnl ========================================================================
dnl    SNMP
dnl ========================================================================

SNMPLIB=""
SNMPCONFIG=""

ENABLE_SNMP="yes"
if test "x${enable_snmp}" = "xno"; then
   ENABLE_SNMP="no"
fi

AC_CHECK_HEADERS(ucd-snmp/snmp.h,[],[],[#include <sys/types.h>
#include <ucd-snmp/asn1.h>])
AC_CHECK_HEADERS(net-snmp/net-snmp-config.h)

if test "x${ENABLE_SNMP}" = "xno"; then
   # nothing
   :
elif test "x${ac_cv_header_net_snmp_net_snmp_config_h}" = "xyes"; then
	AC_PATH_PROGS(SNMPCONFIG, net-snmp-config)
	if test "X${SNMPCONFIG}" = "X"; then
		AC_MSG_RESULT(You need the net_snmp development package to continue.)
		ENABLE_SNMP="no"
	else
		AC_MSG_CHECKING(for special snmp libraries)
		SNMPLIB=`${SNMPCONFIG} --libs`
		AC_MSG_RESULT($SNMPLIB)
	fi
elif test "x${ac_cv_header_ucd_snmp_snmp_h}" = "xyes"; then
	# UCD SNMP
	# ucd-snmp-config does not seem to exist, so just 
	# rely on people having their LDFLAGS set to the path where
	AC_CHECK_LIB(snmp, init_snmp, SNMPLIB="-lsnmp")
	if test "X${SNMPLIB}" = "X"; then
		AC_CHECK_LIB(ucdsnmp, init_snmp, SNMPLIB="-lucdsnmp")
	fi
	if test "X${SNMPLIB}" = "X"; then
		ENABLE_SNMP="no"
		AC_MSG_RESULT("Could not find ucdsnmp libary."
			"Please make sure that libsnmp or libucdsnmp"
			"are in your library path. Or the path to LDFLAGS")
	fi
else
	ENABLE_SNMP="no"
fi

AC_SUBST(SNMPLIB)

dnl ========================================================================
dnl    Stonith Devices
dnl ========================================================================

if test "x${enable_ipmilan}" = "x"; then
	enable_ipmilan="yes"
fi
if test "x${enable_ipmilan}" = "xyes" -o "x${enable_ipmilan}" = "xtry"; then
	AC_MSG_CHECKING(For libOpenIPMI version 1.4 or greater)
	AC_TRY_COMPILE([#include <OpenIPMI/ipmiif.h>],
		       [ #if (OPENIPMI_VERSION_MAJOR == 1) && (OPENIPMI_VERSION_MINOR < 4) 
			 #error "Too Old"
			 #endif ],
		       AC_MSG_RESULT("yes"); enable_ipmilan="yes",
		       AC_MSG_RESULT("no");  enable_ipmilan="no")
else
	enable_ipmilan="no"
fi

AC_CHECK_HEADERS(curl/curl.h)
AC_CHECK_HEADERS(openhpi/SaHpi.h)
AC_CHECK_HEADERS(vacmclient_api.h)

AM_CONDITIONAL(USE_APC_SNMP, test "$ENABLE_SNMP" = "yes")
AM_CONDITIONAL(USE_VACM, test "$ac_cv_header_vacmclient_api_h" = yes)
AM_CONDITIONAL(USE_DRAC3, test "$ac_cv_header_curl_curl_h" = yes -a "$ac_cv_header_libxml_xpath_h" = yes)
AM_CONDITIONAL(USE_OPENHPI, test "$ac_cv_header_openhpi_SaHpi_h" = yes && pkg-config --atleast-version 2.6 openhpi)
AM_CONDITIONAL(IPMILAN_BUILD, test "X$enable_ipmilan" = "Xyes")

dnl ========================================================================
dnl    ZLIB and BZ2
dnl ========================================================================

dnl check if header file and lib are there for zlib
zlib_installed="yes"
AC_CHECK_HEADERS(zlib.h, , [zlib_installed="no"],)
AC_CHECK_LIB(z, compress , , [zlib_installed="no"])
AM_CONDITIONAL(BUILD_ZLIB_COMPRESS_MODULE, test "x${zlib_installed}" = "xyes")
if test "x${zlib_installed}" = "xno"; then
	FatalMissingThing "zlib" \
	  "The zlib library is missing"
fi

bz2_installed="yes"
AC_CHECK_HEADERS(bzlib.h, , [bz2_installed="no"],)
AC_CHECK_LIB(bz2, BZ2_bzBuffToBuffCompress , , [bz2_installed="no"])
AM_CONDITIONAL(BUILD_BZ2_COMPRESS_MODULE, test "x${bz2_installed}" = "xyes")

#if test x$ac_cv_lib_bz2_BZ2_bzBuffToBuffCompress != xyes ; then
#   AC_MSG_ERROR(BZ2 libraries not found)
#fi

if test x$ac_cv_header_bzlib_h != xyes; then
   AC_MSG_ERROR(BZ2 Development headers not found)
fi

dnl ========================================================================
dnl    Upstart via DBus
dnl ========================================================================

if test x$enable_upstart = xyes; then
   PKG_CHECK_MODULES(DBUS, [dbus-1, dbus-glib-1])
   AC_SUBST(DBUS_CFLAGS)
   AC_SUBST(DBUS_LIBS)
   AC_PATH_PROGS(DBUS_BINDING_TOOL, dbus-binding-tool)
fi
AM_CONDITIONAL(UPSTART, test x$enable_upstart = xyes)


dnl ========================================================================
dnl checks for library functions to replace them
dnl
dnl     NoSuchFunctionName:
dnl             is a dummy function which no system supplies.  It is here to make
dnl             the system compile semi-correctly on OpenBSD which doesn't know
dnl             how to create an empty archive
dnl
dnl     scandir: Only on BSD.
dnl             System-V systems may have it, but hidden and/or deprecated.
dnl             A replacement function is supplied for it.
dnl
dnl     setenv: is some bsdish function that should also be avoided (use
dnl             putenv instead)
dnl             On the other hand, putenv doesn't provide the right API for the
dnl             code and has memory leaks designed in (sigh...)  Fortunately this
dnl             A replacement function is supplied for it.
dnl
dnl     strerror: returns a string that corresponds to an errno.
dnl             A replacement function is supplied for it.
dnl
dnl     unsetenv: is some bsdish function that should also be avoided (No 
dnl             replacement)
dnl             A replacement function is supplied for it.
dnl
dnl	strnlen: is a gnu function similar to strlen, but safer.
dnl		We wrote a tolearably-fast replacement function for it.
dnl
dnl	strndup: is a gnu function similar to strdup, but safer.
dnl		We wrote a tolearably-fast replacement function for it.
dnl
dnl	daemon: is a GNU function.  The daemon() function is for programs wishing to
dnl             detach themselves from the controlling terminal and run in the
dnl             background as system daemon
dnl             A replacement function is supplied for it.

AC_REPLACE_FUNCS(alphasort inet_pton NoSuchFunctionName scandir setenv strerror unsetenv strnlen strndup daemon strlcpy strlcat)

dnl ========================================================================
dnl Compiler flags
dnl ========================================================================

dnl Make sure that CFLAGS is not exported. If the user did
dnl not have CFLAGS in their environment then this should have
dnl no effect. However if CFLAGS was exported from the user's
dnl environment, then the new CFLAGS will also be exported
dnl to sub processes.

CC_ERRORS=""
CC_EXTRAS=""

if export | fgrep " CFLAGS=" > /dev/null; then
	SAVED_CFLAGS="$CFLAGS"
	unset CFLAGS
	CFLAGS="$SAVED_CFLAGS"
	unset SAVED_CFLAGS
fi

if test "$GCC" != yes; then
        CFLAGS="$CFLAGS -g"
	enable_fatal_warnings=no
else
        CFLAGS="$CFLAGS -ggdb"

	# We had to eliminate -Wnested-externs because of libtool changes
        EXTRA_FLAGS="-fgnu89-inline
		-fstack-protector-all
		-Wall
		-Waggregate-return
		-Wbad-function-cast 
		-Wcast-qual
		-Wcast-align 
		-Wdeclaration-after-statement
		-Wendif-labels
		-Wfloat-equal
		-Wformat=2
		-Wformat-security
		-Wformat-nonliteral
		-Winline
		-Wmissing-prototypes 
		-Wmissing-declarations 
		-Wmissing-format-attribute
		-Wnested-externs
		-Wno-long-long
		-Wno-strict-aliasing
		-Wpointer-arith 
		-Wstrict-prototypes
    		-Wunsigned-char
		-Wwrite-strings"

# Additional warnings it might be nice to enable one day
#		-Wshadow
#		-Wunreachable-code

	for j in $EXTRA_FLAGS
	do
	  if
	    cc_supports_flag $j
	  then
	    CC_EXTRAS="$CC_EXTRAS $j"
	  fi
	done

dnl In lib/ais/Makefile.am there's a gcc option available as of v4.x

	GCC_MAJOR=`gcc -v 2>&1 | awk 'END{print $3}' | sed 's/[.].*//'`
	AM_CONDITIONAL(GCC_4, test "${GCC_MAJOR}" = 4)

dnl System specific options

	case "$host_os" in
  	*linux*|*bsd*)
		if test "${enable_fatal_warnings}" = "unknown"; then
        		enable_fatal_warnings=yes
        	fi
          	;;
	esac

	if test "x${enable_fatal_warnings}" != xno && cc_supports_flag -Werror ; then
	   enable_fatal_warnings=yes
	else
	   enable_fatal_warnings=no
        fi

	if test "x${enable_ansi}" != xno && cc_supports_flag -std=iso9899:199409 ; then
	  AC_MSG_NOTICE(Enabling ANSI Compatibility)
	  CC_EXTRAS="$CC_EXTRAS -ansi -D_GNU_SOURCE -DANSI_ONLY"
	fi

  	AC_MSG_NOTICE(Activated additional gcc flags: ${CC_EXTRAS})
fi

CFLAGS="$CFLAGS $CC_EXTRAS"

NON_FATAL_CFLAGS="$CFLAGS"
AC_SUBST(NON_FATAL_CFLAGS)

dnl
dnl We reset CFLAGS to include our warnings *after* all function
dnl checking goes on, so that our warning flags don't keep the
dnl AC_*FUNCS() calls above from working.  In particular, -Werror will
dnl *always* cause us troubles if we set it before here.
dnl
dnl
if test "x${enable_fatal_warnings}" = xyes ; then
   AC_MSG_NOTICE(Enabling Fatal Warnings)
   CFLAGS="$CFLAGS -Werror"
fi
AC_SUBST(CFLAGS)

dnl This is useful for use in Makefiles that need to remove one specific flag
CFLAGS_COPY="$CFLAGS"
AC_SUBST(CFLAGS_COPY)

AC_SUBST(LIBADD_DL)	dnl extra flags for dynamic linking libraries
AC_SUBST(LIBADD_INTL)	dnl extra flags for GNU gettext stuff...

AC_SUBST(LOCALE)

dnl Options for cleaning up the compiler output 
PRETTY_CC=""
QUIET_LIBTOOL_OPTS=""
QUIET_MAKE_OPTS=""
if test x"${enable_pretty}" = "xyes"; then
   enable_quiet="yes"
   echo "install_sh: ${install_sh}"
   PRETTY_CC="`pwd`/tools/ccdv"
   dnl It would be nice if this was rebuilt when needed too...
   mkdir `pwd`/tools/ 2>/dev/null
   ${CC} $CFLAGS -o `pwd`/tools/ccdv ${srcdir}/tools/ccdv.c
   CC="\$(PRETTY_CC) ${CC}"
fi
if test "x${enable_quiet}" = "xyes"; then
   QUIET_LIBTOOL_OPTS="--quiet"
   QUIET_MAKE_OPTS="--quiet"
fi

AC_MSG_RESULT(Supress make details: ${enable_quiet})
AC_MSG_RESULT(Pretty print compiler output: ${enable_pretty})

dnl Put the above variables to use
LIBTOOL="${LIBTOOL} --tag=CC \$(QUIET_LIBTOOL_OPTS)"
MAKE="${MAKE} \$(QUIET_MAKE_OPTS)"

AC_SUBST(CC)
AC_SUBST(MAKE)
AC_SUBST(LIBTOOL)
AC_SUBST(PRETTY_CC)
AC_SUBST(QUIET_MAKE_OPTS)
AC_SUBST(QUIET_LIBTOOL_OPTS)

dnl The Makefiles and shell scripts we output
AC_CONFIG_FILES(Makefile				        \
config/Makefile						\
include/Makefile						\
   include/pils/Makefile					\
   include/pils/plugin.h					\
   include/clplumbing/Makefile					\
   include/lrm/Makefile						\
   include/stonith/Makefile					\
lib/Makefile							\
   lib/pils/Makefile						\
   lib/clplumbing/Makefile					\
   lib/stonith/Makefile						\
   lib/lrm/Makefile						\
   lib/plugins/Makefile						\
      lib/plugins/InterfaceMgr/Makefile				\
      lib/plugins/compress/Makefile					\
      lib/plugins/lrm/Makefile					\
         lib/plugins/lrm/dbus/Makefile				\
      lib/plugins/stonith/Makefile				\
         lib/plugins/stonith/ribcl.py				\
         lib/plugins/stonith/external/Makefile			\
            lib/plugins/stonith/external/drac5			\
            lib/plugins/stonith/external/kdumpcheck		\
            lib/plugins/stonith/external/ssh			\
            lib/plugins/stonith/external/ippower9258	\
            lib/plugins/stonith/external/xen0-ha		\
lrm/Makefile					        	\
   lrm/lrmd/Makefile				        	\
   lrm/admin/Makefile				        	\
   lrm/admin/cibsecret				        	\
   lrm/test/Makefile				        	\
   lrm/test/regression.sh					\
   lrm/test/lrmregtest						\
   lrm/test/LRMBasicSanityCheck			        	\
   lrm/test/testcases/Makefile			        	\
logd/Makefile					        	\
logd/logd					        	\
logd/logd.service					        	\
replace/Makefile				        	\
hb_report/Makefile				        	\
   hb_report/hb_report				        	\
doc/Makefile							\
   doc/ha_logd.xml						\
   doc/ha_logger.xml						\
   doc/stonith.xml						\
   doc/meatclient.xml						\
   doc/stonith/Makefile
)

dnl Now process the entire list of files added by previous 
dnl  calls to AC_CONFIG_FILES()
AC_OUTPUT()

dnl *****************
dnl Configure summary
dnl *****************

AC_MSG_RESULT([])
AC_MSG_RESULT([$PACKAGE configuration:])
AC_MSG_RESULT([  Version                  = ${VERSION} (Build: $GLUE_BUILD_VERSION)])
AC_MSG_RESULT([  Features                 =${FEATURES}])
AC_MSG_RESULT([])
AC_MSG_RESULT([  Prefix                   = ${prefix}])
AC_MSG_RESULT([  Executables              = ${sbindir}])
AC_MSG_RESULT([  Man pages                = ${mandir}])
AC_MSG_RESULT([  Libraries                = ${libdir}])
AC_MSG_RESULT([  Header files             = ${includedir}])
AC_MSG_RESULT([  Arch-independent files   = ${datadir}])
AC_MSG_RESULT([  Documentation            = ${docdir}])
AC_MSG_RESULT([  State information        = ${localstatedir}])
AC_MSG_RESULT([  System configuration     = ${sysconfdir}])
AC_MSG_RESULT([])
AC_MSG_RESULT([  Use system LTDL          = ${ac_cv_lib_ltdl_lt_dlopen}])
AC_MSG_RESULT([])
AC_MSG_RESULT([  HA group name            = ${GLUE_DAEMON_GROUP}])
AC_MSG_RESULT([  HA user name             = ${GLUE_DAEMON_USER}])
AC_MSG_RESULT([])
AC_MSG_RESULT([  CFLAGS                   = ${CFLAGS}])
AC_MSG_RESULT([  Libraries                = ${LIBS}])
AC_MSG_RESULT([  Stack Libraries          = ${CLUSTERLIBS}])

