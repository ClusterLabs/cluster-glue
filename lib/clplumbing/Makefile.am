#
# plumbing: OCF general plumbing libraries
#
# Copyright (C) 2002 Alan Robertson, International Business Machines
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#
MAINTAINERCLEANFILES    = Makefile.in


halibdir                = $(libdir)/@HB_PKG@

INCLUDES                = -I$(top_builddir)/include -I$(top_srcdir)/include \
			-I$(top_builddir)/linux-ha -I$(top_srcdir)/linux-ha  \
			-I$(top_builddir)/libltdl -I$(top_srcdir)/libltdl

## libraries

lib_LTLIBRARIES		= libplumb.la libplumbgpl.la

libplumb_la_SOURCES	= 		\
			base64.c	\
			cl_compress.c	\
			cl_log.c	\
			cl_misc.c 	\
			cl_msg.c	\
			cl_msg_types.c  \
			cl_netstring.c	\
			cl_pidfile.c	\
			cl_poll.c	\
			cl_random.c	\
			cl_signal.c	\
			cl_syslog.c	\
			cl_uuid.c	\
			cl_plugin.c	\
			cl_reboot.c	\
			coredumps.c	\
			cpulimits.c	\
			GSource.c	\
			ipcsocket.c	\
			longclock.c	\
			md5.c		\
			mkstemp_mode.c	\
			ocf_ipc.c	\
			proctrack.c	\
			realtime.c	\
			replytrack.c	\
			timers.c	\
			uids.c 	

libplumb_la_LIBADD      = $(top_builddir)/replace/libreplace.la \
			$(top_builddir)/lib/pils/libpils.la
libplumb_la_LDFLAGS	= -version-info 3:0:1

libplumbgpl_la_SOURCES	= setproctitle.c
libplumbgpl_la_LIBADD   = $(top_builddir)/replace/libreplace.la \
			$(top_builddir)/lib/pils/libpils.la
libplumbgpl_la_LDFLAGS	= -version-info 2:0:0

testdir = $(libdir)/@HB_PKG@
test_PROGRAMS = ipctest ipctransientclient ipctransientserver base64_md5_test
test_SCRIPTS  = transient-test.sh

ipctest_SOURCES = ipctest.c
ipctest_LDADD = libplumb.la $(top_builddir)/replace/libreplace.la $(GLIBLIB) \
		$(top_builddir)/lib/pils/libpils.la

noinst_HEADERS = ipctransient.h

#ipctransient_SOURCES = ipctransient.c
#ipctransient_LDADD = libplumb.la $(top_builddir)/replace/libreplace.la $(top_builddir)/heartbeat/libhbclient.la $(GLIBLIB)

ipctransientclient_SOURCES = ipctransientclient.c ipctransientlib.c
ipctransientclient_LDADD = libplumb.la $(top_builddir)/replace/libreplace.la $(GLIBLIB) \
			$(top_builddir)/lib/pils/libpils.la

ipctransientserver_SOURCES = ipctransientserver.c ipctransientlib.c
ipctransientserver_LDADD = libplumb.la $(top_builddir)/replace/libreplace.la $(GLIBLIB) \
			$(top_builddir)/lib/pils/libpils.la

#netstring_test_SOURCES	= netstring_test.c
#netstring_test_LDADD	= libplumb.la $(top_builddir)/replace/libreplace.la libhbclient.la $(gliblib)

base64_md5_test_SOURCES	= base64_md5_test.c
base64_md5_test_LDADD	= libplumb.la $(top_builddir)/replace/libreplace.la $(GLIBLIB)

EXTRA_DIST = $(test_SCRIPTS)
