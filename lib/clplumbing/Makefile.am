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

INCLUDES                = -I$(top_builddir)/include -I$(top_srcdir)/include \
			-I$(top_builddir)/linux-ha -I$(top_srcdir)/linux-ha  \
			-I$(top_builddir)/libltdl -I$(top_srcdir)/libltdl


AM_CFLAGS			= @CFLAGS@  -DALIGNFUNC=@ALIGN@ -DMSGHDR_TYPE=@MSGHDR_TYPE@ -DIPC_TIME_DEBUG

## libraries

lib_LTLIBRARIES		= libplumb.la

libplumb_la_SOURCES	= 		\
			Gmain_timeout.c	\
			GSource.c	\
			base64.c	\
			ipcsocket.c	\
			cl_log.c	\
			cl_malloc.c	\
			cl_msg.c	\
			cl_msg_types.c  \
			cl_netstring.c	\
			cl_poll.c	\
			cl_signal.c	\
			coredumps.c	\
			cpulimits.c	\
			longclock.c	\
			mkstemp_mode.c	\
			ocf_ipc.c	\
			proctrack.c	\
			realtime.c	\
			timers.c	\
			uids.c 		\
			setproctitle.c \
			cl_uuid.c

libplumb_la_LIBADD      = $(top_builddir)/replace/libreplace.la

testdir = $(libdir)/@HB_PKG@
test_PROGRAMS = ipctest ipctransientclient ipctransientserver

libplumb_la_LDFLAGS	= -version-info 1:0:0

ipctest_SOURCES = ipctest.c
ipctest_LDADD = libplumb.la $(top_builddir)/replace/libreplace.la $(GLIBLIB)

#ipctransient_SOURCES = ipctransient.c
#ipctransient_LDADD = libplumb.la $(top_builddir)/replace/libreplace.la $(top_builddir)/heartbeat/libhbclient.la $(GLIBLIB)

ipctransientclient_SOURCES = ipctransientclient.c
ipctransientclient_LDADD = libplumb.la $(top_builddir)/replace/libreplace.la $(GLIBLIB)

ipctransientserver_SOURCES = ipctransientserver.c
ipctransientserver_LDADD = libplumb.la $(top_builddir)/replace/libreplace.la $(GLIBLIB)

#netstring_test_SOURCES	= netstring_test.c
#netstring_test_LDADD	= libplumb.la $(top_builddir)/replace/libreplace.la libhbclient.la $(gliblib)

