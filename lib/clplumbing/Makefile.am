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


CFLAGS			= @CFLAGS@  -DALIGNFUNC=@ALIGN@ -DMSGHDR_TYPE=@MSGHDR_TYPE@

## libraries

lib_LTLIBRARIES		= libplumb.la

libplumb_la_SOURCES	= 		\
			Gmain_timeout.c	\
			base64.c	\
			ipcsocket.c	\
			cl_log.c	\
			cl_poll.c	\
			longclock.c	\
			mkstemp_mode.c	\
			ocf_ipc.c	\
			proctrack.c	\
			timers.c

libplumb_la_LDFLAGS	= -version-info 0:0:0
