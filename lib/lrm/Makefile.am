#
# Author: Sun Jiang Dong <sunjd@cn.ibm.com>
# Copyright (c) 2004 International Business Machines
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
MAINTAINERCLEANFILES = Makefile.in

INCLUDES                	=	-I$(top_builddir)/include -I$(top_srcdir)/include \
					-I$(top_builddir)/libltdl -I$(top_srcdir)/libltdl

lrmdir				=	$(localstatedir)/lib/heartbeat/lrm
COMMONLIBS			=	$(top_builddir)/lib/clplumbing/libplumb.la   \
					$(GLIBLIB)

lib_LTLIBRARIES = liblrm.la
liblrm_la_SOURCES = lrm_msg.c clientlib.c racommon.c
liblrm_la_LDFLAGS = -version-info 2:0:0 $(COMMONLIBS)
liblrm_la_CFLAGS = $(INCLUDES)

install-exec-local:
	$(mkinstalldirs) $(DESTDIR)$(lrmdir)
	-chgrp $(GLUE_DAEMON_GROUP) $(DESTDIR)/$(lrmdir)
	chmod 770 $(DESTDIR)/$(lrmdir)
