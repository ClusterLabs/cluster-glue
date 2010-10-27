#
# pils: Linux-HA heartbeat code
#
# Copyright (C) 2001 Alan Robertson
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


AM_CFLAGS			= @CFLAGS@

## include files
#pkginclude_HEADERS	= $(top_srcdir)/include/pils/plugin.h \
#			$(top_srcdir)/include/pils/interface.h

## binaries
#sbin_PROGRAMS		= main


#main_SOURCES		= main.c

#main_LDADD		= libpils.la @LIBLTDL@ \
#			$(GLIBLIB) \
#			$(top_builddir)/replace/libreplace.la
#main_LDFLAGS		= @LIBADD_DL@ @LIBLTDL@ -export-dynamic @DLOPEN_FORCE_FLAGS@


## libraries

lib_LTLIBRARIES		= libpils.la

plugindir		= $(libdir)/@HB_PKG@/plugins/test
plugin_LTLIBRARIES	= test.la 

libpils_la_SOURCES	= pils.c
libpils_la_LDFLAGS	= -version-info 2:0:0
libpils_la_LIBADD	= $(top_builddir)/replace/libreplace.la	\
			@LIBLTDL@ $(GLIBLIB)
test_la_SOURCES		= test.c
test_la_LDFLAGS		= -export-dynamic -module -avoid-version
