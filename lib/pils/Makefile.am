#
# upmls: Linux-HA heartbeat code
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
			-I$(top_builddir)/libltdl -I$(top_srcdir)/libltdl  \
			-I$(top_builddir)/lib/upmls -I$(top_srcdir)/lib/upmls


CFLAGS			= @CFLAGS@

## include files
#pkginclude_HEADERS	= $(top_srcdir)/include/upmls/plugin.h \
#			$(top_srcdir)/include/pils/interface.h

## binaries
sbin_PROGRAMS		= main


main_SOURCES		= main.c

main_LDADD		= libupmls.la $(top_builddir)/libltdl/libltdlc.la
main_LDFLAGS		= @LIBADD_DL@ @LIBLTDL@ -export-dynamic -dlopen force -dlopen self


## libraries

lib_LTLIBRARIES		= libupmls.la

plugindir		= $(halibdir)/modules/PluginMgr
plugin_LTLIBRARIES	= test.la auth.la

libupmls_la_SOURCES	= pils.c
libupmls_la_LDFLAGS	= -version-info 0:0:0

test_la_SOURCES		= test.c
test_la_LDFLAGS		= -export-dynamic -module -avoid-version

auth_la_SOURCES		= auth.c
auth_la_LDFLAGS		= -export-dynamic -module -avoid-version
