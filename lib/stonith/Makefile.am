#
# Stonith: Shoot The Node In The Head
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
			-I$(top_builddir)/linux-ha -I$(top_srcdir)/linux-ha \
			-I$(top_builddir)/libltdl -I$(top_srcdir)/libltdl


AM_CFLAGS			= @CFLAGS@ -DST_TEXTDOMAIN='"@STONITHPKG@"' \
			-DSTONITH_MODULES='"@stonith_plugindir@"' \
			-DLOCALEDIR='"@LOCALE@"'

## include files

## binaries
sbin_PROGRAMS		= stonith meatclient


stonith_SOURCES		= main.c

stonith_LDADD		= $(top_builddir)/libltdl/libltdlc.la \
			libstonith.la $(GLIBLIB)
stonith_LDFLAGS		= @LIBADD_DL@ @LIBLTDL@ -export-dynamic -dlopen force -dlopen self @LIBADD_INTL@

meatclient_SOURCES	= meatclient.c 
meatclient_LDADD	= $(GLIBLIB)

## libraries

lib_LTLIBRARIES		= libstonith.la

libstonith_la_SOURCES	= expect.c stonith.c
libstonith_la_LDFLAGS	= -version-info 1:0:0
libstonith_la_LIBADD	= -L$(top_builddir)/lib/pils/ \
			-L$(top_builddir)/lib/pils/.libs/ -lpils $(GLIBLIB)

## Man pages

man_MANS		= stonith.8 meatclient.8

EXTRA_DIST              = $(man_MANS)
