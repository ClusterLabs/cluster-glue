#
# InterfaceMgr: Interface manager plugins for Linux-HA
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

if BUILD_ZLIB_COMPRESS_MODULE
zlibmodule = zlib.la
endif

if BUILD_BZ2_COMPRESS_MODULE
bz2module = bz2.la
endif

SUBDIRS                 = 

INCLUDES                = -I$(top_builddir)/include -I$(top_srcdir)/include \
			-I$(top_builddir)/linux-ha -I$(top_srcdir)/linux-ha  \
			-I$(top_builddir)/libltdl -I$(top_srcdir)/libltdl  \
			-I$(top_builddir)/lib/upmls -I$(top_srcdir)/lib/upmls

AM_CFLAGS		= @CFLAGS@

## libraries

halibdir		= $(libdir)/@HB_PKG@
plugindir		= $(halibdir)/plugins/compress
plugin_LTLIBRARIES	= $(zlibmodule) $(bz2module)

zlib_la_SOURCES		= zlib.c
zlib_la_LDFLAGS		= -export-dynamic -module -avoid-version -lz
zlib_la_LIBADD		= $(top_builddir)/replace/libreplace.la 

bz2_la_SOURCES         = bz2.c
bz2_la_LDFLAGS         = -export-dynamic -module -avoid-version -lbz2
bz2_la_LIBADD          = $(top_builddir)/replace/libreplace.la

