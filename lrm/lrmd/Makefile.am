#
#  Author: Sun Jiang Dong <sunjd@cn.ibm.com>
#  Copyright (c) 2002 International Business Machines
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
# along with this program; if not, see <http://www.gnu.org/licenses/>.
#
MAINTAINERCLEANFILES = Makefile.in

AM_CPPFLAGS     = -I$(top_builddir)/include  -I$(top_srcdir)/include     \
                  -I$(top_builddir)/libltdl  -I$(top_srcdir)/libltdl     \
		  -I$(top_builddir)/linux-ha -I$(top_srcdir)/linux-ha    \
		  -I$(top_builddir)          -I$(top_srcdir)

halibdir	=  $(libdir)/@HB_PKG@

COMMONLIBS	=  $(top_builddir)/lib/clplumbing/libplumb.la   \
		   $(GLIBLIB)
#		   $(top_builddir)/lib/apphb/libapphb.la 	

halib_PROGRAMS 	=  lrmd

lrmd_SOURCES 	=  lrmd.c audit.c cib_secrets.c lrmd_fdecl.h lrmd.h

lrmd_LDFLAGS 	=  $(top_builddir)/lib/lrm/liblrm.la 		\
		   $(COMMONLIBS) @LIBLTDL@			\
		   $(top_builddir)/lib/pils/libpils.la

noinst_HEADERS  = lrmd_fdecl.h lrmd.h

# make lrmd's owner as hacluster:haclient?
