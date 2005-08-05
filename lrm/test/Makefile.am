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

INCLUDES 	      =	-I$(top_builddir)/include  -I$(top_srcdir)/include \
			-I$(top_builddir)/linux-ha -I$(top_srcdir)/linux-ha \
			-I$(top_builddir)/libltdl -I$(top_srcdir)/libltdl

COMMONLIBS	      =	$(top_builddir)/lib/clplumbing/libplumb.la	\
			$(top_builddir)/lib/hbclient/libhbclient.la	\
	  		$(top_builddir)/lib/pils/libpils.la	\
			$(top_builddir)/lib/apphb/libapphb.la		\
                        $(GLIBLIB)

LRM_DIR			=	lrm
noinst_PROGRAMS 	= 	apitest plugintest callbacktest

apitest_SOURCES  	= 	apitest.c
apitest_LDFLAGS 	= 	$(COMMONLIBS)
apitest_LDADD 		= 	$(top_builddir)/lib/$(LRM_DIR)/liblrm.la
apitest_DEPENDENCIES    = 	$(top_builddir)/lib/$(LRM_DIR)/liblrm.la

plugintest_SOURCES 	= 	plugintest.c
plugintest_LDADD 	= 	$(top_builddir)/lib/clplumbing/libplumb.la $(GLIBLIB)
plugintest_LDFLAGS 	= 	-L$(top_builddir)/lib/pils -lpils @LIBLTDL@

callbacktest_SOURCES	=	callbacktest.c
callbacktest_LDFLAGS 	= 	$(COMMONLIBS)
callbacktest_LDADD 	= 	$(top_builddir)/lib/$(LRM_DIR)/liblrm.la
callbacktest_DEPENDENCIES    = 	$(top_builddir)/lib/$(LRM_DIR)/liblrm.la

testdir			= 	$(libdir)/heartbeat/lrmtest
test_SCRIPTS		=	LRMBasicSanityCheck
EXTRA_DIST		=	LRMBasicSanityCheck

#install-exec-local:
#	$(mkinstalldirs) $(DESTDIR)/$(testdir)
#	-chgrp $(HA_APIGROUP) $(DESTDIR)/$(testdir)
#	-chmod g+w $(DESTDIR)/$(testdir)
