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

SUBDIRS = testcases

INCLUDES 	      =	-I$(top_builddir)/include  -I$(top_srcdir)/include \
			-I$(top_builddir)/libltdl -I$(top_srcdir)/libltdl

COMMONLIBS	      =	$(top_builddir)/lib/clplumbing/libplumb.la $(GLIBLIB)

noinst_PROGRAMS 	= 	apitest plugintest callbacktest

apitest_SOURCES  	= 	apitest.c
apitest_LDFLAGS 	= 	$(COMMONLIBS)
apitest_LDADD 		= 	$(top_builddir)/lib/$(LRM_DIR)/liblrm.la
apitest_DEPENDENCIES    = 	$(top_builddir)/lib/$(LRM_DIR)/liblrm.la

plugintest_SOURCES 	= 	plugintest.c
plugintest_LDADD 	= 	$(COMMONLIBS)
plugintest_LDFLAGS 	= 	-L$(top_builddir)/lib/pils -lpils @LIBLTDL@

callbacktest_SOURCES	=	callbacktest.c
callbacktest_LDFLAGS 	= 	$(COMMONLIBS)
callbacktest_LDADD 	= 	$(top_builddir)/lib/$(LRM_DIR)/liblrm.la
callbacktest_DEPENDENCIES    = 	$(top_builddir)/lib/$(LRM_DIR)/liblrm.la

testdir		= 	$(datadir)/$(PACKAGE_NAME)/lrmtest
test_SCRIPTS	=	LRMBasicSanityCheck regression.sh evaltest.sh lrmregtest lrmregtest-lsb
test_DATA	=	README.regression defaults descriptions lrmadmin-interface language
#				shouldn't need this, but we do for some versions of autofoo tools
EXTRA_DIST		=	$(test_SCRIPTS) $(test_DATA)
