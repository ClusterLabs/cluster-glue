#
# hbclient library: Linux-HA heartbeat code
#
# Copyright (C) 2001 Michael Moerz
# Copyright (C) 2004 International Business Machines
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

halibdir		= $(libdir)/@HB_PKG@
ha_sbindir		= $(sbindir)

LIBRT 			= @LIBRT@
AM_CFLAGS		= @CFLAGS@

initddir               = @INITDIR@
  
## binary progs
ha_sbin_PROGRAMS  = ha_logger
halib_PROGRAMS	  = ha_logd logtest

ha_logd_SOURCES	  = ha_logd.c
ha_logd_LDADD	  = $(top_builddir)/lib/clplumbing/libplumb.la		\
		    $(top_builddir)/lib/clplumbing/libplumbgpl.la

#		    $(top_builddir)/lib/apphb/libapphb.la

ha_logger_SOURCES = ha_logger.c
ha_logger_LDADD   = $(top_builddir)/lib/clplumbing/libplumb.la

logtest_SOURCES   = logtest.c
logtest_LDADD     = $(top_builddir)/lib/clplumbing/libplumb.la

if HAVE_SYSTEMD
systemdsystemunit_DATA = \
        logd.service
else
initd_SCRIPTS     = logd
endif
