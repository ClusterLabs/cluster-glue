#
# stonith: STONITH plugins for Linux-HA
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

SUBDIRS			= external

INCFILES		= stonith_expect_helpers.h	\
			stonith_plugin_common.h		\
			stonith_signal.h		\
			stonith_config_xml.h

idir=$(includedir)/stonith

i_HEADERS	        = $(INCFILES)

INCLUDES		= -I$(top_builddir)/include -I$(top_srcdir)/include \
			-I$(top_builddir)/linux-ha -I$(top_srcdir)/linux-ha  \
			-I$(top_builddir)/libltdl -I$(top_srcdir)/libltdl


AM_CFLAGS		= @NON_FATAL_CFLAGS@

#
#       We need "vacmclient_api.h" and -lvacmclient to make the VACM
#       plugin work.
#
if USE_VACM
vacm_LIB = vacm.la
else
vacm_LIB =
endif

#
#       We need <ucd-snmp/asn1.h>, <ucd-snmp/snmp_api.h>, <ucd-snmp/snmp.h>
#       <ucd-snmp/snmp_client.h>, <ucd-snmp/mib.h>, -lsnmp and -lcrypto
#       for the apcmastersnmp plugin to work
#

if USE_APC_SNMP
apcmastersnmp_LIB = apcmastersnmp.la wti_mpc.la
else
apcmastersnmp_LIB =
endif
if IPMILAN_BUILD
OPENIPMI_LIB = -lOpenIPMI -lOpenIPMIposix -lOpenIPMIutils
libipmilan_LIB = libipmilan.la
ipmilan_LIB = ipmilan.la
ipmilan_TEST = ipmilantest
else
OPENIPMI_LIB =
libipmilan_LIB =
ipmilan_LIB =
endif
#
#       We need <curl/curl.h>, <libxml/xmlmemory.h>, 
#       <libxml/parser.h>, <libxml/xpath.h>, 
#       -lcurl and -lxml2 for the drac3 plugin to work
#
if USE_DRAC3
drac3_LIB = drac3.la
else
drac3_LIB =
endif

#
#       We need OpenHPI to make the IBM BladeCenter plugin work.
#
if USE_OPENHPI
bladehpi_LIB = bladehpi.la
else
bladehpi_LIB =
endif

noinst_PROGRAMS = $(ipmilan_TEST)
ipmilantest_SOURCES = ipmilan_test.c 
ipmilantest_LDADD = $(libipmilan_LIB) \
			$(top_builddir)/lib/pils/libpils.la \
		    $(top_builddir)/lib/stonith/libstonith.la \
		    $(OPENIPMI_LIB)

## libraries

plugindir	   = $(stonith_plugindir)/stonith2

plugin_LTLIBRARIES =	apcmaster.la	\
			$(apcmastersnmp_LIB)	\
			apcsmart.la		\
			baytech.la		\
			$(bladehpi_LIB)		\
			cyclades.la		\
			$(drac3_LIB)		\
			external.la		\
			rhcs.la		\
			ibmhmc.la		\
			$(ipmilan_LIB)		\
			meatware.la		\
			null.la			\
			nw_rpc100s.la		\
			rcd_serial.la		\
			rps10.la		\
			ssh.la			\
			suicide.la		\
			$(vacm_LIB)		\
			wti_nps.la
noinst_LTLIBRARIES = $(libipmilan_LIB)

apcmaster_la_SOURCES	= apcmaster.c $(INCFILES)
apcmaster_la_LDFLAGS	= -export-dynamic -module -avoid-version
apcmaster_la_LIBADD	= $(top_builddir)/lib/stonith/libstonith.la $(GLIBLIB)

apcmastersnmp_la_SOURCES= apcmastersnmp.c $(INCFILES)
apcmastersnmp_la_LDFLAGS= -export-dynamic -module -avoid-version @SNMPLIB@ \
			  @CRYPTOLIB@
apcmastersnmp_la_LIBADD	= $(top_builddir)/lib/stonith/libstonith.la $(GLIBLIB)

apcsmart_la_SOURCES	= apcsmart.c $(INCFILES)
apcsmart_la_LDFLAGS	= -export-dynamic -module -avoid-version
apcsmart_la_LIBADD	= $(top_builddir)/lib/stonith/libstonith.la $(GLIBLIB)

baytech_la_SOURCES	= baytech.c $(INCFILES)
baytech_la_LDFLAGS	= -export-dynamic -module -avoid-version
baytech_la_LIBADD	= $(top_builddir)/lib/stonith/libstonith.la $(GLIBLIB)

bladehpi_la_SOURCES	= bladehpi.c $(INCFILES)
bladehpi_la_LDFLAGS	= -export-dynamic -module -avoid-version
bladehpi_la_LIBADD	= $(top_builddir)/lib/stonith/libstonith.la $(GLIBLIB) -lopenhpi

cyclades_la_SOURCES	= cyclades.c $(INCFILES)
cyclades_la_LDFLAGS	= -export-dynamic -module -avoid-version
cyclades_la_LIBADD	= $(top_builddir)/lib/stonith/libstonith.la $(GLIBLIB)

drac3_la_SOURCES	= drac3.c drac3_command.c drac3_command.h drac3_hash.c drac3_hash.h	$(INCFILES)
drac3_la_LDFLAGS	= -export-dynamic -module -avoid-version
drac3_la_LIBADD		= $(top_builddir)/lib/stonith/libstonith.la -lcurl -lxml2 $(GLIBLIB)

external_la_SOURCES	= external.c	$(INCFILES)
external_la_LDFLAGS	= -export-dynamic -module -avoid-version
external_la_LIBADD	= $(top_builddir)/lib/stonith/libstonith.la $(top_builddir)/replace/libreplace.la

rhcs_la_SOURCES	= rhcs.c	$(INCFILES)
rhcs_la_LDFLAGS	= -export-dynamic -module -avoid-version
rhcs_la_LIBADD	= $(top_builddir)/lib/stonith/libstonith.la $(top_builddir)/replace/libreplace.la

ibmhmc_la_SOURCES	= ibmhmc.c	$(INCFILES)
ibmhmc_la_LDFLAGS	= -export-dynamic -module -avoid-version
ibmhmc_la_LIBADD	= $(top_builddir)/lib/stonith/libstonith.la $(top_builddir)/replace/libreplace.la $(GLIBLIB)

ipmilan_la_SOURCES	= ipmilan.c ipmilan.h ipmilan_command.c	$(INCFILES)
ipmilan_la_LDFLAGS	= -export-dynamic -module -avoid-version
ipmilan_la_LIBADD	= $(top_builddir)/lib/stonith/libstonith.la $(top_builddir)/replace/libreplace.la $(OPENIPMI_LIB) $(GLIBLIB)

libipmilan_la_SOURCES	= ipmilan.c ipmilan.h ipmilan_command.c	$(INCFILES)
libipmilan_la_LDFLAGS	= -version-info 1:0:0
libipmilan_la_LIBADD	= $(top_builddir)/lib/stonith/libstonith.la $(top_builddir)/replace/libreplace.la $(OPENIPMI_LIB) $(GLIBLIB)

meatware_la_SOURCES	= meatware.c $(INCFILES)
meatware_la_LDFLAGS	= -export-dynamic -module -avoid-version
meatware_la_LIBADD	= $(top_builddir)/lib/stonith/libstonith.la $(GLIBLIB)

null_la_SOURCES		= null.c $(INCFILES)
null_la_LDFLAGS		= -export-dynamic -module -avoid-version
null_la_LIBADD		= $(top_builddir)/lib/stonith/libstonith.la $(GLIBLIB)

nw_rpc100s_la_SOURCES	= nw_rpc100s.c $(INCFILES)
nw_rpc100s_la_LDFLAGS	= -export-dynamic -module -avoid-version
nw_rpc100s_la_LIBADD	= $(top_builddir)/lib/stonith/libstonith.la $(top_builddir)/replace/libreplace.la $(GLIBLIB)

rcd_serial_la_SOURCES	= rcd_serial.c $(INCFILES)
rcd_serial_la_LDFLAGS	= -export-dynamic -module -avoid-version
rcd_serial_la_LIBADD	= $(top_builddir)/lib/stonith/libstonith.la $(GLIBLIB)

rps10_la_SOURCES	= rps10.c $(INCFILES)
rps10_la_LDFLAGS	= -export-dynamic -module -avoid-version
rps10_la_LIBADD		= $(top_builddir)/lib/stonith/libstonith.la $(GLIBLIB)

ssh_la_SOURCES		= ssh.c $(INCFILES)
ssh_la_LDFLAGS		= -export-dynamic -module -avoid-version
ssh_la_LIBADD		= $(top_builddir)/lib/stonith/libstonith.la 

vacm_la_SOURCES		= vacm.c $(INCFILES)
vacm_la_LDFLAGS		= -export-dynamic -module -avoid-version
vacm_la_LIBADD		= $(top_builddir)/lib/stonith/libstonith.la $(top_builddir)/replace/libreplace.la

wti_nps_la_SOURCES	= wti_nps.c $(INCFILES)
wti_nps_la_LDFLAGS	= -export-dynamic -module -avoid-version
wti_nps_la_LIBADD	= $(top_builddir)/lib/stonith/libstonith.la $(top_builddir)/replace/libreplace.la $(GLIBLIB)

wti_mpc_la_SOURCES= wti_mpc.c $(INCFILES)
wti_mpc_la_LDFLAGS= -export-dynamic -module -avoid-version @SNMPLIB@ \
			  @CRYPTOLIB@
wti_mpc_la_LIBADD	= $(top_builddir)/lib/stonith/libstonith.la $(GLIBLIB)

suicide_la_SOURCES	= suicide.c $(INCFILES)
suicide_la_LDFLAGS	= -export-dynamic -module -avoid-version
suicide_la_LIBADD	= $(top_builddir)/lib/stonith/libstonith.la 

stonithscriptdir        =  $(stonith_plugindir)/stonith2

stonithscript_SCRIPTS  	= ribcl.py 
