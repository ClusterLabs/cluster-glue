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

INCLUDES		= -I$(top_builddir)/include -I$(top_srcdir)/include \
			-I$(top_builddir)/linux-ha -I$(top_srcdir)/linux-ha  \
			-I$(top_builddir)/libltdl -I$(top_srcdir)/libltdl
			

AM_CFLAGS			= @CFLAGS@ -DST_TEXTDOMAIN='"@STONITHPKG@"' \
			-DSTONITH_MODULES='"$(stonithlibdir)"' \
			-DLOCALEDIR='"@LOCALE@"' 

EXTRA_DIST = README.meatware README.rcd_serial README.vacm README.drac3 README.ipmilan

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
apcmastersnmp_LIB = apcmastersnmp.la
else
apcmastersnmp_LIB =
endif
if USE_OPENIPMI
OPENIPMI_LIB = -lOpenIPMI
ipmilan_LIB = ipmilan.la
ipmilan_TEST = ipmilantest
else
OPENIPMI_LIB =
ipmilan_LIB =
endif
#
#       We need <curl/curl.h>, <libxml/xmlmemory.h>, 
#       <libxml/parser.h>, <libxml/xpath.h>, 
#       <openssl/bio.h>, <openssl/evp.h>, <openssl/md5.h>, 
#       -lcurl, -lxml2 and -lssl for the drac3 plugin to work
#
if USE_DRAC3
drac3_LIB = drac3.la
else
drac3_LIB =
endif

noinst_PROGRAMS = $(ipmilan_TEST)
ipmilantest_SOURCES = ipmilan_test.c 
ipmilantest_LDADD = $(top_builddir)/lib/plugins/stonith/ipmilan.la $(OPENIPMI_LIB)

## libraries

plugindir	   = $(stonith_plugindir)/stonith
plugin_LTLIBRARIES =	apcmaster.la		\
			$(apcmastersnmp_LIB)	\
			apcsmart.la		\
			baytech.la		\
			$(drac3_LIB)		\
			$(ipmilan_LIB)		\
			meatware.la		\
			null.la			\
			nw_rpc100s.la		\
			rcd_serial.la		\
			rps10.la		\
			ssh.la			\
			$(vacm_LIB)		\
			wti_nps.la

apcmaster_la_SOURCES	= apcmaster.c stonith_signal.h
apcmaster_la_LDFLAGS	= -export-dynamic -module -avoid-version
apcmaster_la_LIBADD	= $(GLIBLIB)

apcmastersnmp_la_SOURCES= apcmastersnmp.c
apcmastersnmp_la_LDFLAGS= -export-dynamic -module -avoid-version @SNMPLIB@ \
			  @CRYPTOLIB@
apcmastersnmp_la_LIBADD	= $(GLIBLIB)

apcsmart_la_SOURCES	= apcsmart.c stonith_signal.h
apcsmart_la_LDFLAGS	= -export-dynamic -module -avoid-version
apcsmart_la_LIBADD	= $(GLIBLIB)

baytech_la_SOURCES	= baytech.c stonith_signal.h
baytech_la_LDFLAGS	= -export-dynamic -module -avoid-version
baytech_la_LIBADD	= $(GLIBLIB)

meatware_la_SOURCES	= meatware.c
meatware_la_LDFLAGS	= -export-dynamic -module -avoid-version
meatware_la_LIBADD	= $(GLIBLIB)

null_la_SOURCES		= null.c
null_la_LDFLAGS		= -export-dynamic -module -avoid-version
null_la_LIBADD		= $(GLIBLIB)

nw_rpc100s_la_SOURCES	= nw_rpc100s.c
nw_rpc100s_la_LDFLAGS	= -export-dynamic -module -avoid-version
nw_rpc100s_la_LIBADD	= $(top_builddir)/replace/libreplace.la $(GLIBLIB)

rps10_la_SOURCES	= rps10.c
rps10_la_LDFLAGS	= -export-dynamic -module -avoid-version
rps10_la_LIBADD		= $(GLIBLIB)

ssh_la_SOURCES		= ssh.c
ssh_la_LDFLAGS		= -export-dynamic -module -avoid-version
ssh_la_LIBADD		= $(top_builddir)/replace/libreplace.la $(GLIBLIB)

ipmilan_la_SOURCES		= ipmilan.c ipmilan.h ipmilan_command.c ipmi_os_handler.c
ipmilan_la_LDFLAGS		= -export-dynamic -module -avoid-version
ipmilan_la_LIBADD		= $(top_builddir)/replace/libreplace.la $(OPENIPMI_LIB) $(GLIBLIB)

vacm_la_SOURCES		= vacm.c
vacm_la_LDFLAGS		= -export-dynamic -module -avoid-version
vacm_la_LIBADD		= $(top_builddir)/replace/libreplace.la

wti_nps_la_SOURCES	= wti_nps.c stonith_signal.h
wti_nps_la_LDFLAGS	= -export-dynamic -module -avoid-version
wti_nps_la_LIBADD	= $(top_builddir)/replace/libreplace.la $(GLIBLIB)

rcd_serial_la_SOURCES	= rcd_serial.c
rcd_serial_la_LDFLAGS	= -export-dynamic -module -avoid-version
rcd_serial_la_LIBADD	= $(GLIBLIB)

drac3_la_SOURCES	= drac3.c drac3_command.c drac3_command.h drac3_hash.c drac3_hash.h
drac3_la_LDFLAGS	= -export-dynamic -module -avoid-version -lcurl -lxml2 -lssl $(GLIBLIB)
#drac3_la_LIBADD		= /usr/lib/libcurl.la
