# Makefile.am for OCF RAs
#
# Author: Sun Jing Dong
# Copyright (C) 2004 IBM
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

EXTRA_DIST           = drac5 dracmc-telnet ibmrsa-telnet ipmi rackpdu vmware vcenter xen0 \
			xen0-ha-dom0-stonith-helper kdumpcheck nut

extdir		     = $(stonith_ext_plugindir)

helperdir	     = $(stonith_plugindir)

ext_SCRIPTS	     = drac5 dracmc-telnet ibmrsa ibmrsa-telnet ipmi riloe ssh vmware vcenter rackpdu xen0 hmchttp \
			xen0-ha kdumpcheck ippower9258 nut libvirt \
			hetzner ec2

helper_SCRIPTS	     = xen0-ha-dom0-stonith-helper
