#
# Copyright (C) 2008 Andrew Beekhof
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

MAINTAINERCLEANFILES	= Makefile.in aclocal.m4 configure DRF/config-h.in \
			  DRF/stamp-h.in libtool.m4 ltdl.m4 libltdl.tar

SUBDIRS			= include $(LIBLTDL_DIR) replace lib lrm logd

ACLOCAL_AMFLAGS		= -I libltdl/m4

RPM_OPTS	= --define "_sourcedir $(RPM_ROOT)" \
		  --define "_specdir $(RPM_ROOT)" \
		  --define "_builddir $(RPM_ROOT)" \
		  --define "_srcrpmdir $(RPM_ROOT)" \
		  --define "_rpmdir $(RPM_ROOT)"

#RPM_ROOT		= $(abs_builddir)
TARFILE			= cluster-glue.tar.gz
RPM_ROOT		= $(top_srcdir)
SPEC			= $(top_srcdir)/cluster-glue.spec

tgz:
	rm -f $(TARFILE)
	hg archive -t tgz $(TARFILE)
	echo Rebuilt $(TARFILE) on `date`

srpm:	tgz
	-rm *.src.rpm
	rpmbuild -bs $(RPM_OPTS) $(SPEC)

rpm:	srpm
	echo To create custom builds, edit the flags and options in pacemaker.spec first
	rpmbuild -ba $(RPM_OPTS) $(SPEC)

mock:	srpm
	mock --root fedora-rawhide-x86_64 --rebuild $(top_builddir)/*.src.rpm

install-exec-local:
	$(INSTALL) -d $(DESTDIR)/$(HA_COREDIR)
	-$(INSTALL) -d -m 700 -o root $(DESTDIR)/$(HA_COREDIR)/root
	-$(INSTALL) -d -m 700 -o nobody $(DESTDIR)/$(HA_COREDIR)/nobody
	$(INSTALL) -d -m 700 $(DESTDIR)/$(HA_COREDIR)/$(GLUE_DAEMON_USER)
	-chown $(GLUE_DAEMON_USER) $(DESTDIR)/$(HA_COREDIR)/$(GLUE_DAEMON_USER)
# Use chown because $(GLUE_DAEMON_USER) may not exist yet

dist-clean-local:
	rm -f autoconf automake autoheader $(TARFILE)

.PHONY: 
