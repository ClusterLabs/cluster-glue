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
# along with this program; if not, see <http://www.gnu.org/licenses/>.
#

-include Makefile

PACKAGE		?= cluster-glue
TARFILE		= $(PACKAGE).tar

RPM_ROOT	= $(shell pwd)
RPM_OPTS	= --define "_sourcedir $(RPM_ROOT)" 	\
		  --define "_specdir $(RPM_ROOT)" 	\
		  --define "_srcrpmdir $(RPM_ROOT)"


getdistro = $(shell test -e /etc/SuSE-release || echo fedora; test -e /etc/SuSE-release && echo suse)
DISTRO ?= $(call getdistro)
TAG    ?= HEAD

tarball:
	rm -f $(TARFILE) $(TARFILE).bz2 $(TARFILE).tmp .tarball-version.tmp .tarball-version
	./buildversion.sh $(TAG) > .tarball-version.tmp && mv .tarball-version.tmp .tarball-version
	git archive --prefix $(PACKAGE)/ $(TAG) > $(TARFILE).tmp
	tar --append --transform 's,^,$(PACKAGE)/,' -f $(TARFILE).tmp .tarball-version
	mv $(TARFILE).tmp $(TARFILE)
	bzip2 $(TARFILE)
	@echo `date`: Rebuilt $(TARFILE).bz2

srpm:	tarball
	rm -f *.src.rpm
	@echo To create custom builds, edit the flags and options in $(PACKAGE)-$(DISTRO).spec first
	rpmbuild -bs --define "dist .$(DISTRO)" $(RPM_OPTS) $(PACKAGE)-$(DISTRO).spec

rpm:	srpm
	rpmbuild $(RPM_OPTS) --rebuild $(RPM_ROOT)/*.src.rpm

