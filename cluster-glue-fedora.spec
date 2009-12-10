# Keep around for when/if required
## define alphatag XXX

%define gname haclient
%define uname hacluster
%define nogroup nobody

# When downloading directly from Mercurial, it will automatically add this prefix
# Invoking 'hg archive' wont but you can add one with: hg archive -t tgz -p "Reusable-Cluster-Components-" -r $upstreamversion $upstreamversion.tar.gz
%global upstreamprefix Reusable-Cluster-Components-
%global upstreamversion d97b9dea436e

Name:		cluster-glue
Summary:	Reusable cluster components
Version:	1.0.2
Release:	0rc1%{?dist}
License:	GPLv2+ and LGPLv2+
Url:		http://www.clusterlabs.org
Group:		System Environment/Base
Source0:	cluster-glue.tar.bz2
Requires:	perl-TimeDate

# Directives to allow upgrade from combined heartbeat packages in Fedora11
Provides:       heartbeat-stonith = 3.0.0-1
Provides:       heartbeat-pils = 3.0.0-1
Obsoletes:      heartbeat-stonith < 3.0.0-1
Obsoletes:      heartbeat-pils < 3.0.0-1
Obsoletes:	heartbeat-common

## Setup/build bits

BuildRoot: %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)

# Build dependencies
BuildRequires: automake autoconf libtool pkgconfig which
BuildRequires: bzip2-devel glib2-devel python-devel libxml2-devel
BuildRequires: OpenIPMI-devel openssl-devel

%if 0%{?fedora} 
BuildRequires:    libcurl-devel libnet-devel
%endif

%if 0%{?fedora} || 0%{?centos} > 4 || 0%{?rhel} > 4
BuildRequires:    libtool-ltdl-devel openhpi-devel 
BuildRequires:    net-snmp-devel >= 5.4
%else
BuildRequires:    gcc-c++
%endif

%if 0%{?fedora} < 12
BuildRequires: e2fsprogs-devel
%else
BuildRequires: libuuid-devel
%endif

%prep
%setup -q -n cluster-glue

./autogen.sh

%configure \
    --enable-fatal-warnings=yes \
    --with-daemon-group=%{gname} \
    --with-daemon-user=%{uname} \
    --localstatedir=%{_var} \
    --libdir=%{_libdir}

%build
make %{?_smp_mflags}

%install
rm -rf %{buildroot}
make install DESTDIR=%{buildroot}

## tree fix up
# Dont package static libs
find %{buildroot} -name '*.a' -exec rm {} \;
find %{buildroot} -name '*.la' -exec rm {} \;

%clean
rm -rf %{buildroot}

# cluster-glue

%description
A collection of common tools that are useful for writing cluster managers 
such as Pacemaker.
Provides a local resource manager that understands the OCF and LSB
standards, and an interface to common STONITH devices.

%files
%defattr(-,root,root)
%dir %{_datadir}/heartbeat
%{_sysconfdir}/init.d/logd
%{_datadir}/heartbeat/ha_cf_support.sh
%{_datadir}/heartbeat/openais_conf_support.sh
%{_datadir}/heartbeat/utillib.sh
%{_datadir}/heartbeat/combine-logs.pl

%{_sbindir}/ha_logger
%{_sbindir}/hb_report
%{_sbindir}/lrmadmin
%{_sbindir}/meatclient
%{_sbindir}/stonith
%{_sbindir}/sbd
%dir %{_libdir}/heartbeat
%dir %{_libdir}/heartbeat/plugins
%dir %{_libdir}/heartbeat/plugins/RAExec
%dir %{_libdir}/heartbeat/plugins/InterfaceMgr
%{_libdir}/heartbeat/lrmd
%{_libdir}/heartbeat/ha_logd
%{_libdir}/heartbeat/plugins/RAExec/*.so
%{_libdir}/heartbeat/plugins/InterfaceMgr/*.so
%dir %{_libdir}/stonith
%dir %{_libdir}/stonith/plugins
%dir %{_libdir}/stonith/plugins/stonith2
%{_libdir}/stonith/plugins/external
%{_libdir}/stonith/plugins/stonith2/*.so
%{_libdir}/stonith/plugins/stonith2/*.py*
%{_libdir}/stonith/plugins/xen0-ha-dom0-stonith-helper
%dir %{_var}/lib/heartbeat
%dir %{_var}/lib/heartbeat/cores
%dir %attr (0700, root, root)		%{_var}/lib/heartbeat/cores/root
%dir %attr (0700, nobody, %{nogroup})	%{_var}/lib/heartbeat/cores/nobody
%dir %attr (0700, %{uname}, %{gname})	%{_var}/lib/heartbeat/cores/%{uname}
%{_mandir}/man1/*
%{_mandir}/man8/*
%doc doc/stonith/README*
%doc logd/logd.cf
%doc AUTHORS
%doc COPYING

# cluster-glue-libs

%package -n cluster-glue-libs
Summary:	Reusable cluster libraries
Group:		Development/Libraries
Requires:	%{name} = %{version}-%{release}
Obsoletes:	libheartbeat2

%description -n cluster-glue-libs
A collection of libraries that are useful for writing cluster managers 
such as Pacemaker.

%pre
getent group %{gname} >/dev/null || groupadd -r %{gname}
getent passwd %{uname} >/dev/null || \
useradd -r -g %{gname} -d %{_var}/lib/heartbeat/cores/hacluster -s /sbin/nologin \
-c "cluster user" %{uname}
exit 0

%post -n cluster-glue-libs -p /sbin/ldconfig

%postun -n cluster-glue-libs -p /sbin/ldconfig

%files -n cluster-glue-libs
%defattr(-,root,root)
%{_libdir}/lib*.so.*
%doc AUTHORS
%doc COPYING.LIB

# cluster-glue-libs-devel

%package -n cluster-glue-libs-devel 
Summary:	Headers and libraries for writing cluster managers
Group:		Development/Libraries
Requires:	%{name} = %{version}-%{release}
Requires:	cluster-glue-libs = %{version}-%{release}
Obsoletes:	libheartbeat-devel

%description -n cluster-glue-libs-devel
Headers and shared libraries for a useful for writing cluster managers 
such as Pacemaker.

%files -n cluster-glue-libs-devel
%defattr(-,root,root)
%dir %{_libdir}/heartbeat/plugins
%dir %{_libdir}/heartbeat/plugins/test
%dir %{_libdir}/heartbeat
%dir %{_datadir}/heartbeat
%{_libdir}/lib*.so
%{_libdir}/heartbeat/ipctest
%{_libdir}/heartbeat/ipctransientclient
%{_libdir}/heartbeat/ipctransientserver
%{_libdir}/heartbeat/transient-test.sh
%{_libdir}/heartbeat/base64_md5_test
%{_libdir}/heartbeat/logtest
%{_includedir}/clplumbing
%{_includedir}/heartbeat
%{_includedir}/stonith
%{_includedir}/pils
%{_datadir}/heartbeat/lrmtest
%{_libdir}/heartbeat/plugins/test/test.so
%doc AUTHORS
%doc COPYING
%doc COPYING.LIB

%changelog
