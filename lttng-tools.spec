%global strato_ver 1

Name:           lttng-tools
Version:        2.9.5
Release:        2.s%{strato_ver}%{?dist}
Summary:        LTTng Trace Control
Requires:       popt >= 1.13, libuuid, libxml2 >= 2.7.6, lttng-ust >= 2.9.0, lttng-ust < 2.10.0, liburcu >= 0.8.4

Group:          Development/Tools
License:        LGPLv2.1 and GPLv2
URL:            http://www.lttng.org
Source0:        http://lttng.org/files/lttng-tools/%{name}-%{version}.tar.bz2
Source1:        lttng-sessiond.service
Source2:        lttng-relayd.service
BuildRequires:  libtool, autoconf, automake, pkgconfig, liburcu-devel >= 0.8.4, libxml2-devel >= 2.7.6, libuuid-devel, lttng-ust-devel >= 2.9.0, lttng-ust-devel < 2.10.0, popt-devel >= 1.13
Requires(pre):  shadow-utils
%systemd_requires

%description
Utilities to control the LTTng kernel and userspace tracers.

%package        devel
Summary:        Development files for %{name}
Group:          Development/Libraries
Requires:       %{name}%{?_isa} = %{version}-%{release}

%description    devel
The %{name}-devel package contains libraries and header files for developing applications that use liblttng-ctl.

%prep
%setup -q

%build
%configure --docdir=%{_docdir}/%{name} --disable-python-bindings
make %{?_smp_mflags} V=1

%install
make install DESTDIR=$RPM_BUILD_ROOT
rm -vf $RPM_BUILD_ROOT%{_libdir}/*.la
install -D -m644 extras/lttng-bash_completion %{buildroot}%{_sysconfdir}/bash_completion.d/lttng
install -D -m644 %{SOURCE1} %{buildroot}%{_unitdir}/lttng-sessiond.service
install -D -m644 %{SOURCE2} %{buildroot}%{_unitdir}/lttng-relayd.service


%pre
getent group tracing >/dev/null || groupadd -r tracing
exit 0

%post
/sbin/ldconfig

%systemd_post lttng-sessiond.service, lttng-relayd.service

%preun
%systemd_preun lttng-sessiond.service, lttng-relayd.service

%postun
/sbin/ldconfig
# Use %systemd_postun instead of %systemd_postun_with_restart
# since we don't want to automatically restard these daemons on
# upgrade (which would clear the currently active sessions).
%systemd_postun lttng-sessiond.service, lttng-relayd.service

%files
%{_mandir}/man1/lttng.1.gz
%{_mandir}/man1/lttng-add-context.1.gz
%{_mandir}/man1/lttng-crash.1.gz
%{_mandir}/man1/lttng-create.1.gz
%{_mandir}/man1/lttng-destroy.1.gz
%{_mandir}/man1/lttng-disable-channel.1.gz
%{_mandir}/man1/lttng-disable-event.1.gz
%{_mandir}/man1/lttng-enable-channel.1.gz
%{_mandir}/man1/lttng-enable-event.1.gz
%{_mandir}/man1/lttng-help.1.gz
%{_mandir}/man1/lttng-list.1.gz
%{_mandir}/man1/lttng-load.1.gz
%{_mandir}/man1/lttng-metadata.1.gz
%{_mandir}/man1/lttng-regenerate.1.gz
%{_mandir}/man1/lttng-save.1.gz
%{_mandir}/man1/lttng-set-session.1.gz
%{_mandir}/man1/lttng-snapshot.1.gz
%{_mandir}/man1/lttng-start.1.gz
%{_mandir}/man1/lttng-status.1.gz
%{_mandir}/man1/lttng-stop.1.gz
%{_mandir}/man1/lttng-track.1.gz
%{_mandir}/man1/lttng-untrack.1.gz
%{_mandir}/man1/lttng-version.1.gz
%{_mandir}/man1/lttng-view.1.gz
%{_mandir}/man8/lttng-relayd.8.gz
%{_mandir}/man8/lttng-sessiond.8.gz
%{_defaultdocdir}/%{name}/LICENSE
%{_defaultdocdir}/%{name}/README.md
%{_defaultdocdir}/%{name}/ChangeLog
%{_defaultdocdir}/%{name}/live-reading-howto.txt
%{_defaultdocdir}/%{name}/quickstart.txt
%{_defaultdocdir}/%{name}/snapshot-howto.txt
%{_defaultdocdir}/%{name}/streaming-howto.txt
%{_bindir}/lttng
%{_bindir}/lttng-crash
%{_bindir}/lttng-sessiond
%{_bindir}/lttng-relayd
%{_libdir}/lttng/libexec/lttng-consumerd
%{_libdir}/liblttng-ctl.so.*
%{_unitdir}/lttng-sessiond.service
%{_unitdir}/lttng-relayd.service
%{_sysconfdir}/bash_completion.d/
%{_datadir}/xml/lttng/session.xsd

%files devel
%{_mandir}/man3/lttng-health-check.3.gz
%{_defaultdocdir}/%{name}/python-howto.txt
%{_defaultdocdir}/%{name}/live-reading-protocol.txt
%{_defaultdocdir}/%{name}/valgrind-howto.txt
%{_includedir}/*
%{_libdir}/liblttng-ctl.a
%{_libdir}/liblttng-ctl.so
%{_libdir}/pkgconfig/lttng-ctl.pc

%changelog
* Wed Jul 26 2017 Ronnie Lazar <ronnie@stratoscale.com> 2.9.5-2
    - Updated to 2.9.5

* Tue Jun 20 2017 Michael Jeanson <mjeanson@efficios.com> 2.9.5-1
    - Updated to 2.9.5

* Thu Mar 09 2017 Michael Jeanson <mjeanson@efficios.com> 2.9.4-1
    - Updated to 2.9.4

* Mon Jan 09 2017 Michael Jeanson <mjeanson@efficios.com> 2.9.3-1
    - Updated to 2.9.3.

* Wed Dec 07 2016 Michael Jeanson <mjeanson@efficios.com> 2.9.0-1
    - Updated to 2.9.0.

* Tue Aug 30 2016 Michael Jeanson <mjeanson@efficios.com> 2.8.1-1
    - Updated to 2.8.1.

* Thu Jun 09 2016 Michael Jeanson <mjeanson@efficios.com> 2.8.0-1
    - Updated to 2.8.0.

* Thu Apr 21 2016 Michael Jeanson <mjeanson@efficios.com> 2.7.2-1
    - Updated to 2.7.2.

* Thu Jan 14 2016 Michael Jeanson <mjeanson@efficios.com> 2.7.1-1
    - Updated to 2.7.1.

* Tue Nov 10 2015 Michael Jeanson <mjeanson@efficios.com> 2.7.0-1
    - Updated to 2.7.0.

* Mon Jun 22 2015 Michael Jeanson <mjeanson@efficios.com> 2.6.0-1
    - Initial revision.
