%define prefix		/usr
%define sysconfdir	/etc
%define PWD		%(pwd)
%define _topdir		%{PWD}/rpm/tmp
%define RELEASE		1
%define rel		%{?CUSTOM_RELEASE} %{!?CUSTOM_RELEASE:%RELEASE}

Summary: Opennap Next Generation Open Source Napster Server
Name: opennap-ng
Version: 0.50-beta2
Release: %rel
Copyright: GPL-2
Group: System Environment/Daemons
URL: http://opennap-ng.org/
Source: %{name}-%{version}.tar.gz
Buildroot: %_tmppath/%{name}-%{version}-root

%description
Opennap-ng is an open source napster server. Napster is a popular protocol for
sharing media files in a distributed fashion. The server acts as a central
database for searching, and allowing group and private chat.

%prep
%setup -q
%build
./configure -q --prefix=/usr
%__make -s

%install
[ -n "${RPM_BUILD_ROOT}" ] && %__rm -rf "${RPM_BUILD_ROOT}"
%__make "DESTDIR=${RPM_BUILD_ROOT}" install
mkdir -p $RPM_BUILD_ROOT/usr/man/man1
install -m 644 man/opennap.1 $RPM_BUILD_ROOT/usr/man/man1/opennap.1
install -m 644 man/metaserver.1 $RPM_BUILD_ROOT/usr/man/man1/metaserver.1
mkdir -p $RPM_BUILD_ROOT/usr/etc/opennap-ng
mkdir -p $RPM_BUILD_ROOT/usr/var/opennap-ng
touch $RPM_BUILD_ROOT/usr/var/opennap-ng/users
touch $RPM_BUILD_ROOT/usr/etc/opennap-ng/motd
#install -m 644 doc/examples/sample.motd $RPM_BUILD_ROOT/usr/etc/opennap-ng/motd

%clean
[ -n "${RPM_BUILD_ROOT}" ] && %__rm -rf "${RPM_BUILD_ROOT}"
( cd "${RPM_BUILD_DIR}" && %__rm -rf "%{name}-%{version}" )

%files
%defattr(-,root,root)
%_sbindir/*
%doc AUTHORS NEWS README COPYING doc/*
%dir /usr/etc/opennap-ng
%config /usr/var/opennap-ng/users
%config /usr/etc/opennap-ng/motd
/usr/man/man1/opennap.1.gz
/usr/man/man1/metaserver.1.gz

%changelog
* Sun Aug 11 2002 Johan Schurer <leodav@users.sf.net>
- created
