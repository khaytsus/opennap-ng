# Makefile.am for opennap-ng

#require automake 1.4
AUTOMAKE_OPTIONS = 1.4

BASE_SUBDIRS = src

SUBDIRS = $(BASE_SUBDIRS)
DIST_SUBDIRS = $(BASE_SUBDIRS)
EXTRA_DIST = debian/changelog	\
	debian/conffiles	\
	debian/control		\
	debian/copyright	\
	debian/dirs		\
	debian/docs		\
	debian/README.debian	\
	debian/rules		\
	debian/TODO.debian	\
	rpm/opennap-ng.spec.in	\
	man/metaserver.1	\
	man/opennap.1		\
	doc/advanced_install.txt\
	doc/ChangeLog.drscholl	\
	doc/ChangeLog.kaenguru	\
	doc/CHARTA		\
	doc/FAQ			\
	doc/manual.html		\
	doc/napster.txt		\
	doc/notes.txt		\
	doc/TODO		\
	doc/WHATSNEW		\
	doc/scripts/dropbanned.pl	\
	doc/scripts/fixfiles	\
	doc/scripts/getfilter.sh	\
	doc/scripts/logchk	\
	doc/scripts/napchk	\
	doc/scripts/opennap.init	\
	doc/scripts/opennap_config.pl	\
	doc/scripts/start_opennap	\
	doc/examples/sample.block	\
	doc/examples/sample.channels	\
	doc/examples/sample.config	\
	doc/examples/sample.config.kaenguru	\
	doc/examples/sample.filter	\
	doc/examples/sample.motd	\
	doc/examples/sample.servers	\
	doc/examples/sample.users          \
	autogen.sh		\
	win/makensis.bat	\
	win/metaserver.vcproj	\
	win/mkpass.vcproj	\
	win/opennap-ng.bmp	\
	win/opennap-ng.ini	\
	win/opennap-ng.nsi	\
	win/opennap.sln		\
	win/opennap.vcproj	\
	win/README.zlib		\
	win/setup.vcproj	

DISTCLEANFILES = config.cache	\
	config.log		\
	debian/substvars	\
	debian/files		\
	build

distclean-local:
	rm -rf rpm/tmp
	rm -rf debian/tmp
	rm -rf autom4te.cache

MAINTAINERCLEANFILES = $(DISTCLEANFILES) \
	COPYING			\
	INSTALL			\
	config.guess		\
	config.sub		\
	depcomp			\
	install-sh		\
	missing			\
	mkinstalldirs		\
	configure		\
	aclocal.m4		\
	Makefile.in		\
	rpm/opennap-ng.spec

.PHONY: log snaplog snapshot mydist mysnap deb rpm

log:
	svn log http://svn.opennap-ng.org/repos/releases/$(VERSION)/ > ChangeLog

snaplog: 
	svn log http://svn.opennap-ng.org/repos/trunk/ > ChangeLog

snapshot:
	$(MAKE) -s dist distdir=$(PACKAGE)-snap`date +"%Y%m%d"`

mydist:
	echo "#ifndef SUBVERSIONREV_H "> src/subversionrev.h
	echo "#define SUBVERSIONREV_H" >>src/subversionrev.h
	echo "#define SUBVERSIONREV \"-RELEASE\"" >>src/subversionrev.h
	echo "#endif" >>src/subversionrev.h
	$(MAKE) -s log
	$(MAKE) -s dist-bzip2

mysnap: 
	svn revert ChangeLog
	svnversion -n . > SvnVersion
	echo "#ifndef SUBVERSIONREV_H "> src/subversionrev.h
	echo "#define SUBVERSIONREV_H" >>src/subversionrev.h
	echo -n "#define SUBVERSIONREV \"-" >>src/subversionrev.h
	echo -n `cat SvnVersion` >>src/subversionrev.h
	echo "\"" >>src/subversionrev.h
	echo "#endif" >>src/subversionrev.h
	$(MAKE) -s snaplog
	$(MAKE) -s dist-bzip2 distdir=$(PACKAGE)-`cat SvnVersion`
	rm SvnVersion
	svn revert src/subversionrev.h


deb:
	fakeroot debian/rules binary

rpm:
	@[ -n "rpm/tmp" ] && rm -rf rpm/tmp
	@mkdir rpm/tmp rpm/tmp/SOURCES rpm/tmp/BUILD rpm/tmp/RPMS rpm/tmp/SRPMS
	$(MAKE) -s dist
	@mv $(PACKAGE)-$(VERSION).tar.gz rpm/tmp/SOURCES
	rpmbuild -ba --quiet --clean rpm/$(PACKAGE).spec
	@echo "Your RPM's and SRPM's are baked and waiting in rpm/tmp/*"
