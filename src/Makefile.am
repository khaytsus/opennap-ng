sbin_PROGRAMS=opennap metaserver opennap_setup

opennap_SOURCES=opennap.h main.c add_file.c discipline.c search.c \
	search.h motd.c hash.h hash.c privmsg.c browse.c abuse.c\
	userflags.c debug.c debug.h login.c whois.c free_user.c \
	join.c part.c public.c part_channel.c \
	announce.c kill_user.c remove_connection.c config.c download.c \
	upload_complete.c topic.c muzzle.c \
	level.c client_quit.c server_login.c \
	server_connect.c synch.c util.c \
	md5.c md5.h hotlist.c remove_file.c list_channels.c \
	list_users.c ping.c resume.c change.c ban.c network.c buffer.c \
	server_usage.c server_links.c init.c handler.c timer.c list.c \
	list.h userdb.c serverlib.c kick.c usermode.c channel.c glob.c \
	redirect.c filter.c hashlist.h hashlist.c class.c \
	napigator.c win32-support.h proxy.c subversionrev.h \
	balloc.c balloc.h tools.h tools.c
opennap_LDADD=$(REGEX)
opennap_DEPENDENCIES=$(REGEX)

metaserver_SOURCES=metaserver.c

opennap_setup_SOURCES=setup.c

EXTRA_opennap_SOURCES=_regex.h regex.c getopt.c

INCLUDES=-DVARDIR=\"@VARDIR@\" -DSHAREDIR=\"@SHAREDIR@\"

MAINTAINERCLEANFILES = Makefile.in \
	stamp-h		\
	stamp-h.in	\
	Makefile	\
	Makefile.in	\
	config.h.in
