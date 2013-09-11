/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
This is free software distributed under the terms of the
GNU Public License.  See the file COPYING for details.

$Id: motd.c 434 2006-09-03 17:48:47Z reech $ */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifndef WIN32
# include <unistd.h>
#endif
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include "opennap.h"
#include "debug.h"

/* in-memory copy of the motd */
static char *Motd = 0;
static int MotdLen = 0;

/* 621
display the server motd */
HANDLER(show_motd)
{
    (void) tag;
    (void) len;
    (void) pkt;

    ASSERT(validate_connection(con));
    CHECK_USER_CLASS("show_motd");

    /* we print the version info here so that clients can enable features
    only present in this server, but without disturbing the windows
    client */
    send_cmd(con, MSG_SERVER_MOTD, "VERSION %s %s%s%s%s%s%s", PACKAGE, VERSION, SUBVERSIONREV,
#ifdef WIN32
        ".win32",
#else
        "",
#endif
#ifdef ROUTING_ONLY
        ".rt",
#else
        "",
#endif
#ifdef HAVE_POLL
		".poll",
#else
		"",
#endif
#ifdef HAVE_LIBPTHREAD
		".thread"
#else
		""
#endif
        );
    send_cmd(con, MSG_SERVER_MOTD, "SERVER %s", global.serverName);
    send_cmd(con, MSG_SERVER_MOTD, "Welcome %s!", con->user->nick);
    send_cmd(con, MSG_SERVER_MOTD, "");
#ifndef WIN32
    send_cmd(con, MSG_SERVER_MOTD, "You are user %d out of %d.", con->fd, global.maxConnections);
#endif
    send_cmd(con, MSG_SERVER_MOTD, "");
    send_cmd(con, MSG_SERVER_MOTD, "There have been %d connections to this server.", stats.logins);
    send_cmd(con, MSG_SERVER_MOTD, "This server has performed %d searches.", stats.search_total);
    send_cmd(con, MSG_SERVER_MOTD, "");

    /* useless information wanted by panasync. :-) and even more by leodav :))*/

    /* motd_init() preformats the entire motd */
    if(Motd) 
	{
        queue_data(con, Motd, MotdLen);
    }
    else 
	{
        send_cmd(con, MSG_SERVER_MOTD, "No MOTD set.");
    }
}

void motd_init(void)
{
    char path[_POSIX_PATH_MAX];
    int fd;
    int len;

    snprintf(path, sizeof(path), "%s/motd", global.shareDir);
    if((fd = open(path, O_RDONLY))==-1)
    {
        if(errno != ENOENT)
            logerr("motd_init", path);
        return;
    }
    /* preformat the motd so it can be bulk dumped to the client */
    while (fake_fgets(Buf, sizeof(Buf) - 1, fd))
    {
        len = strlen(Buf);
        if(Buf[len - 1] == '\n')
            len--;
        if(safe_realloc((void **) &Motd, MotdLen + len + 4))
            break;
        set_tag(&Motd[MotdLen], MSG_SERVER_MOTD);
        set_len(&Motd[MotdLen], len);
        MotdLen += 4;
        memcpy(Motd + MotdLen, Buf, len);
        MotdLen += len;
    }
    close(fd);
    log_message_level( LOG_LEVEL_SERVER, "motd_init: motd is %d bytes", MotdLen);
}

void motd_close(void)
{
    if(Motd)
    {
        FREE(Motd);
        Motd = 0;
        MotdLen = 0;
    }
    ASSERT(MotdLen == 0);
}
