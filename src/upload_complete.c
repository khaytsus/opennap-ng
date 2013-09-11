/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
This is free software distributed under the terms of the
GNU Public License.  See the file COPYING for details.

$Id: upload_complete.c 434 2006-09-03 17:48:47Z reech $ */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>
#include "opennap.h"
#include "debug.h"

/* 608 <recip> "<filename>" */
/* a client sends this message when another user has requested a file from
them and they are accepting the connection.  this should be a
response to the 607 upload request */
HANDLER(upload_ok)
{
    char   *av[2];
    USER   *recip;
    DATUM  *info = 0;
    int     ac;

    (void) tag;
    (void) len;
    CHECK_USER_CLASS("upload_ok");
    ASSERT(validate_connection(con));
    if((ac = split_line(av, sizeof(av) / sizeof(char *), pkt)) != 2)
    {
        log_message_level(LOG_LEVEL_FILES, "upload_ok(): malformed message from %s", con->user->nick);
        print_args(ac, av);
        unparsable(con);
        return;
    }
    recip = hash_lookup(global.usersHash, av[0]);
    if(!recip)
    {
        nosuchuser(con);
        return;
    }
    /* pull the hash from the data base */
    info = hash_lookup(con->uopt->files, av[1]);
    if(!info)
    {
        send_cmd(con, MSG_SERVER_NOSUCH, "Not sharing that file");
        return;
    }
    if(con->user->port == 0)
    {
        /* firewalled user, give the info back to the uploader */
        send_cmd(con, MSG_SERVER_UPLOAD_FIREWALL /* 501 */ , "%s %u %hu \"%s\" %s %d", recip->nick, recip->ip, recip->port, av[1],
#if RESUME
            info->hash,
#else
            "00000000000000000000000000000000",
#endif
            recip->speed);
    }
    else
        /* recipient of this message may be on a remote server, use
        send_user() here */
        send_user(recip, MSG_SERVER_FILE_READY, "%s %u %hu \"%s\" %s %d", con->user->nick, con->user->ip, con->user->port, av[1],
#if RESUME
        info->hash,
#else
        "00000000000000000000000000000000",
#endif
        con->user->speed);
}
