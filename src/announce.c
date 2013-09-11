/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
This is free software distributed under the terms of the
GNU Public License.  See the file COPYING for details.

$Id: announce.c 434 2006-09-03 17:48:47Z reech $ */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifndef WIN32
# include <unistd.h>
#endif /* !WIN32 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "opennap.h"
#include "debug.h"

/* called when receiving a global message */
/* 628 [ <nick> ] <message> */
HANDLER(announce)
{
    USER   *user;

    (void) tag;
    (void) len;
    ASSERT(validate_connection(con));

    if(ISUSER(con))
        user = con->user;
    else
    {
        char   *ptr;

        ASSERT(ISSERVER(con));
        ptr = next_arg_noskip(&pkt);
        if(!pkt)
        {
            log_message_level(LOG_LEVEL_ERROR, "announce: too few arguments in server message");
            return;
        }
        user = hash_lookup(global.usersHash, ptr);
        if(!user)
        {
            log_message_level(LOG_LEVEL_ERROR, "announce: can't find user %s", ptr);
            return;
        }
    }

    ASSERT(validate_user(user));

    /* check to see that the user has privileges */
    if(user->level < LEVEL_ADMIN)
    {
        log_message_level(LOG_LEVEL_SECURITY, "announce: %s is not admin", user->nick);
        if(ISUSER(con))
            permission_denied(con);
        return;
    }

    send_all_clients(tag, "%s %s", user->cloaked ? "Operator" : user->nick, pkt);

    /* pass the message to our peer servers if a local user sent it */
    pass_message_args(con, tag, "%s %s", user->cloaked ? "Operator" : user->nick, pkt);
}

/* 627 [ <nick> ] <message> */
/* send a message to all mods+ */
HANDLER(wallop)
{
    char   *ptr;
    int     l;
    LIST   *list;
    CONNECTION *c;

    (void) tag;
    (void) len;
    ASSERT(validate_connection(con));
    if(con->class == CLASS_USER)
    {
        ASSERT(validate_user(con->user));
        if(con->user->level < LEVEL_MODERATOR)
        {
            permission_denied(con);
            return;
        }
        ptr = con->user->nick;
    }
    else
    {
        ptr = next_arg_noskip(&pkt);
        if(!pkt)
        {
            log_message_level(LOG_LEVEL_ERROR, "wallop: malformed message from %s", pkt);
            return;
        }
    }

    l = form_message(Buf, sizeof(Buf), tag, "%s %s", ptr, pkt);
    pass_message(con, Buf, l);

    for (list = global.modList; list; list = list->next) 
	{
        c = list->data;
        if(c->uopt->usermode & WALLOPLOG_MODE) 
		{
            queue_data(c, Buf, l);
        }
    }
}

/* 10021 :<server> <loglevel> "<message>" */
HANDLER(remote_notify_mods)
{
    int     ac, level;
    char   *av[3];

    (void) len;
    CHECK_SERVER_CLASS("remote_notify_mods");
    if(*pkt != ':')
    {
        log_message_level(LOG_LEVEL_ERROR, "remote_notify_mods: missing server name");
        return;
    }
    ac = split_line(av, FIELDS(av), pkt);
    if(ac < 3)
    {
        log_message_level(LOG_LEVEL_ERROR, "remote_notify_mods: too few parameters");
        print_args(ac, av);
        return;
    }
    level = atoi(av[1]);
    notify_mods(level, "[%s] %s", av[0] + 1, av[2]);
    pass_message_args(con, tag, ":%s %d \"%s\"", av[0] + 1, level, av[2]);
}
