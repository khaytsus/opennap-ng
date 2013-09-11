/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
This is free software distributed under the terms of the
GNU Public License.  See the file COPYING for details.

$Id: ping.c 434 2006-09-03 17:48:47Z reech $ */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include "opennap.h"
#include "debug.h"

/* [ :<user> ] <user> [ <optional args> ] */
HANDLER(ping)
{
    USER *orig, *user;
    char *nick;
    char reason[256];

    (void) len;
    ASSERT(validate_connection(con));

    if(pop_user(con, &pkt, &orig) != 0)
        return;
    nick = pkt;
    pkt = strchr(nick, ' ');
    if(pkt)
        *pkt++ = 0;

    user = hash_lookup(global.usersHash, nick);
    if(!user)
    {
        if(ISUSER(con))
        {
            send_cmd(con, MSG_SERVER_NOSUCH, "ping failed, %s is not online", nick);
        }
        return;
    }

    if(global.BlockWinMX > 0 && user != orig)
    {
        if(tag == MSG_CLIENT_PING)
            user->wantPong++;
        else if(orig->wantPong == 0)
        {
            if(orig->level < LEVEL_MODERATOR)
            {
                discipline_user(orig);
                return;
            }
        }
        else
            orig->wantPong--;
    }

    if(ISUSER(user->con))
    {
        if(!is_ignoring(user->con->uopt->ignore, orig->nick))
        {
            send_cmd(user->con, tag, "%s%s%s", orig->nick, pkt ? " " : "", NONULL(pkt));
        }
        else {
            send_user(orig, MSG_SERVER_NOSUCH, "%s is ignoring you",user->nick);

            /* Check if the user who ignored the other has a lower level than the ignored one ...
            "sender" is the user who sent the request. "user" ist the user who chose to ignore sender. */
            if( user->level < LEVEL_MODERATOR && orig->level > user->level && option(ON_DISCIPLINE_IGNORERS) ) 
			{
                if( global.discipline_ignorers_ban_ttl ) 
				{
                    snprintf( reason, sizeof(reason)-1, "Don't ignore a mod+ ever again (%s)",orig->nick), ban_user_internal( user->con, user->nick, global.discipline_ignorers_ban_ttl, reason);
                    log_message_level(LOG_LEVEL_DEBUG, "%s ignored %s in ping.c",user->nick,orig->nick);
                }
                kill_user_internal(user->con, user, global.serverName, 0, reason);
                return;
            }
        }
    }
    else
    {
        /* send the message to the server which this user appears to be
        behind */
        send_cmd(user->con, tag, ":%s %s%s%s", orig->nick, user->nick, pkt ? " " : "", NONULL(pkt));
    }
}
