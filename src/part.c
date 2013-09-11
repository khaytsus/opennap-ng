/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
This is free software distributed under the terms of the
GNU Public License.  See the file COPYING for details.

$Id: part.c 434 2006-09-03 17:48:47Z reech $ */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>
#include "opennap.h"
#include "debug.h"

/* 401 [ :<nick> ] <channel>
* this function handles the PART(401) command from clients
*/
HANDLER(part)
{
    CHANNEL *chan = 0;
    USER *user;
    char *sender_name;
    char *arg;

    (void) len;
    ASSERT(validate_connection(con));

    if(pop_user_server(con, tag, &pkt, &sender_name, &user) != 0)
        return;
    ASSERT(validate_user(user));

    arg = next_arg(&pkt);
    if(!arg)
    {
        unparsable(con);
        return;
    }

    /* find the requested channel in the user's  list */
    chan = find_channel(user->channels, arg);
    if(!chan)
    {
        if(ISUSER(con))
            send_cmd(con, MSG_SERVER_NOSUCH, "part channel failed: you are not in that channel");
        else
            log_message_level(LOG_LEVEL_SERVER, "part: %s is not on channel %s (from %s)", user->nick, arg, con->host);
        return;
    }

    /* ack the user */
    if(ISUSER(con))
        send_cmd(con, tag, "%s", chan->name);

    if(!chan->local)
    {
        /* NOTE: we use the MSG_CLIENT_PART(401) message instead of
        passing MSG_SERVER_PART(407) to pass between servers because we
        can reuse this same function for both messages easier than
        implementing support for parsing the latter.  The 401 message
        will be translated into a 407 for sending to end users. */
        pass_message_args(con, MSG_CLIENT_PART, ":%s %s", user->nick, chan->name);
    }

    user->channels = list_delete(user->channels, chan);

    /* remove user from the channel members list and notify local clients */
    part_channel(chan, user);
}
