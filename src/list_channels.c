/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
This is free software distributed under the terms of the
GNU Public License.  See the file COPYING for details.

$Id: list_channels.c 434 2006-09-03 17:48:47Z reech $ */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>
#include "opennap.h"
#include "debug.h"

/* because there might be cloaked users on a channel, the effective channel
* count is not the same as the list membership, unless the user issuing
* the list is a mod+
*/
static int effective_channel_count(LIST * list, int mod)
{
    int     count = 0;
    CHANUSER *chanuser;

    if(mod)
        return list_count(list);
    for (; list; list = list->next)
    {
        chanuser = list->data;
        if(!chanuser->user->cloaked || !chanuser->user->desynced)
            count++;
    }
    return count;
}

static void channel_info(void *elem, void *data)
{
    CHANNEL *chan = (CHANNEL *) elem;

    ASSERT(VALID (elem));
    ASSERT(VALID (data));
    if((chan->flags & ON_CHANNEL_PRIVATE) == 0)
        send_cmd((CONNECTION *) data, MSG_SERVER_CHANNEL_LIST /* 618 */ , "%s %d %s", chan->name, effective_channel_count(chan->users, ((CONNECTION *) data)->user-> level >= LEVEL_MODERATOR), chan->topic);
}

/* send a list of channels we know about to the user */
HANDLER(list_channels)
{
    ASSERT(validate_connection(con));

    (void) pkt;         /* unused */
    (void) tag;
    (void) len;

    CHECK_USER_CLASS("list_channels");
    hash_foreach(global.channelHash, channel_info, con);
    send_cmd(con, MSG_SERVER_CHANNEL_LIST_END /* 617 */ , "");
}

static void full_channel_info(CHANNEL * chan, CONNECTION * con)
{
    ASSERT(validate_channel(chan));
    ASSERT(validate_connection(con));
    ASSERT(chan->topic != 0);
    if(((chan->flags & ON_CHANNEL_PRIVATE) == 0) || (con->user->level >= LEVEL_ADMIN))
        send_cmd(con, MSG_SERVER_FULL_CHANNEL_INFO, "%s %d %d %d %d \"%s\"",
        chan->name,
        effective_channel_count(chan->users,
        con->user->level >=
        LEVEL_MODERATOR),
        (chan->flags & ON_CHANNEL_REGISTERED) == 0, chan->level,
        chan->limit, chan->topic);
}

/* 827 */
HANDLER(full_channel_list)
{
    ASSERT(validate_connection(con));
    CHECK_USER_CLASS("list_all_channels");
    (void) pkt;
    (void) len;
    hash_foreach(global.channelHash, (hash_callback_t) full_channel_info, con);
    send_cmd(con, tag, "");
}
