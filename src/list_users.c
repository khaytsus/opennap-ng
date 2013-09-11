/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
This is free software distributed under the terms of the
GNU Public License.  See the file COPYING for details.

$Id: list_users.c 434 2006-09-03 17:48:47Z reech $ */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>
#include <ctype.h>
#include "opennap.h"
#include "debug.h"

/* packet contains: <channel> */
HANDLER(list_users)
{
    CHANNEL *chan;
    LIST   *list;
    CHANUSER *chanUser;

    (void) tag;
    (void) len;
    ASSERT(validate_connection(con));
    CHECK_USER_CLASS("list_users");
    chan = hash_lookup(global.channelHash, pkt);
    if(!chan)
    {
        nosuchchannel(con);
        return;
    }
    ASSERT(validate_channel (chan));
    /* make sure this user is on the channel */
    if(list_find(con->user->channels, chan) == 0)
    {
        send_cmd(con, MSG_SERVER_NOSUCH, "you're not on channel %s", chan->name);
        return;
    }

    for (list = chan->users; list; list = list->next)
    {
        chanUser = list->data;
        ASSERT(chanUser->magic == MAGIC_CHANUSER);
        send_cmd(con, MSG_SERVER_NAMES_LIST /* 825 */ , "%s %s %d %d", chan->name, chanUser->user->nick, chanUser->user->shared, chanUser->user->speed);
    }

    send_cmd(con, MSG_SERVER_NAMES_LIST_END /* 830 */ , "");
}

#define ON_GFLAG_ELITE      1
#define ON_GFLAG_ADMIN      2
#define ON_GFLAG_MODERATOR  4
#define ON_GFLAG_LEECH      8
#define ON_GFLAG_MUZZLED    16
#define ON_GFLAG_CLOAKED    32
#define ON_GFLAG_USERS      64
#define ON_GFLAG_CHANNEL    128
#define ON_GFLAG_USERIP     256

struct guldata
{
    int     flags;
    char   *server;
    char   *chan;
    unsigned int ip;
    unsigned int mask;
    CONNECTION *con;
};

static void global_user_list_cb(USER * user, struct guldata *data)
{
    ASSERT(validate_user(user));
    ASSERT(data != 0);
    if(data->flags)
    {
        /* selectively display users based on user level/muzzle/cloak */
        if(!
            (((data->flags & ON_GFLAG_ADMIN) && user->level == LEVEL_ADMIN)
            || ((data->flags & ON_GFLAG_ELITE) && user->level == LEVEL_ELITE)
            || ((data->flags & ON_GFLAG_MODERATOR)
            && user->level == LEVEL_MODERATOR)
            || ((data->flags & ON_GFLAG_USERS) && user->level == LEVEL_USER)
            || ((data->flags & ON_GFLAG_LEECH) && user->level == LEVEL_LEECH)
            || ((data->flags & ON_GFLAG_MUZZLED) && user->flags & ON_MUZZLED)
            || ((data->flags & ON_GFLAG_CLOAKED) && user->cloaked)
            || ((data->flags & ON_GFLAG_USERIP) && (user->ip & data->mask) == (data->ip & data->mask))))
            return;
    }
    if(data->server && *data->server != '*' && strcasecmp(data->server, user->server) != 0)
        return;         /* no match */
    send_cmd(data->con, MSG_SERVER_GLOBAL_USER_LIST, "%s %s", user->nick, my_ntoa(BSWAP32(user->ip)));
}


/* 831 [server] [flags] */
HANDLER(global_user_list)
{
    struct guldata data;
    char *flag, *ip;

    ASSERT(validate_connection(con));
    (void) len;
    CHECK_USER_CLASS("global_user_list");
    if(con->user->level < LEVEL_MODERATOR)
    {
        permission_denied(con);
        return;
    }
    memset(&data,0,sizeof(data));
    data.con = con;
    data.server = next_arg(&pkt);

    flag = next_arg(&pkt);
    while (flag && *flag)
    {
        switch (*flag)
        {
        case 'e':
            data.flags |= ON_GFLAG_ELITE;
            break;
        case 'a':
            data.flags |= ON_GFLAG_ADMIN;
            break;
        case 'm':
            data.flags |= ON_GFLAG_MODERATOR;
            break;
        case 'u':
            data.flags |= ON_GFLAG_USERS;
            break;
        case 'l':
            data.flags |= ON_GFLAG_LEECH;
            break;
        case 'z':
            data.flags |= ON_GFLAG_MUZZLED;
            break;
        case 'i':
            data.flags |= ON_GFLAG_USERIP;
            ip = next_arg(&pkt);
            if(!ip || !is_address (ip, &data.ip, &data.mask))
                goto guser_end;
            break;
        case 'c':
            data.flags |= ON_GFLAG_CLOAKED;
            break;
        case 'C':
            data.flags |= ON_GFLAG_CHANNEL;
            data.chan = next_arg(&pkt);
            break;
        }
        flag++;
        if(!*flag)
            flag = next_arg(&pkt);
    }

    if(data.flags & ON_GFLAG_CHANNEL)
    {
        CHANNEL *chan;
        LIST   *list;
        CHANUSER *chanUser;

        /* this needs to be unset otherwise global_user_list_cb() will
        * bomb out.
        */
        data.flags &= ~ON_GFLAG_CHANNEL;
        if(data.chan)
        {
            chan = hash_lookup(global.channelHash, data.chan);
            if(chan)
            {
                for (list = chan->users; list; list = list->next)
                {
                    chanUser = list->data;
                    ASSERT(chanUser->magic == MAGIC_CHANUSER);
                    global_user_list_cb(chanUser->user, &data);
                }
            }
            else
                nosuchchannel(con);
        }
    }
    else
        hash_foreach(global.usersHash, (hash_callback_t) global_user_list_cb, &data);
guser_end:
    send_cmd(con, tag, "");    /* end of list */
}
