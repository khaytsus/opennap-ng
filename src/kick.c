/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
This is free software distributed under the terms of the
GNU Public License.  See the file COPYING for details.

$Id: kick.c 434 2006-09-03 17:48:47Z reech $ */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>
#include "opennap.h"
#include "debug.h"

int is_chanop(CHANNEL * chan, USER * user)
{
    LIST   *list;
    CHANUSER *chanUser;

    for (list = chan->users; list; list = list->next)
    {
        chanUser = list->data;
        ASSERT(chanUser->magic == MAGIC_CHANUSER);
        if(chanUser->user == user)
            return(chanUser->flags & ON_CHANNEL_OPERATOR);
    }
    return 0;
}

void sync_channel_user(CONNECTION * con, CHANNEL * chan, CHANUSER * chanUser)
{
    ASSERT(chan->local == 0);

    /* have to correct for desync */
    send_cmd(con, MSG_CLIENT_JOIN, ":%s %s", chanUser->user->nick, chan->name);

    /* restore channel flags */
    if(chanUser->flags & ON_CHANNEL_OPERATOR)
        send_cmd(con, MSG_CLIENT_OP, ":%s %s %s :%u", global.serverName, chan->name, chanUser->user->nick, chan->timestamp);
    if(chanUser->flags & ON_CHANNEL_VOICE)
        send_cmd(con, MSG_CLIENT_CHANNEL_VOICE, ":%s %s %s :%u", global.serverName, chan->name, chanUser->user->nick, chan->timestamp);
    if(chanUser->flags & ON_CHANNEL_MUZZLED)
        send_cmd(con, MSG_CLIENT_CHANNEL_MUZZLE, ":%s %s %s \"\" %u", global.serverName, chan->name, chanUser->user->nick, chan->timestamp);
}

/* 10202 [ :<sender> ] <channel> <user> [ "<reason>" ] */
HANDLER(kick)
{
    char   *av[3];
    char   *senderName;
    int     ac = -1;
    USER   *user, *sender;
    CHANNEL *chan;
    CHANUSER *chanUser;

    (void) len;
    ASSERT(validate_connection(con));
    if(pop_user_server(con, tag, &pkt, &senderName, &sender))
        return;
    if(pkt)
        ac = split_line(av, FIELDS(av), pkt);
    if(ac < 2)
    {
        unparsable(con);
        return;
    }
    chan = hash_lookup(global.channelHash, av[0]);
    if(!chan)
    {
        nosuchchannel(con);
        return;
    }
    if(chan->local && ISSERVER(con))
    {
        log_message_level(LOG_LEVEL_CHANNEL, "kick: server %s accessed local channel %s", con->host, chan->name);
        return;
    }
    user = hash_lookup(global.usersHash, av[1]);
    if(!user)
    {
        if(ISUSER(con))
            send_cmd(con, MSG_SERVER_NOSUCH, "channel kick failed: no such user");
        return;
    }

    if(sender && sender->level < LEVEL_MODERATOR)
    {
        if(list_find(sender->channels, chan) == 0)
        {
            if(ISUSER(con))
                send_cmd(con, MSG_SERVER_NOSUCH, "channel kick failed: you are not on that channel");
            return;
        }
        else if(!is_chanop(chan, sender))
        {
            if(ISUSER(con))
                send_cmd(con, MSG_SERVER_NOSUCH, "channel kick failed: you are not channel operator");
            return;
        }
    }

    /* check if the target user is on the given channel */
    chanUser = find_chanuser(chan->users, user);

    if(!chanUser)
    {
        if(ISUSER(con))
            send_cmd(con, MSG_SERVER_NOSUCH, "channel kick failed: user is not on that channel");
        return;
    }

    if(ac > 2)
        truncate_reason(av[2]);

    if(!chan->local)
        pass_message_args(con, tag, ":%s %s %s \"%s\"", senderName, chan->name, user->nick, (ac > 2) ? av[2] : "");

    if(ISUSER(user->con))
    {
        char   *who;

        if(sender && sender->cloaked && user->level < LEVEL_MODERATOR)
            who = "Operator";
        else
            who = senderName;

        send_cmd(user->con, MSG_CLIENT_PART, chan->name);
        send_cmd(user->con, MSG_SERVER_NOSUCH, "You were kicked from channel %s by%s %s: %s", chan->name, !sender ? "server " : "", who, ac > 2 ? av[2] : "");
    }

    user->channels = list_delete(user->channels, chan);

    notify_ops(chan, "%s%s kicked %s out of channel %s: %s", !sender ? "Server " : "", senderName, user->nick, chan->name, ac > 2 ? av[2] : "");

    /* has to come after the notify_ops() since it uses chan->name and
    chan may disappear if there are no users left
    Greg Prosser <greg@snickers.org> */
    part_channel(chan, user);
}

/* 820 [ :<sender> ] <channel> ["reason"] */
HANDLER(clear_channel)
{
    CHANNEL *chan;
    CHANUSER *chanUser;
    USER   *sender;
    LIST   *list;
    char   *chanName, *senderName;

    (void) len;
    ASSERT(validate_connection(con));
    if(pop_user_server(con, tag, &pkt, &senderName, &sender))
        return;
    chanName = next_arg(&pkt);
    if(!chanName)
    {
        unparsable(con);
        return;
    }
    chan = hash_lookup(global.channelHash, chanName);
    if(!chan)
    {
        nosuchchannel(con);
        return;
    }
    if(!sender)
    {
        log_message_level(LOG_LEVEL_CHANNEL, "clear_channel: error, server %s tried to clear channel %s", con->host, chanName);
        return;
    }

    if(chan->local && ISSERVER(con))
    {
        log_message_level(LOG_LEVEL_CHANNEL, "clear_channel: server %s cleared local channel %s", con->host, chan->name);
        return;
    }

    if(sender->level < LEVEL_MODERATOR && !is_chanop(chan, sender))
    {
        if(ISUSER(con))
            send_cmd(con, MSG_SERVER_NOSUCH, "channel clear failed: not channel operator");
        return;
    }

    if(pkt)
        truncate_reason(pkt);
    if(!chan->local)
        pass_message_args(con, tag, ":%s %s %s", sender->nick, chan->name, NONULL(pkt));
    notify_ops(chan, "%s cleared channel %s: %s", sender->nick, chan->name, NONULL(pkt));
    list = chan->users;
    while (list)
    {
        ASSERT(VALID_LEN(list, sizeof(LIST)));
        chanUser = list->data;
        ASSERT(chanUser->magic == MAGIC_CHANUSER);
        /* part_channel() may free the current `list' pointer so we advance
        it here prior to calling it */
        list = list->next;
        /* this used to avoid kicking users of a higher level, but that
        * lead to many desyncs.  just make it all all-or-nothing event.
        * mods+ can always bypass any channel restrictions anyway
        */
        if(chanUser->user != sender)
        {
            chanUser->user->channels =
                list_delete(chanUser->user->channels, chan);
            if(ISUSER(chanUser->user->con))
            {
                send_cmd(chanUser->user->con, MSG_CLIENT_PART, "%s", chan->name);
                send_cmd(chanUser->user->con, MSG_SERVER_NOSUCH, "%s cleared channel %s: %s", sender->nick, chan->name, NONULL(pkt));
            }
            part_channel(chan, chanUser->user);
        }
    }
}
