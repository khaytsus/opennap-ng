/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
This is free software distributed under the terms of the
GNU Public License.  See the file COPYING for details.

$Id: public.c 434 2006-09-03 17:48:47Z reech $ */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#ifndef WIN32
# include <unistd.h>
#endif
#include <string.h>
#include "opennap.h"
#include "debug.h"

/* static buffer for use by public/emote.  these get called a lot so speed
things up by keeping it around.  there is no chance of either of these
being called from eachother or used elsewhere so this is safe */
static char PublicBuf[2048];

/* determine if `sender' has permission to send to channel `chan' */
static int check_permission(CHANNEL * chan, USER * sender)
{
    LIST   *list;
    CHANUSER *chanUser=NULL;

    for (list = chan->users; list; list = list->next)
    {
        chanUser = list->data;
        if(chanUser->user == sender)
            break;
    }

    if(!list)
    {
        log_message_level(LOG_LEVEL_DEBUG, "check_permission: fatal error, could not find %s on channel %s", sender->nick, chan->name);
        return -1;
    }

    if(sender->level < LEVEL_MODERATOR && (chanUser->flags & ON_CHANNEL_OPERATOR) == 0)
    {
        if(chan->flags & ON_CHANNEL_MODERATED)
        {
            if((chanUser->flags & ON_CHANNEL_VOICE) == 0)
            {
                if(ISUSER(sender->con))
                    send_cmd(sender->con, MSG_SERVER_NOSUCH, "permission denied: channel is moderated");
                return -1;
            }
        }
        else if(chanUser->flags & ON_CHANNEL_MUZZLED)
        {
            if(ISUSER(sender->con))
                send_cmd(sender->con, MSG_SERVER_NOSUCH, "permission denied: muzzled on channel");
            return -1;
        }
    }

    return 0;
}

/* 402 [ :<sender> ] <channel> <text> */
/*  public message to a channel */
HANDLER(public)
{
    CHANNEL *chan;
    USER   *sender;
    LIST   *list;
    char   *ptr;
    char   *sender_name;
    CHANUSER *chanUser;

    ASSERT(validate_connection(con));
    /* save the starting position of the pkt */
    ptr = pkt;
    if(pop_user_server(con, tag, &pkt, &sender_name, &sender))
        return;
    if(sender->flags & ON_MUZZLED)
    {
        if(ISUSER(con))
            send_cmd(con, MSG_SERVER_NOSUCH, "You are muzzled.");
        return;
    }

    /* protect against DoS attack against the windows napster client */
    if(len - (pkt - ptr) > 180)
    {
        pkt[180] = 0;       /* crop the message */
        log_message_level(LOG_LEVEL_DEBUG, "public: cropped %d byte message from user %s", len, sender->nick);
    }

    /* can't use split line here because the text field is considered all
    one item */
    /* extract the channel name. NOTE: we don't use next_arg() here because
    it will strip leading space from the text being sent */
    ptr = next_arg_noskip(&pkt);
    if(!pkt)
    {
        unparsable(con);
        return;
    }

    /* find the channel this message is going to. look the user's joined
    channels since this should be faster than lookup in the hash table */
    chan = find_channel(sender->channels, ptr);
    if(!chan)
    {
        if(ISUSER(con))
            send_cmd(con, MSG_SERVER_NOSUCH, "You are not a member of that channel");
        return;
    }

    if(ISSERVER(con) && chan->local)
    {
        log_message_level(LOG_LEVEL_DEBUG, "public: server %s accessed local channel %s", con->host, chan->name);
        return;
    }

    if(check_permission(chan, sender))
        return;

    /* relay this message to peer servers */
    if(!chan->local)
        pass_message_args(con, tag, ":%s %s %s", sender->nick, chan->name, pkt);

    /* the majority of the users in the channel will see this message, so
    form it one time */
    len = form_message(PublicBuf, sizeof(PublicBuf), MSG_SERVER_PUBLIC, "%s %s %s", chan->name, sender->cloaked ? "Operator" : sender->nick, pkt);

    /* send this message to everyone in the channel */
    for (list = chan->users; list; list = list->next)
    {
        chanUser = list->data;
        ASSERT(chanUser->magic == MAGIC_CHANUSER);
        if(ISUSER(chanUser->user->con))
        {
            if(sender->cloaked && chanUser->user->level > LEVEL_USER)
                send_cmd(chanUser->user->con, MSG_SERVER_PUBLIC, "%s #%s %s", chan->name, sender->nick, pkt);
            else
                queue_data(chanUser->user->con, PublicBuf, len);
        }
    }
}

/* 824 [ :<user> ] <channel> "<text>" */
HANDLER(emote)
{
    CHANUSER *chanUser;
    USER   *user;
    CHANNEL *chan;
    char   *ptr, *av[2];
    char   *sender_name;
    LIST   *list;

    ASSERT(validate_connection(con));
    ptr = pkt;          /* save initial location */
    if(pop_user_server(con, tag, &pkt, &sender_name, &user) != 0)
        return;
    if(user->flags & ON_MUZZLED)
    {
        if(ISUSER(con))
            send_cmd(con, MSG_SERVER_NOSUCH, "You are muzzled");
        return;
    }

    /* protect against DoS attack against the windows napster client */
    if(len - (pkt - ptr) > 180)
    {
        /* crop message */
        pkt[179] = '"';
        pkt[180] = 0;
        log_message_level(LOG_LEVEL_DEBUG, "emote: cropped %d byte message from user %s", len, user->nick);
    }

    if(split_line(av, sizeof(av) / sizeof(char *), pkt) < 2)
    {
        unparsable(con);
        return;
    }

    /* find the channel this message is going to. look the user's joined
    channels since this should be faster than lookup in the hash table */
    chan = find_channel(user->channels, av[0]);
    if(!chan)
    {
        if(ISUSER(con))
            send_cmd(con, MSG_SERVER_NOSUCH, "You are not a member of that channel");
        return;
    }

    if(ISSERVER(con) && chan->local)
    {
        log_message_level(LOG_LEVEL_DEBUG, "emote: server %s accessed local channel %s", con->host, chan->name);
        return;
    }

    if(check_permission(chan, user))
        return;

    /* relay to peer servers */
    if(!chan->local)
        pass_message_args(con, tag, ":%s %s \"%s\"", user->nick, chan->name, av[1]);

    /* majority of the users see the same message, so form it once */
    len = form_message(PublicBuf, sizeof(PublicBuf), tag, "%s %s \"%s\"", chan->name, user->cloaked ? "Operator" : user->nick, av[1]);

    /* send this message to all channel members */
    for (list = chan->users; list; list = list->next)
    {
        chanUser = list->data;
        ASSERT(chanUser->magic == MAGIC_CHANUSER);
        if(ISUSER(chanUser->user->con))
        {
            if(user->cloaked && chanUser->user->level > LEVEL_USER)
                send_cmd(chanUser->user->con, tag, "%s #%s \"%s\"", chan->name, user->nick, av[1]);
            else
                queue_data(chanUser->user->con, PublicBuf, len);
        }
    }
}

/* queues a raw message (tag & length header is assumed to be present */
int send_to_channel(char *name, char *buf, int buflen)
{
    CHANNEL *chan;
    LIST   *list;
    CHANUSER *user;

    /* if the global.channelHash hash table has not been initialized yet, abort */
    if(!global.channelHash)
        return -1;
    chan = hash_lookup(global.channelHash, name);
    /* if nobody is in the log channel, abort */
    if(!chan)
        return -1;
    for (list = chan->users; list; list = list->next)
    {
        user = list->data;
        if(ISUSER(user->user->con))
            queue_data(user->user->con, buf, buflen);
    }
    return 0;
}
