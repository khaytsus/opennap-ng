/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
This is free software distributed under the terms of the
GNU Public License.

$Id: topic.c 434 2006-09-03 17:48:47Z reech $ */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifndef WIN32
# include <unistd.h>
#endif
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "opennap.h"
#include "debug.h"

/* topic for channel has changed */
/* [ :<nick> ] <channel> [topic] */

HANDLER(topic)
{
    CHANNEL *chan;
    int     l;
    char   *chanName, *sender_name, *ptr;
    LIST   *list;
    CHANUSER *chanUser;
    USER   *sender;

    (void) len;
    ASSERT(validate_connection(con));

    if(pop_user_server(con, tag, &pkt, &sender_name, &sender))
        return;

    /* don't use split line because the topic could be multi-word */
    chanName = next_arg(&pkt);
    if(!chanName)
    {
        if(ISUSER(con))
            send_cmd(con, MSG_SERVER_NOSUCH, "topic failed: missing channel name");
        return;
    }

    chan = hash_lookup(global.channelHash, chanName);
    if(!chan)
    {
        nosuchchannel(con);
        return;
    }

    if(chan->local && ISSERVER(con))
    {
        log_message_level(LOG_LEVEL_SERVER, "topic: server %s set topic on local channel %s", con->host, chan->name);
        return;
    }

    if(pkt)
    {
        if(sender && sender->level < LEVEL_MODERATOR)
        {
            if(!list_find(sender->channels, chan))
            {
                if(ISUSER(con))
                    send_cmd(con, MSG_SERVER_NOSUCH, "topic failed: you are not on that channel");
                return;
            }
            if(!(chan->flags & ON_CHANNEL_TOPIC) && !is_chanop(chan, sender))
            {
                if(ISUSER(con))
                    send_cmd(con, MSG_SERVER_NOSUCH, "topic failed: topic is restricted");
                return;
            }
        }

        if(chan->topic)
            FREE(chan->topic);
        /* if the topic is too long, truncate it */
        if(global.maxTopic > 0 && strlen(pkt) > (unsigned) global.maxTopic)
            *(pkt + global.maxTopic) = 0;
        chan->topic = STRDUP(pkt);
        if(!chan->topic)
        {
            OUTOFMEMORY("topic");
            return;
        }
        /* make sure we don't have any wacky characters in the topic */
        for (ptr = chan->topic; *ptr; ptr++)
            if(*ptr == '\r' || *ptr == '\n')
                *ptr = ' ';
        /* relay to peer servers */
        if(!chan->local)
            pass_message_args(con, tag, ":%s %s %s", sender_name, chan->name, chan->topic);

        l = form_message(Buf, sizeof(Buf), tag, "%s %s", chan->name, chan->topic);
        for (list = chan->users; list; list = list->next)
        {
            chanUser = list->data;
            ASSERT(chanUser->magic == MAGIC_CHANUSER);
            if(chanUser->user->local)
                queue_data(chanUser->user->con, Buf, l);
        }
        notify_ops(chan, "%s set topic on %s: %s", sender_name, chan->name, chan->topic);
    }
    else if(ISUSER(con))
    {
        /* return the current topic */
        send_cmd(con, tag, "%s %s", chan->name, chan->topic);
    }
}
