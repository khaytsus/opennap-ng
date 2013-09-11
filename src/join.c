/* Copyright(C) 2000-1 drscholl@users.sourceforge.net
This is free software distributed under the terms of the
GNU Public License.  See the file COPYING for details.

$Id: join.c 434 2006-09-03 17:48:47Z reech $ */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifndef WIN32
# include <unistd.h>
#endif
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "opennap.h"
#include "debug.h"

/* ensure the channel name contains only valid characters */
int invalid_channel(const char *s)
{
    int     count = 0;

    if(option(ON_IRC_CHANNELS) && *s != '#' && *s != '&')
        return 1;       /* must start with # or & */
    s++;
    while (*s)
    {
        if(*s < '!' || *s > '~' || strchr("%$*?\",", *s))
            return 1;
        count++;
        s++;
    }
    return((count == 0) ||(global.maxChanLen > 0 && count > global.maxChanLen));
}

static BAN *is_banned(LIST * bans, const char *nick, const char *host)
{
    char    mask[256];

    snprintf(mask, sizeof(mask), "%s!%s", nick, host);
    for (; bans; bans = bans->next)
    {
        if(glob_match(((BAN *) bans->data)->target, mask))
            return bans->data;
    }
    return 0;
}

/* this function gets called when we see a JOIN from a remote server that
* shouldn't have happened, such as a channel full, +INVITE or a ban.  we
* need to send back a KICK to make sure all servers stay synched.
*/
static void join_desync(CONNECTION * con, const char *chan, USER * user, const char *reason)
{
    log_message_level(LOG_LEVEL_ERROR, "join_desync: server %s is desynced", con->host);
    send_cmd(con, MSG_CLIENT_KICK, ":%s %s %s \"%s\"", global.serverName, chan, user->nick, reason);
}

/* handle client request to join channel */
/* [ :<nick> ] <channel> */
HANDLER(join)
{
    USER   *user;
    CHANNEL *chan;
    LIST   *list;
    CHANUSER *chanUser, *cu;
    int     chanop = 0;
    int     local = 0;
    char    chanbuf[256];   /* needed when creating a rollover channel */
    char   *chan_name;
    char   *sender_name;

    (void) tag;
    (void) len;
    ASSERT(validate_connection(con));
    if(pop_user_server(con, tag, &pkt, &sender_name, &user) != 0)
        return;
    ASSERT(validate_user(user));
    chan_name = next_arg(&pkt);
    if(!chan_name)
    {
        unparsable(con);
        return;
    }

    /* this loop is here in case the channel has a limit so we can create
    the rollover channels */
    ASSERT(sizeof(chanbuf) >=(unsigned int) global.maxChanLen);
    chanbuf[sizeof(chanbuf) - 1] = 0;

    /* automatically prepend # to channel names if missing */
    if(option(ON_IRC_CHANNELS) && *chan_name != '#' && *chan_name != '&')
    {
        if(ISUSER(con))
        {
            /* for older clients that still let channels through with no
            * prefix, automatically prepend it here.  most clients seem to
            * be able to deal with the join for a different channel being
            * set back to them
            */
            snprintf(chanbuf, sizeof(chanbuf), "#%s", chan_name);
            chan_name = chanbuf;
        }
        else
        {
            /* peer server shouldn't have let this through, so we will
            * reject it.
            */
            join_desync(con, chan_name, user, "invalid channel name");
            return;
        }
    }

    /* check if this is a local channel */
    local =(*chan_name == '&');
    if(local && ISSERVER(con))
    {
        log_message_level(LOG_LEVEL_CHANNEL, "join: server %s joined local channel %s", user->nick, user->server, chan_name);
        return;
    }

    if(ISUSER(con))
    {
        if(user->level < LEVEL_MODERATOR)
        {
            /* enforce a maximum channels per user */
            /* TODO: if linked servers have different settings, the channel
            membership could become desynched */
            if(list_count(user->channels) >= global.maxUserChannels)
            {
                if(ISUSER(con))
                    send_cmd(con, MSG_SERVER_NOSUCH, "channel join failed: you may only join %d channels", global.maxUserChannels);
                else
                    join_desync(con, chan_name, user, "joined max channels");
                return;
            }
            if(user->flags & ON_MUZZLED)
            {
                if(ISUSER(con))
                    send_cmd(con, MSG_SERVER_NOSUCH, "channel join failed: can't join channels while muzzled");
                else
                    join_desync(con, chan_name, user, "user is muzzled");
                return;
            }
        }
    }

    for (;;)
    {
        chan = hash_lookup(global.channelHash, chan_name);
        if(!chan)
        {
            /* check if this server allows normals to create channels */
            if((global.serverFlags & ON_STRICT_CHANNELS) && user->level < LEVEL_MODERATOR)
            {
                if(ISUSER(con))
                    send_cmd(con, MSG_SERVER_NOSUCH, "channel join failed: permission denied");
                else
                    join_desync(con, chan_name, user, "can't create channels");
                return;
            }
            if(invalid_channel(chan_name))
            {
                if(ISUSER(con))
                    send_cmd(con, MSG_SERVER_NOSUCH, "channel join failed: invalid channel");
                else
                    join_desync(con, chan_name, user, "invalid channel name");
                return;
            }
            if(!strcasecmp("&LOG", chan_name) && user->level < LEVEL_ADMIN )
            {
                if(ISUSER(con))
                    send_cmd(con, MSG_SERVER_NOSUCH, "channel join failed: you dont belong in &LOG");
                return;
            }
            chan = new_channel();
            if(!chan)
                return;     /* out of memory */
#if ONAP_DEBUG
            chan->magic = MAGIC_CHANNEL;
#endif
            chan->name = STRDUP(chan_name);
            if(!chan->name)
            {
                OUTOFMEMORY("join");
                FREE(chan);
                return;
            }

            chan->local = local;
            chan->level = LEVEL_USER;

#if LOG_CHANNEL
            if(local && !strcasecmp("&LOG", chan->name))
            {
                chan->flags |= ON_CHANNEL_QUIET;
                chan->level = LEVEL_ADMIN;
            }
#endif

            /* we only set the timestamp if a local user creates the
            * channel.  otherwise we have to get it from the remote
            * server since our clocks might not be synched.
            */
            if(ISUSER(con))
                chan->timestamp = global.current_time;

            /* set the default topic */
            snprintf(Buf, sizeof(Buf), "Welcome to the %s channel.", chan->name);
            chan->topic = STRDUP(Buf);
            if(!chan->topic)
            {
                OUTOFMEMORY("join");
                FREE(chan->name);
                FREE(chan);
                return;
            }
            hash_add(global.channelHash, chan->name, chan);
            /* log_message_level(LOG_LEVEL_CHANNEL, "join: creating channel %s", chan->name); */

            if(ISUSER(con))
            {
                /* the first user to enter a channel gets ops.  note that
                * predefined channels with no users never give out ops.
                * this is to prevent people from trying to get ops by
                * riding splits.  we also only set chanop when a local
                * user creates the channel.  this is to avoid problems when
                * syncing servers since the first join message we get is
                * not necessarily the first person who entered the channel
                * on the remote side.  we let the remote server tell us
                * who is opped.
                */
                chanop = 1;
            }
        }
        /* ensure that this user isn't already on this channel */
        else if(list_find(user->channels, chan))
        {
            if(ISUSER(con))
                send_cmd(con, MSG_SERVER_NOSUCH, "channel join failed: already joined channel");
            /* no need to correct desync since we already have the user in
            * the channel.
            */
            return;
        }
        /* check to make sure the user has privilege to join */
        else if(user->level < chan->level)
        {
            if(ISUSER(con))
                send_cmd(con, MSG_SERVER_NOSUCH, "channel join failed: requires level %s", Levels[chan->level]);
            else
                join_desync(con, chan->name, user, "not required level");
            return;
        }
        else
        {
            /* if not mod+, check extra permissions */
            if(user->level < LEVEL_MODERATOR)
            {
                BAN    *ban;

                /* check to make sure this user is not banned from the channel */
                ban = is_banned(chan->bans, user->nick, my_ntoa(BSWAP32(user->ip)));
                if(ban)
                {
                    if(ISUSER(user->con))
                    {
                        send_cmd(user->con, MSG_SERVER_NOSUCH, "channel join failed: banned: %s", NONULL(ban->reason));
                    }
                    else
                        join_desync(con, chan->name, user, "banned from channel");
                    return;
                }

                /* check for invitation */
                if((chan->flags & ON_CHANNEL_INVITE) && !list_find(chan->invited, user))
                {
                    if(ISUSER(con))
                        send_cmd(con, MSG_SERVER_NOSUCH, "channel join failed: invite only");
                    else
                        join_desync(con, chan->name, user, "no invite");
                    return;
                }

                if(chan->limit > 0 && list_count(chan->users) >= chan->limit)
                {
                    if((chan->flags & ON_CHANNEL_REGISTERED) == 0)
                    {
                        /* don't create rollover channels for non-registered
                        * channels.
                        */
                        if(ISUSER(con))
                            send_cmd(con, MSG_SERVER_NOSUCH, "channel join failed: channel full");
                        else
                            join_desync(con, chan->name, user, "channel full");
                        return;
                    }
                    /* for predefined channels, automatically create a rollover
                    channel when full */
                    else
                    {
                        char   *p;
                        int     n = 1;

                        if(chan_name != chanbuf)
                        {
                            strncpy(chanbuf, chan_name, sizeof(chanbuf) - 1);
                            chan_name = chanbuf;
                        }
                        p = chanbuf + strlen(chanbuf);
#define ISDIGIT(c)((c)>=0 &&(c)<='9')
                        while (p > chanbuf && ISDIGIT(*(p - 1)))
                            p--;
                        if(ISDIGIT(*p))
                        {
                            n = atoi(p);
                            *p = 0;
                        }
                        snprintf(chanbuf + strlen(chanbuf), sizeof(chanbuf) - strlen(chanbuf), "%d", n + 1);
                        log_message_level(LOG_LEVEL_CHANNEL, "join: trying channel %s", chanbuf);
                        continue;
                    }
                }
            }
        }
        break;
    }

    ASSERT(validate_channel(chan));

    /* clean up invite lists - do this even when not +INVITE just in case
    * it was present and then the channel was set to -INVITE
    */
    if(chan->invited)
        chan->invited = list_delete(chan->invited, user);

    /* add this channel to the list of this user is subscribed to */
    list = MALLOC(sizeof(LIST));
    if(!list)
    {
        OUTOFMEMORY("join");
        goto error;
    }
    list->data = chan;
    list->next = user->channels;
    user->channels = list;

    /* add this user to the channel members list */
    chanUser = CALLOC(1, sizeof(CHANUSER));
#if ONAP_DEBUG
    chanUser->magic = MAGIC_CHANUSER;
#endif
    chanUser->user = user;

    list = MALLOC(sizeof(LIST));
    if(!list)
    {
        OUTOFMEMORY("join");
        goto error;
    }
    list->data = chanUser;
    list->next = chan->users;
    chan->users = list;

    /* if there are linked servers, send this message along */
    if(!chan->local)
        pass_message_args(con, tag, ":%s %s", user->nick, chan->name);

    /* if local user send an ack for the join */
    if(ISUSER(con))
    {
        /* notify client of success */
        send_cmd(con, MSG_SERVER_JOIN_ACK, "%s", chan->name);

        if((chan->flags & ON_CHANNEL_QUIET) == 0)
        {
            /* send the client the list of current users in the channel */
            for (list = chan->users; list; list = list->next)
            {
                cu = list->data;
                ASSERT(cu != 0);
                ASSERT(cu->magic == MAGIC_CHANUSER);
                if(!cu->user->cloaked || user->level >= LEVEL_MODERATOR)
                    send_cmd(con, MSG_SERVER_CHANNEL_USER_LIST, "%s %s %d %d", chan->name, cu->user->nick, cu->user->shared, cu->user->speed);
            }
        }
    }

    if((chan->flags & ON_CHANNEL_QUIET) == 0)
    {
        /* notify members of the channel that this user has joined */
        for (list = chan->users; list; list = list->next)
        {
            cu = list->data;
            ASSERT(cu != 0);
            ASSERT(cu->magic == MAGIC_CHANUSER);
            if(ISUSER(cu->user->con) && cu->user != user &&(!user->cloaked || cu->user->level >= LEVEL_MODERATOR))
                send_cmd(cu->user->con, MSG_SERVER_JOIN, "%s %s %d %d", chan->name, user->nick, user->shared, user->speed);
        }
    }

    /* notify ops/mods+ of this users status */
    if(chanop)
    {
        notify_ops(chan, "Server %s set %s as operator on channel %s", global.serverName, user->nick, chan->name);
        /* set the flag after the notice so the user isn't notified
        * twice.
        */
        chanUser->flags |= ON_CHANNEL_OPERATOR;
        /* broadcast op message to all servers.  this should *only* happen
        * when a local user creates a new channel.  the reason we do this
        * is to solve the problem of server linking when the first join
        * message we get is not necessarily a channel op.  so we rely on
        * the remote server to tell us which users are opped.
        */
        ASSERT(ISUSER(con));
        if(!chan->local)
            pass_message_args(NULL, MSG_CLIENT_OP, ":%s %s %s :%u", global.serverName, chan->name, user->nick, chan->timestamp);
    }

    if(ISUSER(con))
    {
        if((chan->flags & ON_CHANNEL_QUIET) == 0)
        {
            /* send end of channel list message */
            /* NOTE: for some reason this is the way the napster.com servers send
            the messages.  I'm not sure why they send the end of channel list
            AFTER the join message for yourself */
            send_cmd(con, MSG_SERVER_CHANNEL_USER_LIST_END /*409 */ , "%s", chan->name);
        }

        /* send channel topic */
        ASSERT(chan->topic != 0);
        send_cmd(con, MSG_SERVER_TOPIC, "%s %s", chan->name, chan->topic);
        if(chanop)
            send_cmd(con, MSG_SERVER_NOSUCH, "Server %s set you as operator on channel %s", global.serverName, chan->name);
    }
    return;

error:
    /* set things back to a sane state */
    chan->users = list_delete(chan->users, user);
    user->channels = list_delete(user->channels, chan);
    if(!chan->users)
    {
        log_message_level(LOG_LEVEL_CHANNEL, "join: destroying channel %s", chan->name);
        hash_remove(global.channelHash, chan->name);
    }
    return;
}

/* 823 [ :<sender> ] <channel> [level [timestamp]]
* queries/sets the minimum user level required to enter a channel
*/
HANDLER(channel_level)
{
    char   *sender;
    USER   *senderUser;
    char   *av[3];
    CHANNEL *chan;
    int     level, ac = -1, desync = 0;

    (void) tag;
    (void) len;
    ASSERT(validate_connection(con));

    if(pop_user_server(con, tag, &pkt, &sender, &senderUser))
        return;

    if(pkt)
        ac = split_line(av, sizeof(av) / sizeof(char), pkt);

    if(ac < 1)
    {
        print_args(ac, av);
        unparsable(con);
        return;
    }
    chan = hash_lookup(global.channelHash, av[0]);
    if(!chan)
    {
        nosuchchannel(con);
        return;
    }
    ASSERT(validate_channel);

    if(ac == 1)
    {
        /* query the current mode */
        CHECK_USER_CLASS("channel_level");
        send_cmd(con, MSG_SERVER_NOSUCH, "Channel %s is level %s", chan->name, Levels[chan->level]);
        return;
    }

    level = get_level(av[1]);
    if(level == -1)
    {
        if(ISUSER(con))
            send_cmd(con, MSG_SERVER_NOSUCH, "channel level failed: invalid level");
        return;
    }
    if(chan->level == level)
        return;         /* same value, ignore */

    if(ISSERVER(con) && chan->local)
    {
        log_message_level(LOG_LEVEL_CHANNEL, "channel_level: server %s accessed local channel %s", con->host, chan->name);
        return;
    }

    /* check for permission */
    if(senderUser && senderUser->level < LEVEL_MODERATOR && !is_chanop(chan, senderUser))
    {
        if(ISUSER(con))
        {
            send_cmd(con, MSG_SERVER_NOSUCH, "channel level failed: you are not channel operator");
            return;
        }
        desync = 1;
    }
    /* check the TS if present */
    else if(ISSERVER(con) && ac > 2)
    {
        time_t  ts = atoi(av[2]);

        if(chan->timestamp > 0 &&(ts == 0 || ts > chan->timestamp))
            desync = 1;
        else
            chan->timestamp = ts;
    }

    if(desync)
    {
        /* detected server desync, correct the mode on the remote server */
        log_message_level(LOG_LEVEL_ERROR | LOG_LEVEL_CHANNEL, "channel_level: server %s is desynced", con->host);
        send_cmd(con, tag, ":%s %s %s %u", global.serverName, chan->name, Levels[chan->level], chan->timestamp);
        return;
    }

    if(!chan->local)
        pass_message_args(con, tag, ":%s %s %s %u", sender, chan->name, Levels[level], chan->timestamp);
    chan->level = level;
    notify_ops(chan, "%s set channel %s to level %s", sender, chan->name, Levels[level]);
}

/* 826 [:sender] <channel> [limit [timestamp]]
* queries/sets the max number of users on a channel
*/
HANDLER(channel_limit)
{
    int     ac = -1;
    int     limit;
    int     desync = 0;
    char   *av[3];
    char   *sender;
    USER   *senderUser;
    CHANNEL *chan;

    ASSERT(validate_connection(con));
    (void) len;
    if(pop_user_server(con, tag, &pkt, &sender, &senderUser))
        return;
    if(pkt)
        ac = split_line(av, FIELDS(av), pkt);
    if(ac < 1)
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
    if(ac == 1)
    {
        /*query current limit */
        CHECK_USER_CLASS("channel_limit");
        send_cmd(con, MSG_SERVER_NOSUCH, "Channel %s has limit %d", chan->name, chan->limit);
        return;
    }
    if(ISSERVER(con) && chan->local)
    {
        log_message_level(LOG_LEVEL_CHANNEL, "channel_limit: server %s accessed local channel %s", con->host, chan->name);
        return;
    }
    limit = atoi(av[1]);
    if(limit < 0 || limit > 65535)
    {
        if(ISUSER(con))
            send_cmd(con, MSG_SERVER_NOSUCH, "channel limit failed: invalid limit");
        return;
    }
    if(senderUser && senderUser->level < LEVEL_MODERATOR && !is_chanop(chan, senderUser)) 
    {
        if(ISUSER(con))
        {
            send_cmd(con, MSG_SERVER_NOSUCH, "channel limit failed: you are not channel operator");
            return;
        }
        desync = 1;
    }
    /* check timestamp */
    else if(ISSERVER(con) && ac > 2)
    {
        time_t  ts = atoi(av[2]);

        if(chan->timestamp > 0 &&(ts == 0 || ts > chan->timestamp))
            desync = 1;
        else
            chan->timestamp = ts;
    }

    if(desync)
    {
        /* server is out of sync, reset its limit */
        log_message_level(LOG_LEVEL_ERROR | LOG_LEVEL_CHANNEL, "channel_limit: server %s is desynced", con->host);
        send_cmd(con, tag, ":%s %s %d %u", global.serverName, chan->name, chan->limit, chan->timestamp);
        return;
    }

    /* wait until now to check for this so that if a remote server has
    * a different timestamp we can sync that even if the value is the
    * same
    */
    if(chan->limit == limit)
        return;         /* same value, just ignore it */

    chan->limit = limit;
    if(!chan->local)
        pass_message_args(con, tag, ":%s %s %d %u", sender, chan->name, limit, chan->timestamp);
    notify_ops(chan, "%s set limit on channel %s to %d", sender, chan->name, limit);
}
