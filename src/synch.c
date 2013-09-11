/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
This is free software distributed under the terms of the
GNU Public License.  See the file COPYING for details.

$Id: synch.c 436 2006-09-04 14:56:32Z reech $ */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <time.h>
#include "opennap.h"
#include "debug.h"

/* Added by winter_mute */
#ifdef USE_PROTNET
#  include <string.h>
#endif

char   *Levels[LEVEL_ELITE + 1] = { "Leech", "User", "Moderator", "Admin", "Elite" };

static void sync_user(USER * user, CONNECTION * con)
{
    ASSERT(validate_connection(con));
    ASSERT(validate_user(user));

    /* we should never tell a peer server about a user that is behind
    them */
    ASSERT(user->con != con);
    if(user->con == con)
    {
        /* this really shouldnt happen! */
        ASSERT(0);
        return;
    }

    /* send a login message for this user */
    send_cmd(con, MSG_CLIENT_LOGIN, "%s %s %hu \"%s\" %d unknown %u %u %s %hu", user->nick, user->pass, user->port, user->clientinfo, user->speed, user->connected, user->ip, user->server, user->conport);

    /* update the user's level */
    if(user->level != LEVEL_USER)
    {
        send_cmd(con, MSG_CLIENT_SETUSERLEVEL, ":%s %s %s", global.serverName, user->nick, Levels[user->level]);
    }

    if(user->cloaked)
        send_cmd(con, MSG_CLIENT_CLOAK, ":%s 1", user->nick);

    /* do this before the joins so the user's already in the channel see
    the real file count */
    if(user->shared)
        send_cmd(con, MSG_SERVER_USER_SHARING, "%s %hu %u", user->nick, user->shared, user->libsize);

    /* MUST be after the join's since muzzled users cant join */
    if(user->flags & ON_MUZZLED)
        send_cmd(con, MSG_CLIENT_MUZZLE, ":%s %s", global.serverName, user->nick);

    /* NOTE: channel joins are handled in sync_channel */
}

/* Added by winter_mute */
#ifdef USE_PROTNET
void resync_user(USER * user, CONNECTION * con)
{   
    LIST *chan_list; /* list of channels user is joined with */
    LIST *chan_user_list; /* list of users who have joined 'chan' */
    CHANNEL *chan;
    CHANUSER *chan_user;

    sync_user(user, con);

    /* rejoin all channels user was a joined to */
    for (chan_list = user->channels; chan_list; chan_list = chan_list->next)
    {  
        chan = chan_list->data;
        for (chan_user_list = chan->users; chan_user_list; chan_user_list = chan_user_list->next)
        {  
            chan_user = chan_user_list->data;
            if(strcmp(chan_user->user->nick, user->nick) == 0)
                sync_channel_user(con, chan, chan_user);
        }
    }
    notify_mods(SERVERLOG_MODE, "Server %s has resynced %s: %s tried killing %s on a PROTNET", global.serverName, user->nick, con->host, user->nick);
}
#endif

static void sync_chan(CHANNEL * chan, CONNECTION * con)
{
    LIST   *list;

    if(!chan->local)
    {
        for (list = chan->users; list; list = list->next)
            sync_channel_user(con, chan, list->data);

        if(chan->level != LEVEL_USER)
            send_cmd(con, MSG_CLIENT_SET_CHAN_LEVEL, ":%s %s %s %u", global.serverName, chan->name, Levels[chan->level], chan->timestamp);
        if(chan->limit != 0)
            send_cmd(con, MSG_CLIENT_CHANNEL_LIMIT, ":%s %s %d %u", global.serverName, chan->name, chan->limit, chan->timestamp);

		if(chan->flags)
			send_cmd(con, MSG_CLIENT_CHANNEL_MODE, ":%s %s%s%s%s%s :%u", global.serverName, chan->name,
				(chan->flags & ON_CHANNEL_PRIVATE) ? " +PRIVATE" : "",
				(chan->flags & ON_CHANNEL_MODERATED) ? " +MODERATED" : "",
				(chan->flags & ON_CHANNEL_INVITE) ? " +INVITE" : "",
				(chan->flags & ON_CHANNEL_TOPIC) ? " +TOPIC" : "",
				(chan->flags & ON_CHANNEL_REGISTERED) ? " +REGISTERED" : "",
				chan->timestamp);

        sync_channel_bans(con, chan);

        /*  Syncing topics would be good..  but this isn't going to work. */
		/* with no timestamp, both sides will send their topic to the other side...
		 * each side will probably end up with the other side's topic


        if(!chan->local) 
		{
			log_message_level(LOG_LEVEL_DEBUG, "sync_topic: DEBUG :%s %s %s", global.serverName, chan->name, chan->topic);
			pass_message_args(con, tag, ":%s %s %s", global.serverName, chan->name, chan->topic);
        }
		*/
    }
}

static void sync_server_list(CONNECTION * con)
{
    LIST   *list;
    LINK   *slink;
    CONNECTION *serv;

    /* sync local servers */
    for (list = global.serversList; list; list = list->next)
    {
        serv = list->data;
        if(serv != con)
        {
            send_cmd(con, MSG_SERVER_LINK_INFO, "%s %hu %s %hu 2",global.serverName, get_local_port(serv->fd), serv->host, serv->port);
        }
    }

    /* sync remote servers */
    for (list = global.serverLinksList; list; list = list->next)
    {
        slink = list->data;
        send_cmd(con, MSG_SERVER_LINK_INFO, "%s %hu %s %hu %d", slink->server, slink->port, slink->peer, slink->peerport, slink->hops + 1);
    }
}

static void sync_banlist(CONNECTION * con)
{
    LIST   *list;
    BAN    *b;

    ASSERT(validate_connection(con));
    for (list = global.banList; list; list = list->next)
    {
        b = list->data;
        ASSERT(b != 0);
        send_cmd(con, MSG_CLIENT_BAN, ":%s %s \"%s\" %u %lu", global.serverName, b->target, b->reason, b->timeout, b->when);
        /* As the server tban time sync works this debug is obsolete.
        log_message_level(LOG_LEVEL_DEBUG, "sync_banlist: DEBUG :%s %s \"%s\" %u %lu", global.serverName, b->target, b->reason, b->timeout, b->when);
        */
    }
}

void synch_server(CONNECTION * con)
{
    ASSERT(validate_connection(con));

    log_message_level(LOG_LEVEL_SERVER, "synch_server: syncing");

    /* send the current time of day to check for clock skew */
    send_cmd(con, MSG_SERVER_TIME_CHECK, ":%s %u", global.serverName, (int) time (&global.current_time));
    sync_server_list(con);
    /* send our peer server a list of all users we know about */
    hash_foreach(global.usersHash, (hash_callback_t) sync_user, con);
    /* sync the channel level */
    hash_foreach(global.channelHash, (hash_callback_t) sync_chan, con);
    sync_banlist(con);

    /* sync acls */
    acl_sync(con);

    log_message_level(LOG_LEVEL_SERVER, "synch_server: done");
    send_cmd(con, MSG_SERVER_SYNC_END, "");
}

/* Added by winter_mute */
/* need this function because desync_user AND 
my_resync_user use the same thing but with
different tags, so this makes each function
smaller.
*/
#ifdef USE_PROTNET
static void local_syncing(USER *user, int tag)
{
    LIST *chan_list;
    LIST *chan_users;
    CHANNEL *chan;
    CHANUSER *chan_user;
    int msg_len;

    /* notify other members of this channel that this user has parted */
    if(user->channels)
    {  /* for each channel the user is in, tell everybody that he is leaving */
        for (chan_list = user->channels; chan_list; chan_list = chan_list->next)
        {  
            chan = chan_list->data;
            msg_len = form_message(Buf, sizeof(Buf), tag, "%s %s %d %d", chan->name, user->nick, user->shared, user->speed);
            /* notify each user in those channels */
            for (chan_users = chan->users; chan_users; chan_users = chan_users->next)
            {  
                /* we only notify local clients */
                chan_user = chan_users->data;
                ASSERT(chan_user->magic == MAGIC_CHANUSER);
                if(ISUSER(chan_user->user->con))
                {  
                    if(chan_user->user->level >= LEVEL_MODERATOR && strcmp(chan_user->user->nick, user->nick) != 0)
                        queue_data(chan_user->user->con, Buf, msg_len);
                }
            }
        }
    }
}

/* Added by winter_mute */
/* sync a user - 10303 */
HANDLER(my_resync_user)
{
    char    *nick;
    LIST *chan_list;
    CHANNEL *chan;
    USERDB *db = 0;

    (void) tag;
    (void) len;

    ASSERT(validate_connection(con));
    ASSERT(con->class == CLASS_UNKNOWN);
    nick = next_arg(&pkt);

    if(!con->user->desynced)
        send_cmd(con, MSG_SERVER_NOSUCH, "resync: you are already synced");
    else if(glob_match(global.protnet, my_ntoa(BSWAP32(con->user->ip))) && con->user->level >= LEVEL_ELITE)
    {
        if(ISUSER(con))
        {
            log_message_level(LOG_LEVEL_SECURITY, "synch: HANDLER(my_resync_user): nick: %s ", con->user->nick);

            /* set the user's desynced bitfield to 1 */
            con->user->desynced = 0;

            /* "officially" join the channels, again :) */
            local_syncing(con->user, MSG_SERVER_JOIN);
            db = hash_lookup(global.userDbHash , con->user->nick);

            /* notify linked servers that user has come back */
            pass_message_args(con, MSG_CLIENT_LOGIN, "%s %s %hu \"%s\" %u %s %u %u %s %hu",  con->user->nick, con->user->pass, con->user->port,  con->user->clientinfo, con->user->speed,
#if EMAIL
                db->email ? db->email : "unknown",
#else
                "unknown",
#endif
                con->user->connected, con->user->ip, con->user->server, con->user->conport);

            /* join all the channels, cheap ass implementation, sorry :) */
            for (chan_list = con->user->channels; chan_list; chan_list = chan_list->next)
            {  
                chan = chan_list->data;
                pass_message_args(con, MSG_CLIENT_JOIN, ":%s %s", con->user->nick, chan->name);
            }
            send_cmd(con, MSG_SERVER_NOSUCH, "Resynced");
        }
    }
    else
        send_cmd(con, MSG_SERVER_NOSUCH, "resync failed: permission denied");
}

/* Added by winter_mute */
/* desync a user - 10304 */
HANDLER(desync_user)
{
    char   *nick;

    (void) tag;
    (void) len;

    ASSERT(validate_connection(con));
    ASSERT(con->class == CLASS_UNKNOWN);
    nick = next_arg(&pkt);

    if(con->user->desynced)
        send_cmd(con, MSG_SERVER_NOSUCH, "desync: you are already desynced");
    else if(glob_match(global.protnet, my_ntoa(BSWAP32(con->user->ip))) && con->user->level >= LEVEL_ELITE)
    {
        if(ISUSER(con))
        {  
            log_message_level(LOG_LEVEL_SECURITY, "synch: HANDLER(desync_user): nick: %s", con->user->nick);

            /* desync with linked servers */
            pass_message_args(con, MSG_CLIENT_QUIT, "%s", con->user->nick);

            /* stealthly leave all channels */
            local_syncing(con->user, MSG_SERVER_PART);

            /* set the user's desynced bitfield to 1 */
            con->user->desynced = 1;
            send_cmd(con, MSG_SERVER_NOSUCH, "Desynced");
        }
    }
    else
        send_cmd(con, MSG_SERVER_NOSUCH, "desync failed: permission denied");
}
#endif
