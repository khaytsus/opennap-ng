/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
This is free software distributed under the terms of the
GNU Public License.  See the file COPYING for details.

$Id: browse.c 434 2006-09-03 17:48:47Z reech $ */


#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include "opennap.h"
#include "debug.h"

#ifndef ROUTING_ONLY

typedef struct
{
    short   count;
    short   max;
    USER   *sender;
    USER   *user;
}
BROWSE;

static void browse_callback(DATUM * info, BROWSE * ctx)
{
    /* avoid flooding the client */
    if(ctx->max == 0 || ctx->count < ctx->max)
    {
        send_user(ctx->sender, MSG_SERVER_BROWSE_RESPONSE,"%s \"%s\" %s %u %hu %hu %hu", info->user->nick, info->filename,
#if RESUME
            info->hash,
#else
            "00000000000000000000000000000000",
#endif
            info->size, BitRate[info->bitrate], SampleRate[info->frequency], info->duration);

        ctx->count++;
    }
}

#endif /* ! ROUTING_ONLY */

/* 211 [ :<sender> ] <nick> [ <max> ]
browse a user's files */
HANDLER(browse)
{
    USER   *sender, *user;
    char   *nick;
    char    message[512];
    int     result;
    char    reason[256];

    (void) tag;
    (void) len;
    ASSERT(validate_connection(con));
    if(pop_user(con, &pkt, &sender))
        return;
    nick = next_arg(&pkt);
    if(!nick)
    {
        unparsable(con);
        return;
    }
    user = hash_lookup(global.usersHash, nick);
    if(!user)
    {
        if(ISUSER(con))
        {
            /* the napster servers send a 210 instead of 404 for this case */
            send_cmd(con, MSG_SERVER_USER_SIGNOFF, "%s", nick);
            /* always terminate the list */
            send_cmd(con, MSG_SERVER_BROWSE_END, "%s", nick);
        }
        return;
    }
    ASSERT(validate_user(user));

    if(sender->level == LEVEL_LEECH)
    {
        send_user(sender, MSG_SERVER_BROWSE_END, "%s 0", nick);
        return;
    }

    if(pkt)
    {
        result = atoi(pkt);
        if(result == 0 || (global.maxBrowseResult > 0 && result > global.maxBrowseResult))
            result = global.maxBrowseResult;
    }
    else
        result = global.maxBrowseResult;

    /* MOD+ are exempt from the limits */
    if(sender->level > LEVEL_USER)
        result = global.maxShared;

    if(!option(ON_REMOTE_BROWSE) && (!ISUSER(sender->con) || !ISUSER(user->con)))
    {
        /* remote browsing is not supported */
        send_user(sender, MSG_SERVER_BROWSE_END, "%s %u", user->nick, (user->shared > 0) ? user->ip : 0);
        return;
    }


    if(option(ON_BROWSE_NAG) && ! sender->did640browse && sender->level < LEVEL_MODERATOR ) 
	{
        /* Send a message about the obsolete client method to the other end */
        send_self( con, sender, "Your client issued a server based browse command." );
        send_self( con, sender, "This arcane method of filebrowsing drew up to 75% per day of bandwidth of our network.");
        snprintf( message, sizeof(message), "So we really had to restrict the resultset to %d files.", global.maxBrowseResult);
        send_self( con, sender, message);
        send_self( con, sender, "Please use a client which supports direct client browsing, such as from http://winlop.sf.net ");
        snprintf( message, sizeof(message), "or ask the software producer of your client %s for the implementation of the client browse command", sender->clientinfo);
        send_self( con, sender, message);
        send_self( con, sender, "If you already do, then the other client did not support the client browse method.");
        send_self( con, sender, "Please invite the other user to use a different client which supports client browsing then.");
        send_self( con, sender, "Sorry for the inconvenience.");
    }


    if(ISUSER(user->con))
    {
#ifndef ROUTING_ONLY

        if(user->con->uopt->files)
        {
            BROWSE  data;
            data.count = 0;
            data.user = user;
            data.sender = sender;
            data.max = pkt ? atoi(pkt) : 0;

            /* Mod+ are exempt from the limit exposed in max_browse_result */
            if(( global.maxBrowseResult > 0 && ( data.max > global.maxBrowseResult || data.max==0 ) ) && sender->level == LEVEL_USER)
                data.max = global.maxBrowseResult;
            hash_foreach(user->con->uopt->files, (hash_callback_t) browse_callback, &data);
        }
#endif /* ! ROUTING_ONLY */

        /* send end of browse list message */
        send_user(sender, MSG_SERVER_BROWSE_END, "%s %u", user->nick, user->shared > 0 ? user->ip : 0);
            /* don't send the ip if the user isn't sharing - security */
    }
    else
    {
        /* relay to the server that this user is connected to */
        if(con != user->con)
            send_cmd(user->con, tag, ":%s %s %d", sender->nick, user->nick, result);
        else
        {
            snprintf(reason, sizeof(reason), "browse.c: browse: recip->con=con: sender: %s(%s) recip: %s(%s)", sender->nick, sender->server, user->nick, user->server);
            log_message_level(LOG_LEVEL_DEBUG, reason);
            kill_user_internal(user->con, user, global.serverName, 0, "ghost resync: browse.c: browse"); /* reason); */
        }
    }
}

/* 640 [:sender] nick
* direct browse request
*/
HANDLER(browse_direct)
{
    char   *sender_name, *nick;
    USER   *sender, *user;
    char    reason[256];

    (void) len;
    if(pop_user_server(con, tag, &pkt, &sender_name, &sender))
        return;
    nick = next_arg(&pkt);
    if(!nick)
    {
        unparsable(con);
        return;
    }
    user = hash_lookup(global.usersHash, nick);
    if(!user)
    {
        nosuchuser(con);
        return;
    }

    if(sender->level == LEVEL_LEECH)
    {
        send_user(sender,MSG_SERVER_BROWSE_DIRECT_ERR, "%s \"permission denied: you are a leech\"", user->nick);
        return;
    }

    if(ISUSER(con))
    {
        sender->did640browse=1;
        if(sender->port == 0 && user->port == 0)
        {
            send_cmd(con, MSG_SERVER_BROWSE_DIRECT_ERR, "%s \"Both you and %s are firewalled; you cannot browse or download from them.\"", user->nick, user->nick);
            return;
        }
        else if(user->shared == 0)
        {
            send_cmd(con, MSG_SERVER_BROWSE_DIRECT_ERR, "%s \"%s is not sharing any files.\"", user->nick, user->nick);
            return;
        }
    }

    if(ISUSER(user->con))
    {
        if(!is_ignoring(user->con->uopt->ignore, sender->nick))
        {
            if(user->port == 0)
            {
                /* client being browsed is firewalled.  send full info so
                * a back connection to the browser can be made.
                */
                send_cmd(user->con, MSG_CLIENT_BROWSE_DIRECT, "%s %u %hu", sender_name, sender->ip, sender->port);
            }
            else
            {
                /* directly connected to this server */
                send_cmd(user->con, MSG_CLIENT_BROWSE_DIRECT, "%s", sender_name);
            }
        }
        else
            send_cmd(con, MSG_SERVER_BROWSE_DIRECT_ERR, "%s \"%s is not online.\"", user->nick, user->nick);
    }
    else
    {
        if(con != user->con)
            send_cmd(user->con, MSG_CLIENT_BROWSE_DIRECT, ":%s %s", sender_name, user->nick);
        else
        {
            snprintf(reason, sizeof(reason), "browse.c: browse_direct: recip->con=con: sender: %s(%s) recip: %s(%s)", sender_name, (sender?sender->server:sender_name), user->nick, user->server);
            log_message_level(LOG_LEVEL_DEBUG, reason);
            kill_user_internal(user->con, user, global.serverName, 0, "ghost resync: browse.c: browse_direct"); /* reason); */
        }
    }
}

/* 641 [:sender] nick
* direct browse accept
*/
HANDLER(browse_direct_ok)
{
    char   *sender_name, *nick;
    USER   *sender, *user;
    char    reason[256];

    (void) len;
    if(pop_user_server(con, tag, &pkt, &sender_name, &sender))
        return;
    nick = next_arg(&pkt);
    if(!nick)
    {
        unparsable(con);
        return;
    }
    user = hash_lookup(global.usersHash, nick);
    if(!user)
    {
        nosuchuser(con);
        return;
    }
    if(ISUSER(user->con))
    {
        /* directly connected to this server */
        send_cmd(user->con, MSG_SERVER_BROWSE_DIRECT_OK, "%s %u %hu", sender->nick, sender->ip, sender->port);
    }
    else
    {
        if(con != user->con)
            send_cmd(user->con, MSG_SERVER_BROWSE_DIRECT_OK, ":%s %s", sender_name, user->nick);
        else
        {
            snprintf(reason, sizeof(reason), "browse.c: browse_direct_ok: recip->con=con: sender: %s(%s) recip: %s(%s)", sender_name, (sender?sender->server:sender_name), user->nick, user->server);
            log_message_level(LOG_LEVEL_DEBUG, reason);
            kill_user_internal(user->con, user, global.serverName, 0, "ghost resync: browse.c: browse_direct_ok"); /* reason); */
        }

    }
}

