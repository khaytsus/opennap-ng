/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
This is free software distributed under the terms of the
GNU Public License.  See the file COPYING for details.

$Id: download.c 434 2006-09-03 17:48:47Z reech $ */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>
#include <stdio.h>
#include "opennap.h"
#include "debug.h"

/* 203 [ :<sender> ] <nick> "<filename>" */
/* 500 [ :<sender> ] <nick> "<filename>" */
/* handle client request for download of a file */
HANDLER(download)
{
    char   *av[2], *sender_name;
    USER   *user, *sender;
/*    DATUM  *info = 0; */
    int     ac = -1;
    char   reason[256];

    (void) len;
    ASSERT(validate_connection(con));
    if(pop_user_server(con, tag, &pkt, &sender_name, &sender))
        return;
    if(!sender)
    {
        /* packet came from a server not a user */
        log_message_level(LOG_LEVEL_ERROR, "download.c: download: came from :server, not :user?");
        return;
    }
    if(pkt)
        ac = split_line(av, sizeof(av) / sizeof(char *), pkt);

    if(ac < 2)
    {
        unparsable(con);
        return;
    }

    if(sender->level == LEVEL_LEECH)
    {
        send_user(sender, MSG_SERVER_NOSUCH, "permission denied: you are a leech");
        return;
    }

    /* find the user to download from */
    user = hash_lookup(global.usersHash, av[0]);
    if(!user)
    {
        send_user(sender, MSG_SERVER_SEND_ERROR, "%s \"%s\"", av[0], av[1]);
        return;
    }

    /* if the user holding the requested file is local... */
    if(ISUSER(user->con))
    {
        if(is_ignoring(user->con->uopt->ignore, sender->nick))
        {
            send_user(sender, MSG_SERVER_NOSUCH, "%s is ignoring you",user->nick);

            /* Check if the user who ignored the other has a lower level than the ignored one ...
            "sender" is the user who sent the request. "user" ist the user who chose to ignore sender. */
            if( user->level < LEVEL_MODERATOR && sender->level > user->level && option(ON_DISCIPLINE_IGNORERS) ) 
            {
                snprintf( reason, sizeof(reason)-1, "Don't ignore a mod+ ever again (%s)",sender->nick);
                if( global.discipline_ignorers_ban_ttl ) 
                {
                    ban_user_internal( user->con, user->nick, global.discipline_ignorers_ban_ttl, reason);
                    log_message_level( LOG_LEVEL_FILES, "%s ignored %s in download.c",user->nick,sender->nick);
                }
                kill_user_internal(user->con, user, global.serverName, 0, reason);
                return;
            }

            return;
        }

        /* check to make sure the user is actually sharing this file */
        /* how do we know that the user didnt find this file via direct browse?
        info = hash_lookup(user->con->uopt->files, av[1]);
        if(!info)
        {
            send_user(sender, MSG_SERVER_SEND_ERROR, "%s \"%s\"", user->nick, av[1]);
            return;
        }
        */
    }

    if(tag == MSG_CLIENT_DOWNLOAD)
    {
        if(user->port == 0)
        {
            /* uploader is firewalled, send file info so that downloader can
            send the 500 request */
            if(ISUSER(user->con))
            {
                send_user(sender, MSG_SERVER_FILE_READY, "%s %u %hu \"%s\" %s %d", user->nick, user->ip, user->port, av[1], "00000000000000000000000000000000", user->speed);
            }
            else
            {
                /* not a local user, we have to relay this request since we
                dont' have the file information local.  route it directly
                to the server we know this user is behind. */
                ASSERT(ISSERVER(user->con));
                if(con != user->con)
                    send_cmd(user->con, tag, ":%s %s \"%s\"", sender->nick, user->nick, av[1]);
                else
                {
                    snprintf(reason, sizeof(reason), "download.c: download: recip->con=con: sender: %s(%s) recip: %s(%s)", sender->nick, sender->server, user->nick, user->server);
                    log_message_level(LOG_LEVEL_DEBUG, reason);
                    kill_user_internal(user->con, user, global.serverName, 0, "ghost resync: download.c: download"); /* reason); */
                }
            }
            return;
        }
    }
    else
    {
        ASSERT(tag == MSG_CLIENT_DOWNLOAD_FIREWALL);
        if(user->port != 0)
        {
            /* this user is not firewalled */
            send_user(sender, MSG_SERVER_NOSUCH, "%s is not firewalled", user->nick);
            return;
        }
        if(sender->port == 0)
        {
            /* error, both clients are firewalled */
            ASSERT(ISUSER(con));
            send_cmd(con, MSG_SERVER_FILE_READY, "%s %u %hu \"%s\" firewallerror %d", user->nick, user->ip, user->port, av[1], user->speed);
            return;
        }
    }

    /* if the client holding the file is a local user, send the request
    directly */
    if(ISUSER(user->con))
    {
        send_cmd(user->con, MSG_SERVER_UPLOAD_REQUEST, "%s \"%s\"", sender->nick, av[1]);
    }
    /* otherwise pass it to the peer servers for delivery */
    else
    {
        /* don't use direct delivery here because the server the client is
        connected to needs to consult their db and rewrite this messsage */
        if(con != user->con)
            send_cmd(user->con, MSG_SERVER_UPLOAD_REQUEST, ":%s %s \"%s\"", sender->nick, user->nick, av[1]);
        else
        {
            snprintf(reason, sizeof(reason), "download.c: download: recip->con=con: sender: %s(%s) recip: %s(%s)", sender->nick, sender->server, user->nick, user->server);
            log_message_level(LOG_LEVEL_DEBUG, reason);
            kill_user_internal(user->con, user, global.serverName, 0, "ghost resync: download.c: download"); /* reason); */
        }
    }
}

/* 609 [ :<sender> ] <nick> "<filename>"
this message is normally sent by the *server* when the client, that the file was
requested from, does not accept the upload request.

there are a few clients (audioGnome) who send this message to the server
indicating that the upload request was rejected. For now we do nothing
with it. just record it in the log.

i think we should use this information since we now know that the rejecting
user does not want to upload for some reason.
*/
HANDLER(accept_failed)
{
    USER   *user, *sender;
    char   *av[2], *sender_name;
    int    ac = -1;
    (void) tag;
    (void) len;

    ASSERT(validate_connection(con));
    if(pop_user_server(con, tag, &pkt, &sender_name, &sender))
        return;
    if(pkt)
        ac = split_line(av, sizeof(av) / sizeof(char *), pkt);
    if(ac < 2) 
    {
        unparsable(con);
        return;
    }

    /* find the user */
    user = hash_lookup(global.usersHash, av[0]);
    if(!user)
        return;
    ASSERT(validate_user(user));
    /*    send_user(user, MSG_CLIENT_ACCEPT_FAILED, "%s \"%s\"", sender->nick, av[1]); */
    log_message_level( LOG_LEVEL_SHARE, "accept_failed: %s(%s) : %s rejected upload %s", sender->nick, sender->clientinfo, user->nick, av[1]);
}

static USER *transfer_count_wrapper(CONNECTION * con, char *pkt, int numeric)
{
    USER    *user;

    ASSERT(validate_connection(con));
    if(pop_user(con, &pkt, &user))
        return 0;

    /* Some clients overdo the 218 and 219 tags ... So we have to sort them out first ... */
    if(numeric == 219) 
	{
        user->count219++;
        if( notify_abuse(con, user, 219, user->count219, 1) ) 
		{
            return 0;
        }
    }
    if( numeric == 218 ) 
	{
        user->count218++;
        if( notify_abuse(con, user, 218, user->count218, 1) ) 
		{
            return 0;
        }
    }    
    /* relay to peer servers */
    pass_message_args(con, numeric, ":%s", user->nick);
    return user;
}

/* 220 [ :<user> ] */
HANDLER(upload_start)
{
    USER   *user;

    (void) tag;
    (void) len;
    ASSERT(validate_connection(con));
    user = transfer_count_wrapper(con, pkt, MSG_CLIENT_UPLOAD_START);
    if(!user)
        return;
    ASSERT(validate_user(user));
    user->uploads++;
    user->totalup++;
}

/* 221 [ :<user> ] */
HANDLER(upload_end)
{
    USER   *user;

    (void) tag;
    (void) len;
    ASSERT(validate_connection(con));
    user = transfer_count_wrapper(con, pkt, MSG_CLIENT_UPLOAD_END);
    if(!user)
        return;
    ASSERT(validate_user(user));
    if(user->uploads > 0)
        user->uploads--;
}

/* 218 [ :<user> ] */
HANDLER(download_start)
{
    USER   *user;

    (void) tag;
    (void) len;
    ASSERT(validate_connection(con));
    user = transfer_count_wrapper(con, pkt, MSG_CLIENT_DOWNLOAD_START);
    if(!user)
        return;
    ASSERT(validate_user(user));
    user->downloads++;
    user->totaldown++;
}

/* 219 [ :<user> ] */
HANDLER(download_end)
{
    USER   *user;

    (void) tag;
    (void) len;
    ASSERT(validate_connection(con));
    user = transfer_count_wrapper(con, pkt, MSG_CLIENT_DOWNLOAD_END);
    if(!user)
        return;
    ASSERT(validate_user(user));
    if(user->downloads > 0)
        user->downloads--;
}

/* 600 <user> */
/* client is requesting the link speed of <user> */
HANDLER(user_speed)
{
    USER   *user;

    (void) tag;
    (void) len;
    CHECK_USER_CLASS("user_speed");
    user = hash_lookup(global.usersHash, pkt);
    if(!user)
    {
        nosuchuser(con);
        return;
    }
    ASSERT(validate_user(user));
    send_cmd(con, MSG_SERVER_USER_SPEED /* 601 */ , "%s %d", user->nick, user->speed);
}

/* 626 [ :<nick> ] <user> */
/* client is notifying other party of a failure to connect to their data
port */
HANDLER(data_port_error)
{
    USER   *sender, *user;

    (void) tag;
    (void) len;

    ASSERT(validate_connection(con));
    if(pop_user(con, &pkt, &sender) != 0)
        return;
    ASSERT(validate_user(sender));
    user = hash_lookup(global.usersHash, pkt);
    if(!user)
    {
        nosuchuser(con);
        return;
    }
    ASSERT(validate_user(user));

    /* we pass this message to all servers so the mods can see it */
    pass_message_args(con, tag, ":%s %s", sender->nick, user->nick);

    notify_mods(PORTLOG_MODE, "Notification from %s: %s (%s) - configured data port %hu is unreachable.", sender->nick, user->nick, my_ntoa(BSWAP32(user->ip)), user->port);

    /* if local, notify the target of the error */
    if(user->local)
        send_cmd(user->con, tag, "%s", sender->nick);
}

/* 607 :<sender> <recip> "<filename>" [speed] */
HANDLER(upload_request)
{
    char   *av[3], *sender_name;
    USER   *recip, *sender;
    int     ac = -1;
    char    reason[256];

    (void) tag;
    (void) len;

    ASSERT(validate_connection(con));
    CHECK_SERVER_CLASS("upload_request");
    if(pop_user_server(con, tag, &pkt, &sender_name, &sender))
        return;
    if(!sender)
    {
        /* packet came from a server not a user */
        log_message_level(LOG_LEVEL_ERROR, "download.c: upload_request: came from :server, not :user?");
        return;
    }

    if(pkt)
        ac = split_line(av, sizeof(av) / sizeof(char *), pkt);

    if(ac < 2)
    {
        log_message_level( LOG_LEVEL_FILES, "upload_request: too few args");
        return;
    }
    recip = hash_lookup(global.usersHash, av[0]);
    if(!recip)
    {
        log_message_level( LOG_LEVEL_FILES, "upload_request: %s: no such user", av[0]);
        return;
    }
    ASSERT(validate_user(recip));

    /* if local user, deliver the message */
    if(ISUSER(recip->con))
    {
        send_cmd(recip->con, MSG_SERVER_UPLOAD_REQUEST, "%s \"%s\" %d", sender->nick, av[1], sender->speed);
    }
    else
    {
        /* route the request to the server which the uploader is behind */
        if(con != recip->con)
            send_cmd(recip->con, MSG_SERVER_UPLOAD_REQUEST, ":%s %s \"%s\" %d", sender->nick, recip->nick, av[1], sender->speed);
        else
        {
            snprintf(reason, sizeof(reason), "download.c: download: recip->con=con: sender: %s(%s) recip: %s(%s)", sender->nick, sender->server, recip->nick, recip->server);
            log_message_level(LOG_LEVEL_DEBUG, reason);
            kill_user_internal(recip->con, recip, global.serverName, 0, "ghost resync: download.c: download"); /* reason); */
        }
    }
}

/* 619 <nick> <filename> <limit> */
HANDLER(queue_limit)
{
    char   *av[3];
    int     ac;
    USER   *recip;
    DATUM  *info;

    (void) tag;
    (void) len;
    ASSERT(validate_connection(con));
    CHECK_USER_CLASS("queue_limit");
    ac = split_line(av, sizeof(av) / sizeof(char *), pkt);

    if(ac != 3)
    {
        log_message_level( LOG_LEVEL_FILES, "queue_limit(): wrong number of parameters");
        print_args (ac, av);
        unparsable(con);
        return;
    }
    recip = hash_lookup(global.usersHash, av[0]);
    if(!recip)
    {
        nosuchuser(con);
        return;
    }
    ASSERT(validate_user(recip));
    ASSERT(validate_connection(recip->con));

    /* look up the filesize in the db */
    info = hash_lookup(con->uopt->files, av[1]);
    if(!info)
    {
        send_cmd(con, MSG_SERVER_NOSUCH, "Not sharing that file");
        return;
    }

    /* deliver to user even if remote */
    send_user(recip, MSG_SERVER_LIMIT, "%s \"%s\" %u %s", con->user->nick, av[1], info->size, av[2]);
}

