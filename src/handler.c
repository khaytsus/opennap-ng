/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
This is free software distributed under the terms of the
GNU Public License.  See the file COPYING for details.

$Id: handler.c 434 2006-09-03 17:48:47Z reech $ */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#ifndef WIN32
# include <unistd.h>
#endif
#include "opennap.h"
#include "debug.h"
#if ONAP_DEBUG
# include <ctype.h>
#endif

static  HANDLER(histogram);
static  HANDLER(shistogram);

/* handle notification that a user has quit 
* <user> */
HANDLER(client_quit)
{
    USER *user;

    (void) tag;
    (void) len;
    ASSERT(validate_connection(con));
    CHECK_SERVER_CLASS("client_quit");
    user = hash_lookup(global.usersHash, pkt);
    if(!user)
    {
        log_message_level( LOG_LEVEL_DEBUG, "client_quit: can't find user %s", pkt);
        return;
    }
    ASSERT(validate_user(user));
    if(ISSERVER(user->con))
    {
        pass_message_args(con, tag, "%s", user->nick);
        hash_remove(global.usersHash, user->nick);
    }
    else
    {
        log_message_level( LOG_LEVEL_DEBUG, "client_quit: recieved QUIT for local user %s!", user->nick);
        kill_user_internal(user->con, user, global.serverName, 0, "client_quit: received QUIT");
    }
}

/* 214 */
HANDLER(server_stats)
{
    (void) pkt;
    (void) len;
    (void) tag;
    send_cmd(con, MSG_SERVER_STATS, "%d %d %d", global.usersHash->dbsize, global.fileLibCount, (int) (global.fileLibSize / 1048576.));
}

HANDLER(server_sync_end)
{
    /* 10262 */
    (void) pkt;
    (void) len;
    (void) tag;
    if(ISSERVER(con))
    {
        notify_mods(SERVERLOG_MODE, "Server %s - sync end", con->host);
        log_message_level(LOG_LEVEL_SERVER, "received sync server end from: %s", con->host); 
        send_cmd(con, MSG_SERVER_SYNC_END_ACK, "");
    }
    else
        log_message_level(LOG_LEVEL_ERROR, "Received MSG_SERVER_SYNC_END from non-server");
}

HANDLER(server_sync_end_ack)
{
    /* 10263 */
    (void) pkt;
    (void) len;
    (void) tag;
    if(ISSERVER(con))
    {
        notify_mods(SERVERLOG_MODE, "Server %s sync end ack", con->host);
        log_message_level(LOG_LEVEL_SERVER, "received sync server end ack from: %s", con->host);
        dump_state();
        dump_state();
    }
    else
        log_message_level(LOG_LEVEL_ERROR, "Received MSG_SERVER_SYNC_END_ACK from non-server");
}

/* 10018 :<server> <target> <packet>
allows a server to send an arbitrary message to a remote user */
HANDLER(encapsulated)
{
    char   *nick, ch, *ptr;
    USER   *user;
    char    reason[256];

    (void) tag;
    ASSERT(validate_connection(con));
    CHECK_SERVER_CLASS("encapsulated");
    if(*pkt != ':')
    {
        log_message_level(LOG_LEVEL_ERROR | LOG_LEVEL_SERVER, "encapsulated: server message does not begin with a colon (:)");
        return;
    }
    nick = strchr(pkt + 1, ' ');
    if(!nick)
    {
        log_message_level(LOG_LEVEL_ERROR, "encapsulated: missing target nick");
        return;
    }
    nick++;
    ptr = strchr(nick, ' ');
    if(!ptr)
    {
        log_message_level(LOG_LEVEL_ERROR, "encapsulated: missing encapsulated packet");
        return;
    }
    ch = *ptr;
    *ptr = 0;
    user = hash_lookup(global.usersHash, nick);
    if(!user)
    {
        log_message_level( LOG_LEVEL_CLIENT, "encapsulated: no such user %s", nick);
        return;
    }
    if(user->local)
    {
        ptr++;
        queue_data(user->con, ptr, len - (ptr - pkt));
    }
    else
    {
        *ptr = ch;
        /* avoid copying the data twice by peeking into the send buffer to
        grab the message header and body together */
        /* shouldnt this be sent to just user->con ? 
        pass_message(con, con->recvbuf->data + con->recvbuf->consumed, 4 + len);
        */
        /* need to check con and user->con... packets are currently broadcast, not doing this would generate looping traffic */
        if(con != user->con)
            queue_data(user->con, con->recvbuf->data + con->recvbuf->consumed, 4 + len);
        else
        {
            snprintf(reason, sizeof(reason), "handler.c: encapsulated: recip->con=con: recip: %s(%s)", user->nick, user->server);
            log_message_level(LOG_LEVEL_DEBUG, reason);
            kill_user_internal(user->con, user, global.serverName, 0, "ghost resync: handler.c: encapsulated"); /* reason); */
        }
    }
}

/* the windows napster client will hang indefinitely waiting for this, so
* return what it expects.
*/
static HANDLER(version_check)
{
    (void) pkt;
    (void) tag;
    (void) len;
    if(ISUSER(con))
        send_cmd(con, MSG_CLIENT_VERSION_CHECK, "");
}

/* certain user commands need to be exempt from flood control or the server
* won't work correctly.
*/
#define F_EXEMPT        1   /* exempt from flood control */

typedef struct
{
    unsigned int message;
    HANDLER((*handler));
    unsigned int flags;
    unsigned long count;
    double  bytes;
}
HANDLER;

#define NORMAL(a,b) {a,b,0,0,0}
#define EXEMPT(a,b) {a,b,F_EXEMPT,0,0}

/* this is the table of valid commands we accept from both users and servers
THIS TABLE MUST BE SORTED BY MESSAGE TYPE */
static HANDLER Protocol[] = {
    NORMAL(MSG_SERVER_ERROR, server_error),    /* 0 */
        NORMAL(MSG_CLIENT_LOGIN, login),   /* 2 */
        NORMAL(MSG_CLIENT_VERSION_CHECK, version_check),   /* 4 */
        NORMAL(MSG_CLIENT_LOGIN_REGISTER, login),  /* 6 */
        NORMAL(MSG_CLIENT_REGISTER, register_nick),    /* 7 */
        NORMAL(MSG_CLIENT_CHECK_PASS, check_password), /* 11 */
        NORMAL(MSG_CLIENT_REGISTRATION_INFO, ignore_command),  /* 14 */
#ifndef ROUTING_ONLY
        EXEMPT(MSG_CLIENT_ADD_FILE, add_file), /* 100 */
        EXEMPT(MSG_CLIENT_REMOVE_FILE, remove_file),   /* 102 */
#endif
        NORMAL(MSG_CLIENT_UNSHARE_ALL, unshare_all),   /* 110 */
#ifndef ROUTING_ONLY
        NORMAL(MSG_CLIENT_SEARCH, search), /* 200 */
#endif
        NORMAL(MSG_CLIENT_DOWNLOAD, download), /* 203 */
        NORMAL(MSG_CLIENT_PRIVMSG, privmsg),   /* 205 */
        EXEMPT(MSG_CLIENT_ADD_HOTLIST, add_hotlist),   /* 207 */
        EXEMPT(MSG_CLIENT_ADD_HOTLIST_SEQ, add_hotlist),   /* 208 */
        NORMAL(MSG_CLIENT_BROWSE, browse), /* 211 */
        NORMAL(MSG_SERVER_STATS, server_stats),    /* 214 */
        NORMAL(MSG_CLIENT_RESUME_REQUEST, resume), /* 215 */
        NORMAL(MSG_CLIENT_DOWNLOAD_START, download_start), /* 218 */
        NORMAL(MSG_CLIENT_DOWNLOAD_END, download_end), /* 219 */
        NORMAL(MSG_CLIENT_UPLOAD_START, upload_start), /* 220 */
        NORMAL(MSG_CLIENT_UPLOAD_END, upload_end), /* 221 */
        NORMAL(MSG_CLIENT_CHECK_PORT, ignore_command), /* 300 */
        NORMAL(MSG_CLIENT_REMOVE_HOTLIST, remove_hotlist), /* 303 */
        NORMAL(MSG_CLIENT_IGNORE_LIST, ignore_list),   /* 320 */
        NORMAL(MSG_CLIENT_IGNORE_USER, ignore),    /* 322 */
        NORMAL(MSG_CLIENT_UNIGNORE_USER, unignore),    /* 323 */
        NORMAL(MSG_CLIENT_CLEAR_IGNORE, clear_ignore), /* 326 */
        NORMAL(MSG_CLIENT_JOIN, join), /* 400 */
        NORMAL(MSG_CLIENT_PART, part), /* 401 */
        NORMAL(MSG_CLIENT_PUBLIC, public), /* 402 */
        NORMAL(MSG_SERVER_PUBLIC, public), /* 403 */
        NORMAL(MSG_SERVER_NOSUCH, server_error),   /* 404 */
        NORMAL(MSG_SERVER_TOPIC, topic),   /* 410 */
        NORMAL(MSG_CLIENT_CHANNEL_BAN_LIST, channel_banlist),  /* 420 */
        NORMAL(MSG_CLIENT_CHANNEL_BAN, channel_ban),   /* 422 */
        NORMAL(MSG_CLIENT_CHANNEL_UNBAN, channel_ban), /* 423 */
        NORMAL(MSG_CLIENT_CHANNEL_CLEAR_BANS, channel_clear_bans), /* 424 */
        NORMAL(MSG_CLIENT_DOWNLOAD_FIREWALL, download),    /* 500 */
        NORMAL(MSG_CLIENT_USERSPEED, user_speed),  /* 600 */
        NORMAL(MSG_CLIENT_WHOIS, whois),   /* 603 */
        NORMAL(MSG_CLIENT_SETUSERLEVEL, level),    /* 606 */
        NORMAL(MSG_SERVER_UPLOAD_REQUEST, upload_request), /* 607 */
        NORMAL(MSG_CLIENT_UPLOAD_OK, upload_ok),   /* 608 */
        NORMAL(MSG_CLIENT_ACCEPT_FAILED, accept_failed),   /* 609 */
        NORMAL(MSG_CLIENT_KILL, kill_user),    /* 610 */
        NORMAL(MSG_CLIENT_NUKE, nuke), /* 611 */
        NORMAL(MSG_CLIENT_BAN, ban),   /* 612 */
        NORMAL(MSG_CLIENT_ALTER_PORT, alter_port), /* 613 */
        NORMAL(MSG_CLIENT_UNBAN, unban),   /* 614 */
        NORMAL(MSG_CLIENT_BANLIST, banlist),   /* 615 */
        NORMAL(MSG_CLIENT_LIST_CHANNELS, list_channels),   /* 618 */
        NORMAL(MSG_CLIENT_LIMIT, queue_limit), /* 619 */
        NORMAL(MSG_CLIENT_MOTD, show_motd),    /* 621 */
        NORMAL(MSG_CLIENT_MUZZLE, muzzle), /* 622 */
        NORMAL(MSG_CLIENT_UNMUZZLE, muzzle),   /* 623 */
        NORMAL(MSG_CLIENT_ALTER_SPEED, alter_speed),   /* 625 */
        NORMAL(MSG_CLIENT_DATA_PORT_ERROR, data_port_error),   /* 626 */
        NORMAL(MSG_CLIENT_WALLOP, wallop), /* 627 */
        NORMAL(MSG_CLIENT_ANNOUNCE, announce), /* 628 */
        NORMAL(MSG_CLIENT_BROWSE_DIRECT, browse_direct),   /* 640 */
        NORMAL(MSG_SERVER_BROWSE_DIRECT_OK, browse_direct_ok), /* 641 */
        NORMAL(MSG_CLIENT_CLOAK, cloak),   /* 652 */
        NORMAL(MSG_CLIENT_CHANGE_SPEED, change_speed), /* 700 */
        NORMAL(MSG_CLIENT_CHANGE_PASS, change_pass),   /* 701 */
        NORMAL(MSG_CLIENT_CHANGE_EMAIL, change_email), /* 702 */
        NORMAL(MSG_CLIENT_CHANGE_DATA_PORT, change_data_port), /* 703 */
        NORMAL(MSG_CLIENT_PING_SERVER, ping_server),   /* 750 */
        NORMAL(MSG_CLIENT_PING, ping), /* 751 */
        NORMAL(MSG_CLIENT_PONG, ping), /* 752 */
        NORMAL(MSG_CLIENT_ALTER_PASS, alter_pass), /* 753 */
        NORMAL(MSG_CLIENT_SERVER_RECONFIG, server_reconfig),   /* 800 */
        NORMAL(MSG_CLIENT_SERVER_VERSION, server_version), /* 801 */
        NORMAL(MSG_CLIENT_SERVER_CONFIG, server_config),   /* 810 */
        NORMAL(MSG_CLIENT_CLEAR_CHANNEL, clear_channel),   /* 820 */
        NORMAL(MSG_CLIENT_REDIRECT, redirect_client),  /* 821 */
        NORMAL(MSG_CLIENT_CYCLE, cycle_client),    /* 822 */
        NORMAL(MSG_CLIENT_SET_CHAN_LEVEL, channel_level),  /* 823 */
        NORMAL(MSG_CLIENT_EMOTE, emote),   /* 824 */
        NORMAL(MSG_CLIENT_CHANNEL_LIMIT, channel_limit),   /* 826 */
        NORMAL(MSG_CLIENT_FULL_CHANNEL_LIST, full_channel_list),   /* 827 */
        NORMAL(MSG_CLIENT_KICK, kick), /* 829 */
        NORMAL(MSG_CLIENT_NAMES_LIST, list_users), /* 830 */
        NORMAL(MSG_CLIENT_GLOBAL_USER_LIST, global_user_list), /* 831 */
#ifndef ROUTING_ONLY
        EXEMPT(MSG_CLIENT_ADD_DIRECTORY, add_directory),   /* 870 */
#endif
        NORMAL(920, ignore_command),   /* 920 */

        /* non-standard messages */
        NORMAL(MSG_CLIENT_ADD_SERVER, add_server),     /* 9998 */
        NORMAL(MSG_CLIENT_LIST_SERVER, list_server),   /* 9999 */
        NORMAL(MSG_CLIENT_QUIT, client_quit),      /* 10000 */
        NORMAL(MSG_SERVER_LOGIN, server_login),        /* 10010 */
        NORMAL(MSG_SERVER_LOGIN_ACK, server_login_ack),    /* 10011 */
        NORMAL(MSG_SERVER_USER_SHARING, user_sharing), /* 10012 */
        NORMAL(MSG_SERVER_REGINFO, reginfo),       /* 10014 */
        NORMAL(MSG_SERVER_REMOTE_SEARCH, remote_search),   /* 10015 */
        NORMAL(MSG_SERVER_REMOTE_SEARCH_RESULT, remote_search_result), /* 10016 */
        NORMAL(MSG_SERVER_REMOTE_SEARCH_END, remote_search_end),   /* 10017 */
        NORMAL(MSG_SERVER_ENCAPSULATED, encapsulated), /* 10018 */
        NORMAL(MSG_SERVER_LINK_INFO, link_info),       /* 10019 */
        NORMAL(MSG_SERVER_QUIT, server_disconnect),    /* 10020 - deprecated by 10101 */
        NORMAL(MSG_SERVER_NOTIFY_MODS, remote_notify_mods),    /* 10021 */
        NORMAL(MSG_SERVER_SERVER_PONG, server_pong),   /* 10022 */
        NORMAL(MSG_SERVER_TIME_CHECK, time_check),     /* 10023 */
        NORMAL(MSG_SERVER_WHOIS_NOTIFY, whois_notify), /* 10024 */
        NORMAL(MSG_CLIENT_USERFLAGS, change_userflags),    /* 10050 */
        NORMAL(MSG_CLIENT_CONNECT, server_connect),    /* 10100 */
        NORMAL(MSG_CLIENT_DISCONNECT, server_disconnect),  /* 10101 */
        NORMAL(MSG_CLIENT_KILL_SERVER, kill_server),   /* 10110 */
        NORMAL(MSG_CLIENT_REMOVE_SERVER, remove_server),   /* 10111 */
        NORMAL(MSG_CLIENT_LINKS, server_links),        /* 10112 */
        NORMAL(MSG_CLIENT_USAGE_STATS, server_usage),  /* 10115 */
        NORMAL(MSG_SERVER_SEARCH_STATS, search_cache_stats), /* 10116 */
        NORMAL(MSG_CLIENT_REHASH, rehash),         /* 10117 */
        NORMAL(MSG_CLIENT_VERSION_STATS, client_version_stats),    /* 10118 */
        NORMAL(MSG_CLIENT_WHICH_SERVER, which_server), /* 10119 */
        NORMAL(MSG_CLIENT_PING_ALL_SERVERS, ping_all_servers), /* 10120 */
        NORMAL(MSG_CLIENT_WHO_WAS, who_was),       /* 10121 */
        NORMAL(MSG_CLIENT_MASS_KILL, mass_kill),       /* 10122 */
        NORMAL(MSG_CLIENT_HISTOGRAM, histogram),       /* 10123 */
        NORMAL(MSG_CLIENT_SHISTOGRAM, shistogram),     /* 10125 */ 
        NORMAL(MSG_CLIENT_REGISTER_USER, register_user),   /* 10200 */
        NORMAL(MSG_CLIENT_USER_MODE, user_mode_cmd),   /* 10203 */
        NORMAL(MSG_CLIENT_OP, channel_op),         /* 10204 */
        NORMAL(MSG_CLIENT_DEOP, channel_op),       /* 10205 */
        NORMAL(MSG_CLIENT_CHANNEL_WALLOP, channel_wallop), /* 10208 */
        NORMAL(MSG_CLIENT_CHANNEL_MODE, channel_mode), /* 10209 */
        NORMAL(MSG_CLIENT_CHANNEL_INVITE, channel_invite), /* 10210 */
        NORMAL(MSG_CLIENT_CHANNEL_VOICE, channel_op),  /* 10211 */
        NORMAL(MSG_CLIENT_CHANNEL_UNVOICE, channel_op),    /* 10212 */
        NORMAL(MSG_CLIENT_CHANNEL_MUZZLE, channel_muzzle), /* 10213 */
        NORMAL(MSG_CLIENT_CHANNEL_UNMUZZLE, channel_muzzle),   /* 10214 */
        NORMAL(MSG_CLIENT_CLASS_ADD, generic_acl_add),  /* 10250 */
        NORMAL(MSG_CLIENT_CLASS_DEL, generic_acl_del),  /* 10251 */
        NORMAL(MSG_CLIENT_CLASS_LIST, generic_acl_list),    /* 10252 */
        NORMAL(MSG_CLIENT_DLINE_ADD, generic_acl_add),
        NORMAL(MSG_CLIENT_DLINE_DEL, generic_acl_del),
        NORMAL(MSG_CLIENT_DLINE_LIST, generic_acl_list),
        NORMAL(MSG_CLIENT_ILINE_ADD, generic_acl_add),
        NORMAL(MSG_CLIENT_ILINE_DEL, generic_acl_del),
        NORMAL(MSG_CLIENT_ILINE_LIST, generic_acl_list),
        NORMAL(MSG_CLIENT_ELINE_ADD, generic_acl_add),
        NORMAL(MSG_CLIENT_ELINE_DEL, generic_acl_del),
        NORMAL(MSG_CLIENT_ELINE_LIST, generic_acl_list),
        NORMAL(MSG_SERVER_SYNC_END, server_sync_end), /* 10262 */
        NORMAL(MSG_SERVER_SYNC_END_ACK, server_sync_end_ack), /* 10263 */
        NORMAL(MSG_CLIENT_LOG_LEVEL, log_level_cmd), /* 10264 */


#ifndef ROUTING_ONLY
        EXEMPT(MSG_CLIENT_SHARE_FILE, share_file), /* 10300 */
#endif
        /* Added by winter_mute */
#ifdef USE_PROTNET
        NORMAL(MSG_CLIENT_RESYNC_USER, my_resync_user), /* 10303 */
        NORMAL(MSG_CLIENT_DESYNC_USER, desync_user), /* 10304 */
#endif
};
static int Protocol_Size = sizeof(Protocol) / sizeof(HANDLER);

/* dummy entry used to keep track of invalid commands */
static HANDLER unknown_numeric = { 0, 0, 0, 0, 0 };

/* 10123
* report statistics for server commands.
*/
static HANDLER(histogram)
{
    unsigned long  count = 0;
    double  bytes = 0;
    int     l;

    (void) pkt;
    (void) len;
    CHECK_USER_CLASS("histogram");
    if(con->user->level < LEVEL_MODERATOR )
    {
        permission_denied(con);
        return;
    }
    for (l = 0; l < Protocol_Size; l++)
    {
        if(Protocol[l].count != 0)
            send_cmd(con, tag, "%d %u %.0f", Protocol[l].message, Protocol[l].count, Protocol[l].bytes);
        count += Protocol[l].count;
        bytes += Protocol[l].bytes;
    }
    send_cmd(con, MSG_SERVER_HISTOGRAM, "%d %u %.0f %lu %.0f", unknown_numeric.message, unknown_numeric.count, unknown_numeric.bytes, count, bytes);
}

/* 10125
* report statistics for outging commands.
*/
static HANDLER(shistogram) 
{
    LIST    *list;
    histogram_t *h;
    unsigned long count = 0;
    double   bytes = 0;

    (void) pkt;
    (void) len;
    CHECK_USER_CLASS("shistogram");
    if(con->user->level < LEVEL_MODERATOR ) 
	{
        permission_denied(con);
        return;
    }
    for (list = global.histOutList; list; list = list->next) 
	{
        h = list->data;
        send_cmd(con, tag, "%d %u %u %s", h->tag, h->count, h->len, tag2hrf(h->tag) );
        count += h->count;
        bytes += h->len;
    }
    send_cmd(con, MSG_SERVER_SHISTOGRAM, "%lu %.0f", count, bytes );
}

/* use a binary search to find the table in the entry */
static int find_handler(unsigned int tag)
{
    int     min = 0, max = Protocol_Size - 1, try;

    while (!global.sigCaught)
    {
        try = (max + min) / 2;
        if(tag == Protocol[try].message)
            return try;
        else if(min == max)
            return -1;      /* not found */
        else if(tag < Protocol[try].message)
        {
            if(try == min)
                return -1;
            max = try - 1;
        }
        else
        {
            if(try == max)
                return -1;
            min = try + 1;
        }
        ASSERT(min <= max);
    }
    return -1;
}

/* this is not a real handler, but takes the same arguments as one */
HANDLER(dispatch_command)
{
    int     l;
    tag_count_t *tagcount = 0;
    int     tagDelta;
    u_char  byte;

    ASSERT(validate_connection(con));
    ASSERT(pkt != 0);

    /* HACK ALERT
    the handler routines all assume that the `pkt' argument is nul (\0)
    terminated, so we have to replace the byte after the last byte in
    this packet with a \0 to make sure we dont read overflow in the
    handlers.  the handle_connection() function should always allocate 1
    byte more than necessary for this purpose */
    ASSERT(VALID_LEN(con->recvbuf->data, con->recvbuf->consumed + 4 + len + 1));
    stats.tags++;
    byte = *(pkt + len);
    *(pkt + len) = 0;
    l = find_handler(tag);
    if(l != -1)
    {
        ASSERT(Protocol[l].handler != 0);
        if(ISUSER(con))
        {
            tagcount = hash_lookup(con->user->tagCountHash, (void *) tag);
            if(!tagcount)
            {
                tagcount = CALLOC(1, sizeof(tag_count_t));
                tagcount->count = 0;
                tagcount->lastInterval = global.current_time;
                hash_add(con->user->tagCountHash, (void *) tag, tagcount );
            }
            tagcount->count++;
            if(tagcount->count % 1000 == 0)
            {
                tagDelta =  global.current_time - tagcount->lastInterval;
                if(tagDelta == 0)
                    tagDelta = 1;
                if((1000 / tagDelta) >= 100)
                    log_message_level(LOG_LEVEL_ERROR, "dispatch_command: %s has done \"%s\"(%hu) %lu times (%d/sec)", con->user->nick, tag2hrf(tag), tag, tagcount->count, 1000/tagDelta);
                tagcount->lastInterval = global.current_time;
            }
        }
        else if(ISSERVER(con))
        {
            tagcount = hash_lookup(con->sopt->tagCountHash, (void *) tag);
            if(!tagcount)
            {
                tagcount = CALLOC(1, sizeof(tag_count_t));
                tagcount->count = 0;
                tagcount->lastInterval = global.current_time;
                hash_add(con->sopt->tagCountHash, (void *) tag, tagcount );
            }
            tagcount->count++;
            if(tagcount->count % 1000 == 0)
            {
                tagcount->flag = 0;
                tagDelta =  global.current_time - tagcount->lastInterval;
                if(tagDelta == 0)
                    tagDelta = 1;
                if((1000 / tagDelta) >= 200)
                {
                    log_message_level(LOG_LEVEL_ERROR, "dispatch_command: %s has done \"%s\"(%hu) %lu times (%d/sec)", con->host, tag2hrf(tag), tag, tagcount->count, 1000/tagDelta);
                    tagcount->flag = 1;
                }
                tagcount->lastInterval = global.current_time;
            }
        }
        /*
        if(tag == 10018 || (tag != 2 && (tagcount && tagcount->flag)))
        {
        int     i;
        char    message[4096];

        i=0;
        while (i<=len-1) 
        {
        message[i] = isprint(pkt[i]) ? pkt[i] : '.';
        i++;
        }
        message[i]=0;
        log_message_level(LOG_LEVEL_ERROR, "dispatch_command: tag: %d, pkt: %s", tag, message);
        }
        */
        /* do flood control if enabled */
        if(global.floodTime > 0 && !(Protocol[l].flags & F_EXEMPT) && ISUSER(con))
        {
            /* this command is subject to flood control. */
            if(con->flood_start + global.floodTime < global.current_time)
            {
                /* flood expired, reset counters */
                con->flood_start = global.current_time;
                con->flood_commands = 0;
            }
            else if(++con->flood_commands >= global.floodCommands)
            {
                LIST   *list;

                log_message_level( LOG_LEVEL_CLIENT, "dispatch_command: flooding from %s %s(%hu)", get_user(con, 2), tag2hrf(tag), tag);
                notify_mods(FLOODLOG_MODE, "Flooding from %s!%s %s(%hu)", con->user->nick, con->host, tag2hrf(tag), tag );
                /* stop reading from the descriptor until the flood counter
                * expires.
                */
                clear_read(con->fd);

                /* add to the list of flooders that is check in the main
                * loop.  Since we don't traverse the entire client list we
                * have to keep track of which ones to check for expiration
                */
                list = CALLOC(1, sizeof(LIST));
                list->data = con;
                global.flooderList = list_push(global.flooderList, list);
            }
        }

        /* This is to get some info where e.g. pop_user is called from...  */
        global.current_tag = tag;
        /*
        i=0;
        while (i<=len-1) 
		{
        message[i] = isprint(pkt[i]) ? pkt[i] : '.';
        i++;
        }
        message[i]=0;
        log_message("%hu:R:%hu(%s)\t:%hu:\t%s", con->fd, tag, tag2hrf(tag), len+4, message);
        */
        /* note that we pass only the data part of the packet */
        Protocol[l].handler(con, tag, len, pkt);
        Protocol[l].count++;
        Protocol[l].bytes += len+4;
    }
    else
    {
        log_message_level(LOG_LEVEL_ERROR | LOG_LEVEL_SERVER, "dispatch_command: unknown message: tag=%hu, length=%hu, data=%s", tag, len, pkt);
        unknown_numeric.message = tag;
        unknown_numeric.count++;
        unknown_numeric.bytes += len+4;

        send_cmd(con, MSG_SERVER_NOSUCH, "Unknown command code %hu", tag);
#if ONAP_DEBUG
        /* if this is a server connection, shut it down to avoid flooding the
        other server with these messages */
        if(ISSERVER(con))
        {
            u_char  ch;
            int     bytes;

            /* dump some bytes from the input buffer to see if it helps aid
            debugging */
            bytes = con->recvbuf->datasize - con->recvbuf->consumed;
            /* print at most 128 bytes */
            if(bytes > 128)
                bytes = 128;
            fprintf(stdout, "Dump(%d): ", con->recvbuf->datasize - con->recvbuf->consumed);
            for (l = con->recvbuf->consumed; bytes > 0; bytes--, l++)
            {
                ch = *(con->recvbuf->data + l);
                fputc(isprint(ch) ? ch : '.', stdout);
            }
            fputc('\n', stdout);
        }
#endif /* ONAP_DEBUG */
    }
    /* restore the byte we overwrite at the beginning of this function */
    *(pkt + len) = byte;
}

void handle_connection(CONNECTION * con)
{
    int     n;
    u_short tag, len;
    /* char*   msg[4096]; */

    ASSERT(validate_connection(con));

#ifdef CSC
    if(ISUSER(con)) 
	{
        if(con->uopt->csc) 
		{
            do 
			{
                n = READ(con->fd, Buf, sizeof(Buf));
                if(n <= 0) 
				{
                    if(n == -1) 
					{
                        if(N_ERRNO == EWOULDBLOCK)
                            break;
                        log_message_level(LOG_LEVEL_ERROR, "handle_connection_z: read: %s (errno %d) for host %s (fd %d)", strerror(N_ERRNO), N_ERRNO, con->host, con->fd);
                    } 
					else 
					{
                        log_message_level(LOG_LEVEL_ERROR, "handle_connection_z: EOF from %s", con->user->nick);
                    }
                    destroy_connection(con);
                    return;
                }
                global.bytes_in += n;
                if(global.min_read > 0 && n < global.min_read) 
				{
                    log_message_level(LOG_LEVEL_ERROR, "handle_connection_z: %d bytes from %s", n, con->host);
                }
                if(buffer_decompress(con->recvbuf, con->uopt->zin, Buf, n)) 
				{
                    destroy_connection(con);
                    return;
                }
            } while (n == sizeof(Buf));
            goto dcomp_ok;
        }
    }
#endif

    if(ISSERVER(con)) 
    {
        /* server data is compressed.  read as much as we can and pass it
        to the decompressor.  we attempt to read all data from the socket
        in this loop, which will prevent unnecessary passes through the
        main loop (since select would return immediately) */
        do
        {
            n = READ(con->fd, Buf, sizeof(Buf));
            if(n <= 0)
            {
                if(n == -1)
                {
                    /* try to empty the socket each time, so we read until
                    *  we hit this error (queue empty).  this should only
                    *  happen in the rare event that the data in the queue
                    *  is a multiple of sizeof(Buf)
                    */
                    if(N_ERRNO == EWOULDBLOCK)
                        break;  /* not an error */
                    log_message_level(LOG_LEVEL_ERROR, "handle_connection: read: %s (errno %d) for host %s (fd %d)", strerror(N_ERRNO), N_ERRNO, con->host, con->fd);
                }
                else
                    log_message_level(LOG_LEVEL_SERVER | LOG_LEVEL_ERROR , "handle_connection: EOF from %s", con->host);
                destroy_connection(con);
                return;
            }
            global.bytes_in += n;

            if(global.min_read > 0 && n < global.min_read)
            {
                log_message_level(LOG_LEVEL_ERROR | LOG_LEVEL_SERVER, "handle_connection: %d bytes from %s", n, con->host);
            }

            /* this can safely be called multiple times in this loop.  the
            * decompressor will realloc the output buffer if there is not
            * enough room to store everything
            */
            if(buffer_decompress(con->recvbuf, con->sopt->zin, Buf, n))
            {
                destroy_connection(con);
                return;
            }
            /* if what we read was equal to sizeof(Buf) it's very likely
            * that more data exists in the queue
            */
        } while (n == sizeof(Buf));
    }
    else
    {
        /* create the input buffer if it doesn't yet exist */
        if(!con->recvbuf)
        {
            con->recvbuf = CALLOC(1, sizeof(BUFFER));
            if(!con->recvbuf)
            {
                OUTOFMEMORY("handle_connection");
                destroy_connection(con);
                return;
            }
#if ONAP_DEBUG
            con->recvbuf->magic = MAGIC_BUFFER;
#endif
            con->recvbuf->data = MALLOC(RECVBUF_INITAL_SIZE + 1);
            if(!con->recvbuf->data)
            {
                OUTOFMEMORY("handle_connection");
                destroy_connection(con);
                return;
            }
            con->recvbuf->datamax = RECVBUF_INITAL_SIZE;
        }
        /* read the packet header if we haven't seen it already */
        while (con->recvbuf->datasize < 4)
        {
            n = READ(con->fd, con->recvbuf->data + con->recvbuf->datasize, 4 - con->recvbuf->datasize);
            if(n == -1)
            {
                if(N_ERRNO != EWOULDBLOCK)
                {
                    log_message_level(LOG_LEVEL_ERROR | LOG_LEVEL_SERVER, "handle_connection: read: %s (errno %d) for host %s", strerror(N_ERRNO), N_ERRNO, con->host);
                    destroy_connection(con);
                }
                return;
            }
            else if(n == 0)
            {
                destroy_connection(con);
                return;
            }
            global.bytes_in += n;
            con->recvbuf->datasize += n;
        }
        /* read the packet body */
        memcpy(&len, con->recvbuf->data, 2);
        len = BSWAP16(len);
        if(len > 0)
        {
            if(global.maxCommandLen && len > global.maxCommandLen)
            {
                log_message_level(LOG_LEVEL_ERROR | LOG_LEVEL_SERVER, "handle_connection: %hu byte message from %s", len, con->host);
                destroy_connection(con);
                return;
            }

            /* if there isn't enough space to read the entire body, resize the input buffer */
            if(con->recvbuf->datamax < 4 + len)
            {
                /* allocate 1 extra byte for the \0 that dispatch_command() requires */
                if(safe_realloc((void **) &con->recvbuf->data, 4 + len + 1))
                {
                    OUTOFMEMORY("handle_connection");
                    destroy_connection(con);
                    return;
                }
                con->recvbuf->datamax = 4 + len;
            }
            n = READ(con->fd, con->recvbuf->data + con->recvbuf->datasize, len + 4 - con->recvbuf->datasize);
            if(n == -1)
            {
                /* since the header and body could arrive in separate packets, we have to check for this here so we don't close the
                *  connection on this nonfatal error.  we just wait for the next packet to arrive 
                */
                if(N_ERRNO != EWOULDBLOCK)
                {
                    log_message_level(LOG_LEVEL_ERROR | LOG_LEVEL_SERVER, "handle_connection: read: %s (errno %d) for host %s", strerror(N_ERRNO), N_ERRNO, con->host);
                    destroy_connection(con);
                }
                return;
            }
            else if(n == 0)
            {
                log_message_level(LOG_LEVEL_ERROR, "handle_connection: EOF from %s", con->host);
                destroy_connection(con);
                return;
            }
            con->recvbuf->datasize += n;
            global.bytes_in += n;
        }
    }
    /* process as many complete commands as possible.  for a client this
    will be exactly one, but a server link may have sent multiple commands
    in one compressed packet */
#ifdef CSC
dcomp_ok:
#endif
    while (con->recvbuf->consumed < con->recvbuf->datasize)
    {
        /* if we don't have the complete packet header, wait until we
        read more data */
        if(con->recvbuf->datasize - con->recvbuf->consumed < 4)
            break;
        /* read the packet header */
        memcpy(&len, con->recvbuf->data + con->recvbuf->consumed, 2);
        memcpy(&tag, con->recvbuf->data + con->recvbuf->consumed + 2, 2);
        len = BSWAP16(len);
        tag = BSWAP16(tag);
        /* check if the entire packet body has arrived */
        if(con->recvbuf->consumed + 4 + len > con->recvbuf->datasize)
            break;
        /*
        bzero( msg, 4096 );
        memcpy(&msg, con->recvbuf->data + con->recvbuf->consumed + 4, len);
        log_message_level( LOG_LEVEL_DEBUG, "recv: [%u] %s (%u)", tag, msg, len);
        */
        /* require that the client register before doing anything else */
        if(con->class == CLASS_UNKNOWN &&
            (tag != MSG_CLIENT_LOGIN && tag != MSG_CLIENT_LOGIN_REGISTER &&
            tag != MSG_CLIENT_REGISTER && tag != MSG_SERVER_LOGIN &&
            tag != MSG_SERVER_LOGIN_ACK && tag != MSG_SERVER_ERROR &&
            tag != 4 && /* unknown: v2.0 beta 5a sends this? */
            tag != 300 && tag != 11 && tag != 920))
        {
            log_message_level(LOG_LEVEL_ERROR, "handle_connection: %s is not registered", con->host);
            *(con->recvbuf->data + con->recvbuf->consumed + 4 + len) = 0;
            log_message_level(LOG_LEVEL_ERROR, "handle_connection: tag=%hu, len=%hu, data=%s", tag, len, con->recvbuf->data + con->recvbuf->consumed + 4);
            send_cmd(con, MSG_SERVER_ERROR, "invalid command");
            destroy_connection(con);
            return;
        }

        if(ISUSER(con))
        {
            /* check for end of share/unshare sequence.  in order to avoid
            having to send a single message for each shared file,
            the add_file and remove_file commands set a flag noting the
            start of a possible series of commands.  this routine checks
            to see if the end of the sequence has been reached (a command
            other than share/unshare has been issued) and then relays
            the final result to the peer servers.
            NOTE: the only issue with this is that if the user doesn't
            issue any commands after sharing files, the information will
            never get passed to the peer servers.  This is probably ok
            since this case will seldom happen */
            if(con->user->sharing)
            {
                if(tag != MSG_CLIENT_ADD_FILE
                    && tag != MSG_CLIENT_SHARE_FILE
                    && tag != MSG_CLIENT_ADD_DIRECTORY)
                {
                    pass_message_args(con, MSG_SERVER_USER_SHARING, "%s %hu %u", con->user->nick, con->user->shared, con->user->libsize);
                    con->user->sharing = 0;
                }
            }
            else if(con->user->unsharing)
            {
                if(tag != MSG_CLIENT_REMOVE_FILE)
                {
                    pass_message_args(con, MSG_SERVER_USER_SHARING, "%s %hu %u", con->user->nick, con->user->shared, con->user->libsize);
                    con->user->unsharing = 0;
                }
            }
        }
        /* call the protocol handler */
        dispatch_command(con, tag, len, con->recvbuf->data + con->recvbuf->consumed + 4);
        /* mark data as processed */
        con->recvbuf->consumed += 4 + len;
    }
    if(con->recvbuf->consumed)
    {
        n = con->recvbuf->datasize - con->recvbuf->consumed;
        if(n > 0)
        {
            /* shift down unprocessed data */
            memmove(con->recvbuf->data, con->recvbuf->data + con->recvbuf->consumed, n);
        }
        con->recvbuf->datasize = n;
        con->recvbuf->consumed = 0; /* reset */
    }
}

char* tag2hrf(int tag) 
{
	switch (tag) 
	{
	case MSG_SERVER_ERROR:
		return "server error";       /* 0 */
	case MSG_CLIENT_LOGIN:
		return "login";          /* 2 */
	case MSG_SERVER_EMAIL:
		return "login ack";      /* 3 */
	case MSG_CLIENT_VERSION_CHECK:
		return "version_check";      /* 4 */
	case MSG_CLIENT_LOGIN_REGISTER:
		return "register login"; /* 6 */
	case MSG_CLIENT_REGISTER:
		return "register nick";      /* 7 */
	case MSG_SERVER_REGISTER_OK:
		return "register ok";        /* 8 */
	case MSG_SERVER_REGISTER_FAIL:
		return "register fail";      /* 9 */
	case MSG_SERVER_BAD_NICK:
		return "bad nick";       /* 10 */
	case MSG_CLIENT_CHECK_PASS:
		return "check_password"; /* 11 */
	case MSG_SERVER_PASS_OK:
		return "password ok";        /* 12 */
	case MSG_SERVER_ECHO:
		return "server echo";        /* 13 */
	case MSG_CLIENT_REGISTRATION_INFO:
		return "ignore_command"; /* 14 */
#ifndef ROUTING_ONLY
	case MSG_CLIENT_ADD_FILE:
		return "add_file";       /* 100 */
	case MSG_CLIENT_REMOVE_FILE:
		return "remove_file";        /* 102 */
#endif
	case MSG_CLIENT_UNSHARE_ALL:
		return "unshare_all";        /* 110 */
#ifndef ROUTING_ONLY
	case MSG_CLIENT_SEARCH:
		return "search";     /* 200 */
#endif
	case MSG_SERVER_SEARCH_RESULT:
		return "search result";      /* 201 */
	case MSG_SERVER_SEARCH_END:
		return "search end";     /* 202 */
	case MSG_CLIENT_DOWNLOAD:
		return "download";       /* 203 */
	case MSG_SERVER_FILE_READY:
		return "file ready";     /* 204 */
	case MSG_CLIENT_PRIVMSG:
		return "privmsg";        /* 205 */
	case MSG_SERVER_SEND_ERROR:
		return "send error";     /* 206 */
	case MSG_CLIENT_ADD_HOTLIST:
		return "add_hotlist";        /* 207 */
	case MSG_CLIENT_ADD_HOTLIST_SEQ:
		return "add_hotlist";        /* 208 */
	case MSG_SERVER_USER_SIGNON:
		return "user signon";        /* 209 */
	case MSG_SERVER_USER_SIGNOFF:
		return "user signoff";       /* 210 */
	case MSG_CLIENT_BROWSE:
		return "browse";     /* 211 */
	case MSG_SERVER_BROWSE_RESPONSE:
		return "browse response";    /* 212 */
	case MSG_SERVER_BROWSE_END:
		return "browse end";     /* 213 */
	case MSG_SERVER_STATS:
		return "server stats";       /* 214 */
	case MSG_CLIENT_RESUME_REQUEST:
		return "resume request"; /* 215 */
	case MSG_SERVER_RESUME_MATCH:
		return "resume match";       /* 216 */
	case MSG_SERVER_RESUME_MATCH_END:
		return "resume match end";   /* 217 */
	case MSG_CLIENT_DOWNLOAD_START:
		return "download start"; /* 218 */
	case MSG_CLIENT_DOWNLOAD_END:
		return "download end";       /* 219 */
	case MSG_CLIENT_UPLOAD_START:
		return "upload start";       /* 220 */
	case MSG_CLIENT_UPLOAD_END:
		return "upload end";     /* 221 */
	case MSG_CLIENT_CHECK_PORT:
		return "check port (ignored)";   /* 300 */
	case MSG_SERVER_HOTLIST_ACK:
		return "hotlist ack";        /* 301 */
	case MSG_SERVER_HOTLIST_ERROR:
		return "hotlist error";      /* 302 */
	case MSG_CLIENT_REMOVE_HOTLIST:
		return "remove_hotlist"; /* 303 */
	case MSG_SERVER_DISCONNECTING:
		return "disconnecting";      /* 316 */
	case MSG_CLIENT_IGNORE_LIST:
		return "ignore list";        /* 320 */
	case MSG_SERVER_IGNORE_ENTRY:
		return "ignore entry";       /* 321 */
	case MSG_CLIENT_IGNORE_USER:
		return "ignore user";        /* 322 */
	case MSG_CLIENT_UNIGNORE_USER:
		return "unignore user";      /* 323 */
	case MSG_SERVER_NOT_IGNORED:
		return "not ignored";        /* 324 */
	case MSG_SERVER_ALREADY_IGNORED:
		return "already ignored";    /* 325 */
	case MSG_CLIENT_CLEAR_IGNORE:
		return "clear ignore";       /* 326 */
	case MSG_CLIENT_JOIN:
		return "join";           /* 400 */
	case MSG_CLIENT_PART:
		return "part";           /* 401 */
	case MSG_CLIENT_PUBLIC:
		return "public";     /* 402 */
	case MSG_SERVER_PUBLIC:
		return "public";     /* 403 */
	case MSG_SERVER_NOSUCH:
		return "server error";       /* 404 */
	case MSG_SERVER_JOIN_ACK:
		return "chan join ack";      /* 405 */
	case MSG_SERVER_JOIN:
		return "chan join";      /* 406 */
	case MSG_SERVER_PART:
		return "chan part";      /* 407 */
	case MSG_SERVER_CHANNEL_USER_LIST:
		return "chan list";      /* 408 */
	case MSG_SERVER_CHANNEL_USER_LIST_END:
		return "chan list end";      /* 409 */
	case MSG_SERVER_TOPIC:
		return "chan topic";     /* 410 */
	case MSG_CLIENT_CHANNEL_BAN_LIST:
		return "chan banlist";       /* 420 */
	case MSG_SERVER_CHANNEL_BAN_LIST:
		return "chan banlist";       /* 421 */
	case MSG_CLIENT_CHANNEL_BAN:
		return "chan ban";       /* 422 */
	case MSG_CLIENT_CHANNEL_UNBAN:
		return "chan unban";     /* 423 */
	case MSG_CLIENT_CHANNEL_CLEAR_BANS:
		return "chan clear bans";    /* 424 */
	case MSG_CLIENT_DOWNLOAD_FIREWALL:
		return "download firewall";  /* 500 */
	case MSG_SERVER_UPLOAD_FIREWALL:
		return "upload firewall";    /* 501 */
	case MSG_CLIENT_USERSPEED:
		return "user speed";     /* 600 */
	case MSG_SERVER_USER_SPEED:
		return "user speed";     /* 601 */
	case MSG_CLIENT_WHOIS:
		return "whois";          /* 603 */
	case MSG_SERVER_WHOIS_RESPONSE:
		return "whois";          /* 604 */
	case MSG_SERVER_WHOWAS:
		return "whowas";     /* 605 */
	case MSG_CLIENT_SETUSERLEVEL:
		return "level";          /* 606 */
	case MSG_SERVER_UPLOAD_REQUEST:
		return "upload request"; /* 607 */
	case MSG_CLIENT_UPLOAD_OK:
		return "upload ok";      /* 608 */
	case MSG_CLIENT_ACCEPT_FAILED:
		return "accept failed";      /* 609 */
	case MSG_CLIENT_KILL:
		return "kill";           /* 610 */
	case MSG_CLIENT_NUKE:
		return "nuke";           /* 611 */
	case MSG_CLIENT_BAN:
		return "ban";            /* 612 */
	case MSG_CLIENT_ALTER_PORT:
		return "alter port";     /* 613 */
	case MSG_CLIENT_UNBAN:
		return "unban";          /* 614 */
	case MSG_CLIENT_BANLIST:
		return "banlist";        /* 615 */
	case MSG_SERVER_IP_BANLIST:
		return "ip banlist";     /* 616 */
	case MSG_SERVER_CHANNEL_LIST_END:
		return "chan list end";      /* 617 */
	case MSG_SERVER_CHANNEL_LIST:
		return "chan list";      /* 618 */
	case MSG_CLIENT_LIMIT:
		return "queue limit";        /* 619 */
	case MSG_SERVER_LIMIT:
		return "queue limit";        /* 620 */
	case MSG_CLIENT_MOTD:
		return "motd";           /* 621 */
	case MSG_CLIENT_MUZZLE:
		return "muzzle";     /* 622 */
	case MSG_CLIENT_UNMUZZLE:
		return "unmuzzle";       /* 623 */
	case MSG_CLIENT_UNNUKE:
		return "unnuke?";        /* 624 */
	case MSG_CLIENT_ALTER_SPEED:
		return "alter speed";        /* 625 */
	case MSG_CLIENT_DATA_PORT_ERROR:
		return "data port error";    /* 626 */
	case MSG_CLIENT_WALLOP:
		return "wallop";     /* 627 */
	case MSG_CLIENT_ANNOUNCE:
		return "announce";       /* 628 */
	case MSG_SERVER_NICK_BANLIST:
		return "nick banlist";       /* 629 */
	case MSG_CLIENT_BROWSE_DIRECT:
		return "browse direct";      /* 640 */
	case MSG_SERVER_BROWSE_DIRECT_OK:
		return "browse direct ok";   /* 641 */
	case MSG_SERVER_BROWSE_DIRECT_ERR:
		return "browse direct error";    /* 642 */
	case MSG_CLIENT_CLOAK:
		return "cloak";          /* 652 */
	case MSG_CLIENT_CHANGE_SPEED:
		return "change_speed";       /* 700 */
	case MSG_CLIENT_CHANGE_PASS:
		return "change_pass";        /* 701 */
	case MSG_CLIENT_CHANGE_EMAIL:
		return "change_email";       /* 702 */
	case MSG_CLIENT_CHANGE_DATA_PORT:
		return "change_data_port";   /* 703 */
	case MSG_SERVER_GHOST:
		return "ghost";          /* 748 */
	case MSG_CLIENT_PING_SERVER:
		return "ping server";        /* 750 */
	case MSG_CLIENT_PING:
		return "ping";           /* 751 */
	case MSG_CLIENT_PONG:
		return "pong";           /* 752 */
	case MSG_CLIENT_ALTER_PASS:
		return "alter pass";     /* 753 */
	case MSG_CLIENT_SERVER_RECONFIG:
		return "server reconfig";    /* 800 */
	case MSG_CLIENT_SERVER_VERSION:
		return "server version"; /* 801 */
	case MSG_CLIENT_SERVER_CONFIG:
		return "server config";      /* 810 */
	case MSG_CLIENT_CLEAR_CHANNEL:
		return "clear channel";      /* 820 */
	case MSG_CLIENT_REDIRECT:
		return "redirect client";    /* 821 */
	case MSG_CLIENT_CYCLE:
		return "cycle client";       /* 822 */
	case MSG_CLIENT_SET_CHAN_LEVEL:
		return "channel level";      /* 823 */
	case MSG_CLIENT_EMOTE:
		return "emote";          /* 824 */
	case MSG_SERVER_NAMES_LIST:
		return "names list";     /* 825 */
	case MSG_CLIENT_CHANNEL_LIMIT:
		return "channel limit";      /* 826 */
	case MSG_CLIENT_FULL_CHANNEL_LIST:
		return "full chan list"; /* 827 */
	case MSG_SERVER_FULL_CHANNEL_INFO:
		return "full chan info"; /* 828 */
	case MSG_CLIENT_KICK:
		return "kick";           /* 829 */
	case MSG_CLIENT_NAMES_LIST:
		return "list users";     /* 830 */
	case MSG_CLIENT_GLOBAL_USER_LIST:
		return "global user list";   /* 831 */
	case MSG_SERVER_GLOBAL_USER_LIST:
		return "global user list";   /* 832 */
#ifndef ROUTING_ONLY
	case MSG_CLIENT_ADD_DIRECTORY:
		return "add_directory";      /* 870 */
#endif
	case 920:
		return "ignore_command"; /* 920 */
	case MSG_CLIENT_ADD_SERVER:
		return "add server";     /* 9998 */
	case MSG_CLIENT_LIST_SERVER:
		return "list server";        /* 9999 */
	case MSG_CLIENT_QUIT:
		return "client quit";        /* 10000 */
	case MSG_SERVER_LOGIN:
		return "server login";       /* 10010 */
	case MSG_SERVER_LOGIN_ACK:
		return "server login ack";   /* 10011 */
	case MSG_SERVER_USER_SHARING:
		return "user sharing";       /* 10012 */
	case MSG_SERVER_USER_IP:
		return "user ip";        /* 10013 */
	case MSG_SERVER_REGINFO:
		return "reginfo";        /* 10014 */
	case MSG_SERVER_REMOTE_SEARCH:
		return "remote search";      /* 10015 */
	case MSG_SERVER_REMOTE_SEARCH_RESULT:
		return "remote search result";   /* 10016 */
	case MSG_SERVER_REMOTE_SEARCH_END:
		return "remote search end";  /* 10017 */
	case MSG_SERVER_ENCAPSULATED:
		return "encapsulated";       /* 10018 */
	case MSG_SERVER_LINK_INFO:
		return "link info";      /* 10019 */
	case MSG_SERVER_QUIT:
		return "server disconnect";  /* 10020 - deprecated by 10101 */
	case MSG_SERVER_NOTIFY_MODS:
		return "remote notify_mods"; /* 10021 */
	case MSG_SERVER_SERVER_PONG:
		return "server pong";        /* 10022 */
	case MSG_SERVER_TIME_CHECK:
		return "time check";     /* 10023 */
	case MSG_SERVER_WHOIS_NOTIFY:
		return "whois notify";       /* 10024 */
	case MSG_CLIENT_USERFLAGS:
		return "change userflags";   /* 10050 */
	case MSG_CLIENT_CONNECT:
		return "server connect"; /* 10100 */
	case MSG_CLIENT_DISCONNECT:
		return "server disconnect";  /* 10101 */
	case MSG_CLIENT_KILL_SERVER:
		return "kill server";        /* 10110 */
	case MSG_CLIENT_REMOVE_SERVER:
		return "remove server";      /* 10111 */
	case MSG_CLIENT_LINKS:
		return "server links";       /* 10112 */
	case MSG_CLIENT_USAGE_STATS:
		return "server usage";       /* 10115 */
	case MSG_SERVER_SEARCH_STATS:
		return "search cache stats"; /* 10116 */
	case MSG_CLIENT_REHASH:
		return "rehash";     /* 10117 */
	case MSG_CLIENT_VERSION_STATS:
		return "client version stats";   /* 10118 */
	case MSG_CLIENT_WHICH_SERVER:
		return "which server";       /* 10119 */
	case MSG_CLIENT_PING_ALL_SERVERS:
		return "ping all servers";   /* 10120 */
	case MSG_CLIENT_WHO_WAS:
		return "whowas";     /* 10121 */
	case MSG_CLIENT_MASS_KILL:
		return "mass kill";      /* 10122 */
	case MSG_CLIENT_HISTOGRAM:
		return "histogram recv"; /* 10123 */
	case MSG_SERVER_HISTOGRAM:
		return "histogram recv end"; /* 10124 */
	case MSG_CLIENT_SHISTOGRAM:
		return "histogram send"; /* 10125 */ 
	case MSG_SERVER_SHISTOGRAM:
		return "histogram send end"; /* 10126 */ 
	case MSG_CLIENT_REGISTER_USER:
		return "register user";      /* 10200 */
	case MSG_CLIENT_USER_MODE:
		return "user mode cmd";      /* 10203 */
	case MSG_CLIENT_OP:
		return "chan op";        /* 10204 */
	case MSG_CLIENT_DEOP:
		return "chan deop";      /* 10205 */
	case MSG_CLIENT_CHANNEL_WALLOP:
		return "chan wallop";        /* 10208 */
	case MSG_CLIENT_CHANNEL_MODE:
		return "chan mode";      /* 10209 */
	case MSG_CLIENT_CHANNEL_INVITE:
		return "chan invite";        /* 10210 */
	case MSG_CLIENT_CHANNEL_VOICE:
		return "chan voice";     /* 10211 */
	case MSG_CLIENT_CHANNEL_UNVOICE:
		return "chan unvoice";       /* 10212 */
	case MSG_CLIENT_CHANNEL_MUZZLE:
		return "chan muzzle";        /* 10213 */
	case MSG_CLIENT_CHANNEL_UNMUZZLE:
		return "chan unmuzzle";      /* 10214 */
	case MSG_CLIENT_CLASS_ADD:
		return "acl generic add";    /* 10250 */
	case MSG_CLIENT_CLASS_DEL:
		return "acl generic del";    /* 10251 */
	case MSG_CLIENT_CLASS_LIST:
		return "acl generic list";   /* 10252 */
	case MSG_CLIENT_DLINE_ADD:
		return "acl d-line add"; /* 10253 */
	case MSG_CLIENT_DLINE_DEL:
		return "acl d-line del"; /* 10254 */
	case MSG_CLIENT_DLINE_LIST:
		return "acl d-line list";    /* 10255 */
	case MSG_CLIENT_ILINE_ADD:
		return "acl i-line add"; /* 10256 */
	case MSG_CLIENT_ILINE_DEL:
		return "acl i-line del"; /* 10257 */
	case MSG_CLIENT_ILINE_LIST:
		return "acl i-line list";    /* 10258 */
	case MSG_CLIENT_ELINE_ADD:
		return "acl e-line add"; /* 10259 */
	case MSG_CLIENT_ELINE_DEL:
		return "acl e-line del"; /* 10260 */
	case MSG_CLIENT_ELINE_LIST:
		return "acl e-line list";    /* 10261 */
	case MSG_SERVER_SYNC_END:
		return "server sync end";    /* 10262 */
	case MSG_SERVER_SYNC_END_ACK:      
		return "server sync end ack";/* 10263 */
	case MSG_CLIENT_LOG_LEVEL:
		return "change log level";
	case MSG_CLIENT_SHARE_FILE:
		return "share generic file"; /* 10300 */
	case MSG_CLIENT_BROWSE_NEW:
		return "browse new";     /* 10301 */
	case MSG_SERVER_BROWSE_RESULT_NEW:
		return "browse result new";  /* 10302 */
#ifdef USE_PROTNET  
	case MSG_CLIENT_RESYNC_USER:
		return "resync user";        /* 10303 */
	case MSG_CLIENT_DESYNC_USER:
		return "desync user";        /* 10304 */
#endif
	}
	return "unknown";
}

void add_shist( unsigned int tag, unsigned int len ) 
{
    LIST        *list;
    histogram_t *h;

    for (list = global.histOutList; list; list = list->next) 
	{
        h = list->data;
        if(tag == h->tag) 
		{
            h->count++;
            h->len += len;
            return;
        }
    }

    /* tag not found add one */
    while (1) 
    {   
        h = CALLOC(1, sizeof(histogram_t));
        if(!h)
            break;
        h->tag = tag;
        h->count = 1;
        h->len = len;
        list = CALLOC(1, sizeof(LIST));
        if(!list)
            break;
        list->data = h;
        list->next = global.histOutList;
        global.histOutList = list;
        return;
    }

    OUTOFMEMORY("add_shist");
    if(h)
        FREE(h);
    if(list)
        FREE(list);
    return;
}

