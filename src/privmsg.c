/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
This is free software distributed under the terms of the
GNU Public License.  See the file COPYING for details.

$Id: privmsg.c 434 2006-09-03 17:48:47Z reech $ */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#ifndef WIN32
# include <unistd.h>
#endif
#include <string.h>
#include "opennap.h"
#include "debug.h"

/* loopback command for allowing mods using the windows client to execute
opennap comamnds */
static void operserv(CONNECTION * con, char *pkt)
{
    char   *cmd = next_arg(&pkt);
    unsigned short tag, len;
    char    ch = 0;

    if(!cmd)
        return;
    if(!strcasecmp("chanlevel", cmd))
        tag = MSG_CLIENT_CHANNEL_LEVEL;
    else if(!strcasecmp("links", cmd))
        tag = MSG_CLIENT_LINKS;
    else if(!strcasecmp("stats", cmd))
        tag = MSG_CLIENT_USAGE_STATS;
    else if(!strcasecmp("connect", cmd))
        tag = MSG_CLIENT_CONNECT;
    else if(!strcasecmp("disconnect", cmd))
        tag = MSG_CLIENT_DISCONNECT;
    else if(!strcasecmp("killserver", cmd))
        tag = MSG_CLIENT_KILL_SERVER;
    else if(!strcasecmp("nuke", cmd))
        tag = MSG_CLIENT_NUKE;
    else if(!strcasecmp("register", cmd))
        tag = MSG_CLIENT_REGISTER_USER;
    else if(!strcasecmp("chanlimit", cmd))
        tag = MSG_CLIENT_CHANNEL_LIMIT;
    else if(!strcasecmp("kick", cmd))
        tag = MSG_CLIENT_KICK_USER;
    else if(!strcasecmp("usermode", cmd))
        tag = MSG_CLIENT_USER_MODE;
    else if(!strcasecmp("config", cmd))
        tag = MSG_CLIENT_SERVER_CONFIG;
    else if(!strcasecmp("reconfig", cmd))
        tag = MSG_CLIENT_SERVER_RECONFIG;
    else if(!strcasecmp("cban", cmd))
        tag = MSG_CLIENT_CHANNEL_BAN;
    else if(!strcasecmp("cunban", cmd))
        tag = MSG_CLIENT_CHANNEL_UNBAN;
    else if(!strcasecmp("cbanlist", cmd))
        tag = MSG_CLIENT_CHANNEL_BAN_LIST;
    else if(!strcasecmp("cbanclear", cmd))
        tag = MSG_CLIENT_CHANNEL_CLEAR_BANS;
    else if(!strcasecmp("clearchan", cmd))
        tag = MSG_CLIENT_CLEAR_CHANNEL;
    else if(!strcasecmp("cloak", cmd))
        tag = MSG_CLIENT_CLOAK;
    else if(!strcasecmp("op", cmd))
        tag = MSG_CLIENT_OP;
    else if(!strcasecmp("oplist", cmd))
        tag = MSG_CLIENT_OP;    /* deprecated, but this should work as expected */
    else if(!strcasecmp("deop", cmd))
        tag = MSG_CLIENT_DEOP;
    else if(!strcasecmp("rehash", cmd))
        tag = MSG_CLIENT_REHASH;
    else if(!strcasecmp("server", cmd))
        tag = MSG_CLIENT_WHICH_SERVER;
    else if(!strcasecmp("redirect", cmd))
        tag = MSG_CLIENT_REDIRECT;
    else if(!strcasecmp("cycle", cmd))
        tag = MSG_CLIENT_CYCLE;
    else if(!strcasecmp("whowas", cmd))
        tag = MSG_CLIENT_WHO_WAS;
    else if(!strcasecmp("userflags", cmd))
        tag = MSG_CLIENT_USERFLAGS;
    else if(!strcasecmp("list_server", cmd))
        tag = MSG_CLIENT_LIST_SERVER;
    else if(!strcasecmp("add_server", cmd))
        tag = MSG_CLIENT_ADD_SERVER;
    else if(!strcasecmp("loglevel", cmd))
        tag = MSG_CLIENT_LOG_LEVEL;
    else if(!strcasecmp("help", cmd))
    {
        send_cmd(con, MSG_CLIENT_PRIVMSG, "OperServ Help for OperServ:");
        send_cmd(con, MSG_CLIENT_PRIVMSG, "OperServ cloak - toggles the ability for normal users to see your nick");
        send_cmd(con, MSG_CLIENT_PRIVMSG, "OperServ config <variable> [value] - query/set server configuration");
        send_cmd(con, MSG_CLIENT_PRIVMSG, "OperServ connect <server> [remote_server] - link a server");
        send_cmd(con, MSG_CLIENT_PRIVMSG, "OperServ cycle <nick> <host> - request client reconnect to metaserver <host>");
        send_cmd(con, MSG_CLIENT_PRIVMSG, "OperServ disconnect <server> - delink a server");
        send_cmd(con, MSG_CLIENT_PRIVMSG, "OperServ help - display this help message");
        send_cmd(con, MSG_CLIENT_PRIVMSG, "OperServ killserver [server] - cause a server to shut down");
        send_cmd(con, MSG_CLIENT_PRIVMSG, "OperServ links - shows linked servers");
        send_cmd(con, MSG_CLIENT_PRIVMSG, "OperServ nuke <nick> - unregister a nickname");
        send_cmd(con, MSG_CLIENT_PRIVMSG, "OperServ reconfig <variable> - reset server configuration variable");
        send_cmd(con, MSG_CLIENT_PRIVMSG, "OperServ redirect <nick> <host> <port> - request client connect to server <host>:<port>");
        send_cmd(con, MSG_CLIENT_PRIVMSG, "OperServ register <user> <pass> <email> [level] - register user");
        send_cmd(con, MSG_CLIENT_PRIVMSG, "OperServ rehash [server] - reload the servers config file");
        send_cmd(con, MSG_CLIENT_PRIVMSG, "OperServ stats - display server stats");
        send_cmd(con, MSG_CLIENT_PRIVMSG, "OperServ usermode - sets modes for server messages, unset with -mode - Modes:  Error ban change kill level server muzzle port wallop cloak flood ping msg whois abuse");
        send_cmd(con, MSG_CLIENT_PRIVMSG, "OperServ whowas <nick> - display whois info for a recently logged out client");
        send_cmd(con, MSG_CLIENT_PRIVMSG, "OperServ userflags <nick> <flags> - change userflags of a user. Flags can be Friend or Criminal. To delete a flag put a - in front of the flag");
        send_cmd(con, MSG_CLIENT_PRIVMSG, "OperServ list_server - list the servers file");
        send_cmd(con, MSG_CLIENT_PRIVMSG, "OperServ add_server <hostname> <their_pass> <my_pass> <port> [alias] - adds a temporary server to the servers list");
        send_cmd(con, MSG_CLIENT_PRIVMSG, "OperServ loglevel - sets level for logging, unset with -mode - Modes: server client login files share search debug error security channel stats");
        send_cmd(con, MSG_CLIENT_PRIVMSG, "OperServ END of help for OperServ");
        return;
    }
    else
    {
        send_cmd(con, MSG_SERVER_NOSUCH, "Unknown OperServ command: %s", cmd);
        return;
    }
    if(pkt)
        len = strlen(pkt);
    else
    {
        /* most of the handler routines expect `pkt' to be non-NULL so pass
        a dummy value here */
        pkt = &ch;
        len = 0;
    }
    dispatch_command(con, tag, len, pkt);
}

static void chanserv(CONNECTION * con, char *pkt)
{
    char   *cmd = next_arg(&pkt);
    unsigned short tag, len;
    char    ch = 0;

    if(!cmd)
        return;
    if(!strcasecmp("ban", cmd))
        tag = MSG_CLIENT_CHANNEL_BAN;
    else if(!strcasecmp("unban", cmd))
        tag = MSG_CLIENT_CHANNEL_UNBAN;
    else if(!strcasecmp("banclear", cmd))
        tag = MSG_CLIENT_CHANNEL_CLEAR_BANS;
    else if(!strcasecmp("banlist", cmd))
        tag = MSG_CLIENT_CHANNEL_BAN_LIST;
    else if(!strcasecmp("clear", cmd))
        tag = MSG_CLIENT_CLEAR_CHANNEL;
    else if(!strcasecmp("kick", cmd))
        tag = MSG_CLIENT_KICK;
    else if(!strcasecmp("oplist", cmd))   /* deprecated, but should work */
        tag = MSG_CLIENT_OP;
    else if(!strcasecmp("topic", cmd))
        tag = MSG_SERVER_TOPIC;
    else if(!strcasecmp("limit", cmd))
        tag = MSG_CLIENT_CHANNEL_LIMIT;
    else if(!strcasecmp("drop", cmd))
        tag = MSG_CLIENT_DROP_CHANNEL;
    else if(!strcasecmp("op", cmd))
        tag = MSG_CLIENT_OP;
    else if(!strcasecmp("deop", cmd))
        tag = MSG_CLIENT_DEOP;
    else if(!strcasecmp("wallop", cmd))
        tag = MSG_CLIENT_CHANNEL_WALLOP;
    else if(!strcasecmp("invite", cmd))
        tag = MSG_CLIENT_CHANNEL_INVITE;
    else if(!strcasecmp("mode", cmd))
        tag = MSG_CLIENT_CHANNEL_MODE;
    else if(!strcasecmp("muzzle", cmd))
        tag = MSG_CLIENT_CHANNEL_MUZZLE;
    else if(!strcasecmp("unmuzzle", cmd))
        tag = MSG_CLIENT_CHANNEL_UNMUZZLE;
    else if(!strcasecmp("unvoice", cmd))
        tag = MSG_CLIENT_CHANNEL_UNVOICE;
    else if(!strcasecmp("voice", cmd))
        tag = MSG_CLIENT_CHANNEL_VOICE;
    else if(!strcasecmp("level", cmd))
        tag = MSG_CLIENT_SET_CHAN_LEVEL;
    else if(!strcasecmp("help", cmd))
    {
        send_cmd(con, MSG_CLIENT_PRIVMSG, "ChanServ HELP for ChanServ commands:");
        send_cmd(con, MSG_CLIENT_PRIVMSG, "ChanServ ban <channel> <user> [\"reason\"]");
        send_cmd(con, MSG_CLIENT_PRIVMSG, "ChanServ banclear <channel> - clear all bans");
        send_cmd(con, MSG_CLIENT_PRIVMSG, "ChanServ banlist <channel>");
        send_cmd(con, MSG_CLIENT_PRIVMSG, "ChanServ clear <channel> - kick all users out of channel");
        send_cmd(con, MSG_CLIENT_PRIVMSG, "ChanServ deop <channel> [user [user ...]]");
        send_cmd(con, MSG_CLIENT_PRIVMSG, "ChanServ help");
        send_cmd(con, MSG_CLIENT_PRIVMSG, "ChanServ invite <channel> <user>");
        send_cmd(con, MSG_CLIENT_PRIVMSG, "ChanServ kick <channel> <user> [\"reason\"]");
        send_cmd(con, MSG_CLIENT_PRIVMSG, "ChanServ level <channel> [level] - display/set min user level required to join");
        send_cmd(con, MSG_CLIENT_PRIVMSG, "ChanServ limit <channel> [number] - set max number of users");
        send_cmd(con, MSG_CLIENT_PRIVMSG, "ChanServ mode <channel> [mode [mode ...]]");
        send_cmd(con, MSG_CLIENT_PRIVMSG, "ChanServ muzzle <channel> <user>");
        send_cmd(con, MSG_CLIENT_PRIVMSG, "ChanServ op <channel> [user [user ...] - display/set channel operators");
        send_cmd(con, MSG_CLIENT_PRIVMSG, "ChanServ topic <channel> [topic] - display/set channel topic");
        send_cmd(con, MSG_CLIENT_PRIVMSG, "ChanServ unban <channel>");
        send_cmd(con, MSG_CLIENT_PRIVMSG, "ChanServ unmuzzle <channel> <user>");
        send_cmd(con, MSG_CLIENT_PRIVMSG, "ChanServ unvoice <channel> [user [user ...]]");
        send_cmd(con, MSG_CLIENT_PRIVMSG, "ChanServ voice <channel> [user [user ...]]");
        send_cmd(con, MSG_CLIENT_PRIVMSG, "ChanServ wallop <channel> <text> - send message to all channel operators");
        return;
    }
    else
    {
        send_cmd(con, MSG_CLIENT_PRIVMSG, "ChanServ Unknown command");
        return;
    }
    if(pkt)
        len = strlen(pkt);
    else
    {
        /* most of the handler routines expect `pkt' to be non-NULL so pass
        a dummy value here */
        pkt = &ch;
        len = 0;
    }
    dispatch_command(con, tag, len, pkt);
}

static void nickserv(CONNECTION * con, char *pkt)
{
    char   *cmd = next_arg(&pkt);
    char   *nick;
    char   *pass;
    USER   *user;
    USERDB *db;

    if(!cmd)
        return;
    if(!strcasecmp("ghost", cmd))
    {
        nick = next_arg(&pkt);
        pass = next_arg(&pkt);
        if(!nick || !pass)
        {
            send_cmd(con, MSG_CLIENT_PRIVMSG, "NickServ Missing argument(s)");
            return;
        }
        user = hash_lookup(global.usersHash, nick);
        if(!user)
        {
            send_cmd(con, MSG_CLIENT_PRIVMSG, "NickServ No such user");
            return;
        }
        db = hash_lookup(global.userDbHash , user->nick);
        if(!db)
        {
            send_cmd(con, MSG_CLIENT_PRIVMSG, "NickServ Nick is not registered");
            return;
        }
        if(check_pass (db->password, pass))
        {
            send_cmd(con, MSG_CLIENT_PRIVMSG, "NickServ Invalid password");
            return;
        }
        kill_user_internal(0, user, global.serverName, 0, "ghosted by %s", con->user->nick);
    }
    else if(!strcasecmp("register", cmd))
    {
        db = hash_lookup(global.userDbHash , con->user->nick);
        if(db)
        {
            send_cmd(con, MSG_CLIENT_PRIVMSG, "NickServ your nick is already registered");
            return;
        }
        db = create_db (con->user);
        if(!db)
            return;
        hash_add(global.userDbHash , db->nick, db);
        send_cmd(con, MSG_CLIENT_PRIVMSG, "NickServ your nick has successfully been registered");

        /* pass this on to our peer servers so it gets registered everywhere */
        pass_message_args(con, MSG_CLIENT_REGISTER_USER, ":%s %s %s unknown User", global.serverName, db->nick, con->user->pass);
    }
    else if(!strcasecmp("usermode", cmd))
        user_mode_cmd (con, MSG_CLIENT_USER_MODE, 0, pkt);
    else if(!strcasecmp("nuke", cmd))
    {
    }
    else if(!strcasecmp("help", cmd))
    {
        send_cmd(con, MSG_CLIENT_PRIVMSG, "NickServ NickServ commands:");
        send_cmd(con, MSG_CLIENT_PRIVMSG, "NickServ ghost <nick> <pass> - kill your ghost");
        send_cmd(con, MSG_CLIENT_PRIVMSG, "NickServ register <pass> - register your nickname");
        send_cmd(con, MSG_CLIENT_PRIVMSG, "NickServ server <nick> - display which server a user is on");
        send_cmd(con, MSG_CLIENT_PRIVMSG, "NickServ usermode [flags] - display/set your user mode");
    }
    else if(!strcasecmp("server", cmd))
        which_server(con, MSG_CLIENT_WHICH_SERVER, 0, pkt);
    else
        send_cmd(con, MSG_CLIENT_PRIVMSG, "NickServ Unknown command");
}

/* handles private message commands */
/* [ :<nick> ] <user> <text> */
HANDLER(privmsg)
{
    char   *ptr;
    USER   *sender, *user /* recip */ ;
    char   reason[256];

    (void) tag;
    (void) len;
    ASSERT(validate_connection(con));

    ptr = pkt;          /* save the start offset of pkt for length check */
    if(pop_user(con, &pkt, &sender) != 0)
        return;
    ASSERT(validate_user(sender));

    /* prevent DoS attack againt windows napster client */
    if(len - (pkt - ptr) > 180)
    {
        log_message_level(LOG_LEVEL_DEBUG, "privmsg: truncated %d byte message from %s", len, sender->nick);
        pkt[180] = 0;
    }

    /* check to see if the recipient of the message is local */
    ptr = next_arg_noskip(&pkt);
    if(!pkt)
    {
        unparsable(con);
        return;
    }

    if(ISUSER(con))
    {
        if(sender->level > LEVEL_USER && !strcasecmp(ptr, "operserv"))
        {
            operserv(con, pkt);
            return;
        }
        if(!strcasecmp("chanserv", ptr))
        {
            chanserv(con, pkt);
            return;
        }
        if(!strcasecmp("nickserv", ptr))
        {
            nickserv(con, pkt);
            return;
        }
    }

    /* find the recipient */
    user = hash_lookup(global.usersHash, ptr);
    if(!user)
    {
        nosuchuser(con);
        return;
    }

    if(global.BlockWinMX > 0 && !strncmp("//WantQueue", pkt, sizeof("//WantQueue")-1))
    {
        if(sender->level < LEVEL_MODERATOR)
            discipline_user(sender);
        return;
    }

    /* Discussion with lopster developers gave hints that a "wantqueue " is equal to a "wantqueue"
    as far as lopster is concerned.  :-)
    So we can sort some things like MX downloads out ...

    06/13/2002: TT: Sadly that MX does not follow this simple rule from V3.1 on.
    */

    if(!strncmp("//WantQueue", pkt, sizeof("//WantQueue")-1))
    {
        global.count205mx++;
        global.size205mx+=strlen(pkt);
    } 
    global.count205++;
    global.size205+=strlen(pkt);
/*printf("tag: %d sender: %s \treciep: %s \tpkt: %s\n", 205, sender->nick, user->nick, pkt);
fflush(stdout);
*/
    /* We want to know how many privmsgs are made by moronware ... */
    if(global.count205 > 0 && ! ( global.count205 % 1000) ) 
    {
        log_message_level(LOG_LEVEL_SERVER, "privmsg: all 205: %d %d Bytes - 205WQ: %d (%.1f%%) %d Bytes (%.1f%%)",
            global.count205,
            global.size205,
            global.count205mx, 
            100.0*global.count205mx/global.count205,
            global.size205mx,
            100.0*global.size205mx/global.size205
            );
    }

    /* This one saves the traffic monitored above.  */
    if(option(ON_BREAK_MX_QUEUE) && 
        !strncmp("//WantQueue", pkt, sizeof("//WantQueue")-1) && /* This one handles the winmx type of "//WantQueue" */
        strncmp("//WantQueue ", pkt, sizeof("//WantQueue ")-1)  /* This one handles the lopster type of "//WantQueue " */
        ) 
    {
        return;
    }

    /*  locally connected user */
    if(ISUSER(user->con))
    {
        /* check if the user wishes to receive msgs */
        if((user->con->uopt->usermode & MSGLOG_MODE) == 0)
        {
            send_user(sender, MSG_SERVER_NOSUCH, "%s is unavailable", user->nick);
        }
        /* check to make sure this user is not ignored */
        else if(!is_ignoring(user->con->uopt->ignore, sender->nick))
        {
            /* reconstitute the message */
            send_cmd(user->con, MSG_CLIENT_PRIVMSG, "%s %s", sender->nick, pkt);
        }
        else
        {
            /* notify the sender they are being ignored */
            send_user(sender, MSG_SERVER_NOSUCH, "%s is ignoring you",user->nick);

            /* Check if the user who ignored the other has a lower level than the ignored one ...
            "sender" is the user who sent the request. "user" ist the user who chose to ignore sender. */
            if( user->level < LEVEL_MODERATOR && sender->level > user->level && option(ON_DISCIPLINE_IGNORERS) ) 
			{
                if( global.discipline_ignorers_ban_ttl ) 
                {
                    snprintf( reason, sizeof(reason)-1, "Don't ignore a mod+ ever again (%s)",sender->nick), ban_user_internal( user->con, user->nick, global.discipline_ignorers_ban_ttl, reason);
                    log_message_level(LOG_LEVEL_DEBUG, "%s ignored %s in privmsg.c",user->nick,sender->nick);
                }
                kill_user_internal(user->con, user, global.serverName, 0, reason);
                return;
            }

            if(! strcmp( sender->nick, user->nick) && user->level < LEVEL_MODERATOR) 
            {
                kill_user_internal(user->con, user, global.serverName, 0, "You do not really want to ignore yourself, do you?");
                ban_user_internal( user->con,user->nick,global.discipline_ignorers_ban_ttl, "Ignoring yourself does not fix the problems with your client.");
                return;
            }

        }
    }
    else
    {
        /* pass the message on to our peers since the recipient isn't
        local.  we know which server the client is behind, so we just
        need to send one copy */
        ASSERT(user->con->class == CLASS_SERVER);
        if(con != user->con)
            send_cmd(user->con, MSG_CLIENT_PRIVMSG, ":%s %s %s", sender->nick, user->nick, pkt);
        else
        {
            snprintf(reason, sizeof(reason), "privmsg.c: privmsg: recip->con=con: recip: %s(%s)", user->nick, user->server);
            log_message_level(LOG_LEVEL_DEBUG, reason);
            kill_user_internal(user->con, user, global.serverName, 0, "ghost resync: privmsg.c: privmsg"); /* reason); */
        }
    }
}

/* 320
list ignored users */
HANDLER(ignore_list)
{
    int     n = 0;
    LIST   *list;

    (void) len;
    (void) pkt;
    ASSERT(validate_connection(con));
    CHECK_USER_CLASS("ignore_list");
    for (list = con->uopt->ignore; list; list = list->next, n++)
        send_cmd(con, MSG_SERVER_IGNORE_ENTRY, "%s", list->data);
    send_cmd(con, tag, "%d", n);
}

/*  322 <user>
add user to ignore list */
HANDLER(ignore)
{
    LIST   *list;

    (void) len;
    ASSERT(validate_connection(con));
    CHECK_USER_CLASS("ignore_add");
    if(invalid_nick(pkt))
    {
        invalid_nick_msg(con);
        return;
    }
	/*ensure that this user is not already on the ignore list */
	for (list = con->uopt->ignore; list; list = list->next)
		if(!strcasecmp(pkt, list->data))
		{
			send_cmd(con, MSG_SERVER_ALREADY_IGNORED, "%s", pkt);
			return;     /*already added */
		}
		if(global.maxIgnore > 0 && list_count (con->uopt->ignore) > global.maxIgnore)
		{
			send_cmd(con, MSG_SERVER_NOSUCH, "ignore list is limited to %d users", global.maxIgnore);
			return;
		}
		list = CALLOC(1, sizeof(LIST));
		list->data = STRDUP(pkt);
		list->next = con->uopt->ignore;
		con->uopt->ignore = list;
		send_cmd(con, tag, "%s", pkt);
}

/* 323 <user>
unignore user */
HANDLER(unignore)
{
    LIST  **list, *tmpList;

    (void) len;
    ASSERT(validate_connection(con));
    CHECK_USER_CLASS("ignore_add");
    if(invalid_nick(pkt))
    {
        invalid_nick_msg(con);
        return;
    }
    for (list = &con->uopt->ignore; *list; list = &(*list)->next)
    {
        if(!strcasecmp(pkt, (*list)->data))
        {
            send_cmd(con, tag, "%s", pkt);
            tmpList = *list;
            *list = (*list)->next;
            FREE(tmpList->data);
            FREE(tmpList);
            return;
        }
    }
    send_cmd(con, MSG_SERVER_NOT_IGNORED /* 324 */ , "%s", pkt);
}

/* 326
clear user's ignore list */
HANDLER(clear_ignore)
{
    int     n;

    (void) len;
    (void) pkt;
    ASSERT(validate_connection(con));
    CHECK_USER_CLASS("clear_ignore");
    n = list_count(con->uopt->ignore);
    list_free(con->uopt->ignore, free_pointer);
    con->uopt->ignore = 0;
    send_cmd(con, tag, "%d", n);
}
