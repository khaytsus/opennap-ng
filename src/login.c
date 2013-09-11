/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
This is free software distributed under the terms of the
GNU Public License.  See the file COPYING for details.

$Id: login.c 435 2006-09-03 18:57:03Z reech $ */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "opennap.h"
#include "hashlist.h"
#include "debug.h"

/* Added by spike, changed by winter_mute */
#ifdef USE_INVALID_CLIENTS
int invalid_client(const char *s) 
{  
	return glob_match(global.invalidClients, s) ? 1 : 0;
} 
#endif 

int CheckUserAgainstServerNames(const char *s)
{
    LIST    *list;
    server_auth_t   *auth;
    /* check to make sure a user isn't attempting to use an alias of one
    * of our peer servers. we don't need to check the full dns name because
    * nicks already can't contain a period (.)
    * this is only checking against the local servers list
    */
    for (list = global.serverAliasList; list; list = list->next)
    {
        auth = list->data;
        if(auth->alias && !strcasecmp(auth->alias, s))
            return 1;
    }
    /* let's not forget to check our own name */
    if(!strcasecmp(global.serverName, s))
        return 1;
    return 0;
}


int invalid_nick(const char *s)
{
    int  count = 0;

    /* don't allow anyone to ever have this nick */
    if(!strcasecmp("operserv", s) || !strcasecmp("chanserv", s)
        || !strcasecmp("operator", s) || !strcasecmp("nickserv", s)
#ifdef USE_INVALID_NICKS
        || glob_match(global.invalidNicks, s)
#endif
        )
        return 1;
    if(CheckUserAgainstServerNames( s ))
        return 1;

    if(strchr ("#&:-", *s))
        return 1;  /* nick can't begin with # or & (denotes a channel) */
    while (*s)
    {
        if(*s < '!' || *s > '~' || strchr ("%$*?.!\",\\", *s))
            return 1;
        count++;
        s++;
    }
    /* enforce min/max nick length */
    return(count == 0 || (global.maxNickLen > 0 && count > global.maxNickLen));
}

static void sync_reginfo(USERDB * db)
{
    log_message_level(LOG_LEVEL_SERVER, "sync_reginfo: sending registration info to peers");
    pass_message_args(NULL, MSG_SERVER_REGINFO, ":%s %s %s %s %s %u 0", global.serverName, db->nick, db->password,
#if EMAIL
        db->email,
#else
        "unknown",
#endif
        Levels[db->level], db->created);
}

/* pass a KILL message back to the server where the login request came from.
* this is used to sync up when we can't parse the login message, so we
* have no choice but to kill the client.  note that this only gets passed
* back to the server the request came from.
*/
void kill_client(CONNECTION * con, const char *user, const char *reason)
{
    send_cmd(con, MSG_CLIENT_KILL, ":%s %s \"%s\"", global.serverName, user,reason);
    notify_mods(KILLLOG_MODE, "Server %s killed %s: %s", global.serverName, user,reason);
}

void zap_local_user(CONNECTION * con, const char *reason)
{
    ASSERT(validate_connection(con));
    ASSERT(ISUSER(con));
    ASSERT(reason != NULL);

    /* TODO: there is a numeric for this somewhere */
    send_cmd(con, MSG_SERVER_NOSUCH, "You were killed by server %s: %s", global.serverName, reason);
    send_cmd(con, MSG_SERVER_DISCONNECTING, "0");
    con->killed = 1;  /* dont generate a QUIT message */
    remove_user(con);
    /* avoid free'g con->user in remove_connection().  do
    this here to avoid the ASSERT() in remove_user() */
    con->class = CLASS_UNKNOWN;
    con->uopt = 0;  /* just to be safe since it was free'd */
    con->user = 0;
    destroy_connection(con);
}

#ifndef ROUTING_ONLY
/* if the server is full, try to find the client connected to the server
* the longest that isn't sharing any files.  expell that client to make
* room for other (possibly sharing) clients.
*/
static int eject_client(CONNECTION * con)
{
    int  i, loser = -1, leech = 0, shared = 0x7fffffff;
    time_t when = global.current_time;

    for (i = 0; i < global.clients_num; i++)
    {
        if(ISUSER(global.clients[i]) && global.clients[i] != con &&
            !global.clients[i]->killed && /* skip already killed clients */
            /* allow a client time to start sharing files */
            check_eject_limits(global.clients[i]->user))    /* def'ed in abuse.c */
        {
            /* if we already found a leech, don't boot a LEVEL_USER even
            * if the leech logged in more recently or is sharing files
            */
            if(leech && global.clients[i]->user->level > LEVEL_LEECH)
                continue;

            /* always boot the client with the least files shared. we skip
            * this check when we havent' yet found a leech, but the current
            * user is a leech, so that a leech sharing more files than a
            * regular user will get selected.
            */
            if(leech || (!leech && global.clients[i]->user->level > LEVEL_LEECH))
            {
                if(global.clients[i]->user->shared > shared)
                    continue;
            }

            if(global.clients[i]->user->connected < when)
            {
                loser = i;
                when = global.clients[i]->user->connected;
                if(global.clients[i]->user->level == LEVEL_LEECH)
                    leech = 1;
                shared = global.clients[i]->user->shared;
            }
        }
    }
    if(loser == -1)
        return 0;  /* no client to eject, reject current login */
    eject_internal(con,global.clients[loser]->user);
    return 1;   /* ok for current login to proceed despite being full */
}
#endif

/* find the server name in the cache, or add it if it doesn't yet exist.
* this allows one copy of the server name in memory rather than copying it
* 1000 times for each user
*/
static char *find_server(char *s)
{
    LIST   *list;

    for (list = global.serverNamesList; list; list = list->next)
    {
        if(!strcasecmp(s, list->data))
            return list->data;
    }
    /* not found yet, allocate */
    list = CALLOC(1, sizeof(LIST));
    list->data = STRDUP(s);
    list->next = global.serverNamesList;
    global.serverNamesList = list;
    return list->data;
}

/* 2 <nick> <pass> <port> <client-info> <speed> [email] [build] [compress]
or tag = 6 !!
servers append some additional information that they need to share in
order to link:

2 <nick> <pass> <port> <client-info> <speed> <email> <ts> <ip> <server> <serverport>

<ts> is the time at which the client logged in (timestamp)
<ip> is the client's ip address
<server> is the server they are connected to
<port> is the remote port on the server they are connected to */
HANDLER(login)
{
    char *av[10];
    char *tmppass;
    USER *user;
    LIST *list;
    int   ac, speed, clone_count;
    unsigned short port;
#ifdef CSC
    unsigned int compress;
#endif
    USERDB *db = 0;
    unsigned int ip;
    char *host, realhost[256];
    hashlist_t *clientinfo;
    ip_info_t *info;
#ifndef ROUTING_ONLY
    time_t  deltat;
    float  howmany=0.0;
#endif
    LIST    *chan_list;
    CHANNEL *chan;

    (void) len;
    ASSERT(validate_connection(con));

    if(ISUNKNOWN(con)) // count local only...
		stats.logins++;

    if(ISUSER(con)) 
	{
        send_cmd(con, MSG_SERVER_NOSUCH, "you are already logged in");
        stats.login_ce_already++;
        return;
    }

    ac = split_line(av, FIELDS(av), pkt);

    /* check for the correct number of fields for this message type.  some
    clients send extra fields, so we just check to make sure we have
    enough for what is required in this implementation. */
    if(ISUNKNOWN(con)) 
	{
        /* we have a new local connection let's do it */
        if(ac < 5) 
		{
            stats.login_ce_params++;
#ifdef ONAP_DEBUG
            print_args(ac, av);
#endif
            ibl_kill(con, MSG_SERVER_NOSUCH, "Too few parameters for login.");
            return;
        }
        host = con->host;
        ip = con->ip;
#ifdef USE_INVALID_CLIENTS
        if(invalid_client(av[3])) 
		{
            stats.login_ce_client_banned++;
            ibl_kill(con, MSG_SERVER_ERROR, "Your client, %s, is not allowed on this server.", av[3]);
            return;
        }
#endif

        if(invalid_nick(av[0])) 
		{
            stats.login_ce_invalid_nick++;
            ibl_kill(con, MSG_SERVER_BAD_NICK, "Invalid nick: %s", av[0]);
            return;
        }
        speed = atoi(av[4]);
        if(speed < 0 || speed > 10) 
		{
            stats.login_ce_speed++;
            ibl_kill(con, MSG_SERVER_ERROR, "%s: invalid speed", av[4]);
            return;
        }
        port = (unsigned short)atoi(av[2]);
        if(port < 0 || port > 65535) 
		{
            stats.login_ce_port++;
            ibl_kill(con, MSG_SERVER_ERROR, "%s: invalid port", av[2]);
            return;
        }
    } 
	else
	{
        ASSERT(ISSERVER(con));
        /* we have a user from another linked server login in */
        if(ac < 10) 
		{
            stats.login_se_params++;
            log_message_level( LOG_LEVEL_SERVER, "login: too few parameters from server %s", con->host);
            if(ac > 0) 
			{
                /* send a kill back to this server so we stay synched. */
                kill_client(con, av[0], "bad login message from server");
                /* this could be misleading since we haven't yet checked if
                * this user is already logged in via this or another server.
                * so it could look like we have killed the existing users.
                * however, this shouldn't happen very often since no other
                * OpenNap software exists at the moment.
                */
            }
            return;
        }
        ip = strtoul(av[7], 0, 10);
        strncpy(realhost, my_ntoa(BSWAP32(ip)), sizeof(realhost));
        realhost[sizeof(realhost) - 1] = 0;
        host = realhost;
        if(CheckUserAgainstServerNames(av[0])) 
		{
            // only count local... stats.login_ce_invalid_nick++;
            notify_mods(ERROR_MODE, "login: Invalid userid user %s from server %s", av[0], con->host);
            log_message_level( LOG_LEVEL_SERVER, "login: invalid nick %s from server %s", av[0], con->host);
            kill_client(con, av[0], "login.c: Invalid nick");
            return;
        }
        speed = atoi(av[4]);
        if(speed < 0 || speed > 10) 
		{
            // only count local... stats.login_ce_speed++;
            notify_mods(ERROR_MODE, "Invalid speed %d for user %s from server %s", speed, av[0], con->host);
            log_message_level( LOG_LEVEL_SERVER, "login: invalid speed %d received from server %s", speed,  con->host);
            speed = 0;
        }
        port = (unsigned short)atoi(av[2]);
        if(port < 0 || port > 65535) 
		{
            // only count local... stats.login_ce_port++;
            notify_mods(ERROR_MODE, "Invalid port %d for user %s from server %s", port, av[0], con->host);
            log_message_level( LOG_LEVEL_SERVER, "login: invalid port %d received from server %s", port, con->host);
            port = 0;
            /* TODO: generate a change port command */
        }

    }

    /* check if this server does automatic registration */

    if(tag == MSG_CLIENT_LOGIN_REGISTER) 
	{
        log_message_level( LOG_LEVEL_DEBUG, "tag 6: %s!%s %s (%s:%hu)", av[0], my_ntoa(BSWAP32(ip)), av[3], host, av[2] );
    }


    if(tag == MSG_CLIENT_LOGIN_REGISTER && option(ON_RESTRICT_REGISTRATION)) 
	{
        stats.login_ce_autoreg_off++;
        send_cmd(con,MSG_SERVER_ERROR, "Automatic registration is disabled, contact server admin");
        /* i think we should kill the connection here or ? since we return */
        return;
    }


    /* find info on this host */
    info = hash_lookup(global.clonesHash, (void *) ip);
    if(!info) 
    {
        info = CALLOC(1, sizeof(ip_info_t));
        info->ip = ip;
        hash_add(global.clonesHash, (void *) ip, info);
    }
    /* retrieve registration info (could be NULL) */
    db = hash_lookup(global.userDbHash , av[0]);


    if(ISUNKNOWN(con)) 
    {
        if(global.loginInterval > 0 && (global.current_time - info->last_connect < global.loginInterval)) 
        {
            if( !db || ( db->level < LEVEL_MODERATOR && !( db->flags & ON_FRIEND) ) ) 
            {
                stats.login_ce_too_fast++;
                ibl_kill(con, MSG_SERVER_ERROR, "reconnecting too fast");
                return;
            }
        }
        info->last_connect = global.current_time;
        info->connects++;
#if ROUTING_ONLY
        if(!db || db->level < LEVEL_ADMIN) 
		{
            stats.login_ce_not_admin++;
            log_message_level( LOG_LEVEL_LOGIN, "login: rejected login from %s!%s (not admin+)", av[0], con->host);
            ibl_kill(con, MSG_SERVER_ERROR, "access denied");
            return;
        }
#endif
        if(!db || db->level < LEVEL_MODERATOR) 
		{
            if( db ? (~db->flags & ON_FRIEND) : 1 ) 
			{
#ifndef ROUTING_ONLY
                /* check for login overload and destroy the connection if too many
                users try to login simultaneously e.g. right after server startup.
                Look for friends and otherwise priviledged users for not to piss them off.
                */
                deltat=global.current_time - global.serverStartTime;
                howmany=(float)( deltat>0 ? ( ( (float) global.clients_num / ( float ) deltat ) * 60.0 ): 0.0 );
                if(global.max_new_users_per_minute && ( howmany > (float) global.max_new_users_per_minute) ) 
				{
                    log_message_level( LOG_LEVEL_DEBUG, "login: overload %s: %.1f users/min (%lu/%u)", av[0], howmany, global.clients_num, deltat);
                    send_cmd(con, MSG_SERVER_ERROR, "Connection handler overload");
                    destroy_connection(con);
                    return;
                }
#endif   
                if(global.clients_num >= global.maxConnections) 
				{
#ifndef ROUTING_ONLY
                    /* check if another client can be ejected */
                    if(!option(ON_EJECT_WHEN_FULL) || !eject_client (con))
#endif
                    {
                        stats.login_ce_max_connections++;
                        ibl_kill(con, MSG_SERVER_ERROR, "This server is full (%d connections)", global.maxConnections);
                        return;
                    }
                }
                if(check_ban (con, av[0], host))
                    return;
            }
        }
        if(!db && option(ON_REGISTERED_ONLY)) 
		{
            stats.login_ce_restricted++;
            ibl_kill(con, MSG_SERVER_ERROR, "this is a restricted server");
            return;
        }

    }
	else
	{
        ASSERT(ISSERVER(con));
        info->last_connect = global.current_time;
        // only count local... info->connects++;
    }

/* clone kill was here */

    if(tag == MSG_CLIENT_LOGIN && db == NULL)
    {
        /* the requested nick is not registered.  if we are supposed to
        * automatically register all new accounts, switch the command type
        * here to simulate MSG_CLIENT_LOGIN_REGISTER (6).
        */
        if(option(ON_AUTO_REGISTER))
            tag = MSG_CLIENT_LOGIN_REGISTER;
    }

    if(tag == MSG_CLIENT_LOGIN_REGISTER)
    {
        /* check to see if the account is already registered */
        if(db) 
        {
            stats.login_ce_nick_already_registered++;
            if(ISUNKNOWN(con)) 
            {
                /* this could happen if two clients simultaneously connect and register */
                send_cmd(con, MSG_SERVER_ERROR, "Nick registered to another user");
                destroy_connection(con);
            } 
            else 
            {
                ASSERT(ISSERVER(con));
                /* need to issue a kill and send the registration info
                we have on this server */
                kill_client(con, av[0], "Nick registered to another user");
                sync_reginfo(db);
            }
            return;
        }
        /* else, delay creating db until after we make sure the nick is
        not currently in use */
    }
    else if(db)
    {
        ASSERT(tag == MSG_CLIENT_LOGIN);
        /* if(db->level > LEVEL_USER) { */
        /* check the user's password we don't care anymore about a user pass only mod+*/
        if(check_pass(db->password, av[1]))
        {
            if(ISUNKNOWN(con)) // only count local
				stats.login_ce_password++;
            if(db->level < LEVEL_MODERATOR) 
            {
                log_message_level( LOG_LEVEL_LOGIN, "login: bad password for %s (%s) from %s", db->nick, Levels[db->level], host);
            } 
            else 
            {
                log_message_level( LOG_LEVEL_SECURITY, "login: bad password for %s (%s) from %s", db->nick, Levels[db->level], host);
            }

            if(ISUNKNOWN(con)) 
            {
                ibl_kill(con, MSG_SERVER_ERROR, "Invalid Password");
            } 
            else 
            {
                ASSERT(ISSERVER(con));
                /* if another server let this message pass through, that
                means they probably have an out of date password.  notify
                our peers of the registration info.  note that it could be
                _this_ server that is stale, but when the other servers
                receive this message they will check the creation date and
                send back any entries which are more current that this one.
                kind of icky, but its the best we can do */
                kill_client(con, av[0], "Invalid Password");
                sync_reginfo(db);
            }
            return;
        }
        /* } */
    }

    /* check to make sure that this user isn't ready logged in. */
    user = hash_lookup(global.usersHash, av[0]);
    if(user)
    {
        ASSERT(validate_user(user));

        if(ISUNKNOWN(con)) /* local connection */
        {
            if(option(ON_GHOST_KILL)) /* we are killing ghosts */
            {
                if((con->ip == user->ip) || option(ON_ALLOW_DYNAMIC_GHOSTS) || db) /* if ip matches or killing dynamic ghosts or registered user */
                {
                    if((db && (db->level == LEVEL_ELITE)) || ((user->connected + global.ghost_kill_timer) < global.current_time))
                    {
                        /* kill user->con and continue processing con */
                        pass_message_args(NULL, MSG_CLIENT_KILL, ":%s %s \"ghost (%s)\"", global.serverName, user->nick, user->server);
                        notify_mods(KILLLOG_MODE, "Server %s killed %s: ghost (%s)", global.serverName, user->nick, user->server);
                        if(ISUSER(user->con)) /* user->con is local to me */
                        {
                            /* kill the local user */
                            send_cmd(user->con, MSG_SERVER_GHOST, "");
                            zap_local_user(user->con, "Someone else is logging in as you");
                            /* dont return, continue processing con's login */
                        }
                        else /* user->con is remote */
                        {
                            ASSERT(ISSERVER(user->con)); /* make sure they really are remote */
                            hash_remove(global.usersHash, user->nick); /* remove the user from ourselves */
                            /* dont return, continue processing con's login */
                        }
                    }
                    else
                    {
                        /* tell them they connected too soon and dump con */
                        /*
                        send_cmd(con, MSG_SERVER_ERROR, "Connecting too fast (wait %d s)", (int)(global.ghost_kill_timer + user->connected) - global.current_time);
                        destroy_connection(con);
                        * let's use ibl_kill for this */
                        ibl_kill(con, MSG_SERVER_ERROR, "Connecting too fast");
                        return;
                    }
                }
                else /* ip != or !allow_dynamic_ghosts */
                {
                    /* send message that the nick is already active and kill con */
                    send_cmd(con, MSG_SERVER_ERROR, "%s is already active", user->nick);
                    destroy_connection(con);
                    return;
                }

            }
            else /* we are NOT killing ghosts */
            {
                /* send a message to con that they are already active and kill con */
                send_cmd(con, MSG_SERVER_ERROR, "%s is already active", user->nick);
                destroy_connection(con);
                return;
            }
        }
        else /* connection is coming from another server */
        {
            ASSERT(ISSERVER(con)); /* make sure they really are from elsewhere */
            if(ISSERVER(user->con) && list_count(global.serversList) < 2) /* if known user is remote and i am a leaf */
            {
                /* we should never get here, if we did, something is wrong with my global.usersHash */
                /* let the mods know */
                notify_mods(ERROR_MODE, "login.c: something wrong: nick: %s known: %s new: %s", user->nick, user->server, av[8]);
                /* and let's log this too */
                log_message_level(LOG_LEVEL_ERROR, "login.c: something wrong: nick: %s known: %s new: %s", user->nick, user->server, av[8]);
                /* im going to blindly remove the one i thought i knew of and finish adding the new one i was just told of */
                hash_remove(global.usersHash, user->nick);
                /* no return, drop thru and finish adding con to global.usersHash */
            }
            else
            {

                if(atoi(av[6]) == user->connected)
                {
                    /* what to do, what to do, they both connected at the same time 
                    *  seeing the other server that will be processing this will hit this section too 
                    *  let's kill them both */
                    /* once for user->con */
                    notify_mods(KILLLOG_MODE, "Server %s killed %s: nick collision (%s %s) (connected=)", global.serverName, user->nick, av[8], user->server);
                    pass_message_args(user->con, MSG_CLIENT_KILL, ":%s %s \"nick collision (%s %s) (connected=)\"", global.serverName, user->nick, av[8], user->server);
                    if(ISUSER(user->con)) /* user->con is local to me */
                    {
                        /* kill the local user */
                        zap_local_user(user->con, "Someone else is logging in as you (connected=)");
                    }
                    else /* user->con is remote */
                    {
                        ASSERT(ISSERVER(user->con)); /* make sure they really are remote */
                        hash_remove(global.usersHash, user->nick); /* remove the user from ourselves */
                    }
                    /* and again for con */
                    send_cmd(con, MSG_CLIENT_KILL, ":%s %s \"nick collision (connected=)\"", global.serverName, av[0]);
                    return; /* bail out */
                }
                else 
                {
                    if(atoi(av[6]) < user->connected) /* con is older than user->con */
                    {
                        /* kill user->con as they are younger */
                        /* this kill needs to go to all servers BUT con */
                        notify_mods(KILLLOG_MODE, "Server %s killed %s: nick collision (%s %s) (connected<)", global.serverName, user->nick, av[8], user->server);
                        pass_message_args(con, MSG_CLIENT_KILL, ":%s %s \"nick collision (%s %s) (connected<)\"", global.serverName, user->nick, av[8], user->server);
                        if(ISUSER(user->con)) /* user->con is local to me */
                        {
                            /* kill the local user */
                            zap_local_user(user->con, "Someone else is logging in as you (connected<)");
                        }
                        else /* user->con is remote */
                        {
                            ASSERT(ISSERVER(user->con)); /* make sure they really are remote */
                            hash_remove(global.usersHash, user->nick); /* remove the user from ourselves */
                        }
                        /* dont return, continue processing this con's login */
                    }
                    else /* con is younger than user->con */
                    {
                        /* kill con as they are younger */
                        /* this kill has to go back to con and only con (where they came from) to bump them off */
                        send_cmd(con, MSG_CLIENT_KILL, ":%s %s \"nick collision (%s %s)(connected>)\"", global.serverName, user->nick, av[8], user->server);
                        /* 
                        * need to send something back to con to let them know of user->con
                        * use user->* as it should be the correct information...
                        */
                        send_cmd(con, MSG_CLIENT_LOGIN, "%s %s %hu \"%s\" \"%u\" %s %u %u %s %hu", user->nick, av[1], user->port, user->clientinfo, user->speed,
#if EMAIL
                            db ? db->email : "unknown",
#else
                            "unknown",
#endif /* EMAIL */
                            user->connected, user->ip, user->server, user->conport);
                        /* need to add the user back into the channels the client thinks it is on */
                        for (chan_list = user->channels; chan_list; chan_list = chan_list->next)
                        {  
                            chan = chan_list->data;
                            send_cmd(con, MSG_CLIENT_JOIN, ":%s %s", user->nick, chan->name);
                        }
                        return; /* dont further process, all taken care of */
                    }
                }
            }
        }
    } /* user already logged in check */
    /* we need to do a sanity check here
    *  if we can find in global.usersHash the nick of the logging in user, there is a problem
    */
    user = hash_lookup(global.usersHash, av[0]);
    if(user)
    {
        notify_mods(ERROR_MODE, "login.c: after ghost code, still see user: %s there is something WRONG!!!", av[0]);
        log_message_level(LOG_LEVEL_ERROR, "login.c: after ghost code, still see user: %s there is something WRONG!!!", av[0]);
        if(ISUNKNOWN(con))
        {
            destroy_connection(con);
            return;
        }
    }

    /* bypass restrictions for privileged users */ 
    if(!db || db->level < LEVEL_MODERATOR) 
    {
        if( db ? (~db->flags & ON_FRIEND) : 1 ) 
        {
            /* check for max clones (global).  use >= for comparison since we 
            * are not counting the current connection
            */
            clone_count = check_class(con, info);
            if(clone_count) 
            {
				if(ISUNKNOWN(con)) //count local only...
					stats.login_ce_clone++;
                log_message_level( LOG_LEVEL_DEBUG, "login: clones detected from %s [%d]", my_ntoa(BSWAP32(ip)), clone_count);
                if(ISUNKNOWN(con)) 
                {
                    send_cmd(con, MSG_SERVER_ERROR, "Exceeded maximum connections");
                    destroy_connection(con);
                } 
                else 
                {
                    kill_client(con, av[0], "Exceeded maximum connections");
                }
                return;
            }

        }
    }

    if(tag == MSG_CLIENT_LOGIN_REGISTER)
    {
        /* check to make sure the client isn't registering nicknames too
        * fast.
        */
        if(global.registerInterval > 0 && (global.current_time - info->last_register < global.registerInterval))
        {
            /* client is attempting to register nicks too fast */
            log_message_level( LOG_LEVEL_LOGIN, "login: %s is registering nicks too fast", my_ntoa(BSWAP32(ip)));
            send_cmd(con, MSG_SERVER_ERROR, "reregistering too fast");
            destroy_connection(con);
            return;
        }

        /* create the registration entry now */
        ASSERT(db == 0);
        db = BlockHeapAlloc(userdb_heap); /* CALLOC(1, sizeof(USERDB)); */
        if(db)
        {
            memset(db, 0, sizeof(USERDB));
            strncpy(db->nick, av[0], sizeof(db->nick) - 1);
            db->nick[sizeof(db->nick) - 1] = 0;
            tmppass = generate_pass(av[1]);
            strncpy(db->password, tmppass, sizeof(db->password) - 1);
            db->password[sizeof(db->password) - 1] = 0;
            free(tmppass);
#if EMAIL
            if(ac > 5)
                db->email = STRDUP(av[5]);
            else
            {
                snprintf(Buf, sizeof(Buf), "anon@%s", global.serverName);
                db->email = STRDUP(Buf);
            }
#endif
        }
        if(!db
#if EMAIL
            || !db->email
#endif
            )
        {
            OUTOFMEMORY("login");
            if(con->class == CLASS_UNKNOWN)
                destroy_connection(con);
            userdb_free(db);
            return;
        }
        db->level = LEVEL_USER;
        db->created = global.current_time;
        db->lastSeen = global.current_time;
        if(hash_add(global.userDbHash , db->nick, db))
        {
            log_message_level(LOG_LEVEL_ERROR, "login: hash_add failed (ignored)");
            userdb_free(db);
            db = NULL;
        }

        /* update the timer for registration.  we wait until here so that
        * attempts to register existing nicks don't count against the client.
        * this timer is only to prevent a client from successfully
        * registering nicks too quickly.
        */
        info->last_register = global.current_time;
    }

    /* add clientstring statistics */
    clientinfo = hashlist_add(global.clientVersionHash, av[3], 0);

    user = BlockHeapAlloc(user_heap); /* CALLOC(1, sizeof(USER)); */
    if(user)
    {
        memset(user, 0, sizeof(USER));
#if ONAP_DEBUG
        user->magic = MAGIC_USER;
#endif
        user->nick = STRDUP(av[0]);
        /* if the client version string is too long, truncate it */
        if(global.maxClientString > 0 && strlen(av[3]) > (unsigned) global.maxClientString)
            *(av[3] + global.maxClientString) = 0;
        user->clientinfo = clientinfo->key;
        user->pass = STRDUP(av[1]);
    }
    if(!user || !user->nick || !user->pass)
    {
        OUTOFMEMORY("login");
        goto failed;
    }
    user->port = port;
    user->speed = speed;
    user->con = con;
    user->level = LEVEL_USER; /* default */
    user->ip = ip;
#ifdef USE_PROTNET     /* Added by winter_mute */
    user->desynced = 0;
#endif

    /* if this is a locally connected user, update our information */
    if(ISUNKNOWN(con))
    {
        /* save the ip address of this client */
        user->connected = global.current_time;
        user->local = 1;
        user->conport = con->port;
        user->server = global.serverName; /* NOTE: this is not malloc'd */
        con->uopt = BlockHeapAlloc(useropt_heap); /* CALLOC(1, sizeof(USEROPT)); */

        if(!con->uopt)
        {
            OUTOFMEMORY("login");
            goto failed;
        }
        memset(con->uopt, 0, sizeof(USEROPT));
        con->uopt->usermode = UserMode_int;
        con->user = user;
		con->class = CLASS_USER;
		/* send the login ack */
#ifdef CSC
		if( ac > 7 ) 
		{
			compress = atoi(av[7]);
			if(compress < 1 || compress > 9) 
			{
				log_message_level(LOG_LEVEL_ERROR | LOG_LEVEL_CLIENT, "login: invalid compression level %s for %s!%s", av[7], av[0], con->host);
				notify_mods(ERROR_MODE, "Invalid compression level %s for user %s", av[7], con->host);
				ibl_kill(con, MSG_SERVER_ERROR, "invalid compression level %d", compress);
				goto failed;
			}
			con->compress = compress;
#ifdef EMAIL
			if(db)
				send_cmd(con, MSG_SERVER_EMAIL, "\"%s\" %u", db->email, con->compress);
			else
#endif  /* EMAIL */
				send_cmd(con, MSG_SERVER_EMAIL, "\"anon@%s\" %u", global.serverName, con->compress);
			con->uopt->csc = con->compress;
			if(init_client_compress(con, con->uopt->csc) != 0)
			{
				log_message_level(LOG_LEVEL_ERROR | LOG_LEVEL_CLIENT, "login: init_client_compress failed for %s!%s", av[0], con->host);
				notify_mods(ERROR_MODE, "init_client_compress failed for %s!%s", av[0], con->host);
				goto failed;
			}
		} 
		else 
		{
			send_cmd(con, MSG_SERVER_EMAIL, "anon@%s", global.serverName);
		}
#else /* CSC */
#ifdef EMAIL
        if(db)
            send_cmd(con, MSG_SERVER_EMAIL, "\"%s\"", db->email);
        else
#endif /* EMAIL */
            send_cmd(con, MSG_SERVER_EMAIL, "\"anon@%s\"", global.serverName);
#endif /* CSC */

        user->tagCountHash = hash_init(257, (hash_destroy)TagCountFree);
        hash_set_hash_func(user->tagCountHash, hash_u_int, hash_compare_u_int);

        show_motd(con, 0, 0, NULL);
        server_stats(con, 0, 0, NULL);
    }
	else
	{
        ASSERT(ISSERVER(con));
        user->connected = atoi(av[6]);
        user->server = find_server(av[8]); /* just a ref, not malloc'd */
        user->conport = (unsigned short)atoi(av[9]);
    }

    if(hash_add(global.usersHash, user->nick, user))
    {
        log_message_level(LOG_LEVEL_ERROR, "login: hash_add failed (fatal)");
        goto failed;
    }
    /* Check for proxy usage. */
#ifdef HAVE_LIBPTHREAD
    if(ISUSER(con) && global.proxycheck)
    {
        log_message_level( LOG_LEVEL_DEBUG, "Checking proxy on connection.. (%s)", user->nick);
        ProxyCheck(user);
    }
/*    else
    {
        log_message_level( LOG_LEVEL_DEBUG, "Not checking proxy on connection..");
    }
*/
#endif
    /* keep track of the number of clients from each unique ip address.  we
    * use this to detect clones globally.
    */
    info->users++;

    /* Initialize the abuse-prevention counters */
    /* These tags are being used excessively by some annoying client */
    user->count218=0;
    user->count219=0;
    user->count700=0;
    user->count200=0;
    user->did640browse=0;

    /* pass this information to our peer servers */
    pass_message_args(con, MSG_CLIENT_LOGIN, "%s %s %s \"%s\" \"%s\" %s %u %u %s %hu", user->nick, av[1], av[2], av[3], av[4],
#if EMAIL
        db ? db->email : "unknown",
#else
        "unknown",
#endif /* EMAIL */
        user->connected, user->ip, user->server,
        user->conport);

    log_message_level( LOG_LEVEL_DEBUG, "login: %s!%s:%hu %s (%s:%hu:%hu)", user->nick, my_ntoa(BSWAP32(ip)), user->conport, av[3], user->server, get_local_port(user->con->fd), con->compress);
    if(db)
    {
        db->lastSeen = global.current_time;

        /* sync user->flags and db->flags */
        user->flags = db->flags; 

        /* this must come after the email ack or the win client gets confused */
        if(db->level != LEVEL_USER)
        {
            /* do this before setting the user level so this user is not
            notified twice */
            notify_mods(LEVELLOG_MODE, "Server %s set %s's user level to %s (%d)", global.serverName, user->nick, Levels[db->level], db->level);
            user->level = db->level;
            if(ISUSER(con))
            {
                /* notify users of their change in level */
                send_cmd(con, MSG_SERVER_NOSUCH, "Server %s set your user level to %s (%d).", global.serverName, Levels[user->level], user->level);
                if(user->level >= LEVEL_MODERATOR)
                {
                    LIST   *list = CALLOC(1, sizeof(LIST));

                    list->data = con;
                    global.modList = list_push(global.modList, list);
                }
            }
            /* ensure all servers are synched up.  use the timestamp here
            so that multiple servers all end up with the same value if
            they differ */
            pass_message_args(NULL, MSG_CLIENT_SETUSERLEVEL, ":%s %s %s", global.serverName, user->nick, Levels[user->level]);
        }

        if(db->flags & ON_MUZZLED)
        {
            /* this will result in duplicate messages for the same user from
            each server, but its the only way to guarantee that the user
            is muzzled upon login */
            pass_message_args(NULL, MSG_CLIENT_MUZZLE, ":%s %s \"quit while muzzled\"", global.serverName, user->nick);
            if(ISUSER(con))
                send_cmd(con, MSG_SERVER_NOSUCH, "You have been muzzled by server %s: quit while muzzled", global.serverName);
            notify_mods(MUZZLELOG_MODE, "Server %s has muzzled %s: quit while muzzled", global.serverName, user->nick);
        }
        if(db->flags & ON_FRIEND)
        {
            if(ISUSER(con))
            {
                /* sync friend status with other servers */
                pass_message_args(NULL, MSG_CLIENT_USERFLAGS, ":%s %s %s", global.serverName, user->nick, "Friend");
                send_cmd(con, MSG_SERVER_NOSUCH, "Your userflags are set to FRIEND by %s", global.serverName);
            }
        }
    }

    /* check the global hotlist to see if there are any users waiting to be
    informed of this user signing on */
    for (list = hashlist_lookup(global.hotlistHash, user->nick); list; list = list->next)
    {
        ASSERT(validate_connection(list->data));
        send_cmd(list->data, MSG_SERVER_USER_SIGNON, "%s %d", user->nick, user->speed);
    }
    return;

failed:
    /* clean up anything we allocated here */
    if(!ISSERVER(con))
        destroy_connection(con);
    if(user)
    {
        if(user->nick)
            FREE(user->nick);
        if(user->pass)
            FREE(user->pass);
        if(user->server)
            FREE(user->server);
		BlockHeapFree(user_heap, user); /* FREE(user); */
    }
}

/* check to see if a nick is already registered */
/* 7 <nick> */
HANDLER(register_nick)
{
    USERDB *db;

    (void) tag;
    (void) len;
    ASSERT(validate_connection(con));
    if(con->class != CLASS_UNKNOWN)
    {
        log_message_level( LOG_LEVEL_LOGIN, "register_nick: command received after registration");
        send_cmd(con, MSG_SERVER_NOSUCH, "You are already logged in.");
        return;
    }
    db = hash_lookup(global.userDbHash , pkt);
    if(db)
    {
        send_cmd(con, MSG_SERVER_REGISTER_FAIL, "");
        return;
    }
    if(invalid_nick(pkt))
    {
		if(glob_match("*trade*", pkt))
		{  
			send_cmd(con, MSG_SERVER_BAD_NICK, "This is NOT a trading post, BUZZ OFF!!");
			log_message_level(LOG_LEVEL_ERROR, "login: register_nick: invalid nick (*trade*): %s", pkt);
		}
		else
            send_cmd(con, MSG_SERVER_BAD_NICK, "");
    }
    else
        send_cmd(con, MSG_SERVER_REGISTER_OK, "");
}

/* 10114 :<server> <nick> <password> <level> <email> <created> */
HANDLER(reginfo)
{
    char   *server;
    char   *fields[6];
    USERDB *db;
    int  level;
    int  ac = -1;

    (void) tag;
    (void) len;
    ASSERT(validate_connection(con));
    CHECK_SERVER_CLASS("reginfo");

    if(*pkt != ':')
    {
        log_message_level(LOG_LEVEL_ERROR, "reginfo: message does not begin with :");
        return;
    }
    pkt++;
    server = next_arg(&pkt);
    if(pkt)
        ac = split_line(fields, sizeof(fields) / sizeof(char *), pkt);

    if(ac < 5)
    {
        log_message_level(LOG_LEVEL_ERROR, "reginfo: wrong number of fields");
        return;
    }
    /* look up any entry we have for this user */
    db = hash_lookup(global.userDbHash , pkt);
    if(db)
    {
        /* check the timestamp to see if this is more recent than what
        * we have
        */
        if(atol(fields[4]) > db->created)
        {
            /* our record was created first, notify peers */
            log_message_level(LOG_LEVEL_ERROR, "reginfo: stale reginfo received from %s", server);
            sync_reginfo(db);
            return;
        }
        /* update our record */
        db->password[0] = 0;
#if EMAIL
        FREE(db->email);
#endif
    }
    else
    {
        if(invalid_nick(fields[0]))
        {
            log_message_level(LOG_LEVEL_ERROR, "reginfo: received invalid nickname");
            return;
        }
        db = BlockHeapAlloc(userdb_heap); /* CALLOC(1, sizeof(USERDB)); */
        if(db)
        {
            memset(db, 0, sizeof(USERDB));
            strncpy(db->nick, fields[0], sizeof(db->nick) - 1);
            db->nick[ sizeof(db->nick) - 1] = 0;
        }
		else
        {
            OUTOFMEMORY("reginfo");
            if(db)
                BlockHeapFree(userdb_heap, db); /* FREE(db); */
            return;
        }
        hash_add(global.userDbHash , db->nick, db);
        }
        level = get_level(fields[3]);
        if(level == -1)
        {
            log_message_level(LOG_LEVEL_ERROR, "reginfo: invalid level %s", fields[3]);
            level = LEVEL_USER; /* reset to something reasonable */
        }

        pass_message_args(con, tag, ":%s %s %s %s %s %s %s", server, fields[0], fields[1], fields[2], Levels[level], fields[4], (ac > 5) ? fields[5] : "0");

        /* this is already the MD5-hashed password, just copy it */
        strncpy(db->password, fields[1], sizeof(db->password) - 1);
        db->password[sizeof(db->password) - 1] = 0;
#if EMAIL
        db->email = STRDUP(fields[2]);
        if(!db->email)
        {
            OUTOFMEMORY("reginfo");
            return;
        }
#endif
        db->level = level;
        db->created = atol(fields[4]);
}

/* 10200 [ :<sender> ] <user> <pass> <email> [ <level> ]
admin command to force registration of a nickname */
HANDLER(register_user)
{
    USER   *sender;
    int  ac = -1, level;
    char   *av[4];
    char   *sender_name;
    USERDB *db;
    char   *tmppass;

    (void) len;
    ASSERT(validate_connection(con));
    if(pop_user_server(con, tag, &pkt, &sender_name, &sender))
        return;
    if(sender && sender->level < LEVEL_ADMIN)
    {
        permission_denied(con);
        return;
    }
    if(pkt)
        ac = split_line(av, FIELDS(av), pkt);
    if(ac < 3)
    {
        unparsable(con);
        return;
    }
    if(invalid_nick(av[0]))
    {
        log_message_level( LOG_LEVEL_LOGIN, "login: register_user: invalid nick: %s %s", av[0], my_ntoa(BSWAP32(sender->ip)));
        invalid_nick_msg(con);
        return;
    }
    /* if the user level was specified do some security checks */
    if(ac > 3)
    {
        level = get_level(av[3]);
        /* check for a valid level */
        if(level == -1)
        {
            if(ISUSER(con))
                send_cmd(con, MSG_SERVER_NOSUCH, "Invalid level");
            return;
        }
        /* check that the user has permission to create a user of this level */
        if(sender && sender->level < LEVEL_ELITE && level >= (int)sender->level)
        {
            permission_denied(con);
            return;
        }
    }
    else
        level = LEVEL_USER; /* default */

    /* first check to make sure this user is not already registered */
    if(hash_lookup(global.userDbHash , av[0]))
    {
        if(sender)
            send_user(sender, MSG_SERVER_NOSUCH, "[%s] %s is already registered", global.serverName, av[0]);
        return;
    }

    /* pass the plain text password here */
    pass_message_args(con, tag, ":%s %s %s %s %s", sender_name, av[0], av[1], av[2], ac > 3 ? av[3] : "");

    db = BlockHeapAlloc(userdb_heap); /* CALLOC(1, sizeof(USERDB)); */
    if(!db)
    {
        OUTOFMEMORY("register_user");
        return;
    }
    memset(db, 0, sizeof(USERDB));
    strncpy(db->nick, av[0], sizeof(db->nick) - 1);
    db->nick[sizeof(db->nick) - 1] = 0;
    tmppass = generate_pass(av[1]);
    strncpy(db->password, tmppass, sizeof(db->password) - 1);
    db->password[sizeof(db->password) - 1] = 0;
    free(tmppass);
#if EMAIL
    db->email = STRDUP(av[2]);
    if(!db->email)
    {
        OUTOFMEMORY("register_user");
        BlockHeapFree(userdb_heap, db); /* FREE(db); */
        return;
    }
#endif
    db->level = level;
    db->created = global.current_time;
    db->lastSeen = global.current_time;
    hash_add(global.userDbHash , db->nick, db);

    notify_mods(CHANGELOG_MODE, "%s registered nickname %s (%s)",sender_name, db->nick, Levels[db->level]);
}

/* 11 <user> <password>
check password */
HANDLER(check_password)
{
    char   *nick;

    (void) tag;
    (void) len;
    ASSERT(validate_connection(con));
    ASSERT(con->class == CLASS_UNKNOWN);
    nick = next_arg(&pkt);
    if(!nick)
    {
        unparsable(con);
        return;
    }
    if(!pkt)
    {
        send_cmd(con, MSG_SERVER_NOSUCH,
            "check password failed: missing password");
        return;
    }

    /* Log the attempt to check the password so that a tracking of abusers is possible... */
    if(ISUSER(con))
    {
        log_message_level(LOG_LEVEL_ERROR | LOG_LEVEL_SECURITY | LOG_LEVEL_CLIENT, "check_password: nick=%s, ip=%s, client=%s tag=%d, data=%s",
            con->user->nick, my_ntoa(BSWAP32(con->user->ip)), ISUSER(con) ? con->user->clientinfo : "(unknown)", tag, pkt);
    }
}

/* stub handler for numerics we just ignore */
HANDLER(ignore_command)
{
    ASSERT(validate_connection(con));
    (void) tag;
    (void) len;
    (void) pkt;
    (void) con;
    /* just ignore this message for now */
}

void ip_info_free(ip_info_t *info)
{
    FREE(info);
}

void TagCountFree(tag_count_t *info)
{
    FREE(info);
}

static void cleanup_ip_info_cb(ip_info_t *info, void *unused)
{
    (void) unused;
    if(info->users == 0 &&
        (global.current_time - info->last_connect > global.loginInterval) &&
        (global.current_time - info->last_register > global.registerInterval))
        hash_remove(global.clonesHash, (void *) info->ip);
}

/* this function is periodically called to remove stale info from the
* clone table. if there are no users from this ip logged in and the
* last connect is older than minimum allowed, we can safely remove the
* entry from the list
*/
void cleanup_ip_info(void)
{
    hash_foreach(global.clonesHash, (hash_callback_t) cleanup_ip_info_cb, NULL);
    log_message_level(LOG_LEVEL_DEBUG, "cleanup_ip_info: %d addresses in the table", global.clonesHash->dbsize);
}
