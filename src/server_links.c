/* Copyright (C) 2000 edwards@bitchx.dimension6.com
This is free software distributed under the terms of the
GNU Public License.  See the file COPYING for details.

Modified by drscholl@users.sourceforge.net 2/25/2000.

$Id: server_links.c 434 2006-09-03 17:48:47Z reech $ */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>
#ifndef WIN32
# include <sys/time.h>
# include <unistd.h>
#endif
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <stdio.h>
#include <ctype.h>
#include "opennap.h"
#include "debug.h"


/* 10112 */
/* process client request for server links */
HANDLER(server_links)
{
    LIST   *list;
    LINK   *slink;
    CONNECTION *serv;

    (void) tag;
    (void) len;
    (void) pkt;
    CHECK_USER_CLASS("server_links");
    ASSERT(validate_connection(con));

    /* first dump directly connected servers */
    for (list = global.serversList; list; list = list->next)
    {
        serv = list->data;
        send_cmd(con, MSG_SERVER_LINKS, "%s %hu %s %hu 1", global.serverName, get_local_port(serv->fd), serv->host, serv->port);
    }

    /* dump remote servers */
    for (list = global.serverLinksList; list; list = list->next)
    {
        slink = list->data;
        send_cmd(con, MSG_SERVER_LINKS, "%s %hu %s %hu %d", slink->server, slink->port, slink->peer, slink->peerport, slink->hops);
    }

    /* terminate the list */
    send_cmd(con, MSG_SERVER_LINKS, "");
}

/* 9998 [args] */
/* process client request to add a temporary server in servers file */
HANDLER(add_server)
{
    server_auth_t   *auth;
    char            *av[10];
    int              ac;
    LIST            *list;

    (void) tag;
    (void) len;
    (void) pkt;
    CHECK_USER_CLASS("add_server");
    ASSERT(validate_connection(con));

    if(con->user->level < LEVEL_ELITE
#if defined (USE_INVALID_CLIENTS) || defined (USE_INVALID_NICKS)
        || !glob_match(global.setServerNicks, con->user->nick)
#endif
        )
    {
        permission_denied(con);
        return;
    }

    ac = split_line(av, FIELDS(av), pkt);
    if(ac < 4)
	{
        send_cmd(con, MSG_SERVER_NOSUCH, "add_server: too few parameters (tag=%d)", tag);
        send_cmd(con, MSG_SERVER_NOSUCH, "add_server: use: add_server <hostname> <their_pass> <my_pass> <port> [alias]");
        return;
    }

    auth = CALLOC(1, sizeof(server_auth_t));

    auth->name = STRDUP( av[0] );
    auth->their_pass = STRDUP( av[1] );
    auth->my_pass = STRDUP( av[2] );

    auth->port = atoi( av[3] );
    if(auth->port < 1 || auth->port > 65535) 
	{
        send_cmd(con, MSG_SERVER_NOSUCH, "add_server: invalid port %d", auth->port);
        return;
    }

    if(ac >= 5)
	{
        auth->alias = STRDUP( av[4] );
    }

    log_message_level(LOG_LEVEL_SERVER, "add_server: %s %s %s %hu %s (%s)", auth->name, auth->their_pass, auth->my_pass, auth->port, auth->alias,con->user->nick);
    send_cmd(con, MSG_SERVER_NOSUCH, "add_server: server %s added succesfull.", auth->name);

    list = CALLOC(1, sizeof(LIST));
    list->data = auth;
    list->next = global.serverAliasList;
    global.serverAliasList = list;

}

/* 9999 */
/* process client request to list all servers in servers file */
HANDLER(list_server)
{
    LIST   *list;
    server_auth_t *auth;

    (void) tag;
    (void) len;
    (void) pkt;
    CHECK_USER_CLASS("list_server");
    ASSERT(validate_connection(con));

    if(con->user->level < LEVEL_ELITE
#if defined (USE_INVALID_CLIENTS) || defined (USE_INVALID_NICKS)
        || !glob_match(global.setServerNicks, con->user->nick)
#endif
        )
    {
        permission_denied(con);
        return;
    }
    log_message_level(LOG_LEVEL_SERVER, "list_server: request done by %s", con->user->nick);
    for (list = global.serverAliasList; list; list = list->next)
    {
        auth = list->data;
        send_cmd(con, MSG_SERVER_NOSUCH, "%s: %s %s %s %hu %s", global.serverName, auth->name, auth->their_pass, auth->my_pass, auth->port, auth->alias);
    }
}

/* 750 [ :<sender> ] <server> [args] */
HANDLER(ping_server)
{
    USER   *sender;
    char   *recip;
    char   *sender_name;

    (void) len;
    ASSERT(validate_connection(con));
    if(pop_user_server(con, tag, &pkt, &sender_name, &sender))
        return;
    recip = next_arg(&pkt);
    if(!recip || !strcasecmp(global.serverName, recip))
    {
        /* local server is being pinged */
        if(ISUSER(con)) 
		{
            /* local user issued request */
            send_cmd(con, tag, "%s %s", global.serverName, NONULL(pkt));
        } 
		else 
		{
            /* use inter-server pong message to reply */
            send_cmd(con, MSG_SERVER_SERVER_PONG, ":%s %s %s", global.serverName, sender_name, NONULL(pkt));
        }
    }
    else if(is_server (recip))
    {
        /* client request from remote server to remote server */
        pass_message_args(con, tag, ":%s %s %s", sender_name, recip, NONULL(pkt));
    }
    else if(ISUSER(con))
        send_cmd(con, MSG_SERVER_NOSUCH, "server ping failed: no such server");
    else
        log_message_level(LOG_LEVEL_ERROR, "ping_server: recv'd ping for unknown server %s from server %s (originated from %s)", recip, con->host, sender_name);
}

/* 10022 :<server> <recip> [args]
* server->server pong response
*/
HANDLER(server_pong)
{
    char   *server;
    char   *nick;
    USER   *user;

    CHECK_SERVER_CLASS("server_pong");

    (void) len;
    server = next_arg(&pkt);
    nick = next_arg(&pkt);
    if(!server || !nick)
    {
        log_message_level(LOG_LEVEL_ERROR, "server_pong: error, missing argument(s)");
        return;
    }
    server++;           /* skip the colon */

    user = hash_lookup(global.usersHash, nick);
    if(user)
    {
        if(ISUSER(user->con))
            /* user is local, deliver the response */
            send_cmd(user->con, MSG_CLIENT_PING_SERVER, "%s %s", server, NONULL(pkt));
        else
            /* route directly to the server that the user is behind */
            send_cmd(user->con, tag, ":%s %s %s", server, user->nick, NONULL(pkt));
    }
    /* recip is not a user, check to see if it's the local server */
    else if(!strcasecmp(global.serverName, nick))
    {
        char   *secs;
        char   *usecs;

        /* response is for the local server.  do lag checking  */
        secs = next_arg(&pkt);
        usecs = next_arg(&pkt);
        if(secs && usecs)
        {
            struct timeval tv;

            gettimeofday(&tv, NULL);

            notify_mods(PINGLOG_MODE, "Pong from server %s [%d millisecs]", server, (int) abs((((tv.tv_sec - atoi(secs)) * 1000000. + tv.tv_usec - atoi(usecs)) / 1000000.) * 1000.));

        }
        else
            log_message_level(LOG_LEVEL_ERROR, "server_pong: pong from %s with invalid args", con->host);
    }
    else if(is_server(nick))
        pass_message_args(con, tag, ":%s %s %s", server, nick, NONULL(pkt));
    else
        log_message_level(LOG_LEVEL_ERROR, "server_pong: unknown target %s from server %s", nick, con->host);
}

/* this currently doesn't do anything more than ping the peer servers and
* report the lag times to mods+
*/
void lag_detect (void *p)
{
    LIST   *list;
    CONNECTION *con;
    struct timeval tv;

    (void) p;           /* unused */

    if(global.serversList)
    {
        gettimeofday(&tv, 0);
        /* ping all of our peer servers */
        for (list = global.serversList; list; list = list->next)
        {
            con = list->data;
            send_cmd(con, MSG_CLIENT_PING_SERVER, ":%s %s %u %u", global.serverName, con->host, tv.tv_sec, tv.tv_usec);
        }
        notify_mods(PINGLOG_MODE, "Pinging all peer servers...");
    }
}

/* 10120
* ping all peer servers
*/
HANDLER(ping_all_servers)
{
    (void) tag;
    (void) len;
    (void) pkt;
    CHECK_USER_CLASS("ping_all_servers");
    if(con->user->level < LEVEL_MODERATOR)
    {
        send_cmd(con, MSG_SERVER_NOSUCH, "ping all servers failed: permission denied");
        return;
    }
    lag_detect(0);
}

void free_server_auth(server_auth_t * auth)
{
    FREE(auth->name);
    if(auth->alias)
        FREE(auth->alias);
    FREE(auth->their_pass);
    FREE(auth->my_pass);
    FREE(auth);
}

#ifdef WIN32
/* servers file reading problem fixed for win32, code from 0.44 */
/* added by spyder */
void load_server_auth(void)
{
    char    path[_POSIX_PATH_MAX];
    FILE   *fp;
    int     ac;
    char   *av[10];
    int     line = 0;
    server_auth_t *slink;
    LIST   *list;

    list_free(global.serverAliasList, (list_destroy_t) free_server_auth);
    global.serverAliasList = 0;

    snprintf(path, sizeof(path), "%s/servers", global.shareDir);
    fp = fopen(path, "r");
    if(!fp)
    {
        if(errno != ENOENT)
            logerr("load_server_auth_info", path);
        return;
    }
    log_message("load_server_auth_info: reading %s", path);
    Buf[sizeof(Buf) - 1] = 0;
    while (fgets(Buf, sizeof(Buf) - 1, fp))
    {
        line++;
        if(Buf[0] == '#' || isspace(Buf[0]))
            continue;
        ac = split_line(av, FIELDS(av), Buf);
        if(ac >= 3)
        {
            slink = CALLOC(1, sizeof(server_auth_t));
            slink->name = STRDUP(av[0]);
            slink->their_pass = STRDUP(av[1]);
            slink->my_pass = STRDUP(av[2]);
            if(ac >= 4)
            {
                slink->port = atoi(av[3]);
                if(slink->port < 1 || slink->port > 65535)
                {
                    log_message("load_server_auth_info: invalid port at line %d", line);
                    slink->port = 8888;
                }
                /* if a nickname for the server is given, save it so that
                * we can sheild the real dns name from the masses (used
                * for routing-only servers which we want to make pratically
                * invisible).
                */
                if(ac >= 5)
                    slink->alias = STRDUP(av[4]);
            }
            else
                slink->port = 8888;
            list = CALLOC(1, sizeof(LIST));
            list->data = slink;
            list->next = global.serverAliasList;
            global.serverAliasList = list;
        }
        else
            log_message("load_server_auth_info: too few parameters at line %d", line);
    }

    fclose(fp);
}
#else

void load_server_auth(void)
{
    char    path[_POSIX_PATH_MAX];
    int     fd;
    int     ac;
    char   *av[10];
    int     line = 0;
    server_auth_t *slink;
    LIST   *list;

    list_free(global.serverAliasList, (list_destroy_t) free_server_auth);
    global.serverAliasList = 0;

    snprintf(path, sizeof(path), "%s/servers", global.shareDir);
    if((fd = open(path, O_RDONLY))==-1)
    {
        if(errno != ENOENT)
            logerr("load_server_auth_info", path);
        return;
    }
    log_message_level(LOG_LEVEL_DEBUG, "load_server_auth_info: reading %s", path);
    Buf[sizeof(Buf) - 1] = 0;
    while (fake_fgets(Buf, sizeof(Buf) - 1, fd))
    {
        line++;
        if(Buf[0] == '#' || isspace((int)Buf[0]))
            continue;
        ac = split_line(av, FIELDS(av), Buf);
        if(ac >= 3)
        {
            slink = CALLOC(1, sizeof(server_auth_t));
            slink->name = STRDUP(av[0]);
            slink->their_pass = STRDUP(av[1]);
            slink->my_pass = STRDUP(av[2]);
            if(ac >= 4)
            {
                slink->port = atoi(av[3]);
                if(slink->port < 1 || slink->port > 65535)
                {
                    log_message_level(LOG_LEVEL_ERROR, "load_server_auth_info: invalid port at line %d", line);
                    slink->port = 8888;
                }
                /* if a nickname for the server is given, save it so that
                * we can sheild the real dns name from the masses (used
                * for routing-only servers which we want to make pratically
                * invisible).
                */
                if(ac >= 5)
                    slink->alias = STRDUP(av[4]);
            }
            else
                slink->port = 8888;
            list = CALLOC(1, sizeof(LIST));
            list->data = slink;
            list->next = global.serverAliasList;
            global.serverAliasList = list;
        }
        else
            log_message_level(LOG_LEVEL_ERROR, "load_server_auth_info: too few parameters at line %d", line);
    }

    close(fd);
}
#endif

