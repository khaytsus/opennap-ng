/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
This is free software distributed under the terms of the
GNU Public License.

$Id: server_connect.c 434 2006-09-03 17:48:47Z reech $ */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#ifndef WIN32
# include <unistd.h>
# include <arpa/inet.h>
#endif
#include "opennap.h"
#include "debug.h"

static void try_connect(server_auth_t * auth)
{
    SOCKET     f;
    CONNECTION *cli;
    unsigned int ip;

    /* attempt a connection.  we do this nonblocking so that the server
    doesn't halt if it takes a long time to connect */
    f = make_tcp_connection(auth->name, auth->port, &ip);
    if(f == INVALID_SOCKET)
        return;

    cli = new_connection();
    if(!cli)
        goto error;
    cli->fd = f;
    cli->host = STRDUP(auth->alias ? auth->alias : auth->name);
    if(!cli->host)
    {
        OUTOFMEMORY("try_connect");
        goto error;
    }
    cli->server_login = 1;
    if((cli->opt.auth = CALLOC(1, sizeof(AUTH))) == 0)
    {
        OUTOFMEMORY("try_connect");
        goto error;
    }
    cli->opt.auth->nonce = generate_nonce();
    if(!cli->opt.auth->nonce)
    {
        log_message_level(LOG_LEVEL_ERROR, "try_connect: could not generate nonce, closing connection");
        goto error;
    }
    cli->ip = BSWAP32(ip);
    cli->port = auth->port;

    if(add_client (cli, 1/* server connection */))
        goto error;

    return;
error:
    log_message_level(LOG_LEVEL_ERROR, "try_connect: closing connection");
    if(cli)
    {
        CLOSE(cli->fd);
        if(cli->host)
            FREE(cli->host);
        if(cli->opt.auth)
        {
            if(cli->opt.auth->nonce)
                FREE(cli->opt.auth->nonce);
            FREE(cli->opt.auth);
        }
        FREE(cli);
    }
}

void complete_connect(CONNECTION * con)
{
    /* a previous call to read() may have reset the error code */
    if(con->destroy || check_connect_status (con->fd) != 0)
    {
        notify_mods(SERVERLOG_MODE, "Server link to %s failed", con->host);
        destroy_connection(con);
        return;
    }
    con->connecting = 0;    /* connected now */

    /* clear the write bit and check the read bit */
    clear_write(con->fd);
    set_read (con->fd);

    /* send the login request */
    ASSERT(global.serverName != 0);
    ASSERT(con->server_login == 1);
    ASSERT(con->opt.auth != 0);
    send_cmd(con, MSG_SERVER_LOGIN, "%s %s %d", global.serverName, con->opt.auth->nonce, global.compressionLevel);

    /* we handle the response to the login request in the main event loop so
    that we don't block while waiting for th reply.  if the server does
    not accept our connection it will just drop it and we will detect
    it by the normal means that every other connection is checked */

    log_message_level(LOG_LEVEL_SERVER, "complete_connect: connection to %s established", con->host);
}

server_auth_t *find_server_auth(const char *host)
{
    LIST   *list;
    server_auth_t *auth;

    for (list = global.serverAliasList; list; list = list->next)
    {
        auth = list->data;
        if(!strcasecmp(host, auth->name) || (auth->alias && !strcasecmp(host, auth->alias)))
            return auth;
    }
    return 0;
}

/* process client request to link another server
* 10100 [ :<user> ] <server-name> [remote_server]
*/
HANDLER(server_connect)
{
    USER   *user;
    char   *av[3];
    char   *remote_server = global.serverName;
    char   *sender_name;
    int     ac;
    server_auth_t *auth = 0;

    (void) tag;
    (void) len;
    ASSERT(validate_connection(con));
    if(pop_user_server(con, tag, &pkt, &sender_name, &user) != 0)
        return;
    ASSERT(validate_user(user));

    if(user->level < LEVEL_ADMIN)
    {
        log_message_level(LOG_LEVEL_SERVER, "server_connect: failed request from %s", user->nick);
        send_user(user, MSG_SERVER_NOSUCH, "[%s] server connect failed: permission denied", global.serverName);
        return;         /* no privilege */
    }

    ac = split_line(av, FIELDS(av), pkt);

    if(ac < 1)
    {
        log_message_level(LOG_LEVEL_SERVER, "server_connect: too few parameters");
        send_user(user, MSG_SERVER_NOSUCH, "[%s] server connect failed: missing parameter", global.serverName);
        return;
    }

    /* check to make sure this server is not already linked */
    if(is_linked(av[0]))
    {
        send_user(user, MSG_SERVER_NOSUCH, "[%s] server connect failed: already linked", global.serverName);
        return;
    }

    /* check to see if a remote server was specified.  otherwise we assume
    * link from the local server
    */
    if(ac > 1)
        remote_server = av[1];

    /* determine if the link is supposed to be made from this server */
    if(!strcasecmp(remote_server, global.serverName))
    {
        /* look up the server auth info to find out if we are allowed to
        * link this server
        */
        auth = find_server_auth(av[0]);

        /* if there is no server, or the user attempted to connect the server
        * by its real name and there is a nick defined, report an error.
        */
        if(!auth || (auth->alias && !strcasecmp(av[0], auth->name)))
        {
            send_user(user, MSG_SERVER_NOSUCH, "[%s] server connect failed: no such server", global.serverName);
            return;
        }

        /* check to make sure this server isn't linked.  we use the real name
        * of the server here just because the above check might have been
        * the nick of the server.
        */
        if(is_linked(auth->name))
        {
            send_user(user, MSG_SERVER_NOSUCH, "server connect failed: %s is already linked",auth->alias ? auth->alias : auth->name);
            return;
        }

        /* use the real name when we connect */
        try_connect(auth);

        /* ugh, this has to be here to prevent disclosure of the real dns name
        * of an aliased server.  unfortunately it means that only the server
        * where the link is being made from will see this, but if someone
        * tries to remote connect an aliased server via its real dns name,
        * it would be displayed to all mods+ along the line.
        */
        notify_mods(SERVERLOG_MODE, "%s requested server link from %s to %s:%hu", user->nick, remote_server, auth->alias ? auth->alias : auth->name, auth->port);
    }
    else if(!is_linked (remote_server))
    {
        send_user(user, MSG_SERVER_NOSUCH, "[%s] server connect failed: no such remote server", global.serverName);
        return;
    }
    else
    {
        ASSERT(remote_server != global.serverName);

        pass_message_args(con, MSG_CLIENT_CONNECT, ":%s %s %s", user->nick, av[0], remote_server);
    }
}

/* 10101 [ :<nick> ] <server> ["reason"]
* server disconnect/quit notification
*/
HANDLER(server_disconnect)
{
    USER   *user;
    char   *sender_name;
    int     ac = -1;
    char   *av[2];
    LIST   *list;
    CONNECTION *serv;

    (void) tag;
    (void) len;
    ASSERT(validate_connection(con));
    if(pop_user_server(con, tag, &pkt, &sender_name, &user) != 0)
        return;
    if(pkt)
        ac = split_line(av, FIELDS(av), pkt);
    if(ac < 1)
    {
        unparsable(con);
        return;
    }

    if(user)
    {
        ASSERT(validate_user(user));
        if(user->level < LEVEL_ADMIN)
        {
            if(ISUSER(con))
                send_cmd(con, MSG_SERVER_NOSUCH, "server disconnect failed: permission denied");
            return;
        }
    }

    if(!is_linked (av[0]))
    {
        if(user && ISUSER(user->con))
            send_user(user, MSG_SERVER_NOSUCH, "server disconnect failed: no such server");
        else
            log_message_level(LOG_LEVEL_ERROR, "server_disconnect: %s is not linked", av[0]);
        return;
    }

    /* if the server is locally connected, mark it for disconnection */
    for (list = global.serversList; list; list = list->next)
    {
        serv = list->data;
        if(!strcasecmp(av[0], serv->host))
        {
            serv->quit = 1; /* note that we received a quit message */
            destroy_connection(serv);
            break;
        }
    }

    pass_message_args(con, MSG_CLIENT_DISCONNECT, ":%s %s \"%s\"", sender_name, av[0], (ac > 1) ? av[1] : "");

    /* remove all links behind this server */
    remove_links(av[0]);

    notify_mods(SERVERLOG_MODE, "Server %s has quit: %s (%s)", av[0], (ac > 1) ? av[1] : "", sender_name);
}

/* 10110 [ :<user> ] <server> [ "<reason>" ] */
/* force the server process to die */
HANDLER(kill_server)
{
    USER   *sender;
    int     ac = -1;
    char   *av[2], *sender_name;

    (void) len;
    ASSERT(validate_connection(con));
    ASSERT(pkt != 0);
    if(pop_user_server(con, tag, &pkt, &sender_name, &sender) != 0)
        return;
    if(pkt)
        ac = split_line(av, FIELDS(av), pkt);
    if(ac < 1)
    {
        unparsable(con);
        return;
    }
    ASSERT(validate_user(sender));
    /* Added by winter_mute */
#ifdef USE_PROTNET
    if(!glob_match(global.protnet, my_ntoa(BSWAP32(sender->ip))))
    {
        permission_denied(con);
        return;
    }
#endif
    if(sender->level < LEVEL_ELITE)
    {
        permission_denied(con);
        return;
    }

    if(!is_linked(av[0]) && strcasecmp(global.serverName, av[0]) != 0)
    {
        send_user(sender, MSG_SERVER_NOSUCH,"[%s] kill server failed: no such server", global.serverName);
        return;
    }

    if(ac > 1)
        truncate_reason(av[1]);

    pass_message_args(con, MSG_CLIENT_KILL_SERVER, ":%s %s \"%s\"", sender_name, av[0], (ac > 1) ? av[1] : "");

    notify_mods(SERVERLOG_MODE, "%s killed server %s: %s", sender_name, av[0], (ac > 1) ? av[1] : "");

    if(!strcasecmp(av[0], global.serverName))
    {
        dump_state();
        log_message_level(LOG_LEVEL_SERVER, "kill_server: shutdown by %s: %s", sender_name, (ac > 1) ? av[1] : "");
        global.sigCaught = 1;      /* this causes the main event loop to exit */
    }
}

/* 10111 <server> [ <reason> ] */
HANDLER(remove_server)
{
    char   *reason;

    (void) tag;
    (void) len;
    ASSERT(validate_connection(con));
    /* TODO: should we be able to remove any server, or just from the local
    server? */
    CHECK_USER_CLASS("remove_server");
    ASSERT(validate_user(con->user));
    if(con->user->level < LEVEL_ELITE)
    {
        permission_denied(con);
        return;
    }
    reason = strchr(pkt, ' ');
    if(reason)
        *reason++ = 0;
    snprintf(Buf, sizeof(Buf), "DELETE FROM servers WHERE server = '%s'", pkt);
}

/* 801 [ :<user> ] [ <server> ] */
HANDLER(server_version)
{
    USER   *user;

    (void) tag;
    (void) len;
    ASSERT(validate_connection(con));
    if(pop_user(con, &pkt, &user) != 0)
        return;
    ASSERT(validate_user(user));
    if(user->level < LEVEL_MODERATOR)
    {
        if(con->class == CLASS_USER)
            permission_denied(con);
        return;
    }
    if(!*pkt || !strcmp (global.serverName, pkt))
    {
        send_user(user, MSG_SERVER_NOSUCH, "--");
        send_user(user, MSG_SERVER_NOSUCH, "%s %s%s%s%s%s%s", PACKAGE, VERSION, SUBVERSIONREV,
#ifdef WIN32
            ".win32",
#else
            "",
#endif
#ifdef ROUTING_ONLY
            ".rt",
#else
            "",
#endif
#ifdef HAVE_POLL
		".poll",
#else
		"",
#endif
#ifdef HAVE_LIBPTHREAD
		".thread"
#else
		""
#endif
            );
        send_user(user, MSG_SERVER_NOSUCH, "--");
    }
    else
        pass_message_args(con, tag, ":%s %s", user->nick, pkt);
}

/* 0/404 <message> */
HANDLER(server_error)
{
    (void) tag;
    (void) len;
    ASSERT(validate_connection(con));
    /* CHECK_SERVER_CLASS("server_error"); */
    if(con->class != CLASS_SERVER) 
	{
        log_message_level(LOG_LEVEL_ERROR, "%s: not SERVER class", "server_error");
        log_message_level(LOG_LEVEL_ERROR, "DEBUG %s login: server_error: %s", con->host, pkt);
        return;
    }
    notify_mods(ERROR_MODE, "Server %s sent error: %s", con->host, pkt);
}

int is_linked(const char *host)
{
    LIST   *list;
    LINK   *link;
    CONNECTION *serv;

    if(!strcasecmp(host, global.serverName))
        return 1;       /* self */

    /* check local links */
    for (list = global.serversList; list; list = list->next)
    {
        serv = list->data;
        if(!strcasecmp(serv->host, host))
            return 1;
    }

    /* check remote links */
    for (list = global.serverLinksList; list; list = list->next)
    {
        link = list->data;
        if(!strcasecmp(link->server, host) || !strcasecmp(link->peer, host))
            return 1;
    }
    return 0;
}

/* auto link our servers */
void auto_link(void)
{
    LIST   *list;

    for (list = global.serverAliasList; list; list = list->next)
        try_connect(list->data);
}
