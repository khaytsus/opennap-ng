/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
This is free software distributed under the terms of the
GNU Public License.

$Id: server_login.c 434 2006-09-03 17:48:47Z reech $ */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <limits.h>
#include <time.h>
#include "opennap.h"
#include "debug.h"
#include "md5.h"

/* process a request to establish a peer server connection */
/* <name> <nonce> <compression> */
HANDLER(server_login)
{
    char   *fields[3];
    char    hash[33];
    unsigned int ip;
    struct md5_ctx md;
    int     compress;
    server_auth_t *auth;

    (void) tag;
    (void) len;
    ASSERT(validate_connection(con));
    if(con->class != CLASS_UNKNOWN)
    {
        send_cmd(con, MSG_SERVER_ERROR, "reregistration is not supported");
        destroy_connection(con);
        return;
    }

    if(split_line(fields, sizeof(fields) / sizeof(char *), pkt) != 3)
    {
        log_message_level(LOG_LEVEL_ERROR, "server_login: wrong number of fields");
        send_cmd(con, MSG_SERVER_ERROR, "link failed: invalid parameters");
        destroy_connection(con);
        return;
    }

    log_message_level(LOG_LEVEL_SERVER, "server_login: request from %s (%s)", fields[0], con->host);

    /* check to see if this server is already linked */
    if(is_linked(fields[0]))
    {
        log_message_level(LOG_LEVEL_SERVER, "server_login: %s is already linked", fields[0]);
        notify_mods(SERVERLOG_MODE, "Server %s link failed: already linked", fields[0]);
        send_cmd(con, MSG_SERVER_ERROR, "link failed: already linked");
        destroy_connection(con);
        return;
    }

    auth = find_server_auth(fields[0]);
    if(!auth)
    {
        /* no permission to link */
        log_message_level(LOG_LEVEL_SERVER, "server_login: %s is not in servers file", fields[0]);
        notify_mods(SERVERLOG_MODE, "Server %s link failed: not in servers file", fields[0]);
        send_cmd(con, MSG_SERVER_ERROR, "link failed: not in servers file");
        destroy_connection(con);
        return;
    }

    /* if an alias for this server is given, don't let it link unless its
    * reporting its name as the alias instead of the real name
    */
    if(auth->alias && strcasecmp(auth->alias, fields[0]))
    {
        /* warn the local mods+ */
        notify_mods(SERVERLOG_MODE, "Server %s link failed: must use alias", auth->alias);
        /* notify the peer server why we refused to link */
        send_cmd(con, MSG_SERVER_ERROR, "link failed: you must set your server_name to %s", auth->alias);
        destroy_connection(con);
        return;
    }

    /* make sure this connection is coming from where they say they are */
    /* TODO: make this nonblocking for the rest of the server */
    ip = lookup_ip(auth->name);

    /* con->ip is little-endian, so we need to convert it */
    if(ip != BSWAP32(con->ip))
    {
        char    tmp[sizeof("xxx.xxx.xxx.xxx")];

        /* inet_ntoa() uses a static buffer, so we need to copy the first
        * call so it doesn't get clobbered
        */
        strfcpy(tmp, my_ntoa(BSWAP32(con->ip)), sizeof(tmp));
        log_message_level(LOG_LEVEL_SERVER, "server_login: %s(%s) does not match %s(%s)", con->host, tmp, fields[0], my_ntoa(ip));
        send_cmd(con, MSG_SERVER_ERROR, "link failed: IP address does not match %s", fields[0]);
        notify_mods(SERVERLOG_MODE, "Server %s link failed: %s != %s", fields[0], fields[0], my_ntoa(BSWAP32(con->ip)));
        destroy_connection(con);
        return;
    }

    /* if the peer server connected to us we will just have their ip address
    * as the host, clear that and use the nickname or real dns name as
    * defined by the servers file.
    */
    FREE(con->host);
    con->host = STRDUP(auth->alias ? auth->alias : auth->name);

    compress = atoi(fields[2]);
    if(compress < 0 || compress > 9)
    {
        log_message_level(LOG_LEVEL_SERVER, "server_login: invalid compression level %s", fields[2]);
        notify_mods(SERVERLOG_MODE,"Server %s link failed: invalid compression level %s", con->host, fields[2]);
        send_cmd(con, MSG_SERVER_ERROR, "invalid compression level %d", compress);
        destroy_connection(con);
        return;
    }
    con->compress = (compress < global.compressionLevel) ? compress : global.compressionLevel;

    /* notify local admins of the connection request */
    notify_mods(SERVERLOG_MODE, "Server %s requested link", con->host);

    /* if this is a new request, set up the authentication info now */
    if(!con->server_login)
    {
        con->server_login = 1;
        if((con->opt.auth = CALLOC(1, sizeof(AUTH))) == 0)
        {
            OUTOFMEMORY("server_login");
            destroy_connection(con);
            return;
        }

        if((con->opt.auth->nonce = generate_nonce()) == NULL)
        {
            log_message_level(LOG_LEVEL_SERVER, "server_login: failed to generate nonce");
            send_cmd(con, MSG_SERVER_ERROR, "unable to generate nonce");
            destroy_connection(con);
            return;
        }

        /* respond with our own login request */
        send_cmd(con, MSG_SERVER_LOGIN, "%s %s %d", global.serverName, con->opt.auth->nonce, con->compress);
    }

    con->opt.auth->sendernonce = STRDUP(fields[1]);
    if(!con->opt.auth->sendernonce)
    {
        OUTOFMEMORY("server_login");
        destroy_connection(con);
        return;
    }

    /* send our challenge response */
    /* hash the peers nonce, our nonce and then our password */
    md5_init_ctx(&md);
    md5_process_bytes(con->opt.auth->sendernonce, strlen(con->opt.auth->sendernonce), &md);
    md5_process_bytes(con->opt.auth->nonce, strlen(con->opt.auth->nonce), &md);
    md5_process_bytes(auth->my_pass, strlen(auth->my_pass), &md);
    md5_finish_ctx(&md, hash);
    expand_hex(hash, 16);
    hash[32] = 0;

    /* send the response */
    send_cmd(con, MSG_SERVER_LOGIN_ACK, hash);

    log_message_level(LOG_LEVEL_SERVER, "server_login: ACK for %s sent", con->host);
}

HANDLER(server_login_ack)
{
    struct md5_ctx md5;
    char    hash[33];
    LIST   *list;
    server_auth_t *auth;

    (void) tag;
    (void) len;
    ASSERT(validate_connection(con));

    if(con->class != CLASS_UNKNOWN)
    {
        send_cmd(con, MSG_SERVER_NOSUCH, "reregistration is not supported");
        return;
    }

    if(!con->server_login)
    {
        send_cmd(con, MSG_SERVER_ERROR, "You must login first");
        destroy_connection(con);
        return;
    }

    /* look up the entry in our peer servers database */
    auth = find_server_auth(con->host);
    /* this shouldn't happen, but lets be on the safe side */
    if(!auth)
    {
        send_cmd(con, MSG_SERVER_ERROR, "link failed: you are not authorized");
        destroy_connection(con);
        return;
    }

    /* check the peers challenge response */
    md5_init_ctx(&md5);
    md5_process_bytes(con->opt.auth->nonce, strlen(con->opt.auth->nonce), &md5);
    md5_process_bytes(con->opt.auth->sendernonce, strlen(con->opt.auth->sendernonce), &md5);
    /* password for them */
    md5_process_bytes(auth->their_pass, strlen(auth->their_pass), &md5);
    md5_finish_ctx(&md5, hash);
    expand_hex(hash, 16);
    hash[32] = 0;

    if(strcmp(hash, pkt) != 0)
    {
        log_message_level(LOG_LEVEL_SERVER, "server_login(): invalid password for %s", con->host);
        notify_mods(SERVERLOG_MODE, "Failed server login from %s: invalid password", con->host);
        send_cmd(con, MSG_SERVER_ERROR, "link failed: bad password");
        destroy_connection(con);
        return;
    }

    /* done with authentication, free resources */
    FREE(con->opt.auth->nonce);
    FREE(con->opt.auth->sendernonce);
    FREE(con->opt.auth);
    con->server_login = 0;

    /* set the recv/send buffer length to 16k for server links */
    set_tcp_buffer_len(con->fd, 16384);

    /* put this connection in the shortcut list to the server conections */
    list = CALLOC(1, sizeof(LIST));
    if(!list)
    {
        OUTOFMEMORY("server_login_ack");
        destroy_connection(con);
        return;
    }

    list->data = con;
    global.serversList = list_push(global.serversList, list);

    con->class = CLASS_SERVER;
    con->opt.server = CALLOC(1, sizeof(SERVER));
    con->sopt->tagCountHash = hash_init(257, (hash_destroy)TagCountFree);
    hash_set_hash_func(con->sopt->tagCountHash, hash_u_int, hash_compare_u_int);

    /* set up the compression handlers for this connection */
    if(init_compress(con, con->compress) != 0)
    {
        log_message_level(LOG_LEVEL_ERROR | LOG_LEVEL_SERVER, "server_login: init_compress failed (%s)", con->host);
        destroy_connection(con);
        return;
    }
    log_message_level(LOG_LEVEL_SERVER, "server_login_ack(): server %s has joined", con->host);

    notify_mods(SERVERLOG_MODE, "Server %s has joined", con->host);

    /* notify peer servers this server has joined the cluster */
    pass_message_args(con, MSG_SERVER_LINK_INFO, "%s %hu %s %hu 2", global.serverName, get_local_port(con->fd), con->host, con->port);

    /* synchronize our state with this server */
    synch_server(con);
}

/* 10019 <server> <port> <peer> <peerport> <hops>
* process remote server join message
*/
HANDLER(link_info)
{
    int     ac, port;
    char   *av[5];
    LIST   *list;
    LINK   *slink;

    ASSERT(validate_connection(con));
    CHECK_SERVER_CLASS("link_info");
    (void) len;
    ac = split_line(av, FIELDS(av), pkt);
    if(ac != 5)
    {
        log_message_level(LOG_LEVEL_ERROR, "link_info: wrong number of parameters");
        print_args(ac, av);
        return;
    }

    /* check the existing server link list to make sure this info looks ok.
    * the peer should not be listed as a peer to any other server.
    */
    for (list = global.serversList; list; list = list->next)
    {
        CONNECTION *p = list->data;

        if(!strcasecmp(p->host, av[2]))
        {
            log_message_level(LOG_LEVEL_ERROR, "link_info: %s is already linked locally", av[2]);
            return;
        }
    }

    /* check remote links */
    for (list = global.serverLinksList; list; list = list->next)
    {
        slink = list->data;
        if(!strcasecmp(slink->peer, av[2]))
        {
            log_message_level(LOG_LEVEL_ERROR, "link_info: %s is already listed as a peer to %s", av[2], slink->server);
            return;
        }
    }

    slink = CALLOC(1, sizeof(LINK));
    if(slink)
    {
        slink->server = STRDUP(av[0]);
        slink->peer = STRDUP(av[2]);
    }
    if(!slink || !slink->server || !slink->peer)
    {
        OUTOFMEMORY("link_info");
        goto error;
    }
    port = atoi(av[1]);
    if(port < 0 || port > 65535)
    {
        log_message_level(LOG_LEVEL_ERROR, "link_info: invalid port %d", port);
        port = 0;
    }
    slink->port = port;
    port = atoi(av[3]);
    if(port < 0 || port > 65535)
    {
        log_message_level(LOG_LEVEL_ERROR, "link_info: invalid port %d", port);
        port = 0;
    }
    slink->peerport = port;
    slink->hops = atoi(av[4]);
    if(slink->hops < 2)
    {
        log_message_level(LOG_LEVEL_ERROR, "link_info: invalid hop count %d", slink->hops);
        slink->hops = 2;    /* at least */
    }
    log_message_level(LOG_LEVEL_SERVER, "link_info: %s:%d (%d hops away) via %s:%d", slink->peer, slink->peerport, slink->hops, slink->server, slink->port);
    list = MALLOC(sizeof(LIST));
    if(!list)
    {
        OUTOFMEMORY("link_info");
        goto error;
    }
    list->data = slink;
    global.serverLinksList = list_push(global.serverLinksList, list);
    pass_message_args(con, tag, "%s %d %s %d %d", slink->server, slink->port, slink->peer, slink->peerport, slink->hops + 1);
    notify_mods(SERVERLOG_MODE, "Server %s has joined", slink->peer);
    return;
error:
    if(slink)
    {
        if(slink->server)
            FREE(slink->server);
        if(slink->peer)
            FREE(slink->peer);
        FREE(slink);
    }
}

/* recursively mark entries to reap */
static void mark_links(const char *host)
{
    LIST   *list = global.serverLinksList;
    LINK   *link;

    ASSERT(host != 0);
    for (; list; list = list->next)
    {
        link = list->data;
        ASSERT(link != 0);
        if(link->port != (unsigned short) -1 && link->peerport != (unsigned short) -1)
        {
            if(!strcasecmp(host, link->server))
            {
                link->port = -1;
                link->peerport = -1;
                /* mark servers connected to this peer */
                mark_links(link->peer);
            }
            else if(!strcasecmp(host, link->peer))
            {
                link->port = -1;
                link->peerport = -1;
            }
        }
    }
}

/* reap all server link info behind the server named by `host' */
void remove_links(const char *host)
{
    LIST  **list, *tmpList;
    LINK   *link;

    mark_links(host);
    list = &global.serverLinksList;
    while (*list)
    {
        link = (*list)->data;
        if(link->port == (unsigned short) -1 && link->peerport == (unsigned short) -1)
        {
            tmpList = *list;
            *list = (*list)->next;
            log_message_level(LOG_LEVEL_SERVER, "remove_links: removing link %s -> %s", link->server, link->peer);
            FREE(tmpList);
            FREE(link->server);
            FREE(link->peer);
            FREE(link);
            continue;
        }
        list = &(*list)->next;
    }
}

/* :<server> <time>
* check the time on the remote server to make sure our clocks are not
* too skewed for proper link
*/
HANDLER(time_check)
{
    char   *utc;
    int     delta;

    (void) tag;
    (void) len;
    CHECK_SERVER_CLASS("time_check");
    next_arg(&pkt);
    utc = next_arg(&pkt);
    /* refresh our time just in case it took awhile to get here */
    delta = time(&global.current_time) - atoi(utc);
    if(delta < 0)
        delta *= -1;        /* make positive */
    if(global.maxTimeDelta > 0)
    {
        if(delta > global.maxTimeDelta)
        {
            notify_mods(SERVERLOG_MODE, "Server %s clock skewed by %d seconds, link failed.", con->host, delta);
            send_cmd(con, MSG_SERVER_ERROR, "Clock skewed by %d seconds", delta);
            destroy_connection(con);
            return;
        }
    }
    if(global.warnTimeDelta > 0)
    {
        if(delta > global.warnTimeDelta)
        {
            notify_mods(SERVERLOG_MODE, "Server %s clock skewed by %d seconds", con->host, delta);
            send_cmd(con, MSG_SERVER_ERROR, "Clock skewed by %d seconds", delta);
        }
    }
}
