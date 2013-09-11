/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
This is free software distributed under the terms of the
GNU Public License.  See the file COPYING for details.

$Id: remove_connection.c 434 2006-09-03 17:48:47Z reech $ */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>
#ifndef WIN32
# include <unistd.h>
#endif
#include <stdlib.h>
#include "opennap.h"
#include "hashlist.h"
#include "debug.h"

static void server_split(USER * user, CONNECTION * con)
{
    ASSERT(validate_user(user));
    ASSERT(validate_connection(con));
    ASSERT(con->class == CLASS_SERVER);

    /* check to see if this user was behind the server that just split */
    if(user->con == con)
    {
        /* on split, we have to notify our peer servers that this user
        is no longer online */
        pass_message_args(con, MSG_CLIENT_QUIT, "%s", user->nick);
        /* remove the user from the hash table */
        hash_remove(global.usersHash, user->nick);
    }
}

/* free resources associated with CLASS_USER connection. this is broken out
here so that login() can call this directly to remove a "ghost" user and
allow the new connection to complete. */
void remove_user(CONNECTION * con)
{
    LIST   *u;

    ASSERT(ISUSER(con));

    if(con->user->level >= LEVEL_MODERATOR)
        global.modList = list_delete(global.modList, con);
    if(con->user->tagCountHash)
        free_hash(con->user->tagCountHash);

    /* this needs to be done before calling hash_remove() as the BlockHeap is pointed to via the datum itself */
    if(con->uopt->files)
    {
        log_message_level(LOG_LEVEL_ERROR, "user: %s(%d files), blockheap: size: %d, used: %d, free:%d", con->user->nick, con->user->shared, block_heap_get_size(con->uopt->files_heap), block_heap_get_used(con->uopt->files_heap), block_heap_get_free(con->uopt->files_heap));
        /* indirectly calls free_datum() */
        free_hash(con->uopt->files);
        BlockHeapDestroy(con->uopt->files_heap);
    }

    /* remove user from global list, calls free_user() indirectly */
    ASSERT(validate_user(con->user));
    hash_remove(global.usersHash, con->user->nick);

    /* if this user had hotlist entries, remove them from the lists */
    for (u = con->uopt->hotlist; u; u = u->next)
    {
        ASSERT(hashlist_validate(u->data));
        hashlist_remove(global.hotlistHash, ((hashlist_t *) u->data)->key, con);
    }

    list_free(con->uopt->hotlist, 0);
    list_free(con->uopt->ignore, free_pointer);


	/* sanity check */
	if(con->uopt->searches < 0)
		log_message_level(LOG_LEVEL_ERROR, "remove_user: ERROR, con->uopt->searches < 0!!!");

#ifdef CSC /* this needs to be done here and not in remove_connection as zap_local_user calls this directly */
	if(con->uopt->csc) 
	{
		finalize_client_compress(con->uopt);
		buffer_free(con->uopt->outbuf);
	}
#endif

	BlockHeapFree(useropt_heap, con->uopt); /* FREE(con->uopt); */
}

static void free_server_name(const char *s)
{
    LIST  **list = &global.serverNamesList;
    LIST   *tmp;

    for (; *list; list = &(*list)->next)
    {
        if(s == (*list)->data)
        {
            tmp = *list;
            *list = (*list)->next;
            FREE(tmp->data);
            FREE(tmp);
            break;
        }
    }
}

void remove_connection(CONNECTION * con)
{
    ASSERT(validate_connection(con));

    /* should have been properly shut down */
    if(con->fd != -1)
        log_message_level(LOG_LEVEL_ERROR, "remove_connection: ERROR, con->fd != -1");

    /* if this connection had any pending searches, cancel them */
    cancel_search(con);

    if(ISUSER(con))
    {
        remove_user(con);
    }
    else if(ISSERVER(con))
    {
        /* if we detect that a server has quit, we need to remove all users
        that were behind this server.  we do this by searching the User
        hash table for entries where the .serv member is this connection.
        we also need to send QUIT messages for each user to any other
        servers we have */

        /* first off, lets remove this server from the global.serversList list so
        that pass_message() doesnt try to send message back through this
        server (although we could just pass this connection to it and it
        would avoid sending it) */

        log_message_level(LOG_LEVEL_SERVER, "remove_connection: server split detected (%s)", con->host);
        if(!con->quit)
        {
            notify_mods(SERVERLOG_MODE, "Server %s has quit: EOF", con->host);
            /* notify our peers this server has quit */
            pass_message_args(con, MSG_CLIENT_DISCONNECT, ":%s %s \"EOF\"", global.serverName, con->host);

            /* if this server was linked to other servers, remove the
            * information we have on those links */
            remove_links(con->host);
        }

        global.serversList = list_delete(global.serversList, con);

        /* remove all users that were behind this server from the hash table.
        this should be an infrequent enough occurance than iterating the
        entire hash table does not need to be optimized the way we split
        out the server connections. */
        hash_foreach(global.usersHash, (hash_callback_t) server_split, con);

        finalize_compress (con->sopt);
        buffer_free(con->sopt->outbuf);
        if(con->sopt->tagCountHash)
            free_hash(con->sopt->tagCountHash);
        FREE(con->sopt);

        /* free the server name cache entry */
        free_server_name(con->host);
    }
    else
    {
        ASSERT(con->class == CLASS_UNKNOWN);
        if(con->server_login)
        {
            if(con->opt.auth)
            {
                if(con->opt.auth->nonce)
                    FREE(con->opt.auth->nonce);
                if(con->opt.auth->sendernonce)
                    FREE(con->opt.auth->sendernonce);
                FREE(con->opt.auth);
            }
        }
    }

    /* common data */
    if(con->host)
        FREE(con->host);
    buffer_free(con->sendbuf);
    buffer_free(con->recvbuf);

    /* temp fix to catch bad contexts */
    memset(con, 0xff, sizeof(CONNECTION));

    FREE(con);
}
