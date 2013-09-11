/* Copyright (C) 2000 edwards@bitchx.dimension6.com
This is free software distributed under the terms of the
GNU Public License.  See the file COPYING for details.

Modified by drscholl@users.sourceforge.net 2/25/2000.

$Id: server_usage.c 434 2006-09-03 17:48:47Z reech $ */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <time.h>
#include <string.h>
#include <stdlib.h>
#include "opennap.h"
#include "hashlist.h"
#include "debug.h"

/* 10115 [ :<user> ] [ <server> ] */
HANDLER(server_usage)
{
    USER   *user;
    int     numServers, delta;
    unsigned int mem_used;

    (void) tag;
    (void) len;
    ASSERT(validate_connection(con));
    CHECK_USER_CLASS("server_usage");
    if(pop_user(con, &pkt, &user) != 0)
        return;

    delta = global.current_time - global.last_click;

    if(delta == 0)
        delta = 1;
    if(!*pkt || !strcasecmp(pkt, global.serverName))
    {
        mem_used = MEMORY_USED;
        numServers = list_count(global.serversList);
        send_user(user, MSG_SERVER_USAGE_STATS, "%d %d %d %u %.0f %d %u %u %u %d %d %d %d %.0f %.0f %u",
            global.clients_num - numServers,
            numServers,
            global.usersHash->dbsize,
            global.fileLibCount,
            global.fileLibSize * 1024.0,
            global.channelHash->dbsize,
            global.serverStartTime,
            time(0) - global.serverStartTime,
            /* mem_usage works fine, however teknap by default only shows negative or 0 values. */
            stats.mem_usage?stats.mem_usage:mem_used,
            global.userDbHash ->dbsize,
            (int) (global.bytes_in / delta / 1024),
            (int) (global.bytes_out / delta / 1024),
            global.search_count / delta,
            global.total_bytes_in, 
            global.total_bytes_out,
            Pending_Searches);
    }
    else
        pass_message_args(con, tag, ":%s %s", user->nick, pkt);
}

static void client_version_cb(hashlist_t * v, CONNECTION * con)
{
    ASSERT(validate_connection(con));
    send_cmd(con, MSG_CLIENT_VERSION_STATS, "\"%s\" %d", v->key, v->count);
}

/* 10118
* print client version stats
*/
HANDLER(client_version_stats)
{
    (void) pkt;
    (void) len;
    ASSERT(validate_connection(con));
    CHECK_USER_CLASS("client_version_stats");
    /* because this potentially generates a lot of output, it is restricted
    * to mod+ to avoid abuse.
    */
    if(con->user->level < LEVEL_MODERATOR)
    {
        permission_denied(con);
        return;
    }
    hash_foreach(global.clientVersionHash, (hash_callback_t) client_version_cb, con);
    send_cmd(con, tag, "");    /* terminate the list */
}
