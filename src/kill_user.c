/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
This is free software distributed under the terms of the
GNU Public License.  See the file COPYING for details.

$Id: kill_user.c 434 2006-09-03 17:48:47Z reech $ */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/types.h>
#ifndef WIN32
# include <sys/socket.h>
# include <netinet/in.h>
# include <arpa/inet.h>
#endif
#include "opennap.h"
#include "debug.h"


/* request to kill (disconnect) a user */
/* [ :<nick> ] <user> [ "<reason>" ] */
HANDLER(kill_user)
{
    char   *av[2];
    int     ac = -1;
    USER   *sender, *user;
    char   *sender_name;

    (void) tag;
    (void) len;
    ASSERT(validate_connection(con));

    if(pop_user_server(con, tag, &pkt, &sender_name, &sender))
        return;
    if(pkt)
        ac = split_line(av, FIELDS(av), pkt);
    if(ac < 1)
    {
        if(ISUSER(con))
            send_cmd(con, MSG_SERVER_NOSUCH, "kill failed: too few parameters");
        return;
    }
    user = hash_lookup(global.usersHash, av[0]);
    if(!user)
    {
        if(ISUSER(con))
            send_cmd(con, MSG_SERVER_NOSUCH, "kill failed: no such user");
        return;
    }
    ASSERT(validate_user(user));

    /* Added by winter_mute */
#ifdef USE_PROTNET
    if(ISUSER(user->con) && sender && (sender->level <= user->level) && user->level == LEVEL_ELITE && glob_match(global.protnet, my_ntoa(BSWAP32(user->ip))) && !glob_match(global.protnet, my_ntoa(BSWAP32(sender->ip))))
    {
        if(ISUSER(con))
            send_cmd(con, MSG_SERVER_NOSUCH, "kill failed: permission denied");
        else
            resync_user(user, con);
        return;
    }
#endif

    /* check for permission */
    if(sender && user->level >= sender->level && sender->level < LEVEL_ELITE)
    {
        if(ISUSER(con))
            send_cmd(con, MSG_SERVER_NOSUCH, "kill failed: permission denied");
        return;
    }

    if(ac > 1)
        truncate_reason(av[1]);
#define REASON ((ac > 1) ? av[1] : "")
    kill_user_internal(con, user, sender_name, sender, "%s", REASON);
}

void kill_user_internal(CONNECTION * con, USER * user, const char *sender_name, USER * sender, const char *fmt, ...)
{
    va_list ap;
    char    reason[128], real_reason[128];

    ASSERT(global.maxReason <= (int) sizeof(reason));
    va_start(ap, fmt);
    vsnprintf(reason, sizeof(reason), fmt, ap);
    va_end(ap);

    pass_message_args(con, MSG_CLIENT_KILL, ":%s %s \"%s\"", sender_name, user->nick, reason);

    /* don't send any ghost-kill messages */
    if(strncmp("ghost", reason, 5) && strncmp("share", reason, 5))
    {
        notify_mods(KILLLOG_MODE, "%s%s killed %s: %s", !sender ? "Server " : "", sender_name, user->nick, reason);
    }

    /* forcefully close the client connection if local, otherwise remove
    * from global user list
    */
    if(ISUSER(user->con))
    {
        const char *who;

        if(sender && sender->cloaked && user->level < LEVEL_MODERATOR)
            who = "Operator";
        else
            who = sender_name;
        snprintf(real_reason, sizeof(real_reason), "You have been killed by%s %s: %s", (!sender ? " server" : ""), who, reason);
        zap_local_user(user->con, real_reason);
    }
    else
    {
        /* user is on remote server */
        hash_remove(global.usersHash, user->nick);
    }
}

struct gkilldata
{
    char   *reason;
    USER   *sender;
    unsigned int ip;
    CONNECTION *con;
};

static void mkill_user_cb(USER * user, struct gkilldata *data)
{
    if(user->ip == data->ip)
    {

        /* Added by winter_mute */
#ifdef USE_PROTNET
        if(data->sender && (data->sender->level <= user->level) && user->level == LEVEL_ELITE &&
            glob_match(global.protnet, my_ntoa(BSWAP32(user->ip))) &&
            !glob_match(global.protnet, my_ntoa(BSWAP32(data->sender->ip))))
        {
            ASSERT(ISUSER(data->sender->con));
            send_cmd(data->sender->con, MSG_SERVER_NOSUCH, "kill failed: permission denied");

            return;
        }
#endif

        if(data->sender && user->level >= data->sender->level && data->sender->level < LEVEL_ELITE)
        {
            ASSERT(ISUSER(data->sender->con));
            send_cmd(data->sender->con, MSG_SERVER_NOSUCH, "kill failed: permission denied");
            return;
        }
        kill_user_internal(data->sender->con, user, data->sender->nick, data->sender, "%s", data->reason);
    }
}

/* 10122 <ip> ["reason"]
* mass kill by ip address
*/
HANDLER(mass_kill)
{
    char   *av[2];
    int     ac;
    unsigned int   longip;
    struct gkilldata data;

    (void) tag;
    (void) len;
    ASSERT(validate_connection(con));
    CHECK_USER_CLASS("mass_kill");
    if(con->user->level < LEVEL_MODERATOR)
    {
        permission_denied(con);
        return;
    }
    ac = split_line(av, FIELDS(av), pkt);
    if(ac < 1)
    {
        unparsable(con);
        return;
    }
    longip = inet_addr(av[0]);
    if(longip == (u_int) - 1)
    {
        if(ISUSER(con))
            send_cmd(con, MSG_SERVER_NOSUCH, "kill failed: invalid ip specified %s", av[0]);
        return;
    }
    if(ac > 1)
        truncate_reason(av[1]);
    data.reason = (ac > 1) ? av[1] : "mkill by ip";
    data.ip = longip;
    data.sender = con->user;

    /* we generate a kill message for each killed user rather than passing
    * the mass kill message.
    */
    hash_foreach(global.usersHash, (hash_callback_t) mkill_user_cb, &data);
}
