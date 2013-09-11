/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
This is free software distributed under the terms of the
GNU Public License.  See the file COPYING for details.

$Id: muzzle.c 434 2006-09-03 17:48:47Z reech $ */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "opennap.h"
#include "debug.h"

/* [ :<sender> ] <target-user> [ "<reason>" ]
muzzle/unmuzzle a user */
HANDLER(muzzle)
{
    USER   *user, *sender;
    char   *av[2], *sender_name;
    int     ac = -1;
    USERDB *db;
    u_int   curlevel;
    int     denied = 0;

    (void) len;
    ASSERT(validate_connection(con));

    if(pop_user_server(con, tag, &pkt, &sender_name, &sender))
        return;

    if(pkt)
        ac = split_line(av, FIELDS(av), pkt);

    if(ac < 1)
    {
        unparsable(con);
        return;
    }

    /* find the user to be muzzled.  user may not be currently logged in. */
    user = hash_lookup(global.usersHash, av[0]);

    /* look up this entry in the user db.  may not be registered. */
    db = hash_lookup(global.userDbHash , av[0]);

    /* check for permission to execute */
    if(sender)
    {
        /* non-mods are never allowed to muzzle */
        if(sender->level < LEVEL_MODERATOR)
        {
            denied = 1;
        }
        /* if not Elite, allow muzzling users of lower levels */
        else if(sender->level < LEVEL_ELITE && (user || db))
        {
            curlevel = db ? db->level : user->level;
            if(sender->level <= curlevel)
            {
                denied = 1;
            }
        }

        if(denied)
        {
            send_user(sender, MSG_SERVER_NOSUCH, "[%s] %smuzzle failed: permission denied", global.serverName, (tag == MSG_CLIENT_UNMUZZLE) ? "un" : "");
            if(ISSERVER(con))
            {
                /* fix desync */
                log_message_level( LOG_LEVEL_SERVER, "muzzle: %s is desynced", con->host);
                send_cmd(con, (tag == MSG_CLIENT_MUZZLE) ? MSG_CLIENT_UNMUZZLE : MSG_CLIENT_MUZZLE, ":%s %s \"%s is desynced\"", global.serverName, av[0], con->host);
            }
            return;
        }
    }

    if(!db)
    {
        if(user)
            db = create_db (user);
    }

    if(ac > 1)
        truncate_reason(av[1]);

    if(db)
    {
        if(tag == MSG_CLIENT_MUZZLE)
        {
            if(db->flags & ON_MUZZLED)
                return;     /* already set */
            db->flags |= ON_MUZZLED;
        }
        else
        {
            if(!(db->flags & ON_MUZZLED))
                return;     /* already unset */
            db->flags &= ~ON_MUZZLED;
        }

        if(user)
        {
            if(tag == MSG_CLIENT_MUZZLE)
                user->flags |= ON_MUZZLED;
            else
                user->flags &= ~ON_MUZZLED;

            if(ISUSER(user->con))
            {
                char   *who;

                if(sender && sender->cloaked
                    && user->level < LEVEL_MODERATOR)
                    who = "Operator";
                else
                    who = sender->nick;

                send_cmd(user->con, MSG_SERVER_NOSUCH, "You have been %smuzzled by %s%s: %s", (user->flags & ON_MUZZLED) ? "" : "un", !sender ? "Server " : "", sender_name, (ac > 1) ? av[1] : "");
            }
        }
    }

    /* relay to peer servers */
    pass_message_args(con, tag, ":%s %s \"%s\"", sender_name, av[0], (ac > 1) ? av[1] : "");

    /* notify mods+ of this action */
    notify_mods(MUZZLELOG_MODE, "%s%s has %smuzzled %s: %s", !sender ? "Server " : "", sender_name, (tag == MSG_CLIENT_MUZZLE) ? "" : "un", av[0], (ac > 1) ? av[1] : "");
}
