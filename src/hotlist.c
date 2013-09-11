/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
This is free software distributed under the terms of the
GNU Public License.  See the file COPYING for details.

$Id: hotlist.c 434 2006-09-03 17:48:47Z reech $ */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>
#include <stdlib.h>
#include "opennap.h"
#include "hashlist.h"
#include "debug.h"

/* 207/208 <nick> */
HANDLER(add_hotlist)
{
    hashlist_t *hotlist;
    USER   *user;
    LIST   *list;
    int     count;

    (void) tag;
    (void) len;
    ASSERT(validate_connection(con));
    CHECK_USER_CLASS("add_hotlist");

    if(invalid_nick(pkt))
    {
        send_cmd(con, MSG_SERVER_NOSUCH, "hotlist add failed: invalid nick");
        return;
    }

    /* check to see if this user is over the hotlist limit */
    if(global.maxHotlist > 0 && (count = list_count(con->uopt->hotlist)) > global.maxHotlist)
    {
        /* send_cmd(con, MSG_SERVER_HOTLIST_ERROR, "%s", pkt); */
        return;
    }

    hotlist = hashlist_add(global.hotlistHash, pkt, con);
    if(!hotlist)
    {
        /* already on list, or failure */
        return;
    }
    ASSERT(hashlist_validate(hotlist));

    /* add the hotlist entry to this particular users list */
    list = MALLOC(sizeof(LIST));
    if(!list)
    {
        OUTOFMEMORY("add_hotlist");
        hashlist_remove(global.hotlistHash, pkt, con);
        send_cmd(con, MSG_SERVER_HOTLIST_ERROR, "%s", pkt);
        return;
    }
    list->data = hotlist;
    con->uopt->hotlist = list_push(con->uopt->hotlist, list);

    /* ack the user who requested this */
    send_cmd(con, MSG_SERVER_HOTLIST_ACK, "%s", hotlist->key);

    /* check to see if this user is on so the client is notified
    immediately */
    user = hash_lookup(global.usersHash, hotlist->key);
    if(user)
    {
        ASSERT(validate_user(user));
        send_cmd(con, MSG_SERVER_USER_SIGNON, "%s %d", user->nick,
            user->speed);
    }
}

/* 303 <nick> */
HANDLER(remove_hotlist)
{
    hashlist_t *hotlist;

    (void) tag;
    (void) len;
    ASSERT(validate_connection(con));
    CHECK_USER_CLASS("remove_hotlist");

    hotlist = hash_lookup(global.hotlistHash, pkt);
    if(!hotlist)
        return;
    ASSERT(hashlist_validate(hotlist));

    /* remove the hotlist entry from the user's personal list */
    con->uopt->hotlist = list_delete(con->uopt->hotlist, hotlist);

    hashlist_remove(global.hotlistHash, hotlist->key, con);
}
