/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
This is free software distributed under the terms of the
GNU Public License.  See the file COPYING for details.

$Id: change.c 434 2006-09-03 17:48:47Z reech $ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include "opennap.h"
#include "debug.h"

/* user request to change the data port they are listening on.
703 [ :<user> ] <port> */
HANDLER(change_data_port)
{
    unsigned short     port;
    USER   *user;

    (void) tag;
    (void) len;
    ASSERT(validate_connection(con));
    if(pop_user(con, &pkt, &user) != 0)
        return;
    ASSERT(validate_user(user));
    port = atoi(pkt);

    /* the official server doesn't seem to check the value sent, so this
    error is unique to this implementation */
    if(port >= 0 && port <= 65535)
    {
        user->port = port;
        pass_message_args(con, tag, ":%s %hu", user->nick, user->port);
    }
    else if(ISUSER(con))
        send_cmd(con, MSG_SERVER_NOSUCH, "invalid data port");
}

/* 700 [ :<user> ] <speed> */
/* client is changing link speed */
HANDLER(change_speed)
{
    USER   *user;
    int     spd;
    int     j;
    (void) tag;
    (void) len;
    ASSERT(validate_connection(con));
    if(pop_user(con, &pkt, &user) != 0)
        return;

    /* Some clients change link speed like humans their underwear.
    This causes a lot of traffic on the hub which isn't neccessary at all. */
    j=user->count700;
    user->count700++;
    if( notify_abuse(con, user, 700, user->count700, 1) ) 
	{
        return;
    }

    /* One change linkspeed per client lifetime is enough! */
    if( j ) 
		return;

    spd = atoi(pkt);
    if(spd >= 0 && spd <= 10)
    {
        user->speed = spd;
        pass_message_args(con, tag, ":%s %d", user->nick, spd);
    }
    else if(ISUSER(con))
        send_cmd(con, MSG_SERVER_NOSUCH, "invalid speed");
}

/* 701 [ :<user> ] <password>
change user password */
HANDLER(change_pass)
{
    USER   *user;
    USERDB *db;
    char   *tmppass;

    (void) tag;
    (void) len;
    if(pop_user(con, &pkt, &user) != 0)
        return;
    if(!pkt || !*pkt)
    {
        log_message_level(LOG_LEVEL_SECURITY, "change_pass(): missing new password");
        unparsable(con);
        return;
    }
    /* pass this along even if it is not locally registered.  the user db
    * is distributed so a record for it may reside on another server */
    pass_message_args(con, tag, ":%s %s", user->nick, pkt);
    db = hash_lookup(global.userDbHash , user->nick);
    if(!db)
    {
        log_message_level(LOG_LEVEL_SECURITY, "change_pass(): %s is not registered", user->nick);
        return;
    }
    tmppass = generate_pass(pkt);
    strncpy(db->password, tmppass, sizeof(db->password) - 1);
    db->password[sizeof(db->password) - 1] = 0;
    free(tmppass);
    if(ISUSER(con))
        send_cmd(con, MSG_SERVER_NOSUCH, "password changed");
}

/* 702 [ :<user> ] <email>
change email address */
HANDLER(change_email)
{
#if EMAIL
    USER   *user;
    USERDB *db;

    (void) tag;
    (void) len;
    if(pop_user(con, &pkt, &user) != 0)
        return;
    if(!pkt || !*pkt)
    {
        log_message_level(LOG_LEVEL_SECURITY, "change_email(): missing new email address");
        unparsable(con);
        return;
    }
    pass_message_args(con, tag, ":%s %s", user->nick, pkt);
    db = hash_lookup(global.userDbHash , user->nick);
    if(!db)
    {
        log_message_level(LOG_LEVEL_SECURITY, "change_email(): could not find user %s in the database",
            user->nick);
        return;
    }
    FREE(db->email);
    db->email = STRDUP(pkt);
#else
    (void) tag;
    (void) len;
    (void) pkt;
    (void) con;
#endif
}

/* 613 [ :<sender> ] <user> <port> [ <reason> ]
admin request to change a user's data port */
HANDLER(alter_port)
{
    USER   *sender, *user;
    char   *nick, *port;
    unsigned short     p;

    (void) tag;
    (void) len;
    ASSERT(validate_connection(con));
    if(pop_user(con, &pkt, &sender) != 0)
        return;
    /* check for privilege */
    if(sender->level < LEVEL_MODERATOR)
    {
        log_message_level(LOG_LEVEL_SECURITY, "alter_port(): %s has no privilege to change ports",
            sender->nick);
        permission_denied(con);
        return;
    }

    nick = next_arg(&pkt);
    port = next_arg(&pkt);
    if(!nick || !port)
    {
        unparsable(con);
        return;
    }
    user = hash_lookup(global.usersHash, nick);
    if(!user)
    {
        nosuchuser(con);
        return;
    }
    p = atoi(port);
    if(p < 0 || p > 65535)
    {
        if(ISUSER(con))
            send_cmd(con, MSG_SERVER_NOSUCH, "%d is an invalid port", p);
        return;
    }

    if(pkt)
        truncate_reason(pkt);

    if(user->port != p)
    {
        /* only log when the port value is actually changed, not resets */
        notify_mods(CHANGELOG_MODE, "%s changed %s's data port to %d: %s",
            sender->nick, user->nick, p, NONULL(pkt));
        user->port = p;
    }

    /* if local user, send them the message */
    if(user->local)
        send_cmd(user->con, MSG_CLIENT_ALTER_PORT, "%d", p);

    pass_message_args(con, tag, ":%s %s %d", sender->nick, user->nick, p);

    log_message_level(LOG_LEVEL_SECURITY, "alter_port: %s set %s's data port to %d", sender->nick,
        user->nick, p);
}

/* 753 [ :<sender> ] <nick> <pass> ["reason"]
admin command to change a user's password */
HANDLER(alter_pass)
{
    USER   *sender;
    int     ac = -1;
    char   *av[3];
    char   *sender_name;
    USERDB *db;
    USER   *target;

    ASSERT(validate_connection);
    (void) tag;
    (void) len;
    if(pop_user_server(con, tag, &pkt, &sender_name, &sender))
        return;
    if(sender->level < LEVEL_ADMIN)
    {
        permission_denied(con);
        return;
    }
    if(pkt)
        ac = split_line(av, FIELDS(av), pkt);

    if(ac < 2)
    {
        log_message_level(LOG_LEVEL_SECURITY, "alter_pass(): wrong number of arguments");
        print_args (ac, av);
        unparsable(con);
        return;
    }
    if(invalid_nick(av[0]))
    {
        if(ISUSER(con))
            send_cmd(con, MSG_SERVER_NOSUCH,
            "alter password failed: invalid nickname");
        return;
    }
    target = hash_lookup(global.usersHash, av[0]);
    if(target)
    {
        if( (target->level >= sender->level) && (sender->level < LEVEL_ELITE) )
        {
            send_cmd(con, MSG_SERVER_NOSUCH,
                "alter password failed: permission denied");
            return;
        }
    }

    if(ac > 2)
        truncate_reason(av[2]);
    /* send this now since the account might not be locally registered */
    pass_message_args(con, tag, ":%s %s %s \"%s\"", sender->nick, av[0],
        av[1], (ac > 2) ? av[2] : "");
    db = hash_lookup(global.userDbHash , av[0]);
    if(db)
    {
        char   *newpass;

        if( (db->level >= sender->level) && (sender->level < LEVEL_ELITE) )
        {
            send_cmd(con, MSG_SERVER_NOSUCH,
                "alter password failed: permission denied");
            return;
        }
        newpass = generate_pass (av[1]);
        if(!newpass)
        {
            OUTOFMEMORY("alter_pass");
            return;
        }
        strncpy(db->password, newpass, sizeof(db->password) - 1);
        db->password[sizeof(db->password) - 1] = 0;
        free(newpass);
    }
    notify_mods(CHANGELOG_MODE, "%s changed %s's password: %s",
        sender->nick, av[0], (ac > 2) ? av[2] : "");
}

/* 625 [ :<sender> ] <nick> <speed>
admin command to change another user's reported line speed */
HANDLER(alter_speed)
{
    USER   *sender, *user;
    int     ac;
    u_int   speed;
    char   *av[2];

    ASSERT(validate_connection(con));
    (void) len;
    if(pop_user(con, &pkt, &sender))
        return;
    ac = split_line(av, sizeof(av) / sizeof(char *), pkt);

    if(ac < 2)
    {
        unparsable(con);
        return;
    }
    if(sender->level < LEVEL_MODERATOR)
    {
        permission_denied(con);
        return;
    }
    speed = atoi(av[1]);
    if(speed > 10) 
	{
        if(ISUSER(con))
            send_cmd(con, MSG_SERVER_NOSUCH, "Invalid speed");
        return;
    }
    user = hash_lookup(global.usersHash, av[0]);
    if(!user)
    {
        nosuchuser(con);
        return;
    }
    ASSERT(validate_user(user));
    if(user->speed == speed)
    {
        if(ISUSER(con))
            send_cmd(con, MSG_SERVER_NOSUCH, "%s's speed is already %d",
            user->nick, speed);
        return;
    }
    user->speed = speed;
    pass_message_args(con, tag, ":%s %s %d", sender->nick, user->nick,
        speed);
    notify_mods(CHANGELOG_MODE, "%s changed %s's speed to %d.", sender->nick,
        user->nick, speed);
}

/* 611 [ :<sender> ] <user> [ <reason> ]
nuke a user's account */
HANDLER(nuke)
{
    USER   *sender, *user;
    USERDB *db;
    char   *nick, *sender_name;
    int     level = -1;

    ASSERT(validate_connection(con));
    (void) len;
    if(pop_user_server(con, tag, &pkt, &sender_name, &sender))
        return;
    nick = next_arg(&pkt);
    if(!nick)
    {
        if(ISUSER(con))
            send_cmd(con, MSG_SERVER_NOSUCH,
            "nuke failed: missing nickname");
        else
            log_message_level(LOG_LEVEL_SECURITY, "nuke: missing nick (from server %s)", con->host);
        return;
    }

    if(sender && sender->level < LEVEL_MODERATOR)
    {
        send_user(sender, MSG_SERVER_NOSUCH,
            "[%s] nuke failed: permission denied", global.serverName);
        return;
    }

    db = hash_lookup(global.userDbHash , nick);
    user = hash_lookup(global.usersHash, nick);

    /* if a user issued this nuke, and the target user is either logged in
    * or exists in the database..
    */
    if(sender && sender->level < LEVEL_ELITE && (db || user))
    {
        /* find the target user's level */
        level = user ? user->level : db->level;

        /* sender's level must be greater than the target's, unless user is
        * nuking themself for some reason.
        */
        if(sender->level <= level &&
            strcasecmp(sender->nick, db ? db->nick : user->nick) != 0)
        {
            send_user(sender, MSG_SERVER_NOSUCH,
                "[%s] nuke failed: permission denied", global.serverName);
            return;
        }
    }


    /* Added by winter_mute */
#ifdef USE_PROTNET
    if(sender && user && user->level == LEVEL_ELITE &&
        glob_match(global.protnet, my_ntoa(BSWAP32(user->ip))) &&
        !glob_match(global.protnet, my_ntoa(BSWAP32(sender->ip))) )
    {
        send_user(sender, MSG_SERVER_NOSUCH,
            "[%s] nuke failed: permission denied", global.serverName);
        return;
    }
#endif

    if(db)
        hash_remove(global.userDbHash , db->nick);

    if(pkt)
        truncate_reason(pkt);

    /* if the user is currently logged in, set them to a sane state (one
    * which would not require a db entry.
    */
    if(user)
    {
        /* if the target user is a mod+, remove them from the Mods list */
        if(user->level >= LEVEL_MODERATOR && ISUSER(user->con))
        {
            global.modList = list_delete(global.modList, user->con);
        }

        user->level = LEVEL_USER;
        if(user->cloaked)
        {
            if(ISUSER(user->con))
            {
                send_cmd(user->con, MSG_SERVER_NOSUCH,
                    "You are no longer cloaked.");
            }
            user->cloaked = 0;
        }
        user->flags &= ~ON_MUZZLED;
        if(ISUSER(user->con))
        {
            send_cmd(user->con, MSG_SERVER_NOSUCH,
                "%s nuked your account: %s",
                sender && sender->cloaked ? "Operator" : sender_name,
                NONULL(pkt));
        }
    }

    pass_message_args(con, tag, ":%s %s %s", sender_name, nick,
        NONULL(pkt));

    notify_mods(CHANGELOG_MODE, "%s nuked %s's account: %s",
        sender_name, nick, NONULL(pkt));
}

/* 652 [ :<sender> ] [0 | 1]
* toggle the invisible state of the current user.  when a server is the
* sender of the message, the 1 signifies that the cloak status should
* absolutely be turned on rather than toggled (used for synch)
*/
HANDLER(cloak)
{
    USER   *sender;
    int     bit = -1;
    char   *sender_name;
    char   *bitptr;

    (void) len;
    ASSERT(validate_connection(con));
    if(pop_user_server(con, tag, &pkt, &sender_name, &sender))
        return;

    bitptr = next_arg(&pkt);

    if(bitptr)
    {
        bit = atoi(bitptr);
        if(bit > 1 || bit < 0)
        {
            log_message_level(LOG_LEVEL_SECURITY, "cloak: invalid cloak state %s", bitptr);
            if(ISUSER(con))
                send_cmd(con, MSG_SERVER_NOSUCH,
                "cloak failed: invalid cloak state %s", bitptr);
            return;
        }
    }

    if(bit == -1)
        bit = !sender->cloaked; /* toggle */

    /* always allow the decloak to go through in order to help fix desyncs */
    if(bit == 1)
    {
        if(sender->level < LEVEL_MODERATOR)
        {
            send_user(sender, MSG_SERVER_NOSUCH,
                "[%s] cloak failed: permission denied", global.serverName);
            if(ISSERVER(con))
            {
                log_message_level(LOG_LEVEL_SECURITY, "cloak: %s can't cloak, %s desycned", sender->nick,
                    con->host);
                /*force a decloak */
                send_cmd(con, MSG_CLIENT_CLOAK, ":%s 0", sender->nick);
            }
            return;
        }
    }

    if((bit == 1 && sender->cloaked) || (bit == 0 && !sender->cloaked))
        return;         /*no change */

    sender->cloaked = bit;

    /* always send the absolute state when passing server messages */
    pass_message_args(con, tag, ":%s %d", sender->nick, bit);

    notify_mods(CLOAKLOG_MODE, "%s has %scloaked", sender->nick,
        sender->cloaked ? "" : "de");

    if(ISUSER(con))
        send_cmd(con, MSG_SERVER_NOSUCH, "You are %s cloaked.",
        sender->cloaked ? "now" : "no longer");
}
