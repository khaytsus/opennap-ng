/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
This is free software distributed under the terms of the
GNU Public License.  See the file COPYING for details.

$Id: level.c 436 2006-09-04 14:56:32Z reech $ */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <limits.h>
#include <errno.h>
#include "opennap.h"
#include "debug.h"

/* For now, this will work.  Solaris change done by Squash, but
breaks !Solaris, or perhaps all.  But none the less, leave
the changes for Solaris in, return to normal fgets for others. */

#ifndef SOLARIS

void logmode_change(char *sender, char *whom, int oldlevel, int newlevel)
{
    char    path[_POSIX_PATH_MAX];
    FILE   *fp;

    if(!(global.serverFlags & ON_LOGLEVEL_CHANGE))
        return;
    snprintf(path, sizeof(path), "%s/level.log", global.varDir);
    fp = fopen(path, "a");
    if(!fp)
    {
        logerr("level_log init", path);
        return;
    }
    fprintf(fp, "%s Changed %s's level from %s(%d) to %s(%d)%s", sender, whom, oldlevel != -1 ? Levels[oldlevel] : "unknown", oldlevel, Levels[newlevel], newlevel, LE);

    if(fflush(fp))
    {
        logerr("level_log", "fflush");
        fclose(fp);
        return;
    }
    if(fclose(fp))
        logerr("level_log", "fclose");
}

#endif

#ifdef SOLARIS

void logmode_change(char *sender, char *whom, int oldlevel, int newlevel)
{
    char    path[_POSIX_PATH_MAX];
    int     fd;
    char    outbuf[1024];
    if(!(global.serverFlags & ON_LOGLEVEL_CHANGE))
        return;
    snprintf(path, sizeof(path), "%s/level.log", global.varDir);
    if((fd = open(path, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR))==-1)
    {
        logerr("level_log init", path);
        return;
    }
    snprintf(outbuf, sizeof(outbuf), "%.40s Changed %.40s's level from %.40s(%d) to %s(%d)%s", sender, whom, oldlevel != -1 ? Levels[oldlevel] : "unknown", oldlevel, Levels[newlevel], newlevel, LE);
    fake_fputs(outbuf,fd);
    close(fd);
    return;

}

#endif

/* [ :<nick> ] <user> <level>
change the user level for a user */
HANDLER(level)
{
    char   *sender_name, *av[2];
    USER   *user, *sender;
    int     level, curlevel = -1, ac = -1, desync = 0, savelevel = -1;
    USERDB *db;

    (void) len;
    ASSERT(validate_connection(con));

    if(pop_user_server(con, tag, &pkt, &sender_name, &sender))
        return;

    if(pkt)
        ac = split_line(av, FIELDS(av), pkt);
    if(ac < 2)
    {
        log_message_level(LOG_LEVEL_ERROR | LOG_LEVEL_SECURITY, "level: malformed request");
        print_args(ac, av);
        unparsable(con);
        return;
    }

    if((level = get_level (av[1])) == -1)
    {
        if(ISUSER(con))
            send_cmd(con, MSG_SERVER_NOSUCH, "set user level failed: %s: invalid level", av[1]);
        else
        {
            ASSERT(ISSERVER(con));
            log_message_level(LOG_LEVEL_ERROR | LOG_LEVEL_SECURITY, "level: invalid level %s from server %s", av[1], con->host);
        }
        return;
    }


    /* check to see if the user is registered (might be null) */
    db = hash_lookup(global.userDbHash , av[0]);

    /* check if the user is currently online (might be null) */
    user = hash_lookup(global.usersHash, av[0]);

    /* make sure this is a valid nickname so we don't pass unchecked
    * data across a server link.
    */
    if((!db && !user) && invalid_nick(av[0]))
    {
        if(ISUSER(con))
            send_cmd(con, MSG_SERVER_NOSUCH, "set user level failed: invalid nickname");
        else
            log_message_level(LOG_LEVEL_ERROR | LOG_LEVEL_SECURITY, "level: invalid nickname from server %s", con->host);
        return;
    }

    /* ensure that the user can execute this command */
    if(sender)
    {
        /* a user is not allowed to set another user to a level greater
        * or equal to their own.
        */
        if(level >= sender->level && sender->level < LEVEL_ELITE)
        {
            desync = 1;
        }
        /* check for permission to execute */
        else if(db || user)
        {
            /* find the target's current user level */
            curlevel = db ? db->level : user->level;

            /* we allow a user to set their own level lower, but not
            a user with a level equal to or greater than their own
            unless they are Elite. */
            if(sender->level < LEVEL_ELITE && sender->level <= curlevel && (sender != user || curlevel < LEVEL_MODERATOR))
                desync = 1;

            /* Added by winter_mute */
#ifdef USE_PROTNET
            /* If the users level is elite, their IP is protected and the senders IP is not
            protected, deny them.  i.e., we can't demote an elite on a protected IP unless
            we're on that IP. */
            if(user && sender->level <= curlevel && user->level == LEVEL_ELITE &&
                glob_match(global.protnet, my_ntoa(BSWAP32(user->ip))) &&
                !glob_match(global.protnet, my_ntoa(BSWAP32(sender->ip))))
                desync = 1;
#endif 

        }

        if(desync)
        {
            if(ISUSER(con))
            {
                send_cmd(con, MSG_SERVER_NOSUCH, "set user level failed: permission denied");
            }
            else
            {
                log_message_level(LOG_LEVEL_ERROR, "level: %s is desynched", con->host);
                log_message_level(LOG_LEVEL_ERROR, "level: %s -> %s %s", sender->nick, av[0],Levels[level]);
                if(curlevel != -1)
                {
                    /* reset the user's level on the remote site
                    to avoid desync.  we only do this when we know what the
                    real value should be since the userdb is not fully
                    synched when new servers are added. */
                    send_cmd(con, MSG_CLIENT_SETUSERLEVEL, ":%s %s %s", global.serverName, av[0], Levels[curlevel]);
                }
            }
            return;
        }
    }

    /* if we get here, either we don't have enough info to verify
    * whether the sender can execute and we're just going to pass it
    * along, or it is registered here and ok to proceed.
    */
    if(!db)
    {
        /* if we have no db entry yet and the user is online we are in luck.
        create a stub entry from the USER struct and continue.  otherwise
        we don't do anything but pass this message along to our peer servers
        since we don't have enough info to register. */
        if(user)
            db = create_db(user);
    }

    if(db)
    {
        if(db->level == level)
            return;     /* already set */

        savelevel = db->level;
        db->level = level;

        /* delete flags if userlevel is set to mod+
        no need for friend, muzzled and criminal */
        if(savelevel <= LEVEL_USER && level > LEVEL_USER)
        {
            if(db->flags)
            {
                /* this might need to be changed for use with other userflags */
                db->flags = 0;
            }
        }

        /* if the user is online, we need to do some extra work */
        if(user)
        {
            int     oldlevel = user->level;

            savelevel = oldlevel;
            user->level = level;

            /* do the same as a few lines above */
            if(savelevel <= LEVEL_USER && level > LEVEL_USER)
            {
                if(user->flags)
                    user->flags = 0;
            }

            if(ISUSER(user->con))
            {
                char   *who;

                if(sender && sender->cloaked && level < LEVEL_MODERATOR)
                    who = "Operator";
                else
                    who = sender_name;

                send_cmd(user->con, MSG_SERVER_NOSUCH,
                    "%s%s changed your user level to %s (%d)",
                    !sender ? "Server " : "", who, Levels[level],
                    level);

                if(level >= LEVEL_MODERATOR && oldlevel < LEVEL_MODERATOR)
                {
                    LIST   *list;

                    list = CALLOC(1, sizeof(LIST));
                    list->data = user->con;
                    global.modList = list_push(global.modList, list);
                }
                else if(level < LEVEL_MODERATOR && oldlevel >= LEVEL_MODERATOR)
                {
                    global.modList = list_delete(global.modList, user->con);
                }
            }

            /* non-mod+ users can't decloak so make sure they are
            not cloaked */
            if(user->level < LEVEL_MODERATOR && user->cloaked)
            {
                user->cloaked = 0;
                notify_mods(CHANGELOG_MODE, "%s has decloaked", user->nick);
                if(ISUSER(user->con))
                    send_cmd(user->con, MSG_SERVER_NOSUCH, "You are no longer cloaked.");
            }
        }
    }

    pass_message_args(con, tag, ":%s %s %s", sender_name, av[0], Levels[level]);

    /* if sender != NULL then it's not a server. and if savelevel == -1
    * we're looking at a user that has already signed off, or is not known
    */
    if(sender && savelevel != -1)
    {
        logmode_change(sender_name, av[0], savelevel, level);
    }

    notify_mods(LEVELLOG_MODE, "%s%s changed %s's user level to %s (%d)", !sender ? "Server " : "", sender_name, av[0], Levels[level], level);
}
