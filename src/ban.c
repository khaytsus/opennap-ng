/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
This is free software distributed under the terms of the
GNU Public License.  See the file COPYING for details.

$Id: ban.c 436 2006-09-04 14:56:32Z reech $ */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#ifndef WIN32
# include <unistd.h>
#endif
#include "opennap.h"
#include "debug.h"

void ban_user_internal(CONNECTION *con, char *user, time_t btimeout, char *reason)
{
    BAN    *b;
    LIST   *list;
    char   *banptr, realban[256];
    time_t  timeout = 0;

    (void) con;

    ASSERT(validate_connection(con));
    timeout = btimeout;

    truncate_reason(reason);

    /* Normalize to "user!*" */
    banptr = normalize_ban(user, realban, sizeof(realban));

    /* check to see if this user is already banned */
    for (list = global.banList; list; list = list->next)
    {
        b = list->data;
        if(!strcasecmp(banptr, b->target))
        {
            log_message_level(LOG_LEVEL_ERROR, "ban_user_internal: %s (%s) already banned", realban, banptr);
            return;
        }
    }
    b=create_ban(banptr, global.serverName, reason, global.current_time, btimeout);
    if(!b) 
    {
        log_message_level(LOG_LEVEL_ERROR,"ban_user_internal: Out of memory when banning %s", banptr);
        return;
    }

    notify_mods(BANLOG_MODE, "%s%s banned %s%s%lu%s: %s", "Server ", global.serverName, b->target, (timeout > 0) ? " for " : "", (timeout > 0) ? timeout : 0, (timeout > 0) ? " seconds" : "", b->reason);
    pass_message_args(con, MSG_CLIENT_BAN, ":%s %s \"%s\" %d",global.serverName, user, reason, timeout); 

}

/* Create a ban record and initializes all vars. Returns Pointer to 
record if successful - NULL if not. */
BAN *create_ban(char *target, char *issuer, char *reason, time_t starttime, time_t timeout) 
{
    BAN *b;
    LIST *list;

    list=NULL;

    while (1)
    {
        /* create structure and add to global ban list */
        b = CALLOC(1, sizeof(BAN));
        if(!b)
            break;
        strncpy(b->target, target, sizeof(b->target) - 1);
        b->target[sizeof(b->target) - 1] = 0;
        strncpy(b->setby, issuer, sizeof(b->setby) - 1);
        b->setby[sizeof(b->setby) - 1] = 0;
        strncpy(b->reason, reason, sizeof(b->reason) - 1);
        b->reason[sizeof(b->reason) - 1] = 0;
        b->when = starttime;
        b->timeout = timeout;
        b->when_deleted = 0;
        list = CALLOC(1, sizeof(LIST));
        if(!list) 
		{
            OUTOFMEMORY("ban");
            break;
        }
        list->data = b;
        list->next = global.banList;
        global.banList = list;
        return b;
    };

    /* we only get here on error */
    OUTOFMEMORY("ban");
    free_ban(b);
    if(list)
        FREE(list);
    return NULL;
}


void free_ban(BAN * b)
{
    if(b)
    {
        //if(b->target)
        //    FREE(b->target);
        //if(b->setby)
        //    FREE(b->setby);
        //if(b->reason)
        //    FREE(b->reason);
        FREE(b);
    }
}

char *normalize_ban( char *src, char *dest, int destlen)
{
    int is_ip = 1;
    char *s;
    /* normalize the ban to the full user!host syntax */
    if(strchr(src, '!')) 
    {
        snprintf(dest, destlen, "%s", src);
    } 
    else 
    {
        s = src;
        while (*s)
        {
            if(!(isdigit(*s) || *s == '.'))
                is_ip = 0;
            s++;
        }
        if(is_ip) 
        {
            char   *star;

            /* append a star if the last char is a . so that it means the same
            * as the old-style ban
            */
            if(*src && src[strlen(src) - 1] == '.')
                star = "*";
            else
                star = "";
            snprintf(dest, destlen, "*!%s%s", src, star);  /* must be an ip/dns name? */
        }
        else 
        {
            snprintf(dest, destlen, "%s!*", src);  /* must be a nick */
        }
    }
    /* log_message_level(LOG_LEVEL_DEBUG,"normalize_ban: (%s) --> (%s)", src, dest); */
    return dest;

}

/* 612 [ :<sender> ] <user!ip> [ "<reason>" [ time [starttime] ] ] */
HANDLER(ban)
{
    BAN    *b;
    LIST   *list;
    int     ac = -1;
    char   *av[4], *sendernick;
    char   *banptr, realban[256];
    USER   *sender;
    int     timeout = 0;
    time_t  starttime = 0;

    (void) len;
    ASSERT(validate_connection(con));

    if(pop_user_server(con, tag, &pkt, &sendernick, &sender))
        return;

    if(sender && sender->level < LEVEL_MODERATOR)
    {
        permission_denied(con);
        return;
    }

    if(pkt) 
    {
        /* Do some logging on the server tban sync thing ...  */
        ac = split_line(av, sizeof(av) / sizeof(char *), pkt);
    }
    if(ac < 1)
    {
        unparsable(con);
        return;
    }

    /* When we have 3 args then it's a tban with or without a start time.
    First the timeout to stay compatible to the old semantics */
    if(ac >= 3)
    {
        timeout = atoi(av[2]);
        if(timeout < 0)
        {
            if(ISUSER(con))
                send_cmd(con, MSG_SERVER_NOSUCH, "invalid ban timeout");
            return;
        }
    }

    /* And only if we have 4 args then the new semantics is used.
    The 4th arg is the ban starttime. */
    if( ac == 4 ) 
    {
        starttime=atol(av[3]);
        if(starttime < 0) 
        {
            if(ISUSER(con))
                send_cmd(con, MSG_SERVER_NOSUCH, "invalid ban starttime");
            return;
        }
    } 
    else 
    {
        starttime=global.current_time;
    }

    /* Do some logging on the server tban sync thing ... */
    if( ! ISUSER(con)) 
    {
        log_message_level(LOG_LEVEL_DEBUG, "ban: Server %s issued %d args: \"%s\" \"%s\" \"%s\" \"%s\"", sendernick, ac, av[0], ac>1?av[1]:"", ac>2?av[2]:"",ac>3?av[3]:"");
    }

    banptr = normalize_ban(av[0], realban, sizeof(realban));

    /* check to see if this user is already banned */
    for (list = global.banList; list; list = list->next)
    {
        b = list->data;
        /* If the user is already banned then look for the start time 
        of the ban. If our ban is older ( means smaller ) then ignore the ban 
        request. If our ban is younger then we have to update 
        the start time of the ban to reflect that this user
        had been previously banned on another server.
        This should avoid stale tbans without updating a 
        deletion stub in the banlist and all the hassles around it.
        As unbans are routed meanwhile these stale tbans should disappear quite 
        quickly. */
        if(!strcasecmp(banptr, b->target))
        {
            if(ISUSER(con)) 
            {
                send_cmd(con, MSG_SERVER_NOSUCH, "already banned");
            } 
            else 
            {
                if( b->when > starttime ) 
                {
                    b->when=starttime;
                }
            }
            return;
        }
    }

    if(ac > 1)
        truncate_reason(av[1]);

    b=create_ban(banptr, sendernick, ac > 1 ? av[1] : "", starttime, timeout);
    if( !b ) 
    {
        log_message_level(LOG_LEVEL_ERROR,"ban: Out of memory when banning %s", banptr);
        return;
    }

    notify_mods(BANLOG_MODE, "%s%s banned %s%s%s%s: %s",
        !sender ? "Server " : "", sendernick, b->target, 
        (timeout > 0) ? " for " : "",
        (timeout > 0) ? av[2] : "",
        (timeout > 0) ? " seconds" : "", b->reason);
    pass_message_args(con, tag, ":%s %s \"%s\" %d %lu", sendernick, av[0], ac > 1 ? av[1] : "", timeout, starttime);

}

/* 614 [ :<sender> ] <nick!ip> [ "<reason>" ] */
HANDLER(unban)
{
    /*    USER   *user; */
    USER   *sender;
    LIST  **list, *tmpList;
    BAN    *b;
    int     ac = -1;
    char   *av[2], *sendernick;
    char   *banptr, realban[256];

    /*    (void) tag; */
    (void) len;

    ASSERT(validate_connection(con));

    /* Previously the sender had been just a user causing 
    messages like: pop_user: (tag 614) could not find user
    This means that servers had not been able to unban users. */
    if(pop_user_server(con, tag, &pkt, &sendernick, &sender))
        return;

    /*    if(pop_user(con, &pkt, &user) != 0)
    return;
    */

    if(pkt)
        ac = split_line(av, FIELDS(av), pkt);
    if(ac < 1)
    {
        unparsable(con);
        return;
    }

    /* If the sender is null then the unban has been a server unban. */
    if(sender && sender->level < LEVEL_MODERATOR)
    {
        permission_denied(con);
        return;
    }


    banptr = normalize_ban(av[0], realban, sizeof(realban));
    if(ac > 1)
        truncate_reason(av[1]);

    /* Have some overview over freshly generated code ... 
    Parameters listed: Unbanning server, Unbanned user, and reason. */
    if( ! sender ) 
    {
        log_message_level(LOG_LEVEL_DEBUG,"unban: Server %s unbanned %s: %s", sendernick, banptr, ac > 1 ? av[1] : "");
    }

    for (list = &global.banList; *list; list = &(*list)->next)
    {
        b = (*list)->data;
        if(!strcasecmp(banptr, b->target))
        {
            tmpList = *list;
            *list = (*list)->next;
            FREE(tmpList);
            /* To prevent coredumps when the unbanning user is a server ... */
            if( sender ) 
            {
                notify_mods(BANLOG_MODE, "%s removed ban on %s: %s",sender->nick, b->target, ac > 1 ? av[1] : "");
                pass_message_args(con, tag, ":%s %s \"%s\"", sender->nick,b->target, ac > 1 ? av[1] : "");
            } 
            else 
            {
                notify_mods(BANLOG_MODE, "%s removed ban on %s: %s",sendernick, b->target, ac > 1 ? av[1] : "");
                pass_message_args(con, tag, ":%s %s \"%s\"", sendernick, b->target, ac > 1 ? av[1] : "");
            }
            free_ban(b);
            return;
        }
    }
    if(ISUSER(con))
        send_cmd(con, MSG_SERVER_NOSUCH, "no such ban");
}

/* 615 */
/* show the list of current bans on the server */
HANDLER(banlist)
{
    LIST   *list;
    BAN    *ban;

    (void) tag;
    (void) len;
    (void) pkt;
    if(ISUSER(con))
    {
        /* The banlist is mod+ only from this point on. */
        if(con->user->level < LEVEL_MODERATOR)
        {
            permission_denied(con);
            return;
        }
    }
    ASSERT(validate_connection(con));
    CHECK_USER_CLASS("banlist");
    for (list = global.banList; list; list = list->next)
    {
        ban = list->data;
        send_cmd(con, MSG_SERVER_IP_BANLIST, "%s %s \"%s\" %u %d", ban->target, ban->setby, ban->reason, ban->when, ban->timeout);
    }
    /* terminate the banlist */
    send_cmd(con, MSG_CLIENT_BANLIST, "");
}

int check_ban(CONNECTION * con, const char *nick, const char *host)
{
    LIST   *list;
    BAN    *ban;
    char    mask[256];
    int     deltat;
    int     howmany;

    snprintf(mask, sizeof(mask), "%s!%s", nick, host);
    for (list = global.banList; list; list = list->next)
    {
        ban = list->data;
        if((ban->timeout == 0 || ban->when + ban->timeout > global.current_time) && glob_match(ban->target, mask))
        {
            notify_mods(BANLOG_MODE,"Connection from %s: %s banned: %s",mask, ban->target, NONULL(ban->reason));
            if( ! ban->connect_counter ) 
            {
                ban->firstconnect=global.current_time;
            }
            ban->connect_counter++;

            /* Calculate the time since login in minutes */
            deltat=( global.current_time - ban->firstconnect ) / 60;
            howmany=deltat?ban->connect_counter / deltat:0;

            log_message_level(LOG_LEVEL_LOGIN, "check_ban: %s ( %s ) on %s connected %d times ( %d per minute )",nick,ban->target,host,ban->connect_counter,howmany);

            if(ISUNKNOWN(con)) 
            {
				stats.login_ce_banned++;
                ibl_kill(con, MSG_SERVER_ERROR, "%s banned: %s", ban->target, NONULL(ban->reason));
            }
            else if(ISSERVER(con)) 
            {
                /* issue a kill to remove this banned user */
                pass_message_args(con, MSG_CLIENT_KILL, ":%s %s %s banned: %s", global.serverName, nick, ban->target, NONULL(ban->reason));
                notify_mods(KILLLOG_MODE, "Server %s killed %s: %s banned: %s", global.serverName, nick, ban->target, NONULL(ban->reason));
            }
            return 1;
        }
    }
    return 0;
}

int save_bans(void)
{
    int     fd;
    LIST   *list;
    BAN    *b;
    char    path[_POSIX_PATH_MAX], tmppath[_POSIX_PATH_MAX];
    char    inbuf[1024];
    struct  stat sts;

    log_message_level(LOG_LEVEL_SERVER, "save_bans: dumping ban database" );

    if(global.banList) 
    {
        snprintf(tmppath, sizeof(tmppath), "%s/bans.tmp", global.varDir);
        if((fd = open(tmppath, O_WRONLY | O_CREAT , S_IRUSR | S_IWUSR)) == -1) 
        {
            logerr("save_bans", tmppath);
            return -1;
        }
        for (list = global.banList; list; list = list->next) 
        {
            b = list->data;
            /* As the b->reason is determined by max_reason ( a configurable var ) we must 
            not determine the strings via format specifiers. The same goes for targets, issuers.
            */
            snprintf(inbuf,sizeof(inbuf)-2,"%s %s %lu \"%s\" %d", b->target, b->setby,b->when, b->reason, b->timeout);
            strcat( inbuf, LE );

            fake_fputs( inbuf, fd );
        }
        if(close(fd)) 
        {
            logerr("save_bans", "close");
            return -1;
        }
        snprintf(path, sizeof(path), "%s/bans", global.varDir);
        if(stat(path, &sts) == -1 && errno == ENOENT)
        {
            log_message_level(LOG_LEVEL_DEBUG, "%s file does not exist\n", path);
        }
        else 
        {
            if(unlink(path))
                logerr("save_bans", "unlink");       /* not fatal, may not exist */
        }
        if(rename(tmppath, path)) 
        {
            logerr("save_bans", "rename");
            return -1;
        }
    }                                    
    return 0;
}

int load_bans(void)
{
    int    fd;
    LIST   *list, **last = &global.banList, *p;
    BAN    *b;
    int     ac;
    char   *av[5], path[_POSIX_PATH_MAX];
    char   *banptr, realban[256];
    int    dupban;

    snprintf(path, sizeof(path), "%s/bans", global.varDir);
    if((fd = open(path, O_RDONLY))==-1)
    {
        if(errno != ENOENT)
            logerr("load_bans", path);
        return -1;
    }
    while (fake_fgets(Buf, sizeof(Buf)-1, fd))
    {
        ac = split_line(av, FIELDS(av), Buf);
        if(ac < 1)
            continue;
        banptr = normalize_ban(av[0], realban, sizeof(realban));

        /* check to see if this user is already banned */
        dupban=0;
        for (p = global.banList; p; p = p->next) 
        {
            b = p->data;
            dupban = dupban || (!strcasecmp(banptr, b->target));
        }
        if( dupban )  /* This ban entry had been read before - don't create it again. */
            continue;

        b = CALLOC(1, sizeof(BAN));
        if(!b)
        {
            OUTOFMEMORY("load_bans");
            close(fd);
            return -1;
        }
        strncpy(b->target, banptr, sizeof(b->target) - 1);
        b->target[sizeof(b->target) - 1] = 0;
        if(ac >= 4)
        {
            strncpy(b->setby,av[1], sizeof(b->setby) - 1);
            b->setby[sizeof(b->setby) - 1] = 0;
            b->when = atol(av[2]);
            truncate_reason(av[3]);
            strncpy(b->reason, av[3], sizeof(b->reason) - 1);
            b->reason[sizeof(b->reason) - 1] = 0;
            if(ac > 4)
                b->timeout = atoi(av[4]);
        }
        else
        {
            /* old user ban style */
            strncpy(b->setby, global.serverName, sizeof(b->setby) - 1);
            b->setby[sizeof(b->setby) - 1] = 0;
            b->reason[0] =  0;
            b->when = global.current_time;
        }
        list = CALLOC(1, sizeof(LIST));
        if(!list)
        {
            OUTOFMEMORY("load_bans");
            free_ban(b);
            close(fd);
            return -1;
        }
        b->connect_counter=0;
        list->data = b;
        /* keep the bans in the same order (roughly reverse chronological) */
        *last = list;
        last = &list->next;
    }
    close(fd);
    return 0;
}

/* reap expired bans from the list */
void expire_bans(void)
{
    LIST  **list, *tmp;
    BAN    *b;

    list = &global.banList;
    while (*list)
    {
        b = (*list)->data;
        if(b->timeout > 0 && b->when + b->timeout < global.current_time)
        {
            tmp = *list;
            *list = (*list)->next;
            FREE(tmp);
            /* make sure all servers are synched up */
            pass_message_args(NULL, MSG_CLIENT_UNBAN, ":%s %s \"expired after %d seconds\"", global.serverName, b->target, b->timeout);
            notify_mods(BANLOG_MODE, "%s removed ban on %s: expired after %d seconds", global.serverName, b->target, b->timeout);
            free_ban(b);
            continue;
        }
        list = &(*list)->next;
    }
}


int ibl_check(unsigned int ip) 
{
    LIST   *list;
    BAN    *b;
    char   *cip;

    if(global.ibl_ttl) 
    {
        cip = my_ntoa(BSWAP32(ip));
        for (list = global.internalBanList; list; list = list->next) 
        {
            b = list->data;
            if(!strcasecmp(cip, b->target)) 
            {
#ifdef ONAP_DEBUG
                log_message_level( LOG_LEVEL_DEBUG, "ibl_check: %s is banned: %s", b->target, b->reason);
#endif
                return 1;
            }
        }
    }
    return 0;
}

int ibl_kill(CONNECTION * con, unsigned int msgtype, const char *fmt, ...) 
{
    LIST   *list;
    BAN    *b;
    char   *realban, reason[256] ;
    va_list ap;

    (void) con;
    ASSERT(validate_connection(con));

    va_start(ap, fmt);
    vsnprintf(reason, sizeof(reason), fmt, ap);
    va_end(ap);
    realban = my_ntoa(BSWAP32(con->ip));

    send_cmd( con, msgtype, "%s", reason);
    destroy_connection(con);

    if(global.ibl_ttl) 
    {
        log_message_level( LOG_LEVEL_LOGIN, "ibl_kill: %s %s", realban, reason);
        /* check if already banned */ 
        for (list = global.internalBanList; list; list = list->next) 
        {
            b = list->data;
            if(!strcasecmp(realban, b->target)) 
            {
#ifdef ONAP_DEBUG
                log_message_level(LOG_LEVEL_DEBUG, "ibl_kill: %s already banned", realban);
#endif
                return 1;
            }
        }
        while (1)
        {
            b = CALLOC(1, sizeof(BAN));
            if(!b)
                break;
            strncpy(b->target,realban, sizeof(b->target) - 1);
            b->target[sizeof(b->target) - 1] = 0;
            strncpy(b->reason, reason, sizeof(b->reason) - 1);
            b->reason[ sizeof(b->reason) - 1] = 0;
            b->when = global.current_time;
            b->timeout = global.ibl_ttl;
            list = CALLOC(1, sizeof(LIST));
            if(!list)
                break;
            list->data = b;
            list->next = global.internalBanList;
            global.internalBanList = list;

            return 0;
        };
        /* we only get here on error */
        OUTOFMEMORY("ibl_kill");
        if(b)
            free_ban(b);
        if(list)
            FREE(list);
        return -1;
    } 
    else 
    {
        log_message_level( LOG_LEVEL_LOGIN, "login: killed %s %s", realban, reason);
    }
    return 0;
}

void ibl_expire(void) 
{
    LIST  **list, *tmp;
    BAN    *b;
    int     expired = 0;

    if(stats.ibl_db || global.ibl_ttl) 
    {
        stats.ibl_db = 0;
        list = &global.internalBanList;
        while (*list) 
        {
            b = (*list)->data;
            if(b->timeout > 0 && b->when + b->timeout < global.current_time) 
            {
                log_message_level(LOG_LEVEL_DEBUG, "ibl_expire: %s", b->target);
                expired++;
                tmp = *list;
                *list = (*list)->next;
                FREE(tmp);
                free_ban(b);
                continue;
            } 
            else 
            {
                stats.ibl_db++;
            }
            list = &(*list)->next;
        }
        log_message_level(LOG_LEVEL_SERVER, "ibl_expire: %u expired, %u in internal ban list", expired, stats.ibl_db);
    }
}
