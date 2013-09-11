/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
This is free software distributed under the terms of the
GNU Public License.  See the file COPYING for details.

$Id: channel.c 436 2006-09-04 14:56:32Z reech $ */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <ctype.h>
#ifndef WIN32
# include <unistd.h>
#endif
#include "opennap.h"
#include "debug.h"

/* load the predefined channels */
void load_channels(void)
{
    char    path[_POSIX_PATH_MAX], *name, *slimit, *slevel, *topic, *ptr;
    char    realname[256];
    int     fd;
    int     limit, level, line = 0;
    CHANNEL *chan;
    int     version = 0;

    snprintf(path, sizeof(path), "%s/channels", global.varDir);

    if((fd = open(path, O_RDONLY))==-1)
    {
        if(errno != ENOENT)
            logerr("load_channels", path);
        return;
    }
    if(fake_fgets(Buf, sizeof(Buf), fd) == NULL)
    {
        close(fd);
        return;
    }
    if(!strncmp(":version 1", Buf, 10))
        version = 1;
    else
        lseek(fd, 0, SEEK_SET);

    while (fake_fgets(Buf, sizeof(Buf), fd))
    {
        line++;
        ptr = Buf;
        while (ISSPACE(*ptr))
            ptr++;
        if(*ptr == 0 || (version == 0 && *ptr == '#'))
            continue;       /* blank or comment line */
        name = next_arg(&ptr);
        slimit = next_arg(&ptr);
        slevel = next_arg(&ptr);
        topic = next_arg(&ptr);
        if(!name || !slimit || !slevel || !topic)
        {
            log_message_level(LOG_LEVEL_ERROR, "load_channels: %s:%d: too few parameters", path, line);
            continue;
        }
        /* force new channel name restrictions */
        if(option(ON_IRC_CHANNELS) && *name != '#' && *name != '&')
        {
            snprintf(realname, sizeof(realname), "#%s", name);
            name = realname;
        }
        if(invalid_channel(name))
        {
            log_message_level(LOG_LEVEL_ERROR, "load_channels: %s:%d: %s: invalid channel name", name);
            continue;
        }
        level = get_level(slevel);
        if(level == -1)
        {
            log_message_level(LOG_LEVEL_ERROR, "load_channels: %s:%d: %s: invalid level", path, line, slevel);
            continue;
        }
        limit = atoi(slimit);
        if(limit < 0 || limit > 65535)
        {
            log_message_level(LOG_LEVEL_ERROR, "load_channels: %s:%d: %d: invalid limit", path, line, limit);
            continue;
        }
        chan = hash_lookup(global.channelHash, name);
        if(chan)
        {
            log_message_level(LOG_LEVEL_ERROR, "load_channels: %s:%d: %s is already defined", path, line, name);
            continue;
        }
        chan = new_channel();
        if(chan)
        {
            chan->name = STRDUP(name);
            chan->topic = STRDUP(topic);
            chan->limit = limit;
            chan->level = level;
            chan->flags = ON_CHANNEL_REGISTERED;
            chan->timestamp = global.current_time;
        }
        if(hash_add(global.channelHash, chan->name, chan))
            free_channel(chan);
    }
    close(fd);
}

static void dump_channel_cb(CHANNEL * chan, int fd)
{
    char buf[500];
    /* only save registered channels */
    if(chan->flags & ON_CHANNEL_REGISTERED)
    {
        snprintf(buf, sizeof(buf), "%.100s %d %.100s \"%.100s\"%s", chan->name, chan->limit, Levels[chan->level], chan->topic, LE);
        fake_fputs(buf, fd);
    }
}

void dump_channels(void)
{
    char    path[_POSIX_PATH_MAX], tmppath[_POSIX_PATH_MAX];
    int     fd;
    struct  stat sts;

    snprintf(tmppath, sizeof(tmppath), "%s/channels.tmp", global.varDir);
    if((fd = open(tmppath, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR ))==-1)
    {
        logerr("dump_channels", tmppath);
        return;
    }
    fake_fputs(":version 1", fd);
    fake_fputs(LE, fd);
    hash_foreach(global.channelHash, (hash_callback_t) dump_channel_cb, (void *) fd);
    if(close(fd)) 
	{
        logerr("dump_channels", "close");
    }
    snprintf(path, sizeof(path), "%s/channels", global.varDir);
    if(stat(path, &sts) == -1 && errno == ENOENT)
    {
        log_message_level(LOG_LEVEL_DEBUG, "%s file does not exist\n", path);
    }
    else 
	{
        if(unlink(path))
            logerr("dump_channels", "unlink");       /* not fatal, may not exist */
    }
    if(rename(tmppath, path)) 
	{
        logerr("dump_channels", "rename");
        return;
    }
}

/* 422/423 [ :<sender> ] <channel> <user!ip> ["<reason>"]
* (un)ban a user/ip from the channel
*/
HANDLER(channel_ban)
{
    CHANNEL *chan;
    char   *av[3], *sender;
    int     ac = -1;
    LIST  **list, *tmp;
    BAN    *b = 0;
    char   *banptr, realban[256];
    USER   *senderUser;
    int     found = 0;

    (void) len;
    ASSERT(validate_connection(con));
    if(pop_user_server(con, tag, &pkt, &sender, &senderUser))
        return;
    if(pkt)
        ac = split_line(av, FIELDS(av), pkt);
    if(ac < 2)
    {
        unparsable(con);
        return;
    }
    chan = hash_lookup(global.channelHash, av[0]);
    if(!chan)
    {
        if(ISUSER(con))
            send_cmd(con, MSG_SERVER_NOSUCH, "channel ban failed: no such channel");
        return;
    }

    if(ISSERVER(con) && chan->local)
    {
        log_message_level(LOG_LEVEL_SECURITY, "channel_ban: server %s accessed local channel %s", con->host, chan->name);
        return;
    }

    /* check for permission */
    if(senderUser && senderUser->level < LEVEL_MODERATOR && !is_chanop(chan, senderUser))
    {
        if(ISUSER(con))
            send_cmd(con, MSG_SERVER_NOSUCH, "channel ban failed: you are not operator");
        return;
    }

    banptr = normalize_ban(av[1], realban, sizeof(realban));

    /* ensure this user/ip is not already banned */
    for (list = &chan->bans; *list; list = &(*list)->next)
    {
        b = (*list)->data;
        if(!strcasecmp(b->target, banptr))
        {
            if(tag == MSG_CLIENT_CHANNEL_BAN)
                return;     /* ignore, already banned */
            else
            {
                /* unban */
                ASSERT(tag == MSG_CLIENT_CHANNEL_UNBAN);
                tmp = *list;
                *list = (*list)->next;
                FREE(tmp);
                free_ban(b);
                found = 1;
            }
            break;
        }
    }

    if(ac > 2)
        truncate_reason(av[2]);

    if(tag == MSG_CLIENT_CHANNEL_BAN)
    {
        /* new ban */
        b = CALLOC(1, sizeof(BAN));
        if(b)
        {
            strcpy(b->setby, sender);
            strcpy(b->target, banptr);
            b->when = global.current_time;
            if(ac > 2)
                strcpy(b->reason, av[2]);
        }
        if(!b)
        {
            OUTOFMEMORY("channel_ban");
            return;
        }
        tmp = CALLOC(1, sizeof(LIST));
        if(!tmp)
        {
            OUTOFMEMORY("channel_ban");
            free_ban(b);
            return;
        }
        tmp->data = b;
        chan->bans = list_push(chan->bans, tmp);
    }
    else if(!found)
    {
        /* attempted to unban something that wasn't banned */
        if(ISUSER(con))
            send_cmd(con, MSG_SERVER_NOSUCH, "channel unban failed: no such ban");
        return;
    }

    /* don't reference `b' here since it is free'd when unbanning */

    if(!chan->local)
        pass_message_args(con, tag, ":%s %s %s \"%s\"", sender, chan->name, banptr, (ac > 2) ? av[2] : "");

    notify_ops(chan, "%s%s %sbanned %s from %s: %s", !senderUser ? "Server " : "", sender, (tag == MSG_CLIENT_CHANNEL_UNBAN) ? "un" : "", banptr, chan->name, (ac > 2) ? av[2] : "");
}

/* 420 <channel> */
HANDLER(channel_banlist)
{
    CHANNEL *chan;
    LIST   *list;
    BAN    *b;

    (void) len;
    CHECK_USER_CLASS("channel_banlist");
    chan = hash_lookup(global.channelHash, pkt);
    if(!chan)
    {
        nosuchchannel(con);
        return;
    }
    for (list = chan->bans; list; list = list->next)
    {
        b = list->data;
        /* TODO: i have no idea what the real format of this is.  nap v1.0 just displays whatever the server returns */
        send_cmd(con, MSG_SERVER_CHANNEL_BAN_LIST, "%s %s \"%s\" %u %d", b->target, b->setby, NONULL(b->reason), (int) b->when, b->timeout);
    }
    /* TODO: i assume the list is terminated in the same fashion the other list commands are */
    send_cmd(con, tag, "");
}

void sync_channel_bans(CONNECTION * con, CHANNEL * chan)
{
    LIST   *list;
    BAN    *banptr;

    ASSERT(chan->local == 0);
    for (list = chan->bans; list; list = list->next)
    {
        banptr = list->data;
        send_cmd(con, MSG_CLIENT_CHANNEL_BAN, ":%s %s %s \"%s\"", global.serverName, chan->name, banptr->target, NONULL(banptr->reason));
    }
}

/* 424 [ :<sender> ] <channel> */
HANDLER(channel_clear_bans)
{
    USER   *sender;
    CHANNEL *chan;

    (void) len;
    ASSERT(validate_connection(con));
    if(pop_user(con, &pkt, &sender))
        return;
    if(!pkt)
    {
        unparsable(con);
        return;
    }
    chan = hash_lookup(global.channelHash, pkt);
    if(!chan)
    {
        nosuchchannel(con);
        return;
    }

    if(ISSERVER(con) && chan->local)
    {
        log_message_level(LOG_LEVEL_SECURITY, "clear_channel_bans: server %s accessed local channel %s", con->host, chan->name);
        return;
    }

    if(sender->level < LEVEL_MODERATOR)
    {
        if(list_find(sender->channels, chan) == 0)
        {
            /* not on the channel */
            if(ISUSER(con))
                send_cmd(con, MSG_SERVER_NOSUCH, "channel ban clear failed: you are not on that channel");
            return;
        }
        else if(!is_chanop(chan, sender))
        {
            if(ISUSER(con))
                send_cmd(con, MSG_SERVER_NOSUCH, "channel ban clear failed: you are not channel operator");
            return;
        }
    }

    /* pass just in case servers are desynched */
    if(!chan->local)
        pass_message_args(con, tag, ":%s %s", sender->nick, chan->name);

    if(!chan->bans)
    {
        if(ISUSER(con))
            send_cmd(con, MSG_SERVER_NOSUCH, "There are no bans");
        return;
    }
    list_free(chan->bans, (list_destroy_t) free_ban);
    chan->bans = 0;
    notify_ops(chan, "%s cleared the ban list on %s", sender->nick, chan->name);
}

CHANUSER *find_chanuser(LIST * list, USER * user)
{
    CHANUSER *chanUser;

    for (; list; list = list->next)
    {
        chanUser = list->data;
        ASSERT(chanUser->magic == MAGIC_CHANUSER);
        if(chanUser->user == user)
            return chanUser;
    }
    return 0;
}

static void mass_deop(CHANNEL *chan)
{
    CHANUSER *cu;
    LIST *list;

    for (list = chan->users; list; list=list->next)
    {
        cu = list->data;
        if(cu->flags & ON_CHANNEL_OPERATOR)
        {
            cu->flags &= ~ON_CHANNEL_OPERATOR;
            if(ISUSER(cu->user->con))
            {
                send_cmd(cu->user->con, MSG_SERVER_NOSUCH, "%s deopped you on channel %s: timestamp", global.serverName, chan->name);
                /* don't bother with a notify_chanops() since all ops are
                * currently invalid.
                */
            }
        }
    }
}

/* icky, but we need to find the timestamp quickly.  this is the max number
* of ops/voice that can appear on one line
*/
#define MAX_OPS 6

/* 10204/10205 [ :<sender> ] <channel> <nick> [nick ... [:timestamp] ]
* 10211/10212
* op/deop/voice/unvoice channel user
*/
HANDLER(channel_op)
{
    char   *sender;
    CHANNEL *chan;
    CHANUSER *chanUser = 0;
    USER   *user, *senderUser = 0;
    int     ac = -1;
    char   *av[MAX_OPS + 2];
    int     j;
    char   *ops = 0;
    int     ts;
    int     bit;
    int     give;
    char   *desc;       /* description of operation */

    ASSERT(validate_connection(con));

    (void) len;
    if(pop_user_server(con, tag, &pkt, &sender, &senderUser))
        return;
    if(pkt)
        ac = split_line(av, FIELDS(av), pkt);

    if(ac < 1)
    {
        unparsable(con);
        return;
    }

    chan = hash_lookup(global.channelHash, av[0]);
    if(!chan)
    {
        nosuchchannel(con);
        return;
    }

    if(tag == MSG_CLIENT_OP)
    {
        bit = ON_CHANNEL_OPERATOR;
        give = 1;
        desc = "opp";
    }
    else if(tag == MSG_CLIENT_DEOP)
    {
        bit = ON_CHANNEL_OPERATOR;
        give = 0;
        desc = "deopp";
    }
    else if(tag == MSG_CLIENT_CHANNEL_VOICE)
    {
        bit = ON_CHANNEL_VOICE;
        give = 1;
        desc = "voic";
    }
    else
    {
        ASSERT(tag == MSG_CLIENT_CHANNEL_UNVOICE);
        bit = ON_CHANNEL_VOICE;
        give = 0;
        desc = "devoic";
    }

    if(ac == 1)
    {
        LIST   *list;

        /*user requested a list */
        CHECK_USER_CLASS("channel_op");

        send_cmd(con, MSG_CLIENT_PRIVMSG, "ChanServ %sed users on channel %s:", desc, chan->name);
        for (list = chan->users; list; list = list->next)
        {
            chanUser = list->data;
            if(chanUser->flags & bit)
                send_cmd(con, MSG_CLIENT_PRIVMSG, "ChanServ %s", chanUser->user->nick);
        }
        return;
    }

    /* check timestamp if present */
    if(ISSERVER(con))
    {
        if(chan->local)
        {
            log_message_level(LOG_LEVEL_SECURITY, "channel_op: server %s accessed local channel %s", con->host, chan->name);
            return;
        }

        if(*av[ac - 1] == ':')
        {
            ts = atoi(av[ac - 1] + 1);

            ac--;       /* don't count this in the loops below */

            if(chan->timestamp > 0)
            {
                if(ts > chan->timestamp)
                {
                    /* remote server is desynced */
                    log_message_level(LOG_LEVEL_ERROR, "channel_op: newer TS for channel %s from server %s", chan->name, con->host);
                    log_message_level(LOG_LEVEL_ERROR, "channel_op: ts=%d chan->timestamp=%u", ts, chan->timestamp);
                    return; /* ignore it */
                }
                else if(ts < chan->timestamp)
                {
                    /* channel existed on remote server prior to creation
                    * on this server, deop everyone that we know
                    * about
                    */
                    log_message_level(LOG_LEVEL_ERROR, "channel_op: older TS for channel %s from server %s", chan->name, con->host);
                    log_message_level(LOG_LEVEL_ERROR, "channel_op: ts=%d chan->timestamp=%u", ts, chan->timestamp);
                    mass_deop(chan);
                }
            }
			chan->timestamp = ts;   /* update */
        }
    }

    /* check for permission */
    if(senderUser && senderUser->level < LEVEL_MODERATOR)
    {
        /* if not a mod+, user must be a chanop on the channel */
        if(!is_chanop(chan, senderUser))
        {
            if(ISUSER(con))
            {
                send_cmd(con, MSG_SERVER_NOSUCH, "channel %s failed: you are not channel operator", desc);
            }
            else
            {
                /* desync */
                log_message_level(LOG_LEVEL_SECURITY, "channel_op: %s is not opped on channel %s", senderUser->nick, chan->name);
            }
            return;
        }
    }

    for (j = 1; j < ac; j++)
    {
        user = hash_lookup(global.usersHash, av[j]);
        if(user)
        {
            chanUser = find_chanuser(chan->users, user);
            if(chanUser)
            {
                if(give)
                {
                    if((chanUser->flags & bit) == 0)
                    {
                        /* not opped yet */
                        if(ISUSER(user->con))
                            send_cmd(user->con, MSG_SERVER_NOSUCH, "%s%s %sed you on channel %s", !senderUser ? "Server " : "", sender, desc, chan->name);
                        notify_ops(chan, "%s%s %sed %s on channel %s", !senderUser ? "Server " : "", sender, desc, user->nick, chan->name);
                        chanUser->flags |= bit;
                        if(!chan->local)
                            ops = append_string(ops, " %s", user->nick);
                    }
                }
                else
                {
                    ASSERT(give == 0);
                    if(chanUser->flags & bit)
                    {
                        if(ISUSER(user->con))
                            send_cmd(user->con, MSG_SERVER_NOSUCH, "%s%s %sed you on channel %s", !senderUser ? "Server " : "", sender, desc, chan->name);
                        notify_ops(chan, "%s%s %sed %s on channel %s", !senderUser ? "Server " : "", sender, desc, user->nick, chan->name);
                        chanUser->flags &= ~bit;
                        if(!chan->local)
                            ops = append_string(ops, " %s", user->nick);
                    }
                }
            }
            else
            {
                if(ISUSER(con))
                    send_cmd(con, MSG_SERVER_NOSUCH, "channel %s failed: user is not on channel", desc);
            }
        }
        else
        {
            if(ISUSER(con))
                send_cmd(con, MSG_SERVER_NOSUCH, "channel %s failed: no such user", desc);
        }
    }

    /* if anything changed, pass along info to peer servers */
    if(ops)
    {
        ASSERT(chan->local == 0);
        /* pass the message on to the other servers */
        pass_message_args(con, tag, ":%s %s %s :%u", sender, chan->name, ops, chan->timestamp);
        FREE(ops);
    }
}

void notify_ops(CHANNEL * chan, const char *fmt, ...)
{
    LIST   *list;
    CHANUSER *chanUser;
    char    buf[256];
    int     len;

    va_list ap;

    va_start(ap, fmt);
    vsnprintf(buf + 4, sizeof(buf) - 4, fmt, ap);
    va_end(ap);
    len = strlen(buf + 4);
    set_len(buf, len);
    set_tag(buf, MSG_SERVER_NOSUCH);
    for (list = chan->users; list; list = list->next)
    {
        chanUser = list->data;
        ASSERT(chanUser->magic == MAGIC_CHANUSER);
        if(ISUSER(chanUser->user->con) && ((chanUser->flags & ON_CHANNEL_OPERATOR) || chanUser->user->level > LEVEL_USER)) 
        {
            queue_data(chanUser->user->con, buf, 4 + len);
        }
    }
}

/* 10208 [ :<sender> ] <channel> <text>
sends a message to all channel ops/mods on a given channel */
HANDLER(channel_wallop)
{
    USER   *sender;
    CHANNEL *chan;
    char   *chanName;
    char   *sender_name;

    (void) len;
    ASSERT(validate_connection(con));

    if(pop_user_server(con, tag, &pkt, &sender_name, &sender))
        return;

    chanName = next_arg(&pkt);
    if(!chanName || !pkt)
    {
        unparsable(con);
        return;
    }
    chan = hash_lookup(global.channelHash, chanName);
    if(!chan)
    {
        if(ISUSER(con))
            send_cmd(con, MSG_SERVER_NOSUCH, "channel wallop failed: no such channel");
        return;
    }
    if(sender && sender->level < LEVEL_MODERATOR && !is_chanop(chan, sender))
    {
        if(ISUSER(con))
            send_cmd(con, MSG_SERVER_NOSUCH, "channel wallop failed: you are not channel operator");
        return;
    }
    /* NOTE: there is no check to make sure the sender is actually a member
    of the channel.  this should be ok since channel ops have to be present
    in the channel to issue the command (since they would not have op
    status otherwise, and is_chanop() will fail).  mods+ are assumed to
    be trusted enough that the check for membership is not required. */
    if(!chan->local)
        pass_message_args(con, tag, ":%s %s %s", sender_name, chan->name, pkt);
    notify_ops(chan, "%s [ops/%s]: %s", sender_name, chan->name, pkt);
}

static void add_flag(char *d, int dsize, char *flag, int bit, int onmask, int offmask)
{
    if((onmask & bit) || (offmask & bit))
    {
        int     len = strlen(d);

        snprintf(d + len, dsize - len, "%s%c%s", dsize > 0 ? " " : "", (onmask & bit) ? '+' : '-', flag);
    }
}

static int channel_mode_bit(const char *s)
{
    if(!strcasecmp("topic", s))
        return ON_CHANNEL_TOPIC;
    if(!strcasecmp("registered", s))
        return ON_CHANNEL_REGISTERED;
    if(!strcasecmp("private", s))
        return ON_CHANNEL_PRIVATE;
    if(!strcasecmp("invite", s))
        return ON_CHANNEL_INVITE;
    if(!strcasecmp("moderated", s))
        return ON_CHANNEL_MODERATED;
    return -1;
}

#define MAX_MODE 5

/* 10209 [ :<sender> ] <channel> [mode]
change/display channel mode */
HANDLER(channel_mode)
{
    char   *senderName;
    USER   *sender;
    CHANNEL *chan;
    int     onmask = 0, offmask = 0, bit;
    int     ac = -1;
    char   *av[MAX_MODE + 1];
    int     j;

    (void) len;
    ASSERT(validate_connection(con));
    if(pop_user_server(con, tag, &pkt, &senderName, &sender))
        return;
    if(pkt)
        ac = split_line(av, FIELDS(av), pkt);
    if(ac < 1)
    {
        unparsable(con);
        return;
    }
    chan = hash_lookup(global.channelHash, av[0]);
    if(!chan)
    {
        nosuchchannel(con);
        return;
    }

    /* if no args are given, return the current mode */
    if(ac == 1)
    {
        CHECK_USER_CLASS("channel_mode");
        send_cmd(con, MSG_SERVER_NOSUCH, "mode for channel %s%s%s%s%s%s%s",
            chan->name,
            (chan->flags & ON_CHANNEL_PRIVATE) ? " +PRIVATE" : "",
            (chan->flags & ON_CHANNEL_MODERATED) ? " +MODERATED" : "",
            (chan->flags & ON_CHANNEL_INVITE) ? " +INVITE" : "",
            (chan->flags & ON_CHANNEL_TOPIC) ? " +TOPIC" : "",
            (chan->flags & ON_CHANNEL_REGISTERED) ? " +REGISTERED" : "",
            (chan->flags & ON_CHANNEL_QUIET) ? " +QUIET" : "");
        return;
    }

    /* check for permission */
    if(sender && sender->level < LEVEL_MODERATOR && !is_chanop(chan, sender))
    {
        if(ISUSER(con))
            send_cmd(con, MSG_SERVER_NOSUCH, "channel mode failed: you are not operator");
        return;
    }

    for (j = 1; j < ac; j++)
    {
        if(*av[j] != '+' && *av[j] != '-')
        {
            if(ISUSER(con))
                send_cmd(con, MSG_SERVER_NOSUCH, "channel mode failed: invalid prefix");
            continue;
        }

        bit = channel_mode_bit(av[j] + 1);
        if(bit == ON_CHANNEL_REGISTERED)
        {
            if(sender && sender->level < LEVEL_MODERATOR)
            {
                if(ISUSER(con))
                    send_cmd(con, MSG_SERVER_NOSUCH, "channel mode failed: only mods+ can register channels");
                continue;
            }
        }
        else if(bit == -1)
        {
            if(ISUSER(con))
                send_cmd(con, MSG_SERVER_NOSUCH, "channel mode failed: invalid mode");
            continue;       /* unknown flag */
        }

        if(*av[j] == '+')
        {
            onmask |= bit;
            offmask &= ~bit;
            if((chan->flags & bit) == 0)
                chan->flags |= bit;
            else
                onmask &= ~bit; /* already set */
        }
        else
        {
            ASSERT(*av[j] == '-');
            offmask |= bit;
            onmask &= ~bit;
            if(chan->flags & bit)
                chan->flags &= ~bit;
            else
                offmask &= ~bit;    /* not set */
        }
    }

    /* only take action if something actually changed */
    if(onmask || offmask)
    {
        char    msg[512];

        msg[0] = 0;
        add_flag(msg, sizeof(msg), "PRIVATE", ON_CHANNEL_PRIVATE, onmask, offmask);
        add_flag(msg, sizeof(msg), "MODERATED", ON_CHANNEL_MODERATED, onmask, offmask);
        add_flag(msg, sizeof(msg), "INVITE", ON_CHANNEL_INVITE, onmask, offmask);
        add_flag(msg, sizeof(msg), "TOPIC", ON_CHANNEL_TOPIC, onmask, offmask);
        add_flag(msg, sizeof(msg), "REGISTERED", ON_CHANNEL_REGISTERED, onmask, offmask);
        notify_ops(chan, "%s%s changed mode on channel %s:%s", !sender ? "Server " : "", senderName, chan->name, msg);

        if(!chan->local)
            pass_message_args(con, tag, ":%s %s %s", senderName, chan->name, msg);

        /* handle the -REGISTERED case here.  if there are no users in the
        * channel, we get rid of it
        */
        if((offmask & ON_CHANNEL_REGISTERED) && !chan->users)
        {
            log_message_level(LOG_LEVEL_CHANNEL, "channel_mode: destroying channel %s", chan->name);
            hash_remove(global.channelHash, chan->name);
        }
    }
}

static int is_member(CHANNEL * chan, USER * user)
{
    LIST   *list;
    CHANUSER *chanUser;

    for (list = chan->users; list; list = list->next)
    {
        chanUser = list->data;
        if(chanUser->user == user)
            return 1;
    }
    return 0;
}

/* 10210 [ :<sender> ] <channel> <user>
invite a user to a channel */
HANDLER(channel_invite)
{
    USER   *sender, *user;
    int     ac = -1;
    char   *av[2];
    char   *sender_name;
    LIST   *list;
    CHANNEL *chan;

    (void) len;
    ASSERT(validate_connection(con));
    if(pop_user_server(con, tag, &pkt, &sender_name, &sender))
        return;
    if(pkt)
        ac = split_line(av, FIELDS(av), pkt);
    if(ac < 2)
    {
        unparsable(con);
        return;
    }
    chan = hash_lookup(global.channelHash, av[0]);
    if(!chan)
    {
        nosuchchannel(con);
        return;
    }
    if(ISSERVER(con) && chan->local)
    {
        log_message_level(LOG_LEVEL_CHANNEL, "channel_invite: server %s accessed local channel %s", con->host, chan->name);
        return;
    }
    if(!(chan->flags & ON_CHANNEL_INVITE))
    {
        if(ISUSER(con))
            send_cmd(con, MSG_SERVER_NOSUCH, "channel is not invite only");
        return;
    }
    /*ensure the user is on this channel */
    if(sender->level < LEVEL_MODERATOR && !is_member (chan, sender))
    {
        permission_denied(con);
        return;
    }
    user = hash_lookup(global.usersHash, av[1]);
    if(!user)
    {
        nosuchuser(con);
        return;
    }
    if(is_member(chan, user))
    {
        if(ISUSER(con))
            send_cmd(con, MSG_SERVER_NOSUCH, "user is already in channel");
        return;
    }
    /*ensure the user is not already invited */
    if(list_find(chan->invited, user))
        return;         /* already invited */

    list = CALLOC(1, sizeof(LIST));
    list->data = user;
    list->next = chan->invited;
    chan->invited = list;

    if(!chan->local)
        pass_message_args(con, tag, ":%s %s %s", sender->nick, chan->name, user->nick);

    if(ISUSER(user->con))
    {
        send_cmd(user->con, MSG_SERVER_NOSUCH, "%s invited you to channel %s", sender->nick, chan->name);
    }

    notify_ops(chan, "%s invited %s to channel %s", sender->nick, user->nick, chan->name);
}

/* 10213/10214 [:sender] <channel> <user> ["reason"]
channel muzzle/unmuzzle */
HANDLER(channel_muzzle)
{
    char   *senderName;
    USER   *sender, *user;
    CHANNEL *chan;
    LIST   *list;
    CHANUSER *chanUser;
    int     ac = -1;
    char   *av[3];

    (void) len;
    ASSERT(validate_connection(con));
    if(pop_user_server(con, tag, &pkt, &senderName, &sender))
        return;
    if(pkt)
        ac = split_line(av, FIELDS(av), pkt);
    if(ac < 1)
    {
        unparsable(con);
        return;
    }
    chan = hash_lookup(global.channelHash, av[0]);
    if(!chan)
    {
        nosuchchannel(con);
        return;
    }

    /* list muzzled users */
    if(ac == 1)
    {
        LIST   *list;

        CHECK_USER_CLASS("channel_muzzle");
        send_cmd(con, MSG_CLIENT_PRIVMSG, "ChanServ muzzled users on channel %s:", chan->name);
        for (list = chan->users; list; list = list->next)
        {
            chanUser = list->data;
            if(chanUser->flags & ON_CHANNEL_VOICE)
                send_cmd(con, MSG_CLIENT_PRIVMSG, "ChanServ %s", chanUser->user->nick);
        }
        return;
    }

    /* find target user */
    user = hash_lookup(global.usersHash, av[1]);
    if(!user)
    {
        nosuchuser(con);
        return;
    }

    if(sender && sender->level < LEVEL_MODERATOR
        && !is_chanop(chan, sender))
    {
        if(ISUSER(con))
            send_cmd(con, MSG_SERVER_NOSUCH, "channel muzzle failed: you are not operator");
        return;
    }

    for (list = chan->users; list; list = list->next)
    {
        chanUser = list->data;
        if(chanUser->user == user)
        {
            if(tag == MSG_CLIENT_CHANNEL_MUZZLE)
            {
                chanUser->flags |= ON_CHANNEL_MUZZLED;
            }
            else
                chanUser->flags &= ~ON_CHANNEL_MUZZLED;
            if(ISUSER(chanUser->user->con))
            {
                char   *who;

                if(sender && sender->cloaked && chanUser->user->level < LEVEL_MODERATOR)
                    who = "Operator";
                else
                    who = senderName;

                send_cmd(chanUser->user->con, MSG_SERVER_NOSUCH,
                    "%s%s %smuzzled you on channel %s: %s",
                    !sender ? "Server " : "", who,
                    (chanUser->flags & ON_CHANNEL_MUZZLED) ? "" : "un",
                    chan->name, (ac > 2) ? av[2] : "");
            }
            notify_ops(chan, "%s%s %smuzzled %s on channel %s: %s",
                !sender ? "Server " : "",
                senderName,
                (chanUser->flags & ON_CHANNEL_MUZZLED) ? "" : "un",
                user->nick, chan->name, (ac > 2) ? av[2] : "");
            break;
        }
    }
    if(!chan->local)
        pass_message_args(con, tag, ":%s %s %s \"%s\"", senderName, chan->name, user->nick, (ac > 2) ? av[2] : "");
}
