/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
This is free software distributed under the terms of the
GNU Public License.  See the file COPYING for details.

$Id: serverlib.c 434 2006-09-03 17:48:47Z reech $ */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef WIN32
# include <unistd.h>
#endif
#include "opennap.h"
#include "debug.h"

void send_cmd(CONNECTION * con, unsigned int msgtype, const char *fmt, ...)
{
    va_list ap;
    size_t  l;

    va_start(ap, fmt);
    vsnprintf(Buf + 4, sizeof(Buf) - 4, fmt, ap);
    va_end(ap);

    set_tag(Buf, msgtype);
    l = strlen(Buf + 4);
    set_len(Buf, l);
    queue_data(con, Buf, 4 + l);
}

/* wrapper for pass_message() */
void pass_message_args(CONNECTION * con, u_int msgtype, const char *fmt, ...)
{
    va_list ap;
    size_t  l;

    if(!global.serversList)
        return;         /* nothing to do */

    va_start(ap, fmt);
    vsnprintf(Buf + 4, sizeof(Buf) - 4, fmt, ap);
    va_end(ap);
    set_tag(Buf, msgtype);
    l = strlen(Buf + 4);
    set_len(Buf, l);
    pass_message(con, Buf, l + 4);
}

/* this function sends a command to an arbitrary user without the caller
needing to know if its a local client or not */
void send_user(USER * user, int tag, char *fmt, ...)
{
    int     len, offset;
    va_list ap;

    if(user->local)
    {
        /* deliver directly */
        va_start(ap, fmt);
        vsnprintf(Buf + 4, sizeof(Buf) - 4, fmt, ap);
        va_end(ap);
        set_tag(Buf, tag);
        len = strlen(Buf + 4);
        set_len(Buf, len);
    }
    else
    {
        /* encapsulate and send to remote server */
        snprintf(Buf + 4, sizeof(Buf) - 4, ":%s %s ", global.serverName, user->nick);
        offset = strlen(Buf + 4);
        set_tag(Buf, MSG_SERVER_ENCAPSULATED);
        va_start(ap, fmt);
        vsnprintf(Buf + 8 + offset, sizeof(Buf) - 8 - offset, fmt, ap);
        va_end(ap);
        set_tag(Buf + 4 + offset, tag);
        len = strlen(Buf + 8 + offset);
        set_len(Buf + 4 + offset, len);
        len += offset + 4;
        set_len(Buf, len);
    }
    queue_data(user->con, Buf, len + 4);
}

/* no such user */
void nosuchuser(CONNECTION * con)
{
    ASSERT(validate_connection(con));
    if(ISUSER(con))
        send_cmd(con, MSG_SERVER_NOSUCH, "User is not currently online.");
}

void permission_denied(CONNECTION * con)
{
    ASSERT(validate_connection(con));
    if(ISUSER(con))
        send_cmd(con, MSG_SERVER_NOSUCH, "permission denied");
}

/* send a message to all peer servers.  `con' is the connection the message
was received from and is used to avoid sending the message back from where
it originated. */
void pass_message(CONNECTION * con, char *pkt, size_t pktlen)
{
    LIST   *list;

    for (list = global.serversList; list; list = list->next)
        if(list->data != con)
            queue_data(list->data, pkt, pktlen);
}

/* destroys memory associated with the CHANNEL struct.  this is usually
not called directly, but in association with the hash_remove() and
hash_destroy() calls */
void free_channel(CHANNEL * chan)
{
    ASSERT(validate_channel(chan));
    FREE(chan->name);
    if(chan->topic)
        FREE(chan->topic);
    ASSERT(chan->users == 0);
    list_free(chan->users, 0);
    list_free(chan->bans, (list_destroy_t) free_ban);
    ASSERT(chan->invited == 0);
    list_free(chan->invited, 0);   /* free invite list */
    FREE(chan);
}

#ifdef ONAP_DEBUG
int validate_connection(CONNECTION * con)
{
    /* does not work with mempool */
    ASSERT_RETURN_IF_FAIL(VALID_LEN(con, sizeof(CONNECTION)), 0);
    ASSERT_RETURN_IF_FAIL(con->magic == MAGIC_CONNECTION, 0);
    ASSERT_RETURN_IF_FAIL((con->class == CLASS_USER) ^ (con->user == 0), 0);
    ASSERT_RETURN_IF_FAIL(VALID_STR(con->host), 0);
    if(con->sendbuf)
        ASSERT_RETURN_IF_FAIL(buffer_validate(con->sendbuf), 0);
    if(con->recvbuf)
        ASSERT_RETURN_IF_FAIL(buffer_validate(con->recvbuf), 0);
    if(ISUSER(con))
    {
        if(con->uopt)
        {
            ASSERT_RETURN_IF_FAIL(VALID_LEN(con->uopt, sizeof(USEROPT)), 0);
            ASSERT_RETURN_IF_FAIL(list_validate(con->uopt->hotlist), 0);
        }
    }
    return 1;
}

int validate_user(USER * user)
{
    /* this doesn't work with the mempool since it is an offset into
    a preallocated chunk */
    ASSERT_RETURN_IF_FAIL(VALID_LEN(user, sizeof(USER)), 0);
    ASSERT_RETURN_IF_FAIL(user->magic == MAGIC_USER, 0);
    ASSERT_RETURN_IF_FAIL(VALID_STR(user->nick), 0);
    ASSERT_RETURN_IF_FAIL(VALID_STR(user->clientinfo), 0);
    ASSERT_RETURN_IF_FAIL(user->con == 0 || VALID_LEN(user->con, sizeof(CONNECTION)), 0);
    ASSERT_RETURN_IF_FAIL(list_validate(user->channels), 0);
    return 1;
}

int validate_channel(CHANNEL * chan)
{
    ASSERT_RETURN_IF_FAIL(VALID_LEN(chan, sizeof(CHANNEL)), 0);
    ASSERT_RETURN_IF_FAIL(chan->magic == MAGIC_CHANNEL, 0);
    ASSERT_RETURN_IF_FAIL(VALID_STR(chan->name), 0);
    ASSERT_RETURN_IF_FAIL(list_validate(chan->users), 0);
    return 1;
}
#endif

/* like pop_user(), but allows `nick' to be another server */
int pop_user_server(CONNECTION * con, int tag, char **pkt, char **nick, USER ** user)
{
    if(ISSERVER(con))
    {
        if(**pkt != ':')
        {
            log_message_level( LOG_LEVEL_SERVER, "pop_user_server: (tag %d) server message missing sender (from %s)", tag, con->host);
            return -1;
        }
        (*pkt)++;
        *nick = next_arg(pkt);
        if(!is_server (*nick))
        {
            *user = hash_lookup(global.usersHash, *nick);
            if(!*user)
            {
                log_message_level( LOG_LEVEL_SERVER, "pop_user_server: (tag %d) could not find user %s (from %s)",tag, *nick, con->host);
                return -1;
            }
        }
        else
            *user = 0;
    }
    else
    {
        ASSERT(ISUSER(con));
        *user = con->user;
        *nick = (*user)->nick;
    }
    return 0;
}

int pop_user(CONNECTION * con, char **pkt, USER ** user)
{
    ASSERT(validate_connection(con));
    ASSERT(pkt != 0 && *pkt != 0);
    ASSERT(user != 0);
    if(ISSERVER(con))
    {
        char   *ptr;

        if(**pkt != ':')
        {
            /*      log_message_level( LOG_LEVEL_SERVER, "pop_user: (tag %d) server message did not contain nick: %s",global.current_tag, *pkt); */
            return -1;
        }
        ++*pkt;
        ptr = next_arg(pkt);
        *user = hash_lookup(global.usersHash, ptr);
        if(!*user)
        {
            /*      log_message_level( LOG_LEVEL_SERVER, "pop_user: (tag %d) could not find user %s",global.current_tag, ptr); */
            return -1;
        }

        /* this should not return a user who is local to us.  if so, it
        means that some other server has passed us back a message we
        sent to them */
        if((*user)->local)
        {
            log_message_level( LOG_LEVEL_DEBUG, "pop_user: (tag %d) error, received server message for local user!",global.current_tag); 
            return -1;
        }
    }
    else
    {
        ASSERT(con->class == CLASS_USER);
        ASSERT(con->user != 0);
        *user = con->user;
    }
    return 0;

}

void unparsable(CONNECTION * con)
{
    ASSERT(validate_connection(con));
    if(ISUSER(con))
        send_cmd(con, MSG_SERVER_NOSUCH, "parameters are unparsable");
}

void nosuchchannel(CONNECTION * con)
{
    ASSERT(validate_connection(con));
    if(ISUSER(con))
        send_cmd(con, MSG_SERVER_NOSUCH, "no such channel");
}

/* returns nonzero if `s' is the name of a server */
int is_server(const char *s)
{
    LIST   *list;
    CONNECTION *con;
    LINK   *link;

    for (list = global.serversList; list; list = list->next)
    {
        con = list->data;
        if(!strcasecmp(s, con->host))
            return 1;
    }
    for (list = global.serverLinksList; list; list = list->next)
    {
        link = list->data;
        if(!strcasecmp(s, link->server) || !strcasecmp(s, link->peer))
            return 1;
    }
    return 0;
}

/* returns nonzero if `nick' is in list `ignore' */
int is_ignoring(LIST * ignore, const char *nick)
{
    for (; ignore; ignore = ignore->next)
        if(!strcasecmp(nick, ignore->data))
            return 1;
    return 0;
}

void invalid_channel_msg(CONNECTION * con)
{
    ASSERT(validate_connection(con));
    if(ISUSER(con))
        send_cmd(con, MSG_SERVER_NOSUCH, "invalid channel");
}

void truncate_reason(char *s)
{
    if(global.maxReason > 0 && strlen(s) > (unsigned) global.maxReason)
        *(s + global.maxReason) = 0;
}

void invalid_nick_msg(CONNECTION * con)
{
    if(ISUSER(con))
        send_cmd(con, MSG_SERVER_NOSUCH, "invalid nickname");
}

CONNECTION *new_connection(void)
{
    CONNECTION *c = CALLOC(1, sizeof(CONNECTION));

    if(!c)
    {
        OUTOFMEMORY("new_connection");
        return 0;
    }
#ifdef ONAP_DEBUG
    c->magic = MAGIC_CONNECTION;
#endif
    return c;
}

static int vform_message(char *d, int dsize, int tag, const char *fmt, va_list ap)
{
    int     len;

    vsnprintf(d + 4, dsize - 4, fmt, ap);
    len = strlen(d + 4);
    set_tag(d, tag);
    set_len(d, len);
    return(len + 4);
}

int form_message(char *d, int dsize, int tag, const char *fmt, ...)
{
    va_list ap;
    int     len;

    va_start(ap, fmt);
    len = vform_message(d, dsize, tag, fmt, ap);
    va_end(ap);
    return len;
}

void send_cmd_pre(CONNECTION * con, unsigned int tag, const char *prefix, const char *fmt, ...)
{
    va_list ap;
    int     len;

    va_start(ap, fmt);
    /* if the user's client supports use of real numerics send the raw */
    if(con->numerics) 
	{
        len = vform_message(Buf, sizeof(Buf), tag, fmt, ap);
    }
	else
	{
        /*otherwise prefix it with a descriptive string and send it as a 404 */
        strncpy(Buf + 4, prefix, sizeof(Buf) - 4);
        len = strlen(Buf + 4);
        vsnprintf(Buf + 4 + len, sizeof(Buf) - 4 - len, fmt, ap);
        len += strlen(Buf + 4 + len);
        set_tag(Buf, MSG_SERVER_NOSUCH);
        set_len(Buf, len);
        len += 4;
    }
    queue_data(con, Buf, len);
    va_end(ap);
}

static char *logLevels[] = { "SERVER", "CLIENT", "LOGIN", "FILES", "SHARE", "SEARCH", "DEBUG", "ERROR", "SECURITY", "CHANNEL", "STATS", "" };

unsigned short set_loglevel(char *mode, unsigned short level)
{
    char   *av;
    int     neg = 0;
    int     i, p;

    av = next_arg(&mode);
    while (av)
    {
        if(!strcasecmp(av, "ALL"))
            level = LOG_LEVEL_ALL;
        else if(!strcasecmp(av, "NONE"))
            level = 0;
        else if(*av == '-')
        {
            neg = 1;
            av++;
        }
        else
            neg = 0;
        for (i = 0, p = 1; *logLevels[i]; i++, p <<= 1)
        {
            if(!strcasecmp(av, logLevels[i]))
            {
                if(neg)
                    level &= (LOG_LEVEL_ALL ^ p);
                else
                    level |= p;
                break;
            }
        }
        av = next_arg(&mode);
    }
    return level;
}

char *log_level2hrf(unsigned short level, char *buffer)
{
    int     p, i, buflen;
    char    buf[250];
    if(level == 0)
        strcpy(buf, "NONE");
    else
    {
        buf[0] = 0;
        for (i = 0, p = 1; *logLevels[i]; i++, p <<= 1)
        {
            if(level & p)
            {
                buflen = strlen(buf);
                snprintf((buf + buflen), sizeof(buf) - buflen, "%s%s", buflen > 0 ? " " : "", logLevels[i]);
            }
        }
    }
    strcpy(buffer, buf);
    return buffer;
}

/* 10264 [mode] - change or report log_level */

HANDLER(log_level_cmd)
{
    USER   *sender;
    unsigned short level = 0;
    char   *sender_name;
    char   buffer[256];

    (void) tag;
    (void) len;
    CHECK_USER_CLASS("user_mode");
    ASSERT(validate_connection(con));
    if(pop_user_server(con, tag, &pkt, &sender_name, &sender))
        return;
    if(!sender)
        return;
    if(sender->level < LEVEL_ADMIN)
    {
        permission_denied(con);
        return;
    }
    if(!pkt || !*pkt)
    {
        send_cmd(con, MSG_CLIENT_PRIVMSG, "%s log_level: %s", global.serverName, log_level2hrf(global.logLevel, buffer));
        return;
    }

    level = set_loglevel(pkt, global.logLevel);
    if(global.logLevel != level)
    {
        global.logLevel = level;
        send_cmd(con, MSG_CLIENT_PRIVMSG, "%s log_level: %s", global.serverName, log_level2hrf(global.logLevel, buffer));
    }
}

