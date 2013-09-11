/* Copyright (C) 2000-1 edwards@bitchx.dimension6.com
This is free software distributed under the terms of the
GNU Public License.  See the file COPYING for details.

$Id: usermode.c 434 2006-09-03 17:48:47Z reech $ */

/*
* written by Colten Edwards.
*/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "opennap.h"
#include "debug.h"

static char *User_Levels[] = { "ERROR", "BAN", "CHANGE", "KILL", "LEVEL", "SERVER", "MUZZLE", "PORT", "WALLOP", "CLOAK", "FLOOD", "PING", "MSG", "WHOIS", "ABUSE", "" };

unsigned int UserMode_int = LOGALL_MODE;
char   *UserMode;


unsigned int set_usermode(char *mode, unsigned int level)
{
    char   *av;
    int     neg = 0;
    int     i, p;

    av = next_arg(&mode);
    while (av)
    {
        if(!strcasecmp(av, "ALL"))
            level = LOGALL_MODE;
        else if(!strcasecmp(av, "NONE"))
            level = 0;
        else if(*av == '-')
        {
            neg = 1;
            av++;
        }
        else
            neg = 0;
        for (i = 0, p = 1; *User_Levels[i]; i++, p <<= 1)
        {
            if(!strcasecmp(av, User_Levels[i]))
            {
                if(neg)
                    level &= (LOGALL_MODE ^ p);
                else
                    level |= p;
                break;
            }
        }
        av = next_arg(&mode);
    }
    return level;
}

void config_user_level(char *mode)
{
    unsigned int level = UserMode_int;
    int     i, buflen, p;
    char    buffer[300];

    if(!mode)
    {
        UserMode_int = LOGALL_MODE;
        UserMode = STRDUP("ALL");
        return;
    }
    level = set_usermode(mode, UserMode_int);
    if(level == 0 || level == LOGALL_MODE)
    {
        UserMode_int = level;
        FREE(UserMode);
        UserMode = STRDUP(level == 0 ? "NONE" : "ALL");
        return;
    }
    buffer[0] = 0;
    for (i = 0, p = 1; *User_Levels[i]; i++, p <<= 1)
    {
        if(level & p)
        {
            buflen = strlen(buffer);
            snprintf(buffer + buflen, sizeof(buffer) - buflen, "%s%s", buflen > 0 ? " " : "", User_Levels[i]);
        }
    }
    FREE(UserMode);
    UserMode = STRDUP(buffer);
    UserMode_int = level;
}

/* 10203 [mode] */
HANDLER(user_mode_cmd)
{
    USER   *sender;
    int     i, p;
    unsigned int level = 0;
    char   *sender_name;

    (void) tag;
    (void) len;
    CHECK_USER_CLASS("user_mode");
    ASSERT(validate_connection(con));
    if(pop_user_server(con, tag, &pkt, &sender_name, &sender))
        return;
    if(!pkt || !*pkt)
    {
        char    buffer[250];
        int     buflen;

        if(sender->con->uopt->usermode == 0)
            strcpy(buffer, "NONE");
        else
        {
            buffer[0] = 0;
            for (i = 0, p = 1; *User_Levels[i]; i++, p <<= 1)
            {
                if(sender->con->uopt->usermode & p)
                {
                    buflen = strlen(buffer);
                    snprintf(buffer + buflen, sizeof(buffer) - buflen, "%s%s", buflen > 0 ? " " : "", User_Levels[i]);
                }
            }
        }
        send_cmd(con, MSG_SERVER_USER_MODE, "%s", buffer);
        return;
    }

    level = set_usermode(pkt, con->uopt->usermode);
    if(sender->con->uopt->usermode != level)
        sender->con->uopt->usermode = level;
}
