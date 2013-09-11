/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
This is free software distributed under the terms of the
GNU Public License.  See the file COPYING for details.

$Id: userflags.c 434 2006-09-03 17:48:47Z reech $ */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include "opennap.h"
#include "debug.h"


char *User_Flags[] = { "MUZZLED", "FRIEND", "CRIMINAL", "" };


/* set special flags to give normal users privileges
[ :<sender> ] user [ "<flags|none>" ]
*/
HANDLER(change_userflags)
{
    USER    *sender, *user;
    USERDB  *db;
    int      i, p, neg, ac = -1;
    char    *av[2], *sender_name, *flags;

    (void) len;
    ASSERT(validate_connection(con));

    if(pop_user_server(con, tag, &pkt, &sender_name, &sender))
	{
        return;
	}

    if(sender && sender->level < global.level_to_set_flags)
    {
        permission_denied(con);
        return;
    }

    if(pkt)
        ac = split_line(av, FIELDS(av), pkt);

    /* search for users that have any flag set
    ####################################################################
    This one belongs to the gusers handler and not into the flag handler.
    meanwhile you can do a search in your local users file using:

    grep -v -e 1$ -e 0$ users

    to seek for all users having other flags than "1" and "0" set.
    ( which means all users except "muzzled" and "none" )
    ####################################################################
    */
    if(ac == 0 && ISUSER(con))
    {
		USERDB  *udb;
		HASHENT *he;
		int j;
		send_cmd(con, MSG_SERVER_NOSUCH, "local users with any flag set:");
		for (i = 0; i < global.userDbHash->numbuckets; i++) 
		{
			he = global.userDbHash->bucket[i];
			while (he) 
			{
				udb = he->data;
				if(udb->flags) 
				{
					char    buffer[250];
					int     buflen;
					/* send_cmd(con, MSG_SERVER_NOSUCH, "%s", udb->nick);  */
					buffer[0] = 0;
					for (j = 0, p = 1; *User_Flags[j]; j++, p <<= 1) 
					{
						if(udb->flags & p) 
						{
							buflen = strlen(buffer);
							snprintf(buffer + buflen, sizeof(buffer) - buflen, "%s%s", buflen > 0 ? " " : "",User_Flags[j]);
						}
					}
					send_cmd(con, MSG_SERVER_NOSUCH, "userflags for \"%s\" are: %s", udb->nick, buffer);
				}
				he = he->next;
			}
		}
		return;
    }
    else if(ac < 0)
    {
        log_message_level(LOG_LEVEL_ERROR, "change_userflags: unparsable flag request");
        unparsable(con);
        return;
    }

    /* lookup given username. user might be empty if given username is not a
    known user, db might be empty if the user is not in the userdb */
    db = hash_lookup(global.userDbHash, av[0]);
    user = hash_lookup(global.usersHash, av[0]);

    if(!db && !user)
    {
        if(ISUSER(con))
            send_cmd(con, MSG_SERVER_NOSUCH, "no such user: %s", av[0]);
        return;
    }

    /* ######## if no flags are given, the current flags for the specified user are printed */
    if( ac == 1 )
    {
        if(ISUSER(con)) 
		{
            char    buffer[250];
            int     buflen;
            buffer[0] = 0;
            for (i = 0, p = 1; *User_Flags[i]; i++, p <<= 1) 
			{
                if(db && db->flags & p) 
				{
                    buflen = strlen(buffer);
                    snprintf(buffer + buflen, sizeof(buffer) - buflen, "%s%s", buflen > 0 ? " " : "",User_Flags[i]);
                }
            }
            send_cmd(con, MSG_SERVER_NOSUCH, "userflags for %s are: %s", av[0], db ? (*buffer?buffer:"NONE") : "NONE");
        }
        return;
    }


    /* ######## Else the flag for the user specified has to be altered in any way */
    if(!db)
    {
        if(!strncasecmp(av[1], "none", 4))
        {
            send_cmd(con, MSG_SERVER_NOSUCH, "%s is not registered. so there is no need to delete his user flags", av[0]);
            return;
        }
        db = create_db(user);
    }

    if(db)
    {
        /* Skip one char if there is a "-" sign before the flag name */
        neg=( *av[1] == '-' );
        if(neg) 
		{
            av[1]++;
        }
        flags="";
        /* set userflags accordingly to the string in av[1] */
        for (i = 0, p = 1; *User_Flags[i]; i++, p <<= 1) 
		{
            if(!strcasecmp(av[1], User_Flags[i])) 
			{
                if(neg) 
				{
                    db->flags &= ~p;
                } 
				else 
				{
                    db->flags |= p;
                }
                if(user) 
				{
                    user->flags = db->flags;
                }
                flags=User_Flags[i];
                break;
            }
        }
        if(!strncasecmp(av[1], "none", 4))
        {
            db->flags = 0;
            if(user) 
			{
                user->flags = db->flags;
            }
        }
        if(!flags) 
		{
            if(ISUSER(con)) 
			{
                log_message_level(LOG_LEVEL_ERROR, "change_userflags: Invalid flags from %s for %s (%s)", sender_name, av[0], flags);
                send_cmd(con, MSG_SERVER_NOSUCH, "invalid flags");
            }
            return;
        }
        pass_message_args(con, MSG_CLIENT_USERFLAGS, ":%s %s %s%s", sender_name, av[0], neg?"-":"", strncasecmp(av[1], "none", 4)?flags:"NONE");
        if(user) 
		{
            if(ISUSER(user->con)) 
			{
                notify_mods(LEVELLOG_MODE, "%s set userflags for %s to: %s%s", sender_name, db->nick, neg?"-":"", strncasecmp (av[1], "none", 4)?flags:"NONE");
                send_cmd(user->con, MSG_SERVER_NOSUCH,"Your userflags are set to %s%s by %s", neg?"-":"", strncasecmp (av[1], "none", 4)?flags:"NONE", sender_name);
            }
        }
    }
}

