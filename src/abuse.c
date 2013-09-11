/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
This is free software distributed under the terms of the
GNU Public License.  See the file COPYING for details.
$Id: abuse.c 438 2006-10-04 10:48:08Z khaytsus $ */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>
#include <stdio.h>
#include <time.h>
#include "opennap.h"
#include "debug.h"

/* 
Handling of server abusage by braindead clients. 
We experienced a lot of traffic coming from some clients
abusing several tags. These clients will get a warning
message stating that their client is buggy and should be updated.
This module handles the other abuses like violating the 
eject_limits as well.
*/

/* Returns 1 if the eject_limits are violated */
int check_eject_limits( USER *user ) 
{
#ifndef ROUTING_ONLY
    int ret;
   ret = ( 
        /* Leech-Handler - this one is simple - kick if they move ... */
        ( (user->level == LEVEL_LEECH) && option(ON_EJECT_LEECHES) ) || 

        /* Criminal-Handler - Kick em if they finished sharing */
        ( ( (user->flags & ON_CRIMINAL) && option(ON_DISCIPLINE_BLOCK) ) &&
        ( user->sharing == 0 ) && 
        /* Are they connected less than ... seconds? --> don't kick */
        ( (user->connected + global.ejectAfter) < global.current_time ) && 

        /* Are they connected shortly since the server started? --> don't kick */
        ( ((time_t) global.serverStartTime + (time_t) global.eject_grace_time ) < (time_t) global.current_time )


        ) ||

        /* or ... enter the  User Handler - this one is more complicated ... */
        (   option(ON_EJECT_WHEN_FULL) &&
            (user->level == LEVEL_USER) &&

            /* Are they sharing less than ... FILES ***AND*** less than ... Bytes --> Kick == 1! */
            ( (user->shared < global.eject_limit_files) && (user->libsize < global.eject_limit_libsize) ) &&

            /* But: Are they still in progress of sharing files(1)? --> Don't kick == 0 */
            ( user->sharing == 0 ) &&

            /* But: Are they set to FRIEND? --> Don't kick! == 0 */
            !(user->flags & ON_FRIEND) &&

            /* Are they connected less than ... seconds? --> don't kick */
            ( (user->connected + global.ejectAfter) < global.current_time ) && 

            /* Are they connected shortly since the server started? --> don't kick */
            ( ((time_t) global.serverStartTime + (time_t) global.eject_grace_time ) < (time_t) global.current_time ) &&

            /* Are they if a channel?  If so exempt, if not, out they go */
            ( !user->channels || !option(ON_EJECT_NOCHANNELS) )
          )
        );
   return ret;
#else
    return 0;
#endif
}



#ifndef ROUTING_ONLY
/* Kills and tbans a user ( or a leech ) according to the parameters in eject_* 
This procedure relies completely on the fact that eject_limits were checked
prior to this call. No checking to avoid pissing off good users is done here.

*/
void eject_internal( CONNECTION *con, USER * user) 
{
    char reason[256], banned[256], size1[40], size2[40];
    time_t bttl;
    USERDB *db;

    /* users flagged criminal are to be banned if the flag "discipline_block" is set - 
    regardless of their eject_* limits 
    */
    if( ( option(ON_EJECT_ALSO_BANS) && ( global.eject_ban_ttl > 0 )) || 
        ( (user->flags & ON_CRIMINAL) && option(ON_DISCIPLINE_BLOCK) )    )
    {
        if(( user->level <= LEVEL_USER) & !(user->flags & ON_CRIMINAL) ) 
        {
            snprintf( reason, sizeof(reason)-1, "You shared less than %d files or %.1f Gb (%d files/%.1f Gb)", global.eject_limit_files, global.eject_limit_libsize / 1048576., user->shared, user->libsize / 1048576.);
            bttl = global.eject_ban_ttl;
        } 
        else if(user->flags & ON_CRIMINAL) 
        {
            snprintf( reason, sizeof(reason)-1, "You shared blocked files on IP: %s date: %s", my_ntoa(BSWAP32(user->ip)), ctime (&user->connected));
            /* Cut off the last \n of the ctime() result */
            reason[strlen(reason)-1]=0; 
            bttl = global.discipline_block_ban_ttl;
        } 
        else 
        {
            snprintf( reason, sizeof(reason)-1, "You are set to level LEECH");
            bttl = global.eject_ban_ttl;
        }

        /* If set to 1 ban user!* if set to 2 ban *!ip, otherwise ban user!ip */

        if( global.abuse_bans_ip == 1 ) 
        {
            snprintf( banned, sizeof(banned), "%s", user->nick );
        } 
        else 
        {
            if( global.abuse_bans_ip == 2 ) 
            {
                snprintf( banned, sizeof(banned), "*!%s", my_ntoa(BSWAP32(user->ip)) );
            } 
            else 
            {
                snprintf( banned, sizeof(banned), "%s!%s", user->nick, my_ntoa(BSWAP32(user->ip)) );
            }
        }
        ban_user_internal( con, banned, bttl, reason);
    }

    if( user->level == LEVEL_LEECH && option(ON_EJECT_LEECHES) ) 
    {
        snprintf( reason, sizeof(reason)-1, "Leech ejection to make room for real users.");
    } 
    else if( user->flags & ON_CRIMINAL ) 
    {
        snprintf( reason, sizeof(reason)-1, "You shared blocked files on IP: %s date %s", my_ntoa(BSWAP32(user->ip)), ctime (&user->connected));
        /* Cut off the last \n of the ctime() result */
        reason[strlen(reason)-1]=0; 

        /* We believe in the good of ppl. so we reset the flag after the killban 
        Everyone might get another chance.

        07/14/2002: TT: This is the point where an user account rather should get
        nuked instead of resetting the flag. This is to avoid 
        the user getting "password failures" instead of "you are banned:"
        */
        db = hash_lookup(global.userDbHash , user->nick);

        /* Remove the user account from the list of users */

        if(db) 
        {
            hash_remove(global.userDbHash , db->nick);
        }

        /* The user is still online. So reset the state of this record to a value
        which requires no registration unless they are mod+, we don't want to
        nuke them even if they are naughty. 
        07/21/2002 TT: Made the mod+ kick more configurable. I think the best 
        solution would be to be more careful when setting someone
        to mod+.
        */
        if(user && /* So we have a user record eh? */
            ( ( ( user->level <= LEVEL_MODERATOR || user->flags & ON_FRIEND ) && !option(ON_DISCIPLINE_BLOCK_MOD)) ||  /* consider the level if the flag is not set  */
            option(ON_DISCIPLINE_BLOCK_MOD) ) /* And if the flag is set - beat the crap outta the record regardless of the level */

            ) 
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
                        send_cmd(user->con, MSG_SERVER_NOSUCH, "You are no longer cloaked.");
                    }
                    user->cloaked = 0;
                }
                /* Reset all flags of the user including ON_CRIMINAL and such */
                user->flags = 0;
                if(ISUSER(user->con) && user->level < LEVEL_MODERATOR) 
                {
                    send_cmd(user->con, MSG_SERVER_NOSUCH,"%s nuked your account: %s", global.serverName, user->nick);
                }

                /* Spread the word to the other servers to gain a consistent user base ... */
                pass_message_args(con, MSG_CLIENT_NUKE, ":%s %s Criminal account nuke", global.serverName, user->nick);
                notify_mods(CHANGELOG_MODE, "Server %s nuked %s:  Criminal account nuke", global.serverName, user->nick);
            }

            /* Reset mod+ flags - but don't reset the flag if the mod+ is protected by discipline_block_mod.
            If the mod+ had been protected there should be some control instance of having the flag set
            as every server owner should know what his mod+ are doing. 
            If the mod+ had not been protected by the flag then he is nuked by the lines above.
            So the following if() is redundant:
            if(user && user->level >= LEVEL_MODERATOR) 
			{
            notify_mods(ABUSE_MODE, "%s killed %s (%s) for questionable material", global.serverName, user->nick, user->level);
            user->flags = 0;
            } */

            /* the old code simply reset the flags...
            if( db && user ) 
			{
            db->flags &= ~ON_CRIMINAL;
            user->flags &= ~ON_CRIMINAL;
            }
            */

    } 
    else 
    {
        snprintf( reason, sizeof(reason)-1, "You have to share at least %d files or %s, but you only share %d files/%s.", global.eject_limit_files, print_size(size1, sizeof(size1), global.eject_limit_libsize * 1024), user->shared, print_size(size2, sizeof(size2), user->libsize * 1024));
    }

    /* We pass NULL as the connection handle as the kill origins here and is not to be routed */
    kill_user_internal(0, user, global.serverName, 0, reason);
}

#endif

/* Send a PrivMsg to a user with the user himself as sender */
void send_self(CONNECTION * con, USER * user, char *message) 
{
    if(ISUSER(user->con)) 
    {
        send_cmd(con, MSG_CLIENT_PRIVMSG, "%s %s", user->nick, message);
    } 
    else 
    {
        send_cmd(con, MSG_CLIENT_PRIVMSG, ":%s %s %s", user->nick, user->nick, message);
    }
}

/* 
Parameters:
*con        the connection the user has.
*user       the userrecord of the connection
tag     the tag the user issued
counter     the userentry of the tag e.g. user->count219
ignoretag   if true then return flag to ignore the tag else return false.
*/
int notify_abuse(CONNECTION * con, USER *user, int tag, int counter, int ignoretag) 
{
    char    message[1024];
    int     deltat;
    int     howmany;
    /*int     i,a;
    short int   abused;
    */
    
#ifndef ROUTING_ONLY
    /* this is a wonderful place to check some limits ... :-) 
    But make sure that only connections of the own server are kicked.
    You never know how the limits on other servers are.
    */
    /* actually this is a very bad place for this as we have code that
    * tries to send to a con after this function.  this was making the 
    * con go away
    
    if( ISUSER(con) && check_eject_limits( user ) ) 
	{
        eject_internal( con, user );
        return 1;
    } 
    */
#endif

    /* if we are not doing either of these, bail */
    if(  ( ! global.max_searches_per_minute && tag == 200 )  || ( ! global.max_tags_per_minute ) )
        return 0;

    /* Calculate the time since login in minutes */
    deltat=( global.current_time - user->connected ) / 60;


    /* If the threshold is not exceeded then simply return 0 to show that nothing went wrong */

    /* On request of moni4711 the tag 200 is handled a bit different ... */
    if( tag == 200 ) 
    {
        /* this will not happen, handled above 
        if( ! global.max_searches_per_minute ) 
        {
            return 0;
        }
        */
        if( deltat < global.evaluate_search_abuse_after_secs) 
        {
            return 0;
        }
        /* We have to rethink the grace ammount of tags as a lot of
        users relogin when they are hit by the limit */
        if( counter <= global.evaluate_search_abuse_after_tags ) 
        {
            return 0;
        }
        counter-=global.evaluate_search_abuse_after_tags;
    }

    howmany=deltat?( counter/deltat ):0;
    /*
    a=counter % global.notify_user_abuse_frequency;
    i=counter % global.notify_mod_abuse_frequency;
    
    abused=(tag==200)?(howmany > global.max_searches_per_minute):( howmany > global.max_tags_per_minute );
    */
    if( /* this is handled above ! global.max_tags_per_minute || */ !((tag==200)?(howmany > global.max_searches_per_minute):( howmany > global.max_tags_per_minute )) ) 
	{
        return 0;
    } 
	else 
	{
        /* Check for some flags in the global section */
        if( option(ON_NOTIFY_MOD_ABUSE) && ! (counter % global.notify_mod_abuse_frequency) ) 
		{
            notify_mods(ABUSE_MODE, "%s (%d files) has client %s and is abusing tag %s(%d) (%d times/min %d total) ", user->nick, user->shared, user->clientinfo, tag2hrf (tag), tag, howmany, counter);
        }

        if( option(ON_NOTIFY_USER_ABUSE) && !(counter % global.notify_user_abuse_frequency) && 
            ( (user->level < LEVEL_MODERATOR ) || ( user->level>=LEVEL_MODERATOR && ! option(ON_NO_MOD_ANNOYING) ) )
            ) 
		{
                if( tag == 200 ) 
				{
                    snprintf( message, sizeof(message),
                        "You issued %d search requests per minute ( %d total in %d seconds ). Allowed is a max of %d requests per minute.",
                        howmany,
                        counter,
                        deltat,
                        global.max_searches_per_minute);
                    send_self(con, user, message);

                    snprintf(message, sizeof(message),
                        "Traffic analysis showed that this excessive searching draws a lot of bandwidth of our network without any use to you or anybody else."
                        );
                    send_self(con, user, message);

                    snprintf(message, sizeof(message),
                        "Because of this your searches will fail until your ratio is below %d searches per minute again.",
                        global.max_searches_per_minute
                        );
                    send_self(con, user, message);

                    snprintf(message, sizeof(message),
                        "Failed searches which produce an error message will not count to your ratio."
                        );
                    send_self(con, user, message);

                    snprintf(message, sizeof(message),
                        "Please set your client to a lower search frequency so that this limit isn't hit any more."
                        );
                    send_self(con, user, message);

                    snprintf(message, sizeof(message),
                        "Sorry for the inconvenience and enjoy your stay."
                        );
                    send_self(con, user, message);

                } 
				else 
				{
                    snprintf(message, sizeof(message),
                        "Your client %s issued %d commands of the type %d (%d per minute). This command is therefore very likely to be ignored here, as",
                        user->clientinfo,
                        counter,
                        tag,
                        howmany
                        );
                    send_self(con, user, message);

                    snprintf(message, sizeof(message),
                        "traffic analysis showed that it drew up to 75%% of the whole bandwidth of our network without any use to you or anybody else."
                        );
                    send_self(con, user, message);

                    snprintf(message, sizeof(message), 
                        "We believe that this excessive usage of the command %d is a bug of your client as other clients don't behave like this.",
                        tag
                        );
                    send_self(con, user, message);

                    snprintf(message, sizeof(message), 
                        "We would therefore like you to write a bugreport to the producer of your client %s or",
                        user->clientinfo
                        );
                    send_self(con, user, message);

                    snprintf(message, sizeof(message), 
                        "to use a different client for your filesharing needs, please."
                        );
                    send_self(con, user, message);

                    snprintf(message, sizeof(message), 
                        "Thank you for reading this. Enjoy your stay here."
                        );
                    send_self(con, user, message);

                    snprintf(message, sizeof(message), 
                        "P.S.: This message will reappear every %dth time your client sends the command %d to the server. Sorry for the inconvenience.", 
                        global.notify_user_abuse_frequency,
                        tag
                        );
                    send_self(con, user, message);
                }
            }
            return ignoretag;
    }

}
