/* $Id: discipline.c 434 2006-09-03 17:48:47Z reech $
*
*    Open Source Napster Server - Peer-To-Peer Indexing/Chat Daemon
*    Copyright (C) 2001  drscholl@users.sourceforge.net
*
*    This program is free software; you can redistribute it and/or modify
*    it under the terms of the GNU General Public License as published by
*    the Free Software Foundation; either version 2 of the License, or
*    (at your option) any later version.
*
*    This program is distributed in the hope that it will be useful,
*    but WITHOUT ANY WARRANTY; without even the implied warranty of
*    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*    GNU General Public License for more details.
*
*    You should have received a copy of the GNU General Public License
*    along with this program; if not, write to the Free Software
*    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif


#include <stdlib.h>
#include "opennap.h"

#ifndef NULL
# define NULL ((void*)0)
#endif

void discipline_user(USER * user)
{
    USERDB *db;

    if(global.BlockWinMX > 1)
        kill_user_internal(user->con, user, global.serverName, 0, "");
    else
    {
        /* set the user to LEECH */

        if(ISUSER(user->con))
        {
            /* remove from local mods+ list */
            if(user->level > LEVEL_USER)
                global.modList = list_delete(global.modList, user->con);
        }

        /* if the user is sharing any files, remove them now */
        if(user->shared)
        {
            unshare_all_internal(user);
            pass_message_args(NULL, MSG_CLIENT_UNSHARE_ALL, ":%s", user->nick);
        }

        user->level = LEVEL_LEECH;
        if(user->cloaked)
        {
            notify_mods(CHANGELOG_MODE, "%s has decloaked", user->nick);
            user->cloaked = 0;
        }

        db = hash_lookup(global.userDbHash , user->nick);
        if(!db)
            db = create_db(user);  /*  not registered, force it now */
        db->level = LEVEL_LEECH;

        notify_mods(LEVELLOG_MODE, "Server %s set %s's level to Leech (0)", global.serverName, user->nick);

        pass_message_args(NULL, MSG_CLIENT_SETUSERLEVEL, ":%s %s Leech", global.serverName, user->nick);
    }
}
