/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
This is free software distributed under the terms of the
GNU Public License.  See the file COPYING for details.

$Id: remove_file.c 434 2006-09-03 17:48:47Z reech $ */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>
#include "opennap.h"
#include "debug.h"

#ifndef ROUTING_ONLY

/* 102 <filename> */
HANDLER(remove_file)
{
    USER   *user;
    DATUM  *info;
    unsigned int fsize;

    (void) tag;
    (void) len;
    ASSERT(validate_connection(con));
    CHECK_USER_CLASS("remove_file");
    user = con->user;
    if(!user->shared)
    {
        send_cmd(con, MSG_SERVER_NOSUCH, "Not sharing any files");
        return;
    }

    ASSERT(pkt != 0);
    if(!*pkt)
    {
        send_cmd(con, MSG_SERVER_NOSUCH, "remove file failed: missing argument");
        return;
    }

    /* find the file in the user's list */
    info = hash_lookup(con->uopt->files, pkt);
    if(!info)
    {
        send_cmd(con, MSG_SERVER_NOSUCH, "Not sharing that file");
        return;
    }

    /* adjust the global state information */
    fsize = info->size / 1024;  /* kB */

    if(fsize > user->libsize)
    {
        log_message_level(LOG_LEVEL_SHARE, "remove_file: bad lib size for %s, fsize=%u user->libsize=%u", user->nick, fsize, user->libsize);
        user->libsize = fsize;  /* prevent negative count */
    }
    user->libsize -= fsize;

    if(fsize > global.fileLibSize)
    {
        log_message_level(LOG_LEVEL_SHARE, "remove_file: bad lib size for %s, fsize=%u global.fileLibSize=%f", user->nick, fsize, global.fileLibSize);
        global.fileLibSize = fsize;   /* prevent negative count */
    }
    global.fileLibSize -= fsize;

    ASSERT(global.fileLibCount > 0);
    global.fileLibCount--;

    ASSERT(global.localSharedFiles > 0);
    global.localSharedFiles--;

    user->shared--;
    user->unsharing = 1;    /* note that we are unsharing */

    /* this invokes free_datum() indirectly */
    hash_remove(con->uopt->files, info->filename);
}
#endif /* ! ROUTING_ONLY */
