/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
This is free software distributed under the terms of the
GNU Public License.

$Id: add_file.c 434 2006-09-03 17:48:47Z reech $ */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#ifndef WIN32
# include <unistd.h>
#endif
#include <limits.h>
#include "opennap.h"
#include "debug.h"

#ifndef ROUTING_ONLY

/* allowed bitrates for MPEG V1/V2 Layer III */
const int BitRate[19] = { 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 192, 224, 256, 320, 512 };

/* allowed sample rates for MPEG V2/3 */
const int SampleRate[6] = { 16000, 24000, 22050, 32000, 44100, 48000 };

#if ONAP_DEBUG
int validate_flist(FileList * p)
{
    int     count = 0;
    DList  *list;

    ASSERT_RETURN_IF_FAIL(VALID_LEN(p, sizeof(FileList)), 0);
    ASSERT_RETURN_IF_FAIL(p->magic == MAGIC_FLIST, 0);
    ASSERT_RETURN_IF_FAIL(VALID_LEN(p->key, strlen(p->key) + 1), 0);

    for (list = p->list; list; list = list->next, count++)
        ;
    ASSERT_RETURN_IF_FAIL(p->count == count, 0);
    return 1;
}
#endif

/* its assumed that `key' is all lowercase */
static void sInsertFile(HASH * table, char *key, DATUM * d, TokenRef * ref)
{
    FileList *files;
    DList  *dlist;

    ASSERT(table != 0);
    ASSERT(key != 0);
    ASSERT(d != 0);
    files = hash_lookup(table, key);
    /* if there is no entry for this particular word, create one now */
    if(!files)
    {
        files = CALLOC(1, sizeof(FileList));
        if(!files)
        {
            OUTOFMEMORY("sInsertFile");
            return;
        }
#if ONAP_DEBUG
        files->magic = MAGIC_FLIST;
#endif
        files->key = STRDUP(key);
        if(!files->key)
        {
            OUTOFMEMORY("sInsertFile");
            FREE(files);
            return;
        }
        if(hash_add(table, files->key, files))
        {
            FREE(files->key);
            FREE(files);
            return;
        }
    }
    ASSERT(validate_flist(files));

    dlist = CALLOC(1, sizeof(DList));
    if(!dlist)
    {
        OUTOFMEMORY("list");
        if(!files->list)
            hash_remove(table, files->key);
        return;
    }
    dlist->data = d;

    /* order is not important, push to beginning of list for speed */
    if(files->list)
        files->list->prev = dlist;
    dlist->next = files->list;
    files->list = dlist;
    files->count++;

    /* this is conditional since we don't keep track of the key when
    * inserting the hash value for the RESUME function.
    */
    if(ref)
    {
        /* we keep a pointer to the flist in which this file is inserted,
        * and the individual list element so that deletion doesn't require
        * scanning the entire list (which could be quite long).
        */
        ref->flist = files;
        ref->dlist = dlist; /* allows for quick deletion */
    }
}

/* common code for inserting a file into the various hash tables */
static void sInsertDatum(DATUM * info, char *av)
{
    LIST   *tokens, *ptr;
    unsigned int fsize;
    char   *p;
    int     numTokens;
    int     i;

    ASSERT(info != 0);
    ASSERT(av != 0);

    if(!info->user->con->uopt->files)
    {
        /* create the hash table */
        info->user->con->uopt->files = hash_init(257, (hash_destroy) free_datum);
        if(!info->user->con->uopt->files)
        {
            OUTOFMEMORY("sInsertDatum");
            return;
        }
    }

    hash_add(info->user->con->uopt->files, info->filename, info);

    if(option(ON_IGNORE_SUFFIX))
    {
        p = strrchr(av, '.');
        if(p)
            *p = 0;
    }

    /* split the filename into words */
    tokens = tokenize(av, NULL);

    numTokens = list_count(tokens);
    if(numTokens > kOMaxTokens)
    {
        log_message_level( LOG_LEVEL_FILES, "sInsertDatum: file has %d tokens (%d max)", numTokens, kOMaxTokens);
        /* strip of the leading tokens since these will be the least
        * specific.
        */
        while (numTokens > kOMaxTokens)
        {
            ptr = tokens;
            tokens = tokens->next;
            FREE(ptr);
            numTokens--;
        }
    }

    /* the filename may not consist of any searchable words, in which
    * case its not entered into the index.  this file will only be seen
    * when browsing the user possessing it
    */
    if(numTokens > 0)
    {
        info->tokens = MALLOC(sizeof(TokenRef) * numTokens);
        if(!info->tokens)
        {
            OUTOFMEMORY("sInsertToken");
            hash_remove(info->user->con->uopt->files, info->filename);
//            FREE(info->filename);
            BlockHeapFree(info->user->con->uopt->files_heap, info);
            list_free(tokens, 0);
            return;
        }
        info->numTokens = numTokens;

        for (i = 0, ptr = tokens; i < numTokens; i++, ptr = ptr->next)
            sInsertFile(global.FileHash, ptr->data, info, &info->tokens[i]);

        list_free(tokens, 0);
    }

#if RESUME
    /* index by md5 hash */
    sInsertFile(global.MD5Hash, info->hash, info, 0);
#endif

    fsize = info->size / 1024;  /* in kbytes */
    info->user->shared++;
    info->user->libsize += fsize;
    global.fileLibSize += fsize;      /* this is actually kB, not gB */
    global.fileLibCount++;
    global.localSharedFiles++;
    info->user->sharing = 1;    /* note that we began sharing */
}

static DATUM *sNewDatum(char *filename, char *hash, BlockHeap *heap)
{
    DATUM  *info = BlockHeapAlloc(heap); /* CALLOC(1, sizeof(DATUM)); */

    (void) hash;
    if(!info)
    {
        OUTOFMEMORY("sNewDatum");
        return 0;
    }
	memset(info, 0, sizeof(DATUM));
    strncpy(info->filename, filename, sizeof(info->filename) - 1);
    info->filename[sizeof(info->filename) - 1] = 0;
#if RESUME
    strncpy(info->hash, hash, sizeof(info->hash) - 1);
    info->hash[sizeof(info->hash) - 1] = 0;
    strlower(info->hash);
#endif
    return info;
}

static int sBitrateToMask(int bitrate, USER *user)
{
    unsigned int i;

    for (i = 0; i < sizeof(BitRate) / sizeof(int); i++)

    {
        if(bitrate <= BitRate[i])
            return i;
    }
    log_message_level( LOG_LEVEL_FILES, "sBitrateToMask: invalid bit rate %d (%s, \"%s\")", bitrate, user->nick, user->clientinfo);
    return 0;           /* invalid bitrate */
}

static int sFreqToMask(int freq, USER * user)
{
    unsigned int i;
    for (i = 0; i < sizeof(SampleRate) / sizeof(int); i++)

    {
        if(freq <= SampleRate[i])
            return i;
    }
    log_message_level( LOG_LEVEL_FILES, "sFreqToMask: invalid sample rate %d (%s, \"%s\")", freq, user->nick, user->clientinfo);
    return 0;
}

/* 100 "<filename>" <md5sum> <size> <bitrate> <frequency> <time>
client adding file to the shared database */
HANDLER(add_file)
{
    char   *av[6];
    char   *fn;
    DATUM  *info;
    unsigned int fsize;
    USERDB *db;


    (void) tag;
    (void) len;
    ASSERT(validate_connection(con));

    CHECK_USER_CLASS("add_file");

    ASSERT(validate_user(con->user));

    if(!option(ON_ALLOW_SHARE))
        return;
    if(con->user->level==LEVEL_LEECH)
        return;

    if(global.maxShared && con->user->shared >= global.maxShared)
    {
        /* Changed by Davide Scola <davide.gnu@disi.unige.it> */
        if(!con->user->warned)
        {
            send_cmd(con, MSG_SERVER_NOSUCH, "You may only share %d files", global.maxShared);
            con->user->warned++;
        }
        return;
    }

    if(split_line(av, sizeof(av) / sizeof(char *), pkt) != 6)
    {
        unparsable(con);
        return;
    }


    fn = split_filename(av[0]);
    if(!fn)
    {
        send_cmd(con, MSG_SERVER_NOSUCH, "Sorry, unable to parse '%s'", av[0]);
        return;
    }

    if(av[1] - av[0] > _POSIX_PATH_MAX + 2)
    {
        send_cmd(con, MSG_SERVER_NOSUCH, "filename too long");
        return;
    }

    /* ensure we have a valid byte count */
    fsize = strtoul(av[2], 0, 10);
    /* check for overflow */
    if(con->user->libsize + fsize < con->user->libsize)
    {
        log_message_level( LOG_LEVEL_FILES, "add_file: %u byte file would overflow %s's library size", fsize, con->user->nick);
        return;
    }

    if(is_blocked(av[0])) 
	{
        /* If set remember the state of the user in the userdb. Update his flags so that he gets banned as soon as 
        he finishes sharing. This is because if an innocent user shares a file which matches the block pattern
        then you have the logfiles to justify or to revoke the ban later on the list of files he shared.
        mod+ and others are *not* exempt of the ban.
        */
        if( option(ON_DISCIPLINE_BLOCK) & !( con->user->flags & ON_CRIMINAL) ) 
		{
            /* Force registration of this user */
            db = hash_lookup(global.userDbHash , con->user->nick);

            /* The userentry does not exist - create it! */
            if(!db) 
			{
                db = create_db(con->user);
            }

            /* Update the flag ON_CRIMINAL */
            db->flags |= ON_CRIMINAL;
            con->user->flags |= ON_CRIMINAL;
            /* But don't pass the flag to the other servers. It'll be enough if they get the ban later 
            If they get the flag transmitted they might start banning the user before all evidence is 
            captured.
            */

            /* Now the user is marked as criminal - let him proceed with his file sharing actions by now with the
            difference that the WHOLE remaining filelist is dumped to the logfiles  ... */

        }
        if( !(con->user->flags & ON_CRIMINAL) ) 
		{
            if( option(ON_NOTIFY_MOD_BLOCK) ) 
			{
                notify_mods(BANLOG_MODE, "\"%s\" (%s) tried to share \"%s\"",con->user->nick, my_ntoa(BSWAP32(con->user->ip)), av[0]);
            }
            log_message_level( LOG_LEVEL_FILES, "add_file: blocked file ( %lu bytes ) from %s (%s): %s", fsize, con->user->nick, my_ntoa(BSWAP32(con->user->ip)), av[0]);
            return;
        }
    }

    /* We should show all files of a suspect in the logfiles to get a complete view over the 
    suspects library and to possibly introduce some new search patterns into the block file */
    if( con->user->flags & ON_CRIMINAL ) 
    {
        if( option(ON_NOTIFY_MOD_BLOCK) ) 
        {
            notify_mods(BANLOG_MODE, "\"%s\" (%s) tried to share \"%s\"",con->user->nick, my_ntoa(BSWAP32(con->user->ip)), av[0]);
        }
        log_message_level( LOG_LEVEL_FILES, "add_file: blocked file ( %lu bytes ) from %s (%s): %s", fsize, con->user->nick, my_ntoa(BSWAP32(con->user->ip)), av[0]);
        return;
    }

    /* make sure this isn't a duplicate - only compare the basename, not
    * including the directory component
    */
    if(con->uopt->files && hash_lookup(con->uopt->files, av[0]))
    {
        send_cmd(con, MSG_SERVER_NOSUCH, "duplicate file");
        return;
    }

    /* Enforce the lower size limit on this file when min_file_size != 0 */
    if(global.min_file_size && ( fsize < global.min_file_size) ) 
    {
        send_cmd(con, MSG_SERVER_NOSUCH, "Size %u too small (%u min) (%s)", fsize, global.min_file_size, av[0]);
        return;
    }


    /* create the db record for this file */

    /* make sure we have a heap to create this in */
    if(!con->uopt->files)
        con->uopt->files_heap = BlockHeapCreate(sizeof(DATUM), (int)((getpagesize()/sizeof(DATUM)) - 1));
    info = sNewDatum(av[0], av[1], con->uopt->files_heap);
    if(!info)
        return;
    info->user = con->user;
    info->size = fsize;
    info->bitrate = sBitrateToMask(atoi(av[3]), con->user);
    info->frequency = sFreqToMask(atoi(av[4]), con->user);
    info->duration = atoi(av[5]);
    info->type = CT_MP3;
    sInsertDatum(info, fn);
}

char   *Content_Types[] = {
    "mp3",          /* not a real type, but what we use for audio/mp3 */
        "audio",
        "video",
        "application",
        "image",
        "text"
};

/* 10300 "<filename>" <size> <hash> <content-type> */
HANDLER(share_file)
{
    char   *av[4];
    char   *fn;
    DATUM  *info;
    int     i, type;
    unsigned int fsize;

    (void) len;
    (void) tag;

    ASSERT(validate_connection(con));
    CHECK_USER_CLASS("share_file");

    if(!option(ON_ALLOW_SHARE))
        return;
    if(con->user->level==LEVEL_LEECH)
        return;
    if(global.maxShared && con->user->shared >= global.maxShared)
    {
        log_message_level( LOG_LEVEL_FILES, "add_file: %s is already sharing %d files", con->user->nick, con->user->shared);

        /* Changed by Davide Scola <davide.gnu@disi.unige.it> */
        if(ISUSER(con) && !con->user->warned)
        {
            send_cmd(con, MSG_SERVER_NOSUCH, "You may only share %d files", global.maxShared);
            con->user->warned++;
        }

        return;
    }

    if(split_line(av, sizeof(av) / sizeof(char *), pkt) != 4)
    {
        unparsable(con);
        return;
    }

    if(is_blocked(av[0]))
        return;

    fn = split_filename(av[0]);
    if(!fn)
    {
        send_cmd(con, MSG_SERVER_NOSUCH, "Sorry, unable to parse '%s'", av[0]);
        return;
    }

    /* make sure the content-type looks correct */
    type = -1;
    for (i = CT_AUDIO; i < CT_UNKNOWN; i++)
    {
        if(!strcasecmp(Content_Types[i], av[3]))
        {
            type = i;
            break;
        }
    }
    if(type == -1)
    {
        log_message_level( LOG_LEVEL_FILES, "share_file: not a valid type: %s", av[3]);
        if(ISUSER(con) == CLASS_USER)
            send_cmd(con, MSG_SERVER_NOSUCH, "%s is not a valid type", av[3]);
        return;
    }

    if(av[1] - av[0] > _POSIX_PATH_MAX + 2)
    {
        send_cmd(con, MSG_SERVER_NOSUCH, "filename too long");
        return;
    }

    if(con->uopt->files && hash_lookup(con->uopt->files, av[0]))
    {
        send_cmd(con, MSG_SERVER_NOSUCH, "duplicate file");
        return;
    }

    fsize = strtoul(av[1], 0, 10);
    if(fsize + con->user->libsize < con->user->libsize)
    {
        log_message_level( LOG_LEVEL_FILES, "share_file: %u byte file would overflow %s's library size", fsize, con->user->nick);
        return;
    }

    if(!con->uopt->files)
        con->uopt->files_heap = BlockHeapCreate(sizeof(DATUM), (int)(getpagesize()/sizeof(DATUM))-1);

    info = sNewDatum(av[0], av[2], con->uopt->files_heap);
    if(!info)
        return;
    info->user = con->user;
    info->size = fsize;
    info->type = type;

    sInsertDatum(info, fn);
}

/* 870 "<directory>" "<basename>" <md5> <size> <bitrate> <freq> <duration> [ ... ]
client command to add multiple files in the same directory */
HANDLER(add_directory)
{
    char   *dir, *basename, *md5, *size, *bitrate, *freq, *duration, *fn;
    char    path[_POSIX_PATH_MAX], dirbuf[_POSIX_PATH_MAX];
    int     pathlen, fsize;
    DATUM  *info;

    (void) tag;
    (void) len;
    ASSERT(validate_connection(con));
    CHECK_USER_CLASS("add_directory");
    if(!option(ON_ALLOW_SHARE))
        return;
    if(con->user->level==LEVEL_LEECH)
        return;
    dir = next_arg(&pkt);  /* directory */
    if(!dir)
    {
        log_message_level( LOG_LEVEL_FILES, "add_directory: missing directory component");
        return;
    }
    pathlen = strlen(dir);
    if((size_t) pathlen >= sizeof(dirbuf) - 1)
    {
        log_message_level( LOG_LEVEL_FILES, "add_directory: directory component is too long, ignoring");
        return;
    }
    ASSERT((size_t) pathlen < sizeof(dirbuf) - 1);
    dirbuf[sizeof(dirbuf) - 1] = 0;    /* ensure nul termination */
    strncpy(dirbuf, dir, sizeof(dirbuf) - 1);

    if(pathlen > 0 && dirbuf[pathlen - 1] != '\\')
    {
        dirbuf[pathlen++] = '\\';
        dirbuf[pathlen] = 0;
        if((size_t) pathlen >= sizeof(dirbuf) - 1)
        {
            ASSERT((size_t) pathlen < sizeof(dirbuf));
            log_message_level( LOG_LEVEL_FILES, "add_directory: directory component is too long, ignoring");
            return;
        }
    }

    /* if the client passes a dir + file that is longer than 255 chars,
    * strncpy() won't write a \0 at the end of the string, so ensure that
    * this always happens
    */
    path[sizeof(path) - 1] = 0;

    while (pkt)
    {
        if(global.maxShared && con->user->shared >= global.maxShared)
        {
            /* Changed by Davide Scola <davide.gnu@disi.unige.it> */
            if(!con->user->warned)
            {
                send_cmd(con, MSG_SERVER_NOSUCH, "You may only share %d files", global.maxShared);
                con->user->warned++;
            }

            return;

        }
        basename = next_arg(&pkt);
        md5 = next_arg(&pkt);
        size = next_arg(&pkt);
        bitrate = next_arg(&pkt);
        freq = next_arg(&pkt);
        duration = next_arg(&pkt);
        if(!basename || !md5 || !size || !bitrate || !freq || !duration)
        {
            unparsable(con);
            return;
        }

        strncpy(path, dirbuf, sizeof(path) - 1);
        strncpy(path + pathlen, basename, sizeof(path) - 1 - pathlen);

        ASSERT(path[sizeof(path) - 1] == 0);

        /* TODO: still seeing crashes here, we must be overwriting the
        * stack on occasion.  quit now if we detect this condition
        */
        if(path[sizeof(path) - 1] != 0)
        {
            log_message_level(LOG_LEVEL_ERROR, "add_directory: ERROR! buffer overflow detected");
            return;
        }

        if(is_blocked(path))
            continue;

        fn = split_filename(path);
        if(!fn)
        {
            send_cmd(con, MSG_SERVER_NOSUCH, "Sorry, unable to parse '%s'", path);
            return;
        }

        if(con->uopt->files && hash_lookup(con->uopt->files, path))
        {
            send_cmd(con, MSG_SERVER_NOSUCH, "Duplicate file");
            continue;       /* get next file */
        }

        fsize = atoi(size);
        if(fsize < 1)
        {
            send_cmd(con, MSG_SERVER_NOSUCH, "invalid size");
            continue;
        }

        /* create the db record for this file */
        if(!con->uopt->files)
            con->uopt->files_heap = BlockHeapCreate(sizeof(DATUM), (int)(getpagesize()/sizeof(DATUM))-1);

        info = sNewDatum(path, md5, con->uopt->files_heap);
        if(!info)
            return;
        info->user = con->user;
        info->size = fsize;
        info->bitrate = sBitrateToMask(atoi(bitrate), con->user);
        info->frequency = sFreqToMask(atoi(freq), con->user);
        info->duration = atoi(duration);
        info->type = CT_MP3;

        sInsertDatum(info, fn);
    }
}

#endif /* ! ROUTING_ONLY */

/* 10012 <nick> <shared> <size>
remote server is notifying us that one of its users is sharing files */
HANDLER(user_sharing)
{
    char   *av[3];
    USER   *user;
    int     n;
    double  libsize;
    int     err = 0;

    (void) len;
    ASSERT(validate_connection(con));
    CHECK_SERVER_CLASS("user_sharing");
    if(split_line(av, sizeof(av) / sizeof(char *), pkt) != 3)
    {
        log_message_level( LOG_LEVEL_SHARE, "user_sharing: wrong number of arguments");
        return;
    }
    user = hash_lookup(global.usersHash, av[0]);
    if(!user)
    {
        log_message_level( LOG_LEVEL_SHARE, "user_sharing: no such user %s (from %s)", av[0],
            con->host);
        return;
    }

    do
    {
        n = atoi(av[1]);
        if(n < 0)
        {
            log_message_level( LOG_LEVEL_SHARE, "user_sharing: negative file count for user %s", user->nick);
            err = 1;
            break;
        }
        ASSERT(global.fileLibCount >= user->shared);
        global.fileLibCount -= user->shared;
        global.fileLibCount += n;
        user->shared = n;

        libsize = strtoul(av[2], 0, 10);
        if(libsize < 0)
        {
            log_message_level( LOG_LEVEL_SHARE, "user_sharing: negative library size for user %s", user->nick);
            err = 1;
            break;
        }

        if(global.fileLibSize < user->libsize)
        {
            log_message_level( LOG_LEVEL_SHARE, "user_sharing: error: global.fileLibSize=%f, user->libsize=%u user->nick=%s", global.fileLibSize, user->libsize, user->nick);
            global.fileLibSize = user->libsize;   /* prevent negative count */
            err = 1;
            break;
        }
        global.fileLibSize -= user->libsize;
        global.fileLibSize += libsize;
        user->libsize = (unsigned int)libsize;
    }
    while (0);

    if(err)
    {
        /* reset counts */
        global.fileLibCount -= user->shared;
        global.fileLibSize -= user->libsize;
        user->shared = 0;
        user->libsize = 0;
    }

    pass_message_args(con, tag, "%s %hu %u", user->nick, user->shared, user->libsize);
}

void unshare_all_internal(USER * user)
{
    if(user->shared)
    {
#ifndef ROUTING_ONLY
        if(ISUSER(user->con))
        {
            /* local user */
            free_hash(user->con->uopt->files);
            user->con->uopt->files = 0;
            ASSERT(global.localSharedFiles >= user->shared);
            global.localSharedFiles -= user->shared;
        }
#endif /* !ROUTING_ONLY */
        if(user->libsize > global.fileLibSize)
        {
            log_message_level( LOG_LEVEL_SHARE, "unshare_all: sender->libsize=%u global.fileLibSize=%f", user->libsize, global.fileLibSize);
            global.fileLibSize = user->libsize;
        }
        ASSERT(global.fileLibSize >= user->libsize);
        global.fileLibSize -= user->libsize;
        ASSERT(global.fileLibCount >= user->shared);
        global.fileLibCount -= user->shared;
        user->libsize = 0;
        user->shared = 0;
    }
}

/* 110 [:sender]
* unshare all files.  this will handle the case of a remote server forcing
* a local client to unshare all files as well, so we can have the hub
* perform this action.
*/
HANDLER(unshare_all)
{
    USER   *sender;
    char   *sender_name;

    (void) len;
    if(pop_user_server(con, tag, &pkt, &sender_name, &sender))
        return;
    if(!sender)
    {
        log_message_level(LOG_LEVEL_ERROR, "unshare_all: error: received unshare message from server %s", sender_name);
        return;
    }
    if(ISUSER(con))
    {
        if(sender->shared == 0)
            return;     /* nothing to unshare */
        send_cmd(con, tag, "%d", sender->shared);
    }
    unshare_all_internal(sender);
    pass_message_args(con, tag, ":%s", sender->nick);
}
