/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
This is free software distributed under the terms of the
GNU Public License.  See the file COPYING for details.

$Id: userdb.c 436 2006-09-04 14:56:32Z reech $ */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <sys/types.h>
#include <sys/stat.h>
#ifndef WIN32
# include <unistd.h>
#endif
#include <fcntl.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <time.h>
#include "opennap.h"
#include "debug.h"

/* HASH   *User_Db = 0;     moved to global.userDbHash */

int get_level(const char *s)
{
    if(!strncasecmp("lee", s, 3))
        return LEVEL_LEECH;
    if(!strncasecmp("use", s, 3))
        return LEVEL_USER;
    if(!strncasecmp("mod", s, 3))
        return LEVEL_MODERATOR;
    if(!strncasecmp("eli", s, 3))
        return LEVEL_ELITE;
    if(!strncasecmp("adm", s, 3))
        return LEVEL_ADMIN;
    return -1;
}

void userdb_free(USERDB * p)
{
    if(p)
    {
#if EMAIL
        if(p->email)
            FREE(p->email);
#endif
        BlockHeapFree(userdb_heap, p); /* FREE(p); */
    }
}

int userdb_init(void)
{
    int     fd;
    int     ac, regen = 0, level;
    char   *av[7], path[_POSIX_PATH_MAX];
    USERDB *u;
    struct  stat sts;
    char   *tmppass;

    snprintf(path, sizeof(path), "%s/users", global.varDir);
    if(stat(path, &sts) == -1 && errno == ENOENT)
    {
        log_message_level(LOG_LEVEL_DEBUG, "%s file does not exist\n", path);
        return -1;
    }

    fd = open(path, O_RDONLY);
    if(fd == -1)
    {
        logerr("userdb_init", path);
        return -1;
    }
    global.userDbHash  = hash_init(257, (hash_destroy) userdb_free);
    userdb_heap = BlockHeapCreate(sizeof(USERDB), 10);
    log_message_level(LOG_LEVEL_SERVER, "userdb_init: reading %s", path);
    if(fake_fgets(Buf, sizeof(Buf), fd))
    {
        if(strncmp(":version 1", Buf, 10))
        {
            regen = 1;
            lseek(fd,0,SEEK_SET);
        }
    }
    while (fake_fgets(Buf, sizeof(Buf), fd))
    {
        ac = split_line(av, FIELDS(av), Buf);
        if(ac >= 6)
        {
            if(invalid_nick(av[0]))
            {
                log_message_level(LOG_LEVEL_ERROR, "userdb_init: %s: invalid nickname", av[0]);
                continue;
            }
            u = BlockHeapAlloc(userdb_heap); /* CALLOC(1, sizeof(USERDB)); */
            if(u)
            {
                memset(u, 0, sizeof(USERDB));
                strncpy(u->nick, av[0], sizeof(u->nick) - 1);
                u->nick[sizeof(u->nick) - 1] = 0;
                if(regen)
                {
                    tmppass = generate_pass(av[1]);
                }
                else
                {
                    tmppass = STRDUP(av[1]);
                }
                strncpy(u->password, tmppass, sizeof(u->password) - 1);
                u->password[sizeof(u->password) - 1] = 0;
                free(tmppass);
#if EMAIL
                u->email = STRDUP(av[2]);
#endif
            }
            if(!u
#if EMAIL
                || !u->email
#endif
                )
            {
                OUTOFMEMORY("userdb_init");
                if(u)
                    userdb_free(u);
                close(fd);
                return -1;
            }
            level = get_level(av[3]);
            if(level < 0 || level > LEVEL_ELITE)
            {
                log_message_level(LOG_LEVEL_ERROR, "userdb_init: invalid level %s for user %s", av[3], u->nick);
                level = LEVEL_USER;
            }
            u->level = level;
            u->created = atol(av[4]);
            u->lastSeen = atol(av[5]);
            if(ac > 6)
                u->flags = atoi(av[6]); /* u_short, atoi() is fine */
			else
				u->flags = 0;
			if(u->flags > 7)
			{
				log_message_level(LOG_LEVEL_ERROR, "userdb_init: userflags for user %s out of range: %hu", u->nick, u->flags);
				u->flags = 0;
			}
            hash_add(global.userDbHash , u->nick, u);
        }
        else
        {
            log_message_level(LOG_LEVEL_ERROR, "userdb_init: bad user db entry");
            print_args(ac, av);
        }
    }
    close(fd);
    log_message_level(LOG_LEVEL_SERVER, "userdb_init: %d registered users", global.userDbHash ->dbsize);
    /* reformat to version 1 specification */
    if(regen)
        userdb_dump();
    return 0;
}

static void dump_userdb(USERDB * db, int fd)
{
    char outbuf[1024];

    if(global.current_time - db->lastSeen >= global.nickExpire)
    {
        if(db->level < LEVEL_MODERATOR && !db->flags)
        {
            strcpy(Buf, ctime (&db->lastSeen));
            Buf[strlen(Buf) - 1] = 0;
            log_message_level( LOG_LEVEL_DEBUG, "dump_userdb: %s has expired (last seen %s)", db->nick, Buf);
            hash_remove(global.userDbHash , db->nick);
            return;
        }
        /* warn, but dont nuke expired accounts for privileged users */
        /*
        if(db->flags) 
		{
        flag = User_Flags[db->flags];
        }
		else
		{
        flag = "None";
        }
        log_message_level( LOG_LEVEL_SERVER, "dump_userdb: %s has expired (ignored: level=%s flag=%s)",
        db->nick, Levels[db->level], flag);
        */
        log_message_level( LOG_LEVEL_SERVER, "dump_userdb: %s has expired (ignored: level=%s)", db->nick, Levels[db->level]);
    }
	
	if(db->flags > 7)
	{
		log_message_level(LOG_LEVEL_ERROR, "dump_userdb: userflags for %s out of range: %hu", db->nick, db->flags);
		db->flags = 0;
	}

#ifdef EMAIL
    snprintf(outbuf, sizeof(outbuf), "%s %s %s %s %d %u %hu%s", db->nick, db->password, db->email, Levels[db->level], (int) db->created, (int) db->lastSeen, db->flags, LE);
#else
    snprintf(outbuf, sizeof(outbuf), "%s %s unknown %s %d %u %hu%s", db->nick, db->password,  Levels[db->level], (int) db->created, (int) db->lastSeen, db->flags, LE);
#endif
    fake_fputs(outbuf,fd);
}

int userdb_dump (void)
{
    int     fd;
    char    path[_POSIX_PATH_MAX], tmppath[_POSIX_PATH_MAX];
    struct  stat stat;

    log_message_level(LOG_LEVEL_SERVER, "userdb_dump: dumping user database");
    snprintf(tmppath, sizeof(tmppath), "%s/users.tmp", global.varDir);
    if((fd = open(tmppath, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR ))==-1)
    {
        logerr("userdb_dump", tmppath);
        return -1;
    }
    fake_fputs(":version 1", fd);
    fake_fputs(LE, fd);
    hash_foreach(global.userDbHash , (hash_callback_t) dump_userdb, (void *) fd);
    if(fstat(fd,&stat)==-1) 
	{
        log_message_level(LOG_LEVEL_SERVER,  "userdb_dump: fstat failed!");
        return 0;
    }
    if(stat.st_size==0) 
	{
        log_message_level(LOG_LEVEL_SERVER,  "userdb_dump: fstat on users.tmp returned 0 file size!");
        return 0;
    }

    if(close(fd))
    {
        logerr("userdb_dump", "close");
        return -1;
    }
    snprintf(path, sizeof(path), "%s/users", global.varDir);
    if(unlink(path))
        logerr("userdb_dump", "unlink");   /* not fatal, may not exist */
    if(rename(tmppath, path))
    {
        logerr("userdb_dump", "rename");
        return -1;
    }
    log_message_level(LOG_LEVEL_SERVER,  "userdb_dump: wrote %d entries", global.userDbHash ->dbsize);
    return 0;
}

/* create a default USERDB record from the existing user */
USERDB *create_db(USER * user)
{
    char   *tmppass;
    USERDB *db = BlockHeapAlloc(userdb_heap); /* CALLOC(1, sizeof(USERDB)); */

    if(db)
    {
        memset(db, 0, sizeof(USERDB));
        strncpy(db->nick, user->nick, sizeof(db->nick) - 1);
        db->nick[sizeof(db->nick) - 1] = 0;
        tmppass = generate_pass(user->pass);
        strncpy(db->password, tmppass, sizeof(db->password) - 1);
        db->password[sizeof(db->password) - 1] = 0;
        free(tmppass);
#if EMAIL
        snprintf(Buf, sizeof(Buf), "anon@%s", global.serverName);
        db->email = STRDUP(Buf);
#endif
        db->level = user->level;
        db->created = global.current_time;
        db->lastSeen = global.current_time;
    }
    if(!db
#if EMAIL
        || !db->email
#endif
        )
    {
        OUTOFMEMORY("create_db");
        userdb_free(db);
        return 0;
    }
    if(hash_add(global.userDbHash , db->nick, db))
    {
        userdb_free(db);
        return 0;
    }
    return db;
}
