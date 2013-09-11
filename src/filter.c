/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
This is free software distributed under the terms of the
GNU Public License.  See the file COPYING for details.

$Id: filter.c 436 2006-09-04 14:56:32Z reech $ */

/* simple filtering mechanism to weed out entries which have too many
* matches.  this used to be hardcoded, but various servers will need
* to tailor this to suit their own needs.  see sample.filter for an
* example list of commonly occuring words
*/

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

#ifndef ROUTING_ONLY

#ifndef HAVE_REGCOMP
# include "_regex.h"
#else
# include <regex.h>
#endif

/* HASH   *Filter = 0;  moved to global.filterHash  */
/* static LIST *Block = 0;  moved to global.blockList */

static void dump_filter (char *token, int fd)
{
    char outbuf[1024];

    snprintf(outbuf, sizeof(outbuf), "%s%s", token, LE);
    fake_fputs(outbuf,fd);
}

int filter_dump(void)
{
    int     fd;
    char    path[_POSIX_PATH_MAX], tmppath[_POSIX_PATH_MAX];
    struct  stat sts;

    log_message_level(LOG_LEVEL_SERVER, "filter_dump: dumping filter database");
    snprintf(tmppath, sizeof(tmppath), "%s/filter.tmp", global.varDir);
    if((fd = open(tmppath, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR ))==-1)
    {
        logerr("filter_dump", tmppath);
        return -1;
    }
    hash_foreach(global.filterHash, (hash_callback_t) dump_filter, (void *) fd);
    if(fstat(fd,&sts)==-1) 
	{
        log_message_level(LOG_LEVEL_SERVER,  "filter_dump: fstat failed!");
        return 0;
    }
    if(sts.st_size==0) 
	{
        log_message_level(LOG_LEVEL_SERVER,  "filter_dump: fstat on filter.tmp returned 0 file size!");
        return 0;
    }
    if(close(fd)) 
    {
        logerr("filter_dump", "close");
        return -1;
    }
    snprintf(path, sizeof(path), "%s/filter", global.varDir);
    if(stat(path, &sts) == -1 && errno == ENOENT)
    {
        log_message_level(LOG_LEVEL_DEBUG, "%s file does not exist\n", path);
    }
    else 
    {
        if(unlink(path))
            logerr("filter_dump", "unlink");       /* not fatal, may not exist */
    }
    if(rename(tmppath, path)) 
    {
        logerr("filter_dump", "rename");
        return -1;
    }
    return 0;
}                                    

static void load_filter_internal(HASH * h, const char *file)
{
    char    path[_POSIX_PATH_MAX];
    char    buf[128], *token;
    int     len;
    int     fd;

    snprintf(path, sizeof(path), "%s/%s", global.varDir, file);
    if((fd = open(path, O_RDONLY))==-1)
    {
        if(errno != ENOENT)
            log_message_level(LOG_LEVEL_ERROR, "load_filter_internal: open: %s: %s (errno %d)", path, strerror(errno), errno);
        return;
    }
    while (fake_fgets(buf, sizeof(buf) - 1, fd))
    {
        len = strlen(buf);
        while (len > 0 && isspace((int)buf[len - 1]))
            len--;
        buf[len] = 0;
        /* need to convert to lowercase since the hash table is
        * case-sensitive
        */
        strlower(buf);
        token = STRDUP(buf);
        hash_add(h, token, token);
    }
    close(fd);
}

void load_filter(void)
{
    if(global.filterHash)
        free_hash(global.filterHash);
    global.filterHash = hash_init(257, free_pointer);
    /* set to case-sensitive function for speed.  we always convert to
    * lower case before insertion.
    */
    /* Hoshi */
    /*    hash_set_hash_func(global.filterHash, hash_string, hash_compare_string); */
    hash_set_hash_func(global.filterHash, hash_string, (hash_compare_t) 1);
    load_filter_internal(global.filterHash, "filter");
}

void load_block(void)
{
    char    path[_POSIX_PATH_MAX];
    char    buf[256];
    char    err[256];
    char    exp[256];
    int     len;
    int     fd;
    regex_t *rx;
    int     line = 0;
    LIST  **head = &global.blockList;
    int     n;

    log_message_level(LOG_LEVEL_DEBUG, "load_block: free'g old list");

    while (*head)
    {
        LIST   *ptr = *head;

        *head = (*head)->next;
        regfree (ptr->data);
        FREE(ptr);
    }

    snprintf(path, sizeof(path), "%s/block", global.shareDir);
    if((fd = open(path, O_RDONLY))==-1)
    {
        if(errno != ENOENT)
            log_message_level(LOG_LEVEL_ERROR, "load_block: open: %s: %s (errno %d)", path, strerror(errno), errno);
        return;
    }
    log_message_level(LOG_LEVEL_DEBUG, "load_block: reading %s", path);
    while (fake_fgets(buf, sizeof(buf) - 1, fd))
    {
        line++;
        /* Hoshi */
        /*  if(buf[0] == '#') */
        if(buf[0] == '#' || buf[0] == 10 || buf[0] == 13)
            continue;
        len = strlen(buf);
        while (len > 0 && isspace((int)buf[len - 1]))
            len--;
        buf[len] = 0;
        snprintf(exp, sizeof(exp), "(^|[^[:alpha:]])%s($|[^[:alpha:]])", buf);
        log_message_level(LOG_LEVEL_DEBUG, "load_block: added RE: \"%s\"", exp);
        rx = CALLOC(1, sizeof(regex_t));
        if(!rx)
        {
            OUTOFMEMORY("load_block");
            break;
        }
        n = regcomp(rx, exp, REG_EXTENDED | REG_ICASE | REG_NOSUB);
        if(n)
        {
            err[0] = 0;
            regerror(n, rx, err, sizeof(err));
            log_message_level(LOG_LEVEL_ERROR, "load_block: %s: %d: %s", path, line, err);
            FREE(rx);
            continue;
        }
        *head = CALLOC(1, sizeof(LIST));
        (*head)->data = rx;
        head = &(*head)->next;
    }
    close(fd);
    log_message_level(LOG_LEVEL_DEBUG, "load_block: done");
}

int is_filtered(char *s)
{
    return(hash_lookup(global.filterHash, s) != 0);
}

int is_blocked(char *s)
{
    LIST   *ptr = global.blockList;

    for (; ptr; ptr = ptr->next)
        if(regexec(ptr->data, s, 0, NULL, 0) == 0)
        {
            return 1;
        }
        return 0;
}
#endif /* ! ROUTING_ONLY */
