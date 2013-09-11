/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
This is free software distributed under the terms of the
GNU Public License.  See the file COPYING for details.

$Id: init.c 434 2006-09-03 17:48:47Z reech $ */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifndef WIN32
# include <grp.h>
# include <pwd.h>
# include <unistd.h>
# include <sys/types.h>
# include <netdb.h>
# include <limits.h>
# include <netinet/in.h>
# include <arpa/inet.h>
#endif /* !WIN32 */
#include <signal.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#ifdef __EMX__
# include <stdlib.h>
# define _POSIX_PATH_MAX _MAX_PATH
#endif /* __EMX__ */
#include "opennap.h"
#include "hashlist.h"
#include "debug.h"
#if HAVE_MLOCKALL
# include <sys/mman.h>
#endif /* HAVE_MLOCKALL */

static void lookup_hostname(void)
{
    struct hostent *he;

    /* get our canonical host name */
    gethostname(Buf, sizeof(Buf));
    he = gethostbyname(Buf);
    if(he)
        global.serverName = STRDUP(he->h_name);
    else
    {
        log_message_level(LOG_LEVEL_ERROR | LOG_LEVEL_SERVER, "lookup_hostname: unable to find fqdn for %s", Buf);
        global.serverName = STRDUP(Buf);
    }
}

#ifndef WIN32
static void sighandler(int sig)
{
    log_message_level(LOG_LEVEL_SERVER, "sighandler: caught signal %d", sig);
    switch (sig)
    {
    case SIGHUP:
        reload_config();
        cycle_files(); 
        break;
    case SIGINT:
    case SIGTERM:
        global.sigCaught = 1;
        break;
    case SIGUSR1:
        CLEANUP();
        break;
    }
}

#if defined(PARANOID) && defined(ONAP_DEBUG)
static void wipe_user_pass(USER * user, void *unused)
{
    (void) unused;
    memset(user->pass, 0, strlen(user->pass));
}

static void wipe_server_pass(server_auth_t * auth)
{
    memset(auth->their_pass, 0, strlen(auth->their_pass));
    memset(auth->my_pass, 0, strlen(auth->my_pass));
}

static void handle_sigsegv(int sig)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_DFL;
    sigaction(SIGSEGV, &sa, 0);    /* set back to default */

    /* every C primer says not to do this, but it seems to work... =) */
    fprintf(stderr, "handle_sigsegv: caught sigsegv, wiping passwords\n");
    fflush(stderr);

    (void) sig;
    /* wipe the user/server passwords before dumping core */
    hash_foreach(global.userDbHash , (hash_callback_t) wipe_user_pass, 0);
    list_foreach(global.serverAliasList, (list_callback_t) wipe_server_pass, 0);

    kill(getpid(), SIGSEGV);  /* raise the signal again so we get a core */
}
#endif /* PARANOID */

static int drop_privs(void)
{
    int     n;
    char   *p;
    struct passwd *pw;
    struct group *gr;

    n = strtol(USE_GID, &p, 10);
    if(*p)
    {
        /* probably a string */
        gr = getgrnam(USE_GID);
        if(!gr)
        {
            log_message_level(LOG_LEVEL_ERROR | LOG_LEVEL_SERVER, "drop_privs: unable to find gid for group %s", USE_GID);
            return -1;
        }
        n = gr->gr_gid;
    }
    if(setgid(n))
    {
        logerr("drop_privs", "setgid");
        return -1;
    }

    n = strtol(USE_UID, &p, 10);
    if(*p)
    {
        /* probably a string */
        pw = getpwnam(USE_UID);
        if(!pw)
        {
            log_message_level(LOG_LEVEL_ERROR | LOG_LEVEL_SERVER, "drop_privs: unable to find uid for user %s", USE_UID);
            return -1;
        }
        n = pw->pw_uid;
    }
    if(setuid(n))
    {
        logerr("drop_privs", "setuid");
        return -1;
    }

    return 0;
}
#endif

/* write the pid to a file so an external program can check to see if the
process is still running. */
static void dump_pid(void)
{
    int     fd;
    char    path[_POSIX_PATH_MAX];
    char    outbuf[128];

    log_message_level(LOG_LEVEL_DEBUG, "dump_pid: pid is %d", getpid());
    snprintf(path, sizeof(path), "%s/opennap-ng.pid", global.varDir);
    if((fd = open(path, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR))==-1)
    {
        logerr("dump_pid", path);
        return;
    }
    snprintf(outbuf, sizeof(outbuf), "%d\n", (int) getpid());
    fake_fputs(outbuf,fd);
    close(fd);
}

void cycle_files()
{

    /* Gives opennap the ability to re-open the log file after a HUP for
    logrotate, etc. */

#ifndef WIN32
    if(global.serverFlags & ON_BACKGROUND)
    {
        char    path[_POSIX_PATH_MAX];
        int     fd = global.logfile;

        log_message_level(LOG_LEVEL_DEBUG, "cycle_files: Cycling log file..");
        snprintf(path, sizeof(path), "%s/log", global.varDir);
        if(fd)
        {
			log_message_level(LOG_LEVEL_DEBUG, "cycle_files: fd: %d", fd);
		    close(fd);
            fd = open(path, O_CREAT | O_WRONLY | O_APPEND, S_IRUSR | S_IWUSR);
            if(fd > 0)
            {
                global.logfile = fd;
                if(dup2 (fd, 1) == -1)
                {
                    logerr("cycle_files", "dup2");
                }
            }
            else
            {
                logerr("cycle_files", path);
            }
        }
    }
#endif
}

int init_server(void)
{
#ifndef WIN32
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sighandler;
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGPIPE, &sa, NULL);
#   ifndef __EMX__
    sa.sa_flags = SA_RESTART;
#   endif /* ! __EMX__ */
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGALRM, &sa, NULL);
#   ifdef PARANOID
#       ifndef ONAP_DEBUG
    sa.sa_handler = handle_sigsegv;
    sigaction(SIGSEGV, &sa, NULL);
#       endif /* ONAP_DEBUG */
#   endif /* PARANOID */
#endif /* !WIN32 */

    log_message_level(LOG_LEVEL_SERVER, "init_server: version %s%s starting", VERSION, SUBVERSIONREV);

    global.serverStartTime = time(&global.current_time);

    /* load default configuration values */
    config_defaults();

    /* load the config file - note that if CHROOT is defined we are already
    * chrooted when we get here.  we are also running as uid 0 because
    * some of the ulimit's might need to be altered before starting up.
    * so read the config file now, set limits and then drop privs before
    * loading any other files.
    */
    if(config(1))
        return -1;

#if !defined(WIN32) && !defined(__EMX__)
    /* change umask to something more secure */
    umask(077);

    if(set_max_connections(global.hardConnLimit))
        return -1;
    if(global.maxDataSize != -1 && set_data_size(global.maxDataSize))
        return -1;
    if(global.maxRssSize != -1 && set_rss_size(global.maxRssSize))
        return -1;
#if HAVE_MLOCKALL
    /* prevent swapping by locking all memory into real memory */
    if(option(ON_LOCK_MEMORY) && mlockall(MCL_CURRENT | MCL_FUTURE))
        logerr("init_server", "mlockall");
#endif /* HAVE_MLOCKALL */

    if(getuid() == 0)
        drop_privs();
    ASSERT(getuid() != 0);
    ASSERT(getgid() != 0);

    /* log message to show that we really have dropped privs.  if CHROOT
    * was defined, we should also be locked in the jail.  we never need 
    * root privs again and only the config files need to be accessed.
    */
    log_message_level(LOG_LEVEL_SERVER, "init_server: running as user %d, group %d", getuid(), getgid());
#endif /* !WIN32 */

    /* if running in daemon mode, reopen stdout as a log file */
    if(global.serverFlags & ON_BACKGROUND)
    {
        char    path[_POSIX_PATH_MAX];
        int fd;

        snprintf(path, sizeof(path), "%s/log", global.varDir);
        fd = open(path, O_CREAT | O_WRONLY | O_APPEND, S_IRUSR | S_IWUSR);
        global.logfile = fd;
        log_message_level(LOG_LEVEL_DEBUG, "Opening log file fd: %d", global.logfile);
        if(fd > 0)
        {
            /* close stdout */
            if(dup2(fd, 1) == -1)
            {
                logerr("init_server", "dup2");
                return -1;
            }
            //log_message_level(LOG_LEVEL_DEBUG, "Closing log file fd: %d", fd);
            //close(fd);
        }
        else
        {
            logerr("init_server", path);
            return -1;
        }
    }

#ifdef PID
    dump_pid();
#endif  
    log_message_level(LOG_LEVEL_SERVER, "init server: FD SETSIZE is %d", FD_SETSIZE);
    /* if not defined in the config file, get the system name */
    if(!global.serverName)
        lookup_hostname();
    log_message_level(LOG_LEVEL_SERVER, "init_server: my hostname is %s", global.serverName);

    hash_init_real();

    /* read the user database.  we do this even for routing servers so that
    * we keep track of who is allowed to log in.  eventually this should
    * probably just keep track of the few users that are allowed instead of
    * keeping everyone...
    */
    if(userdb_init())
    {
        log_message_level(LOG_LEVEL_ERROR, "init_server: userdb_init failed.  State dir is %s, make sure your users file is there.  Maybe you need to read the documentation.", VARDIR);
        return -1;
    }

    /* initialize hash tables.  the size of the hash table roughly cuts
    the max number of matches required to find any given entry by the same
    factor.  so a 256 entry hash table with 1024 entries will take rougly
    4 comparisons max to find any one entry.  we use prime numbers here
    because that gives the table a little better spread */
    global.usersHash = hash_init(1069, (hash_destroy) free_user);
    global.channelHash = hash_init(257, (hash_destroy) free_channel);
    global.hotlistHash = hash_init(521, 0);
    global.whoWasHash = hash_init(1069, (hash_destroy) free_whowas);

    global.clonesHash = hash_init(1069, (hash_destroy) ip_info_free);
    hash_set_hash_func(global.clonesHash, hash_u_int, hash_compare_u_int);

    /* routing-only servers don't care about any of this crap... */
#ifndef ROUTING_ONLY
    global.FileHash = hash_init(7919, 0); /* was 4001 but now we are approaching 1M files on a server, this will bring matches down...*/
    /* set to case-sensitive version.  we always convert to lower case, so
    * we want to speed the comparison up
    */
    hash_set_hash_func(global.FileHash, hash_string, hash_compare_string);
#if RESUME
    global.MD5Hash = hash_init(7919, 0); /* was 4001 */
    hash_set_hash_func(global.MD5Hash, hash_string, hash_compare_string);
#endif
    load_bans();
    load_block();
    load_filter();
    load_channels();
    acl_init();
#endif /* !ROUTING_ONLY */
    global.clientVersionHash = hash_init(257, (hash_destroy) hashlist_free);

    init_random();
    motd_init();
    load_server_auth();

    initBlockHeap();
    /* we subtract one here for the BlockHeap overhead that is added, so we stay inside the pagesize (hopfully) */
    user_heap = BlockHeapCreate(sizeof(USER), (int)(getpagesize()*16/sizeof(USER)) - 1);
    useropt_heap = BlockHeapCreate(sizeof(USEROPT), (int)(getpagesize()*8/sizeof(USEROPT)) - 1);
    destroy_list_heap = BlockHeapCreate(sizeof(LIST), (int)(getpagesize()/sizeof(LIST)) - 1);

    /* figure out what my local ip address is so that when users connect via
    * localhost they can still xfer files.  do this here because
    * server_name can get changed to server_alias below.
    */
    global.iface = inet_addr(global.Listen_Addr);
    if(global.iface != INADDR_ANY)
        global.serverIP = global.iface;
    else
        global.serverIP = lookup_ip(global.serverName);

#ifndef ROUTING_ONLY
    /* set default values for napigator reporting if they were not
    * explicitly set in the config file
    */
    global.stat_server_fd = INVALID_SOCKET;
    if(global.report_name == NULL)
        global.report_name = STRDUP(global.serverName);
    if(global.report_ip == NULL)
        global.report_ip = STRDUP(my_ntoa(global.serverIP));
    if(global.report_port == 0)
        global.report_port = atoi(global.serverPortList->data);

    if(global.stat_server)
        log_message_level(LOG_LEVEL_SERVER, "init: napigator reporting set to %s -> %s:%d", global.report_name, global.report_ip, global.report_port);
#endif

    if(global.serverAlias)
    {
        /* switch to using the alias if its defined.   we delay until here
        * because we need to find the local servers' ip when clients connect
        * via localhost.
        */
        if(global.serverName)
            FREE(global.serverName);
        global.serverName = STRDUP(global.serverAlias);
        log_message_level(LOG_LEVEL_SERVER, "init_server: using %s as my name", global.serverName);
    }

    return 0;
}
