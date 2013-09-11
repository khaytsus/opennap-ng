/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
This is free software distributed under the terms of the
GNU Public License.  See the file COPYING for details.

$Id: metaserver.c 430 2006-07-29 20:22:19Z reech $ */

/* a simple napster metaserver.  redirects clients to a specific set of
servers */

#if HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>

#ifdef WIN32
# include "win32-support.h"
# define strdup _strdup
#else
# include <signal.h>
# include <unistd.h>
# include <sys/socket.h>
# include <netinet/in.h>
# include <arpa/inet.h>
# define WRITE write
# define CLOSE close
#endif /* WIN32 */

#if HAVE_POLL
#include <sys/poll.h>
#endif /* HAVE_POLL */

#if HAVE_SYSLOG
#include <syslog.h>
#endif

char    metafile[_POSIX_PATH_MAX];
char   *hosts[64];
int     numhosts = 0;
volatile int sig_meta = 0;

#ifndef HAVE_SOCKLEN_T
typedef unsigned int socklen_t;
#endif


#ifndef WIN32
static void
handler (int sig)
{
    if (sig == SIGHUP)
        sig_meta++;
}
#endif

static void
usage (void)
{
    puts ("usage: metaserver [ -fsv ] [ -c CONFIG ] [ -l IP ] [ -p <port> ] [ host:port ... ]");
    puts ("  -c CONFIG  use list of servers in file CONFIG");
    puts ("  -f         run the metaserver in the background");
    puts ("  -v         display version number and exit");
    puts ("  -l IP      listen only on interface for IP");
    puts ("  -p <port>  listen for connection on <port> (default is 8875)");
    puts ("  -s         disable syslog messages");
    puts ("\n  if no arguments are given, defaults to 127.0.0.1:8888");
    exit (1);
}

static void
read_metafile (char *filename)
{
    char    buffer[90];

    FILE   *fp;

    fp = fopen (filename, "r");
    if (!fp)
        return;
    while (fgets (buffer, sizeof (buffer) - 1, fp))
    {
        buffer[strlen (buffer) - 1] = 0;
        if (strlen (buffer) > 0 && buffer[0] != '#')
            hosts[numhosts++] = strdup (buffer);
    }
    fclose (fp);
}

int
main (int argc, char **argv)
{
    struct sockaddr_in sin;
    int     i, s, f, port = 8875;
    int     location = 0;
    int     sys_log = 1;
    int     background = 0;

#if HAVE_POLL
    struct pollfd ufd;
#else
    fd_set  set;
#endif /* HAVE_POLL */
    socklen_t sinsize;

#ifndef WIN32
    struct sigaction sa;
#endif
    unsigned int iface = INADDR_ANY;

#ifdef WIN32
    WSADATA wsa;

    WSAStartup (MAKEWORD (1, 1), &wsa);
#endif /* !WIN32 */

    metafile[0] = 0;

    while ((i = getopt (argc, argv, "hfl:vp:c:s")) != EOF)
    {
        switch (i)
        {
        case 'l':
            iface = inet_addr (optarg);
            break;
        case 'p':
            port = atoi (optarg);
            break;
        case 'c':
            strcpy (metafile, optarg);
            break;
        case 'f':
            background ^= 1;
            break;
        case 's':
            sys_log ^= 1;
            break;
        case 'v':
            printf ("%s metaserver version %s\n", PACKAGE, VERSION);
            exit (1);
        default:
            usage ();
        }
    }

    /* read in the host list */
    if (!metafile[0])
    {
        if (!argv[optind])
            hosts[numhosts++] = strdup ("127.0.0.1:8888");  /* use default host */
        else
        {
            while (argv[optind])
            {
                hosts[numhosts++] = strdup (argv[optind]);
                optind++;
            }
        }
    }
    else
        read_metafile (metafile);

#ifndef WIN32
    /* set some signal handlers so we can shut down gracefully */
    memset (&sa, 0, sizeof (sa));
    sa.sa_handler = handler;
    sigaction (SIGINT, &sa, 0);
    sigaction (SIGTERM, &sa, 0);
    sa.sa_flags = SA_RESTART;
    sigaction (SIGHUP, &sa, NULL);
#endif

    memset (&sin, 0, sizeof (sin));
    sin.sin_port = htons (port);
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = iface;

    s = socket (PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s < 0)
    {
        perror ("socket");
        exit (1);
    }
    if (bind (s, (struct sockaddr *) &sin, sizeof (sin)) < 0)
    {
        perror ("bind");
        exit (1);
    }
    if (listen (s, 50) < 0)
    {
        perror ("listen");
        exit (1);
    }

#ifndef WIN32
    if (background && fork ())
        _exit (0);
#endif

#if HAVE_SYSLOG
    if (sys_log)
        openlog ("metaserver", LOG_PID, LOG_LOCAL6);
#endif

    location = 0;
#if HAVE_POLL
    memset (&ufd, 0, sizeof (ufd));
    ufd.fd = s;
    ufd.events = POLLIN | POLLHUP;
#endif /* HAVE_POLL */
    for (;;)
    {
#if HAVE_POLL
        i = poll (&ufd, 1, -1);
#else
        FD_ZERO (&set);
        FD_SET (s, &set);
        i = select (s + 1, &set, 0, 0, 0);
#endif /* HAVE_POLL */
        if (i == -1)
        {
            /* re-read configuration files */
            if (sig_meta)
            {
                for (i = 0; i < numhosts; i++)
                    free (hosts[i]);
                numhosts = 0;
                location = 0;
                sig_meta = 0;
                read_metafile (metafile);
                continue;
            }
            perror (
#if HAVE_POLL
                "poll"
#else
                "select"
#endif
                );
            break;
        }

        sinsize = sizeof (sin);
        f = accept (s, (struct sockaddr *) &sin, &sinsize);
        if (f < 0)
        {
            perror ("accept");
            break;
        }
        WRITE (f, hosts[location], strlen (hosts[location]));
        WRITE (f, "\n", 1);
#if HAVE_SYSLOG
        if (sys_log)
            syslog (LOG_ERR, "Redirecting %s to %s", inet_ntoa (sin.sin_addr),
            hosts[location]);
#endif
        location = (location + 1) % numhosts;
        CLOSE (f);
    }
    CLOSE (s);
#if HAVE_SYSLOG
    closelog ();
#endif
    exit (0);
}
