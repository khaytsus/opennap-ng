/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
This is free software distributed under the terms of the
GNU Public License.  See the file COPYING for details.

$Id: proxy.c 257 2005-03-11 16:53:02Z Kintaro $ */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#ifdef HAVE_LIBPTHREAD
# include <pthread.h>
#endif
#include <string.h>

#ifndef WIN32
# include <sys/types.h>
# include <sys/stat.h>
# include <fcntl.h>
# include <errno.h>
# include <unistd.h>
# include <sys/socket.h>
# include <netinet/in.h>
# include <arpa/inet.h>
# include <string.h>
# include <sys/time.h>
# include <limits.h>
#endif /* !WIN32 */
#include "opennap.h"


#ifdef HAVE_LIBPTHREAD

unsigned int ProxyTimeout = 60;
char *ProxyTestHost = "192.168.2.4";
unsigned short ProxyTestPort = 80;

static int proxy_connect(unsigned int ip, unsigned short port)
{
    struct sockaddr_in sin;
    int fd;

    if((fd = socket(PF_INET, SOCK_STREAM, 0)) == -1)
        return -1;

    memset(&sin, 0, sizeof(struct sockaddr_in));

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ip;
    sin.sin_port = htons(port);

    log_message_level(LOG_LEVEL_DEBUG, "Checking for %s:%d",my_ntoa(BSWAP32(ip)),port);

    if(connect(fd, (struct sockaddr *) &sin, sizeof(struct sockaddr_in)) ==
        -1)
    {
        close(fd);
        return -1;
    }

    return fd;
}

static int proxy_read(int fd, char *data, size_t bytes)
{
    fd_set rfds;
    struct timeval tv;

    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);

    tv.tv_sec = ProxyTimeout;
    tv.tv_usec = 0;

    if(select(fd + 1, &rfds, NULL, NULL, &tv) <= 0)
        return -1;

    return read(fd, data, bytes);
}

/* a simple Proxy Scanner
* TODO: check for HTTP Post Proxy, Cisco Router, FTP Proxy
*    WinGates it works but I would send to server also ip:port\r\n and control the answer
*/
void *proxy_scanner(void *ptr)
{
    USER *user = (USER *) ptr;
    char data[256];
    int fd, i, port, n;
    unsigned int d_addr = htonl(inet_addr(ProxyTestHost));    /* FIXME: cambiare con una variabile di default */
    unsigned short d_port = ProxyTestPort;

    log_message_level(LOG_LEVEL_DEBUG, "Starting thread %x", pthread_self());

    send_cmd(user->con, MSG_SERVER_NOSUCH, "This server runs an open proxy monitor to prevent abuse");
    send_cmd(user->con, MSG_SERVER_NOSUCH, "If you see various connections from %s or %s", global.serverName, my_ntoa(BSWAP32(global.serverIP)));
    send_cmd(user->con, MSG_SERVER_NOSUCH, "please disregard them, as they are the detector in action");

    /* Check for WinGates */
    if((fd = proxy_connect(user->ip, 23)) != -1)
    {
        if(proxy_read(fd, data, 9) == 9)
        {
            if(proxy_read(fd, data, 8) == 8)
            {
                data[8] = 0;

                if(!strcasecmp(data, "WinGate>") || !strcasecmp(data, "Too Many"))
                {
                    ibl_kill(user->con, MSG_SERVER_ERROR, "WinGate are not allowed");
                    close(fd);
                    pthread_exit(NULL);
                }
            }
        }

        close(fd);
    }

    /* Check for Socks4 */
    if((fd = proxy_connect(user->ip, 1080)) != -1)
    {
        snprintf(data, sizeof(data), "%c%c%c%c%c%c%c%c%c", 4, 1, (d_port >> 8) & 0xFF, d_port & 0xFF, (d_addr >> 24) & 0xFF, (d_addr >> 16) & 0xFF, (d_addr >> 8) & 0xFF, d_addr & 0xFF, 0);

        if(write(fd, data, 9) == 9)
        {
            if(proxy_read(fd, data, 2) == 2)
            {
                if(data[1] == 90)
                {
                    ibl_kill(user->con, MSG_SERVER_ERROR, "Socks4 are not allowed");
                    close(fd);
                    pthread_exit(NULL);
                }
            }
        }

        close(fd);
    }

    /* Check for socks5 */
    if((fd = proxy_connect(user->ip, 1080)) != -1)
    {
        snprintf(data, sizeof(data), "%c%c%c", 5, 1, 0);

        if(write(fd, data, 3) == 3)
        {
            if(proxy_read(fd, data, 2) == 2)
            {
                if(data[0] == 5 || !data[1])
                {
                    snprintf(data, sizeof(data), "%c%c%c%c%c%c%c%c%c%c", 5, 1, 0, 1, (d_addr >> 24) & 0xFF, (d_addr >> 16) & 0xFF, (d_addr >> 8) & 0xFF, d_addr & 0xFF, (d_port >> 8) & 0xFF, d_port & 0xFF);

                    if(write(fd, data, 10) == 10)
                    {
                        if(proxy_read(fd, data, 2) == 2)
                        {
                            if(data[0] == 5 || !data[1])
                            {
                                ibl_kill(user->con, MSG_SERVER_ERROR, "Socks5 are not allowed");
                                close(fd);
                                pthread_exit(NULL);
                            }
                        }
                    }
                }
            }
        }

        close(fd);
    }

    /* Check for HTTP Proxy */
    for (i = 0, port = 80; i < 3; i++)
    {
        if(i == 1)
            port = 3128;
        else if(i == 2)
            port = 8080;

        if((fd = proxy_connect(user->ip, port)) == -1)
            continue;

        /* FIXME: guarda che d_addr è un int nn una stringa! */
        snprintf(data, sizeof(data), "CONNECT %s:%d HTTP/1.0\r\n\r\n", ProxyTestHost, ProxyTestPort);

        if(write(fd, data, strlen(data)) == (int) strlen(data))
        {
            if((n = proxy_read(fd, data, 15)) >= 12)
            {
                data[n] = 0;

                if(!strncasecmp (data, "HTTP/1.0 200", 12) || !strncasecmp (data, "HTTP/1.1 200 Co", 15))
                {
                    ibl_kill(user->con, MSG_SERVER_ERROR, "HTTP Proxy are not allowed");
                    close(fd);
                    pthread_exit(NULL);
                }
            }
        }

        close(fd);
    }

    pthread_exit(NULL);
}

void ProxyCheck(USER *user)
{
    pthread_t thread;
    pthread_create(&thread, NULL, proxy_scanner, (void *) user);
}

#endif
