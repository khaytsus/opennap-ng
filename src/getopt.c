/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
This is free software distributed under the terms of the
GNU Public License.  See the file COPYING for details.

$Id: getopt.c 434 2006-09-03 17:48:47Z reech $ */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>

#define EOF -1

int optind = 1;
char *optarg;

/* -b 500 -v */
int _getopt(int ac, char **av, const char *opts)
{
    const char *p;

    while (optind < ac)
    {
        if(*av[optind] == '-')
        {
            p = strchr(opts, av[optind][1]);
            if(!p)
                return '?';
            if(*(p + 1) == ':')
            {
                /* requires arg */
                optind++;
                if(!av[optind] || *av[optind] == '-')
                    return ':'; /* missing argument */
                optarg = av[optind];
            }
            else
                optarg = 0;
            optind++;
            return *p;
        }
        else
            break;
    }
    optarg = 0;
    return EOF;
}
