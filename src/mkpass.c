/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
This is free software distributed under the terms of the
GNU Public License.  See the file COPYING for details.

$Id: mkpass.c 374 2005-04-20 23:01:29Z reech $ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifndef WIN32
#include <unistd.h>
#endif
#include <stdlib.h>
#include "md5.h"
#include "opennap.h"
#include "debug.h"

/* needed for the random number generation */
time_t Current_Time = 0;

static char alphabet[] =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
#define alphabet(c) alphabet[(unsigned int)c]


/* needed for win32 standalone build */
#ifdef WIN32
GLOBAL global;

char    Buf[2048];
int     Index_Path_Depth = 2;
int     Log_Level = 0;
u_int   Server_Flags = 0;

int send_to_channel (char *name, char *buf, int buflen) {
    return 0;
}

#endif

void init_random (void)
{
    ASSERT (global.current_time != 0);

    /* force generation of a different seed if respawning quickly by adding
    the pid of the current process */
    srand (global.current_time + getuid () + getpid ());
}

/* fake_fputs makes it easier to write to a file, while not having
the limitations on some UNIXes that are associated with fopen() */

int fake_fputs(const char *buf, int fd) {
    int x;
    x=strlen(buf);
    if (write(fd, buf, x)!=x) {
        return(EOF);
    }
    return(x);
}

void get_random_bytes (char *d, int dsize)
{
    int     i = 0, v;

    while (i < dsize)
    {
        v = rand ();
        d[i++] = v & 0xff;
        if (i < dsize)
            d[i++] = (v >> 8) & 0xff;
        if (i < dsize)
            d[i++] = (v >> 16) & 0xff;
        if (i < dsize)
            d[i++] = (v >> 24) & 0xff;
    }
}


static int b64_encode (char *out, int *outsize, char *in, int insize)
{
    unsigned char a, b, c, d;
    char   *pout = out;

    while (insize > 0)
    {
        c = d = 0xff;
        a = (*in >> 2) & 0x3f;
        b = (*in & 0x3) << 4;
        in++;
        insize--;
        if (insize)
        {
            b |= (*in >> 4) & 0xf;
            c = (*in & 0xf) << 2;
            in++;
            insize--;
            if (insize)
            {
                c |= (*in >> 6) & 0x3;
                d = *in & 0x3f;
                in++;
                insize--;
            }
        }
        *out++ = alphabet (a);
        *out++ = alphabet (b);
        if (c != 0xff)
        {
            *out++ = alphabet (c);
            if (d != 0xff)
                *out++ = alphabet (d);
            else
                *out++ = '=';
        }
        else
        {
            *out++ = '=';
            *out++ = '=';
        }
    }
    *out = 0;
    *outsize = out - pout;
    return 0;
}


static char b64_lookup[128] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
        -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1
};

#define b64_lookup(c) b64_lookup[(unsigned int)c]

static int b64_decode (char *out, int *outsize, const char *in)
{
    unsigned char a, b, c, d;
    unsigned char b2, b3;
    char   *pout = out;

    while (*in)
    {
        a = b64_lookup (*in++);
        b = b64_lookup (*in++);
        *out++ = a << 2 | b >> 4;
        b2 = b << 4;
        if (*in && *in != '=')
        {
            c = b64_lookup (*in++);
            b2 |= c >> 2;
            *out++ = b2;
            b3 = c << 6;
            if (*in && *in != '=')
            {
                d = b64_lookup (*in++);
                b3 |= d;
                *out++ = b3;
            }
            else
                break;
        }
        else
            break;
    }
    *outsize = out - pout;
    return 0;
}


int check_pass (const char *info, const char *pass)
{
    struct md5_ctx md;
    char    hash[16], real[16];
    int     realsize;

    ASSERT (info != 0);
    ASSERT (pass != 0);
    if (*info != '1' || *(info + 1) != ',')
        return -1;
    info += 2;
    md5_init_ctx (&md);
    md5_process_bytes (info, 8, &md);
    info += 8;
    if (*info != ',')
        return -1;
    info++;
    md5_process_bytes (pass, strlen (pass), &md);
    md5_finish_ctx (&md, hash);
    realsize = sizeof (real);
    b64_decode (real, &realsize, info);
    ASSERT (realsize == 16);
    if (memcmp (real, hash, 16) == 0)
        return 0;
    return -1;
}

char   *generate_pass (const char *pass)
{
    struct md5_ctx md;
    char    hash[16];
    char    output[36];     /* 1,xxxxxxxx,xxxxxxxxxxxxxxxxxxxxxxx== */
    int     outsize;
    int     i;

    ASSERT (pass != 0);
    output[0] = '1';
    output[1] = ',';
    get_random_bytes (output + 2, 8);
    for (i = 0; i < 8; i++)
        output[i + 2] = alphabet[((unsigned int) output[i + 2]) % 64];
    output[10] = ',';
    md5_init_ctx (&md);
    md5_process_bytes (output + 2, 8, &md);
    md5_process_bytes (pass, strlen (pass), &md);
    md5_finish_ctx (&md, hash);
    outsize = sizeof (output) - 11;
    b64_encode (output + 11, &outsize, hash, 16);
    output[sizeof (output) - 3] = 0;    /* strip the trailing == */
    return (STRDUP (output));
}


static void
usage (void)
{
    fputs("usage: mkpass [-m|-n filename|-c hashedpw] [-u username] -p password\n", stderr);
    fputs(" -n filename  create New userdb 'filename' with given -u and -p\n", stderr);
    fputs(" -c hashedpw  Check hashed password against -p passwd \n", stderr);
    fputs(" -m           Make hashed password from -p passwd\n", stderr);
    fputs(" -u username  use this as Username\n", stderr);
    fputs(" -p password  use this as Password\n", stderr);
    exit(1);
}

int
main (int argc, char **argv)
{
    char *s, *pass = 0, *user = 0, *file = 0, *hpass = 0;
    int i, mode = 0, fd = 0;

    INIT ();
    while ((i = getopt (argc, argv, "u:p:c:n:mvh")) != -1) {
        switch (i) {
    case 'u':
        user = optarg;
        break;
    case 'p':
        pass = optarg;
        break;
    case 'm':
        mode = 0;
        break;
    case 'c':
        mode = 1;
        hpass = optarg;
        break;
    case 'n':
        mode = 2;
        file = optarg;
        break;
    default:
        usage ();
        }
    }
    switch (mode) {
    case 0:
        if (!pass) {
            fputs("Sorry, need a -p password to make a hashed one for you!\n", stderr);
            usage();
        }
        Current_Time = time(0);
        init_random();
        s = generate_pass( pass );
        puts(s);
        if (check_pass(s, pass))
            fputs("Jikes! an error (can't hash this one try with another password)\n", stderr);
        FREE(s);
        CLEANUP();
        break;
    case 1:
        if (!hpass) {
            fputs("Sorry, need some hashed password to check!\n", stderr);
            usage();
        }
        if (!pass) {
            fputs("Sorry, need a -p password to check against with\n", stderr);
            usage();
        }
        if (check_pass (hpass, pass))
            puts("Nope, invalid password!");
        else
            puts("OK, they match ;-)");
        break;
    case 2:
        if (!pass) {
            fputs("Sorry, need a -p password to check against with\n", stderr);
            usage();
        }
        if (!user) {
            fputs("Yes, I also need a -u username to do this.\n", stderr);
            usage();
        }
        if (!file)
            file = "users";
        Current_Time = time(0);
        init_random();
        s = generate_pass( pass );
        if (!(fd = open( file, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR))) {
            fprintf(stderr, "Sorry, can't create file %s\n", file);
        } else {
            fake_fputs( ":version 1\n", fd);
            fake_fputs( user, fd );
            fake_fputs( " ", fd );
            fake_fputs( s, fd );
            fake_fputs( " unknown Elite 0 0 0\n", fd );
        }
        close( fd );
        FREE(s);
        CLEANUP();
        puts( "All done!" );
        break;
    }
    exit (0);
}
