/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
This is free software distributed under the terms of the
GNU Public License.  See the file COPYING for details.

$Id: util.c 434 2006-09-03 17:48:47Z reech $

This file contains various utility functions useful elsewhere in this
server */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <stdlib.h>
#include <time.h>
#ifndef WIN32
# include <sys/time.h>
# include <unistd.h>
# include <sys/socket.h>
# include <netinet/in.h>
# include <arpa/inet.h>
#else
# include <process.h>
#endif
#include "md5.h"
#include "opennap.h"
#include "debug.h"

/* send a message to all local mods */
void notify_mods(unsigned int level, const char *fmt, ...)
{
    int     len;
    va_list ap;
    LIST   *list;
    CONNECTION *con;

    va_start(ap, fmt);
    vsnprintf(Buf + 4, sizeof(Buf) - 4, fmt, ap);
    va_end(ap);
    set_tag(Buf, MSG_SERVER_NOSUCH);
    len = strlen(Buf + 4);
    set_len(Buf, len);
    for (list = global.modList; list; list = list->next)
    {
        con = list->data;
        if( (con->uopt->usermode & level) && ISUSER(con) ) 
		{
            queue_data(con, Buf, len + 4);
        }
    }
}

#ifdef WIN32
SIZE_T CurrentMemUsage( void )
{
    HANDLE proc;
    PROCESS_MEMORY_COUNTERS counters;

    proc = OpenProcess(  PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, GetCurrentProcessId() );
    if(NULL == proc)
        return 0;

    GetProcessMemoryInfo( proc, &counters, sizeof(counters));
    CloseHandle( proc );
    return counters.WorkingSetSize;
}

SIZE_T MaxMemUsage( void )
{
    HANDLE proc;
    PROCESS_MEMORY_COUNTERS counters;

    proc = OpenProcess(  PROCESS_QUERY_INFORMATION |
        PROCESS_VM_READ,
        FALSE, GetCurrentProcessId() );
    if(NULL == proc)
        return 0;

    GetProcessMemoryInfo( proc, &counters, sizeof(counters));
    CloseHandle( proc );
    return counters.PeakWorkingSetSize;
}

int win32_gettimeofday( struct timeval* tv, void* timezone )
{
    FILETIME time;
    double   timed;

    GetSystemTimeAsFileTime( &time );

    /* Apparently Win32 has units of 1e-7 sec (tenths of microsecs)
    * 4294967296 is 2^32, to shift high word over
    * 11644473600 is the number of seconds between
    * the Win32 epoch 1601-Jan-01 and the Unix epoch 1970-Jan-01
    * Tests found floating point to be 10x faster than 64bit int math.
    */

    timed = ((time.dwHighDateTime * 4294967296e-7) - 11644473600.0) + (time.dwLowDateTime  * 1e-7);

    tv->tv_sec  = (long) timed;
    tv->tv_usec = (long) ((timed - tv->tv_sec) * 1e6);

    return 0;
}

#endif

/* fake_fputs makes it easier to write to a file, while not having
the limitations on some UNIXes that are associated with fopen() */

int fake_fputs(const char *buf, int fd) 
{
    int x;
    x=strlen(buf);
    if(write(fd, buf, x)!=x) 
	{
        return(EOF);
    }
    return(x);
}

/* fake_fgets makes it easier to read a file one line at a time,
while not having the limitations on some UNIXes that are
associated with fopen() */

char *fake_fgets(char *buf, int max_len, int fd)
{
    int quotopen;    /* Ensures that "\n" enclosed in quotes do not cause line break */
    char inbuf;
    char *singleline;
    char *lineptr;
    int r=1;

    if((singleline=(char *)malloc(max_len+1))==NULL) 
	{
        logerr("fake_fgets",strerror(errno));
        return(NULL);
    }

    lineptr=singleline;
    inbuf=0;
    quotopen=0;
    while((r==1) && ( ((inbuf!='\n') || quotopen)) &! ( (lineptr-singleline) > (max_len-1)) ) 
	{
        r=read(fd, &inbuf,1);
        if(quotopen && (inbuf=='"'))
		{
            quotopen = 0;
        } 
		else if(!quotopen && (inbuf=='"')) 
		{
            quotopen = 1;
        }
        lineptr[0]=inbuf;
        lineptr++;
    }

    if(r!=1) 
	{
        free(singleline);
        return(NULL);
    }

    lineptr[0]=0;
    strcpy(buf,singleline);
    free(singleline);
    return(buf);
}

#ifndef HAVE_STRSEP
/* non-gnu libc systems don't have strsep(), so for them we write our own 
* This IS glibc-2.3's strsep function */
char *strsep(char **stringp, const char *delim)
{
    char *begin, *end;
    begin = *stringp;
    if(begin == NULL)
        return NULL;
    /* A frequent case is when the delimiter string contains only one
    * character.  Here we don't need to call the expensive `strpbrk'
    * function and instead work using `strchr'.  */
    if(delim[0] == 0 || delim[1] == 0)
    {
        char ch = delim[0];
        if(ch == 0)
            end = NULL;
        else
        {
            if(*begin == ch)
                end = begin;
            else if(*begin == 0)
                end = NULL;
            else
                end = strchr(begin + 1, ch);
        }
    }
    else
        /* Find the end of the token.  */
        end = strpbrk(begin, delim);

    if(end)
    {
        /* Terminate the token and set *STRINGP past NUL character.  */
        *end++ = 0;
        *stringp = end;
    }
    else
        /* No more delimiters; this is the last token.  */
        *stringp = NULL;

    return begin;
}
#endif
/* writes `val' as a two-byte value in little-endian format */
void set_val(char *d, unsigned short val)
{
    val = BSWAP16(val);
    memcpy(d, &val, 2);
}

/* this is like strtok(2), except that all fields are returned as once.  nul
bytes are written into `pkt' and `template' is updated with pointers to
each field in `pkt' */
/* returns: number of fields found. */
int split_line(char **template, int templatecount, char *pkt)
{
    int     i = 0;

    if(!pkt)
        return -1;
    while (ISSPACE(*pkt))
        pkt++;
    while (*pkt && i < templatecount)
    {
        if(*pkt == '"')
        {
            /* quoted string */
            pkt++;
            template[i++] = pkt;
            pkt = strchr(pkt, '"');
            if(!pkt)
            {
                /* bogus line */
                return -1;
            }
            *pkt++ = 0;
            if(!*pkt)
                break;
            pkt++;      /* skip the space */
        }
        else
        {
            template[i++] = pkt;
            pkt = strpbrk(pkt, " \t\r\n");
            if(!pkt)
                break;
            *pkt++ = 0;
        }
        while (ISSPACE(*pkt))
            pkt++;
    }
    return i;
}

#ifndef ROUTING_ONLY
/* this is like split_line(), except it splits a directory specification into
path specification and filename, based on the prefix to the believed name
of the actual file */
/* returns: pointer to filename */
char   *split_filename(char *fqfn)
{
    char   *lastptr, *firstptr = fqfn;
    int     i = 0, mode = 0;

    if(!fqfn)
        return NULL;
    while (ISSPACE(*fqfn))
        fqfn++;
    while (*fqfn)
    {
        if(!mode)
        {
            if(*fqfn == '/')
                mode = 1;
            if(*fqfn == 92)
                mode = 2;
        }
        fqfn++;
    }
    lastptr = fqfn;
    while (fqfn-- > firstptr && i < global.fileIndexPathDepth)
    {
        switch (mode)
        {
        case 1:     /* UNIX Spec */
            if(*fqfn == '/')
            {
                lastptr = (fqfn + 1) ? (fqfn + 1) : fqfn;
                i++;
            }
            break;

        case 2:     /* DOS Spec */
            if(*fqfn == 92)
            {
                lastptr = (fqfn + 1) ? (fqfn + 1) : fqfn;
                i++;
            }
            break;
        }
    }
    return lastptr;
}
#endif /* ! ROUTING_ONLY */

static char hex[] = "0123456789ABCDEF";

void expand_hex(char *v, int vsize)
{
    int     i;

    for (i = vsize - 1; i >= 0; i--)
    {
        v[2 * i + 1] = hex[v[i] & 0xf];
        v[2 * i] = hex[(v[i] >> 4) & 0xf];
    }
}

void init_random(void)
{
    ASSERT(global.current_time != 0);

    /* force generation of a different seed if respawning quickly by adding
    the pid of the current process */
    srand(global.current_time + getuid () + getpid ());
}

void get_random_bytes(char *d, int dsize)
{
    int     i = 0, v;

    while (i < dsize)
    {
        v = rand();
        d[i++] = v & 0xff;
        if(i < dsize)
            d[i++] = (v >> 8) & 0xff;
        if(i < dsize)
            d[i++] = (v >> 16) & 0xff;
        if(i < dsize)
            d[i++] = (v >> 24) & 0xff;
    }
}

/* generate our own nonce value */
char   *generate_nonce(void)
{
    char   *nonce;

    nonce = MALLOC(17);
    if(!nonce)
    {
        OUTOFMEMORY("generate_nonce");
        return 0;
    }
    nonce[16] = 0;

    get_random_bytes(nonce, 8);

    /* expand the binary data into hex for transport */
    expand_hex(nonce, 8);

    return nonce;
}

CHANNEL *new_channel(void)
{
    CHANNEL *c = CALLOC(1, sizeof(CHANNEL));

    if(!c)
    {
        OUTOFMEMORY("new_channel");
        return 0;
    }
#ifdef ONAP_DEBUG
    c->magic = MAGIC_CHANNEL;
#endif
    return c;
}

char   *strfcpy(char *dest, const char *src, size_t destlen)
{
    strncpy(dest, src, destlen);
    dest[destlen - 1] = 0;
    return dest;
}

#if LOG_CHANNEL
static int Logging = 0;
#endif

void log_message(const char *fmt, ...)
{
	va_list ap;


	char    buf[1024];
	int     len;
	char   *msg;

	/* strfcpy(buf + 4, "&LOG opennap ", sizeof(buf) - 4); */
	snprintf(buf + 4, sizeof(buf) - 4, "&LOG %s ", global.serverName);
	len = strlen(buf + 4);
	msg = buf + len + 4;
	va_start(ap, fmt);
	vsnprintf(buf + 4 + len, sizeof(buf) - 4 - len, fmt, ap);
	va_end(ap);
#if LOG_CHANNEL
	/* prevent infinite loop */
	if(!Logging)
	{
		len += strlen(buf + 4 + len);
		set_tag(buf, MSG_SERVER_PUBLIC);
		set_len(buf, len);

		Logging = 1;
		(void) send_to_channel("&LOG", buf, len + 4);
		Logging = 0;
	}

	/* Temporary fix to avoid NO errors on console if log_stdout 0 is set. 
	Almost all things use log_message_level so this should be very
	quiet except for big errors. */
#endif
	/* display log msg on console */
	if(option(ON_LOG_STDOUT) || (global.logLevel == 2047) ) 
	{
		char timebuf[64];
		time_t curtime;
		struct tm *loctime;
		curtime = time(NULL);
		loctime = localtime(&curtime);
		strftime(timebuf, 64, "%b %d %H:%M:%S ", loctime);
		fputs(timebuf , stdout);
		fputs(msg, stdout);
		fputc('\n', stdout);
		fflush(stdout);
	}
}

void log_message_level(int level, const char *fmt, ...)
{
	int log_level = global.logLevel;

	if( (level & log_level) && level != 0) 
	{
		va_list ap;


		char    buf[1024];
		int     len;
		char   *msg;

		/* strfcpy (buf + 4, "&LOG opennap ", sizeof(buf) - 4); */
		snprintf(buf + 4, sizeof(buf) - 4, "&LOG %s ", global.serverName);
		len = strlen(buf + 4);
		msg = buf + len + 4;
		va_start(ap, fmt);
		vsnprintf(buf + 4 + len, sizeof(buf) - 4 - len, fmt, ap);
		va_end(ap);
#if LOG_CHANNEL
		/* prevent infinite loop */
		if(!Logging)
		{
			len += strlen(buf + 4 + len);
			set_tag(buf, MSG_SERVER_PUBLIC);
			set_len(buf, len);

			Logging = 1;
			(void) send_to_channel("&LOG", buf, len + 4);
			Logging = 0;
		}
#endif
		/* display log msg on console */
		if(option(ON_LOG_STDOUT)) 
		{
			char timebuf[64];
			time_t curtime;
			struct tm *loctime;
			curtime = time(NULL);
			loctime = localtime(&curtime);
			strftime(timebuf, 64, "%b %d %H:%M:%S ", loctime);
			fputs(timebuf, stdout);
			fputs(msg, stdout);
			fputc('\n', stdout);
			fflush(stdout);
		}
	}
}


/* like next_arg(), except we don't skip over additional whitespace */
char   *next_arg_noskip(char **s)
{
    char   *r = *s;

    *s = strchr(r, ' ');
    if(*s)
        *(*s)++ = 0;
    return r;
}

char   *next_arg(char **s)
{
    char   *r = *s;

    if(!r)
        return 0;
    while (ISSPACE(*r))
        r++;
    if(!*r)
        return 0;
    if(*r == '"')
    {
        r++;
        *s = strchr(r, '"');
    }
    else
        *s = strpbrk(r, " \t\r\n");
    if(*s)
    {
        *(*s)++ = 0;
        while (ISSPACE(**s))
            ++ * s;
        if(!**s)
            *s = 0;     /* no more arguments */
    }
    return r;
}

char   *strlower(char *s)
{
    char   *r = s;

    ASSERT(s != 0);
    while (*s)
    {
        *s = tolower((unsigned char) *s);
        *s++;
    }
    return r;
}

/* this is nasty but a necessary evil to avoid using a static buffer */
char   *append_string(char *in, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(Buf, sizeof(Buf), fmt, ap);
    va_end(ap);
    if(!in)
        return STRDUP(Buf);
    else
    {
        int     len = strlen(in);

        if(safe_realloc((void **) &in, len + strlen(Buf) + 1))
            return 0;
        strcpy(in + len, Buf);
        return in;
    }
}

int safe_realloc(void **ptr, int bytes)
{
    void   *t;

    t = REALLOC(*ptr, bytes);
    if(!t)
        return -1;
    *ptr = t;
    return 0;
}

void print_args(int ac, char **av)
{
    int     i;

    printf("print_args: [%d]", ac);
    for (i = 0; i < ac; i++)
        printf(" \"%s\"", av[i]);
    fputc('\n', stdout);
}

static char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
#define alphabet(c) alphabet[(unsigned int)c]

static int b64_encode(char *out, int *outsize, char *in, int insize)
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
        if(insize)
        {
            b |= (*in >> 4) & 0xf;
            c = (*in & 0xf) << 2;
            in++;
            insize--;
            if(insize)
            {
                c |= (*in >> 6) & 0x3;
                d = *in & 0x3f;
                in++;
                insize--;
            }
        }
        *out++ = alphabet(a);
        *out++ = alphabet(b);
        if(c != 0xff)
        {
            *out++ = alphabet(c);
            if(d != 0xff)
                *out++ = alphabet(d);
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

static int b64_decode(char *out, int *outsize, const char *in)
{
    unsigned char a, b, c, d;
    unsigned char b2, b3;
    char   *pout = out;

    while (*in)
    {
        a = b64_lookup(*in++);
        b = b64_lookup(*in++);
        *out++ = a << 2 | b >> 4;
        b2 = b << 4;
        if(*in && *in != '=')
        {
            c = b64_lookup(*in++);
            b2 |= c >> 2;
            *out++ = b2;
            b3 = c << 6;
            if(*in && *in != '=')
            {
                d = b64_lookup(*in++);
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

int check_pass(const char *info, const char *pass)
{
    struct md5_ctx md;
    char    hash[16], real[16];
    int     realsize;

    ASSERT(info != 0);
    ASSERT(pass != 0);
    if(*info != '1' || *(info + 1) != ',')
        return -1;
    info += 2;
    md5_init_ctx(&md);
    md5_process_bytes(info, 8, &md);
    info += 8;
    if(*info != ',')
        return -1;
    info++;
    md5_process_bytes(pass, strlen(pass), &md);
    md5_finish_ctx(&md, hash);
    realsize = sizeof(real);
    b64_decode(real, &realsize, info);
    ASSERT(realsize == 16);
    if(memcmp(real, hash, 16) == 0)
        return 0;
    return -1;
}

char   *generate_pass(const char *pass)
{
    struct md5_ctx md;
    char    hash[16];
    char    output[36];     /* 1,xxxxxxxx,xxxxxxxxxxxxxxxxxxxxxxx== */
    int     outsize;
    int     i;

    ASSERT(pass != 0);
    output[0] = '1';
    output[1] = ',';
    get_random_bytes(output + 2, 8);
    for (i = 0; i < 8; i++)
        output[i + 2] = alphabet[((unsigned int) output[i + 2]) % 64];
    output[10] = ',';
    md5_init_ctx(&md);
    md5_process_bytes(output + 2, 8, &md);
    md5_process_bytes(pass, strlen(pass), &md);
    md5_finish_ctx(&md, hash);
    outsize = sizeof(output) - 11;
    b64_encode(output + 11, &outsize, hash, 16);
    output[sizeof(output) - 3] = 0;    /* strip the trailing == */
    return(STRDUP(output));
}

CHANNEL *find_channel(LIST * channels, const char *s)
{
    for (; channels; channels = channels->next)
        if(!strcasecmp(((CHANNEL *) channels->data)->name, s))
            return channels->data;
    return 0;
}

void free_pointer(void *p)
{
    FREE(p);
}

/* check to make sure this string is a valid host name.  include the glob
* characters
*/
int invalid_host(const char *p)
{
    while (*p)
    {
        if(!isalnum((int)*p) || !strchr(".-?*", *p))
            return 1;
        p++;
    }
    return 0;
}

char* get_user( CONNECTION *con, int mode ) 
{
	switch (mode) 
	{
	case 1:
		snprintf( Buf, sizeof(Buf), "%s!%s", con->user->nick, con->host );
		break;
	case 2: 
		snprintf( Buf, sizeof(Buf), "%s!%s (%s)", con->user->nick, con->host, con->user->clientinfo );
		break;
	case 3:
		snprintf( Buf, sizeof(Buf), "%s!%s (%s:%hu:%hu)", con->user->nick, con->host, con->user->server, con->user->conport, con->compress );
		break;
	default:
		snprintf( Buf, sizeof(Buf), "%s!%s (%s:%s:%hu:%hu)", con->user->nick, con->host, con->user->clientinfo, con->user->server, con->user->conport, con->compress );
	}
	return Buf;
}

/* borowed from lopster ;) */
char *print_size(char *str, int strlen, double bytes) 
{
    if(bytes < 1024)
        snprintf(str, strlen, "%ld B", (long) bytes);
    else if(bytes < 1024 * 128)
        snprintf(str, strlen, "%.2f KB", bytes / 1024.0);
    else if(bytes < 1024 * 1024)
        snprintf(str, strlen, "%.1f KB", bytes / 1024.0);
    else if(bytes < 1024 * 1024 * 128)
        snprintf(str, strlen, "%.2f MB", bytes / 1024.0 / 1024.0);
    else if(bytes < 1024 * 1024 * 1024)
        snprintf(str, strlen, "%.1f MB", bytes / 1024.0 / 1024.0);
    else
        snprintf(str, strlen, "%.1f GB", bytes / 1024.0 / 1024.0 / 1024.0);
    return str;
}

#ifdef WIN32
char *win32_strerror(int WSAErr) 
{
    char *err = 0;
    switch (WSAErr) 
	{
    case 0:
        err = "No Error";
        break;
    case 10004:
        err = "Interrupted system call";
        break;
    case 10009:
        err = "Bad file number";
        break;
    case 10013:
        err = "Permission denied";
        break;
    case 10014:
        err = "Bad address";
        break;
    case 10022:
        err = "Invalid argument";
        break;
    case 10024:
        err = "Too many open files";
        break;
    case 10035:
        err = "Operation would block";
        break;
    case 10036:
        err = "Operation now in progress";
        break;
    case 10037:
        err = "Operation already in progress";
        break;
    case 10038:
        err = "Socket operation on non-socket";
        break;
    case 10039:
        err = "Destination address required";
        break;
    case 10040:
        err = "Message too long";
        break;
    case 10041:
        err = "Protocol wrong type for socket";
        break;
    case 10042:
        err = "Bad protocol option";
        break;
    case 10043:
        err = "Protocol not supported";
        break;
    case 10044:
        err = "Socket type not supported";
        break;
    case 10045:
        err = "Operation not supported on socket";
        break;
    case 10046:
        err = "Protocol family not supported";
        break;
    case 10047:
        err = "Address family not supported by protocol family";
        break;
    case 10048:
        err = "Address already in use";
        break;
    case 10049:
        err = "Can't assign requested address";
        break;
    case 10050:
        err = "Network is down";
        break;
    case 10051:
        err = "Network is unreachable";
        break;
    case 10052:
        err = "Net dropped connection or reset";
        break;
    case 10053:
        err = "Software caused connection abort";
        break;
    case 10054:
        err = "Connection reset by peer";
        break;
    case 10055:
        err = "No buffer space available";
        break;
    case 10056:
        err = "Socket is already connected";
        break;
    case 10057:
        err = "Socket is not connected";
        break;
    case 10058:
        err = "Can't send after socket shutdown";
        break;
    case 10059:
        err = "Too many references, can't splice";
        break;
    case 10060:
        err = "Connection timed out";
        break;
    case 10061:
        err = "Connection refused";
        break;
    case 10062:
        err = "Too many levels of symbolic links";
        break;
    case 10063:
        err = "File name too long";
        break;
    case 10064:
        err = "Host is down";
        break;
    case 10065:
        err = "No Route to Host";
        break;
    case 10066:
        err = "Directory not empty";
        break;
    case 10067:
        err = "Too many processes";
        break;
    case 10068:
        err = "Too many users";
        break;
    case 10069:
        err = "Disc Quota Exceeded";
        break;
    case 10070:
        err = "Stale NFS file handle";
        break;
    case 10091:
        err = "Network SubSystem is unavailable";
        break;
    case 10092:
        err = "WINSOCK DLL Version out of range";
        break;
    case 10093:
        err = "Successful WSASTARTUP not yet performed";
        break;
    case 10071:
        err = "Too many levels of remote in path";
        break;
    case 11001:
        err = "Host not found";
        break;
    case 11002:
        err = "Non-Authoritative Host not found";
        break;
    case 11003:
        err = "Non-Recoverable errors: FORMERR, REFUSED, NOTIMP";
        break;
    case 11004:
        err = "Valid name, no data record of requested type, No address, look for MX record";
        break;
    default:
        err = strerror( WSAErr );
    }
    return err;
}
#endif
