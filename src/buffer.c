/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
This is free software distributed under the terms of the
GNU Public License.  See the file COPYING for details.

$Id: buffer.c 434 2006-09-03 17:48:47Z reech $ */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifndef WIN32
# include <unistd.h>
# include <sys/time.h>
#endif /* !WIN32 */
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#ifdef CSC
# include <ctype.h>
#endif
#include "opennap.h"
#include "debug.h"

static BUFFER *buffer_new(void)
{
    BUFFER *r = CALLOC(1, sizeof(BUFFER));

    if(!r)
    {
        OUTOFMEMORY("buffer_new"); //this doesnt return anymore
		return 0;
    }
#if ONAP_DEBUG
    r->magic = MAGIC_BUFFER;
#endif
    r->data = MALLOC(BUFFER_SIZE);
    if(!r->data)
    {
        OUTOFMEMORY("buffer_new"); //this doesnt return anymore...
        FREE(r);
		return 0;
    }
    r->datamax = BUFFER_SIZE;
    return r;
}

/* append bytes to the buffer */
static BUFFER *buffer_queue(BUFFER * b, char *d, int dsize)
{
	BUFFER *r = b;
	int     count;

	if(b)
		while (b->next)
			b = b->next;
	while (dsize > 0)
	{
		if(!b)
			r = b = buffer_new ();
		else if(b->datasize == b->datamax)
		{
			b->next = buffer_new ();
			b = b->next;
		}
		if(!b)
		{
			/*something really bad just happened!  no choice but to close
			this connection since it will be out of sync */
			buffer_free(r);
			return 0;
		}
		count = dsize;
		/* dsize could be greater than what is allocated */
		if(count > b->datamax - b->datasize)
			count = b->datamax - b->datasize;
		memcpy(b->data + b->datasize, d, count);
		b->datasize += count;
		dsize -= count;
		d += count;
	}
	return r;
}

/* consume some bytes from the buffer */
BUFFER *buffer_consume(BUFFER * b, int n)
{
    ASSERT(buffer_validate(b));
    ASSERT(b->consumed + n <= b->datasize);
    b->consumed += n;
    if(b->consumed >= b->datasize)
    {
        BUFFER *p = b;

        b = b->next;
        FREE(p->data);
        FREE(p);
    }
    return b;
}

BUFFER *buffer_append(BUFFER * a, BUFFER * b)
{
    BUFFER *r = a;

    ASSERT(b != 0);
    if(!a)
        return b;
    ASSERT(buffer_validate(a));
    while (a->next)
        a = a->next;
    a->next = b;
    return r;
}

int buffer_size(BUFFER * b)
{
    int     n = 0;

    ASSERT(b == 0 || buffer_validate(b));
    for (; b; b = b->next)
        n += b->datasize - b->consumed;
    return n;
}

void buffer_free(BUFFER * b)
{
    BUFFER *p;

    ASSERT(b == 0 || buffer_validate(b));
    while (b)
    {
        p = b;
        b = b->next;
        FREE(p->data);
        FREE(p);
    }
}

#if ONAP_DEBUG
int buffer_validate(BUFFER * b)
{
    ASSERT_RETURN_IF_FAIL(VALID_LEN(b, sizeof(BUFFER)), 0);
    ASSERT_RETURN_IF_FAIL(b->magic == MAGIC_BUFFER, 0);
    ASSERT_RETURN_IF_FAIL(b->datasize <= b->datamax, 0);
    ASSERT_RETURN_IF_FAIL(b->data == 0 || VALID_LEN(b->data, b->datasize), 0);
    ASSERT_RETURN_IF_FAIL(b->consumed == 0 || b->consumed < b->datasize, 0);
    ASSERT_RETURN_IF_FAIL(b->next == 0 || VALID_LEN(b->next, sizeof(BUFFER *)), 0);
    return 1;
}
#endif /* ONAP_DEBUG */

static BUFFER *buffer_compress(z_streamp zip, BUFFER ** b)
{
    BUFFER *r = 0, **pr;
    int     n, bytes, flush;

    ASSERT(buffer_validate(*b));

    /* set up the input */
    bytes = (*b)->datasize - (*b)->consumed;
    zip->next_in = (u_char *) (*b)->data + (*b)->consumed;
    zip->avail_in = bytes;
    /* force a flush if this is the last input to compress */
    flush = ((*b)->next == 0) ? Z_SYNC_FLUSH : Z_NO_FLUSH;
    /* set to 0 so we allocate in the loop */
    zip->avail_out = 0;

    pr = &r;

    do
    {
        if(zip->avail_out == 0)
        {
            /* allocate a new buffer to hold the rest of the compressed data */
            *pr = buffer_new ();
            if(!*pr)
                break;
            /* mark the buffer as completely full then remove unused data
            when we exit this loop */
            (*pr)->datasize = (*pr)->datamax;
            zip->next_out = (unsigned char *) (*pr)->data;
            zip->avail_out = (*pr)->datasize;
        }
        n = deflate(zip, flush);
        if(n != Z_OK)
        {
            log_message_level(LOG_LEVEL_ERROR, "buffer_compress: deflate: %s (error %d)", NONULL(zip->msg), n);
            break;
        }
        pr = &(*pr)->next;
    }
    while (zip->avail_out == 0 && flush == Z_SYNC_FLUSH);

    /* subtract any uncompressed bytes */
    bytes -= zip->avail_in;
    *b = buffer_consume(*b, bytes);

    if(r)
    {
        pr = &r;
        while ((*pr)->next)
            pr = &(*pr)->next;
        (*pr)->datasize -= zip->avail_out;
        /* this should only happen for the first created buffer if the
        input was small and there was a second buffer in the list */
        if((*pr)->datasize == 0)
        {
            ASSERT(r->next == 0);
            if(r->next != 0)
                log_message_level(LOG_LEVEL_ERROR,"buffer_compress: ERROR! r->next was not NULL");
            FREE(r->data);
            FREE(r);
            r = 0;
        }
    }

    return r;
}

/* assuming that we receive relatively short blocks via the network (less
than 16kb), we uncompress all data when we receive it and don't worry
about blocking.

NOTE: this is the only buffer_*() function that does not use the memory
pool.  each server gets its own real input buffer */
int buffer_decompress(BUFFER * b, z_streamp zip, char *in, int insize)
{
    int     n;

    ASSERT(buffer_validate(b));
    ASSERT(insize > 0);
    zip->next_in = (unsigned char *) in;
    zip->avail_in = insize;
    zip->next_out = (unsigned char *) b->data + b->datasize;
    zip->avail_out = b->datamax - b->datasize;
    /* set this to the max size and subtract what is left after the inflate */
    b->datasize = b->datamax;
    do
    {
        /* if there is no more output space left, create some more */
        if(zip->avail_out == 0)
        {
            /* allocate one extra byte to write a \0 char */
            if(safe_realloc((void **) &b->data, b->datamax + insize + 1))
            {
                OUTOFMEMORY("buffer_decompress");
                return -1;
            }
            b->datamax += insize;
            zip->next_out = (unsigned char *) b->data + b->datasize;
            zip->avail_out = b->datamax - b->datasize;
            /* set this to the max size and subtract what is left after the
            inflate */
            b->datasize = b->datamax;
        }
        n = inflate (zip, Z_SYNC_FLUSH);
        if(n != Z_OK)
        {
            log_message_level(LOG_LEVEL_ERROR, "buffer_decompress: inflate: %s (error %d)", NONULL(zip->msg), n);
            return -1;
        }
    }
    while (zip->avail_out == 0);
    /* subtract unused bytes */
    b->datasize -= zip->avail_out;

    return 0;
}

int init_compress(CONNECTION * con, int level)
{
    int     n;

    ASSERT(validate_connection(con));
    ASSERT(ISSERVER(con));

    con->sopt->zin = CALLOC(1, sizeof(z_stream));
    if(!con->sopt->zin)
    {
        OUTOFMEMORY("init_compress");
		exit(-99);
        //return -1;
    }
    con->sopt->zout = CALLOC(1, sizeof(z_stream));
    if(!con->sopt->zout)
    {
        FREE(con->sopt->zin);
        OUTOFMEMORY("init_compress");
		exit(-99);
        //return -1;
    }
    n = inflateInit(con->sopt->zin);
    if(n != Z_OK)
    {
        log_message_level(LOG_LEVEL_ERROR, "init_compress: inflateInit: %s (%d)", NONULL(con->sopt->zin->msg), n);
        return -1;
    }
    n = deflateInit(con->sopt->zout, level);
    if(n != Z_OK)
    {
        log_message_level(LOG_LEVEL_ERROR, "init_compress: deflateInit: %s (%d)", NONULL(con->sopt->zout->msg), n);
        return -1;
    }
    log_message_level(LOG_LEVEL_DEBUG, "init_compress: compressing server stream at level %d", level);
    return 0;
}

void finalize_compress(SERVER * serv)
{
    int     n;

    n = deflateEnd(serv->zout);
    if(n != Z_OK)
        log_message_level(LOG_LEVEL_ERROR,"finalize_compress: deflateEnd: %s (%d)",  NONULL(serv->zout->msg), n);
    n = inflateEnd(serv->zin);
    if(n != Z_OK)
        log_message_level(LOG_LEVEL_ERROR, "finalize_compress: inflateEnd: %s (%d)", NONULL(serv->zin->msg), n);
    FREE(serv->zin);
    FREE(serv->zout);
}

int send_queued_data(CONNECTION * con)
{
    int     n;
    BUFFER *r;

    ASSERT(validate_connection(con));

    if(con->destroy)
    {
        /* connection is being shut down, just ignore it */
        clear_write(con->fd);  /* just to be sure */
        return -1;
    }

    if(ISSERVER(con))
    {
        /* compress server output until we have at least 16k waiting (about
        * the size of the tcp buffer for the socket)
        */
        while (con->sopt->outbuf && buffer_size(con->sendbuf) < 16384)
        {
            /* buffer_compress will only compress the first buffer in the
            * list, so we possibly need to call it multiple times.
            */
            r = buffer_compress(con->sopt->zout, &con->sopt->outbuf);
            if(!r)
                break;
            con->sendbuf = buffer_append(con->sendbuf, r);
        }

        /* for large networks, it might be desirable not to send data every
        * time through the main loop.  this adds support for queuing up
        * a larger amount of data before actually doing a write()
        */
        if(global.serverChunk > 0)
        {
            /* check to see if enough data has been accumulated to send */
            if(buffer_size(con->sendbuf) < global.serverChunk)
            {
                clear_write(con->fd);  /* turn off check for write */
                return 0;   /* wait until more data is recv'd */
            }
        }
    }
#ifdef CSC
    if(ISUSER(con)) 
    {
        if(con->uopt->csc) 
        {
            while (con->uopt->outbuf) /* let's compress it all and be done with it && buffer_size (con->sendbuf) < 16384) */
            {
                r = buffer_compress(con->uopt->zout, &con->uopt->outbuf);
                if(!r) 
                {
                    break;
                }
                con->sendbuf = buffer_append(con->sendbuf, r);
            }
        }
    }
#endif

    /* write until the queue is consumed, or we would block */
    while (con->sendbuf)
    {
        n = WRITE(con->fd, con->sendbuf->data + con->sendbuf->consumed, con->sendbuf->datasize - con->sendbuf->consumed);
        if(n == -1) 
        {
            if(N_ERRNO != EWOULDBLOCK && N_ERRNO != EDEADLK && N_ERRNO != ENOBUFS) 
            {
                clear_write(con->fd);  /* just to be sure */
                log_message_level(LOG_LEVEL_ERROR, "send_queued_data: write: %s (errno %d) for host %s", strerror(N_ERRNO), N_ERRNO, con->host);
                return -1;
            }
            break;
        } 
        else if(n == 0) 
        {
            log_message_level(LOG_LEVEL_ERROR, "send_queued_data: wrote 0 bytes to fd %d", con->fd);
            break;
        }
        global.bytes_out += n;

        /* mark data as written */
        con->sendbuf = buffer_consume(con->sendbuf, n);
    }

    /* check to make sure the queue hasn't gotten too big */
#ifdef CSC
    if(ISUSER(con)) 
    {
        if(con->uopt->csc) 
        {
            if(buffer_size(con->uopt->outbuf) > global.clientQueueLen) 
            {
                log_message_level(LOG_LEVEL_ERROR, "send_queued_data_z: output buffer for %s exceeded %u bytes", con->host, global.clientQueueLen);
                return -1;
            }
        }
    }
    else
    {
#endif

        if(ISSERVER(con)) 
        {
            /* for a server, we will have up to 16k in con->sendbuf, and then
            * possibly a lot more in con->sopt->outbuf.  the latter
            * is uncompressed data.
            */
            if(buffer_size(con->sopt->outbuf) > global.serverQueueMaxLen) 
            {
                log_message_level(LOG_LEVEL_ERROR, "send_queued_data_s: output buffer (con->sopt->outbuf) for %s exceeded %u bytes(%u)", con->host, global.serverQueueMaxLen, buffer_size(con->sopt->outbuf));
                return -1;
            }
            if(buffer_size(con->sendbuf) > global.serverQueueMaxLen)
            {
                log_message_level(LOG_LEVEL_ERROR, "send_queued_data_s: output buffer (con->sendbuf) for %s exceeded %u bytes(%u)", con->host, global.serverQueueMaxLen, buffer_size(con->sendbuf));
                return -1;
            }

        } 
        else if(buffer_size(con->sendbuf) > global.clientQueueLen) 
        {
            log_message_level(LOG_LEVEL_ERROR, "send_queued_data: output buffer for %s exceeded %u bytes", con->host, global.clientQueueLen);
            return -1;
        }

#ifdef CSC
    }
    if(con->sendbuf || (ISSERVER(con) && con->sopt->outbuf) || (ISUSER(con) && con->uopt->outbuf))
#else
        if(con->sendbuf || (ISSERVER(con) && con->sopt->outbuf))
#endif
            /* still need to write */
            set_write(con->fd);
        else
            /* output queue is empty, clear the write bit */
            clear_write(con->fd);

        return 0;
    }

void queue_data(CONNECTION * con, char *s, int ssize)
{
    u_short tag;

    ASSERT(validate_connection(con));

    /* The strlen of the *s is checked for strlen > 0 and then the tag is added to the histogram */
    if(s) 
    {
        memcpy(&tag, s + 2, 2);
        tag = BSWAP16(tag);
        add_shist( tag, ssize );
        /*  log_message( "%hu:S:%hu(%s)\t:%hu\t%s", con->fd, tag, tag2hrf(tag), ssize, s + 4); */
    } 
    else 
    {
        log_message_level(LOG_LEVEL_DEBUG, "DEBUG:queue_data: zero string! len=%i, fd=%hu", ssize, con->fd);
        return;
    }

#ifdef CSC
    if(ISUSER(con) && !con->destroy) 
	{
        if(con->uopt->csc) 
        {
            con->uopt->outbuf = buffer_queue(con->uopt->outbuf, s, ssize);
            if(!con->uopt->outbuf) 
            {
                destroy_connection(con);
            }
            /* unlike server-server connections we do flush here */
            /* if(buffer_size ( con->uopt->outbuf) > 500 ) { */
            if(send_queued_data(con) == -1) 
            {
                destroy_connection(con);
            }
            return;
        }
    }
#endif
    if(ISSERVER(con))
    {
        /* always queue server data so we can compress it more effciently */
        con->sopt->outbuf = buffer_queue(con->sopt->outbuf, s, ssize);
        if(!con->sopt->outbuf)
            destroy_connection(con);
        /* server connections are always flushed at the end of the main
        * event loop, so we don't need to call set_write() here
        */
    }
    else if(!con->destroy)
    {
        /* if no output is queued, immediately attempt to send it now to
        * avoid copying
        */
        if(!con->sendbuf)
        {
#ifndef ALWAYS_QUEUE
            int     n = WRITE(con->fd, s, ssize);
            if(n == -1)
            {
                if(N_ERRNO != EWOULDBLOCK) 
                {
                    log_message_level(LOG_LEVEL_ERROR, "queue_data: %s: write: %s (errno %d)", con->host, strerror(N_ERRNO), N_ERRNO);
                    destroy_connection(con);
                    return;
                }
                /* queue the data */
            } 
            else 
            {
                global.bytes_out += n;
                if(n == ssize) 
                {
                    return;     /* all written, nothing else to do */
                } 
                else 
                {
                    /* queue the portion that didn't get written */
                    s += n;
                    ssize -= n;
                }
            }
#endif /* ! ALWAYS_QUEUE */
            /* we want to know when the socket becomes writable again */
            set_write(con->fd);
        }

        con->sendbuf = buffer_queue(con->sendbuf, s, ssize);
        if(!con->sendbuf)
            destroy_connection(con);
    }
}

#ifdef CSC
int init_client_compress(CONNECTION * con, unsigned int level)
{
    int n;

    ASSERT(validate_connection(con));
    ASSERT(ISUSER(con));
    con->uopt->zin = CALLOC(1, sizeof(z_stream));
    if(!con->uopt->zin) 
    {
        OUTOFMEMORY("init_client_compress");
        return -1;
    }
    con->uopt->zout = CALLOC(1, sizeof(z_stream));
    if(!con->uopt->zout) 
    {
        FREE(con->uopt->zin);
        OUTOFMEMORY("init_client_compress");
        return -1;
    }
    n = inflateInit(con->uopt->zin);
    if(n != Z_OK) 
    {
        log_message_level(LOG_LEVEL_ERROR, "init_client_compress: inflateInit: %s (%d)", NONULL(con->uopt->zin->msg), n);
        return -1;
    }
    n = deflateInit(con->uopt->zout, level);
    if(n != Z_OK) 
    {
        log_message_level(LOG_LEVEL_ERROR, "init_client_compress: deflateInit: %s (%d)", NONULL(con->uopt->zout->msg), n);
        return -1;
    }
    log_message_level(LOG_LEVEL_LOGIN, "init_client_compress: compressing client stream at level %d", level);
    stats.zusers++;
    return 0;
}

void finalize_client_compress(USEROPT * usr)
{
    int     n;

    n = deflateEnd(usr->zout);
    if(n != Z_OK)
        log_message_level(LOG_LEVEL_ERROR, "finalize_client_compress: deflateEnd: %s (%d)", NONULL(usr->zout->msg), n);
    n = inflateEnd(usr->zin);
    if(n != Z_OK)
        log_message_level(LOG_LEVEL_ERROR, "finalize_client_compress: inflateEnd: %s (%d)", NONULL(usr->zin->msg), n);
    FREE(usr->zin);
    FREE(usr->zout);
    /* This is done in reap_connections where it should be.. */
    stats.zusers--;
}

void buf_print (char *s, size_t ssize, char *reason ) 
{
    unsigned int n;

    fprintf( stdout, reason );
    fputc( '\"', stdout);
    n = 0;
    while (n < ssize) 
	{
        fputc( isprint((int)s[n]) ? s[n] : '.', stdout);
        n++;
    }
    fprintf( stdout, "\" size (%u)", n );
    fputc( '\n', stdout);
}
#endif
