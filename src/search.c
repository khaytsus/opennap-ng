/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
This is free software distributed under the terms of the
GNU Public License.  See the file COPYING for details.

$Id: search.c 434 2006-09-03 17:48:47Z reech $ */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <limits.h>
#include "opennap.h"
#include "debug.h"
#include "search.h"

/* structure used when handing a search for a remote user */
typedef struct
{
    CONNECTION *con;        /* connection to user that issused the search,
                            or the server they are connected to if
                            remote */
    char   *nick;       /* user who issued the search */
    char   *id;         /* the id for this search */
    short   count;      /* how many ACKS have been recieved? */
    short   numServers;     /* how many servers were connected at the time
                            this search was issued? */
    time_t  timestamp;      /* when the search request was issued */
}
DSEARCH;

static LIST *Remote_Search = 0;

/* keep a pointer to the end of the list for fast append */
static LIST **Remote_Search_Tail = &Remote_Search;

/* keep count of how many searches we are waiting for */
unsigned int Pending_Searches = 0;

static void search_end(CONNECTION * con, const char *id)
{
    if(ISUSER(con))
    {
        if(con->uopt->searches <= 0)
        {
            log_message_level(LOG_LEVEL_ERROR, "search_end: ERROR, con->uopt->searches <= 0!!!!!!");
            con->uopt->searches = 0;
        }
        else
            con->uopt->searches--;
        send_cmd(con, MSG_SERVER_SEARCH_END, "");
    }
    else
    {
        send_cmd(con, MSG_SERVER_REMOTE_SEARCH_END, "%s", id);
    }
}

static void free_dsearch(DSEARCH * d)
{
    if(d)
    {
        if(d->id)
            FREE(d->id);
        if(d->nick)
            FREE(d->nick);
        FREE(d);
    }
}

static char *generate_search_id(void)
{
    char   *id = MALLOC(9);
    u_short i;

    if(!id)
    {
        OUTOFMEMORY("generate_search_id");
        return 0;
    }
    for (i = 0; i < 8; i++)
        id[i] = 'A' + (rand() % 26);
    id[8] = 0;
    return id;
}

/* initiate a distributed search request.  `con' is where we received the
* request from (could be from a locally connected user or from another
* server.  `user' is the end-client that issued the search originally,
* `id' is the search id if receieved from a peer server, NULL if from
* a locally connected client.  `request' is the search string received from
* the client indicating what results they want.
*/
static int dsearch_alloc(CONNECTION * con, USER * user, const char *id, const char *request)
{
    DSEARCH *dsearch;
    LIST   *ptr;

    /* generate a new request structure */
    dsearch = CALLOC(1, sizeof(DSEARCH));
    if(!dsearch)
    {
        OUTOFMEMORY("search_internal");
        return -1;
    }
    dsearch->timestamp = global.current_time;
    if(id)
    {
        if((dsearch->id = STRDUP(id)) == 0)
        {
            OUTOFMEMORY("search_internal");
            FREE(dsearch);
            return -1;
        }
    }
    /* local client issued the search request, generate a new search id so
    * that we can route the results from peer servers back to the correct
    * user
    */
    else if((dsearch->id = generate_search_id()) == 0)
    {
        FREE(dsearch);
        return -1;
    }
    dsearch->con = con;
    dsearch->nick = STRDUP(user->nick);
    if(!dsearch->nick)
    {
        OUTOFMEMORY("search_internal");
        free_dsearch(dsearch);
        return -1;
    }

    /* keep track of how many replies we expect back */
    dsearch->numServers = list_count(global.serversList);
    /* if we recieved this from a server, we expect 1 less reply since
    we don't send the search request back to the server that issued
    it */
    if(ISSERVER(con))
        dsearch->numServers--;

    ptr = CALLOC(1, sizeof(LIST));
    if(!ptr)
    {
        OUTOFMEMORY("search_internal");
        free_dsearch(dsearch);
        return -1;
    }
    ptr->data = dsearch;

    /* append search to the tail of the list. */
    *Remote_Search_Tail = ptr;
    Remote_Search_Tail = &ptr->next;

    Pending_Searches++;

    /* pass this message to all servers EXCEPT the one we recieved
    it from (if this was a remote search) */
    pass_message_args(con, MSG_SERVER_REMOTE_SEARCH, "%s %s %s", user->nick, dsearch->id, request);

    return 0;
}

#ifndef ROUTING_ONLY

/* parameters for searching */
typedef struct
{
    CONNECTION *con;        /* connection for user that issued search */
    USER   *user;       /* user that issued the search */
    int     minbitrate;
    int     maxbitrate;
    int     minfreq;
    int     maxfreq;
    int     minspeed;
    int     maxspeed;
    unsigned int minsize;
    unsigned int maxsize;
    int     minduration;
    int     maxduration;
    int     type;       /* -1 means any type */
    char   *id;         /* if doing a remote search */
}
SEARCH;

/* returns nonzero if there is already the token specified by `s' in the list */
static int duplicate(LIST * list, const char *s)
{
    ASSERT(s != 0);
    for (; list; list = list->next)
    {
        ASSERT(list->data != 0);
        if(!strcmp (s, list->data))
            return 1;
    }
    return 0;
}

/* consider the apostrophe to be part of the word since it doesn't make
sense on its own */
#define WORD_CHAR(c) \
    (isalnum((unsigned char)(c))||(c)=='\''||(unsigned char)(c) > 128)

/* return a list of word tokens from the input string.  if excludes != NULL,
* consider words prefixed with a minus (`-') to be excluded words, and
* return them in a separate list
*/
LIST   *tokenize(char *s, LIST ** exclude_list)
{
    LIST   *r = 0, **cur = &r;
    char   *ptr;
    int     exclude;
    /*    int     lbefore,lafter; */

    /* there may be existing entries, find the end of the list */
    if(exclude_list)
        while (*exclude_list)
            exclude_list = &(*exclude_list)->next;

    while (*s)
    {
        exclude = 0;
        while (*s && !WORD_CHAR(*s))
        {
            /* XXX this will catch stupid things like  "- -fast" or
            * "- slow", but we'll make it fast for the basic case instead
            * of worrying about it.
            */
            if(exclude_list && *s == '-')
                exclude = 1;
            s++;
        }
        ptr = s;
        while (WORD_CHAR(*ptr))
            ptr++;
        if(*ptr)
            *ptr++ = 0;

        strlower(s);
        /* don't bother with common words, if there is more than 5,000 of
        any of these it doesnt do any good for the search engine because
        it won't match on them.  its doubtful that these would narrow
        searches down any even after the selection of the bin to search */
        /* new dynamic table from config file */
        if(is_filtered(s))
        {
            s = ptr;
            continue;
        }

        /* don't add duplicate tokens to the list.  this will cause searches
        on files that have the same token more than once to show up how
        ever many times the token appears in the filename */
        if((!exclude && duplicate (r, s)) || (exclude && duplicate(*exclude_list, s)))
        {
            s = ptr;
            continue;
        }

        if(exclude)
        {
            *exclude_list = CALLOC(1, sizeof(LIST));
            if(!*exclude_list)
            {
                OUTOFMEMORY("tokenize");
                return r;
            }
            (*exclude_list)->data = s;
            exclude_list = &(*exclude_list)->next;
        }
        else
        {
            *cur = CALLOC(1, sizeof(LIST));
            if(!*cur)
            {
                OUTOFMEMORY("tokenize");
                return r;
            }
            (*cur)->data = s;
            cur = &(*cur)->next;
        }

        s = ptr;
    }
    return r;
}

/* remove this datum from the lists for each keyword it is indexed under */
void free_datum(DATUM * d)
{
    u_int     i;
    TokenRef *ref;
#if RESUME
    FileList *flist;
#endif

	if(d->numTokens > 0)
	{
		for (i = 0; i < d->numTokens; i++)
		{
			ref = &d->tokens[i];

			ASSERT(validate_flist(ref->flist));

			/* de-link the element pointing to this file */
			if(ref->dlist->prev)
				ref->dlist->prev->next = ref->dlist->next;
			else
			{
				/* this is the head of the list, update the flist struct.  if
				* we just free this pointer, the flist struct would have a bogus
				* pointer
				*/
				ref->flist->list = ref->dlist->next;
			}

			/* update the back pointer of the next element (if it exists) */
			if(ref->dlist->next)
				ref->dlist->next->prev = ref->dlist->prev;

			if(ref->dlist != NULL)
				FREE(ref->dlist);

			ref->flist->count--;
			/* if there are no more files in this bin, erase it */
			if(ref->flist->count == 0)
			{
				ASSERT(ref->flist->list == 0);
				hash_remove(global.FileHash, ref->flist->key);
				FREE(ref->flist->key);
				FREE(ref->flist);
			}
		}

		FREE(d->tokens);
	}

#if RESUME
    flist = hash_lookup(global.MD5Hash, d->hash);
    if(flist)
    {
        DList *list;

        ASSERT(validate_flist (flist));
        for (list = flist->list; list; list = list->next)
        {
            if(list->data == d)
            {
                if(list->prev)
                    list->prev->next =  list->next;
                else
                {
                    /* element is head of list, update the flist pointer */
                    flist->list = list->next;
                }
                if(list->next)
                    list->next->prev = list->prev;
                FREE(list);
                break;
            }
        }

        flist->count--;
        /* if there are no more files in this bin, erase it */
        if(flist->count == 0)
        {
            ASSERT(flist->list == 0);
            hash_remove(global.MD5Hash, flist->key);
            FREE(flist->key);
            FREE(flist);
        }
    }
    else
        log_message_level(LOG_LEVEL_DEBUG, "free_datum: error, no hash entry for file %s", d->filename);
#endif

    BlockHeapFree(d->user->con->uopt->files_heap, d); /* FREE(d); */
}

static int sContainsFileList(DATUM *d, FileList *f)
{
    u_int i;

    for (i = 0; i < d->numTokens; i++)
        if(d->tokens[i].flist == f)
            return 1;
    return 0;
}

static int fdb_search(LIST * contains, LIST * excludes, int maxhits, SEARCH * crit)
{
    LIST   *words = 0;      /* matched words */
    LIST   *exclude_words = 0;  /* words NOT to match */
    LIST **listptr;
    LIST   *list;       /* temp pointer for creation of `words' list */
    LIST   *pWords;     /* iteration pointer for `words' list */
    DList   *ptok;
    FileList  *flist = 0, *tmp;
    DATUM  *d;
    int     hits = 0;
    int     is_match;
    char   *token;

    stats.search_total++;
    global.search_count++;

    if(!contains)
    {
        /* this shouldn't happen because we catch this condition down where
        * fdb_search() is called and report it back to the user
        */
        log_message_level(LOG_LEVEL_ERROR, "fdb_search: error, tokens==NULL");
        return 0;
    }

    /* find the file list with the fewest files in it */
    listptr = &words;
    for (list = contains; list; list = list->next)
    {
        tmp = hash_lookup(global.FileHash, list->data);
        if(!tmp) 
		{
            /* There ain't no match for this word in the hash table. 
            So no match at all can be achieved */
            /* Free up the list created so far - if any ... */
            list_free(words, 0);
            return 0;
        }
        ASSERT(validate_flist (tmp));
        /* keep track of the flist with the fewest entries in it.  we use
        * this below to refine the search.  we use the smallest subset
        * of possible matches to narrow the search down.
        */
        if(!flist || tmp->count < flist->count)
            flist = tmp;
        else if(flist->count >= global.fileCountThreshold)
        {
            log_message_level(LOG_LEVEL_DEBUG, "fdb_search: token \"%s\" contains %d files", flist->key, flist->count);
            token = STRDUP( flist->key );
            strlower( token );
            hash_add( global.filterHash, token, token );
            filter_dump();
        }

        /* keep track of the list of search terms to match.  we use this
        * later to ensure that all of these tokens appear in the files we
        * are considering as possible matches
        */
        *listptr = CALLOC(1, sizeof(LIST));
        if(!*listptr)
        {
            OUTOFMEMORY("fdb_search");
        }
        else
        {
            (*listptr)->data = tmp; /* current word */
            listptr = &(*listptr)->next;
        }
    }

    /* find the list of words to exclude, if any */
    listptr = &exclude_words;
    for (list = excludes; list; list = list->next)
    {
        tmp = hash_lookup(global.FileHash, list->data);
        if(tmp)
        {
            *listptr = CALLOC(1, sizeof(LIST));
            if(!*listptr)
            {
                OUTOFMEMORY("fdb_search");
            }
            else
            {
                (*listptr)->data = tmp;
                listptr = &(*listptr)->next;
            }
        }
    }

    /* find the list of files which contain all search tokens.  we do this
    * by iterating the smallest list of files from each of the matched
    * search terms.  for each file in that list, ensure the file is a member
    * of each of the other lists as well
    */
    for (ptok = flist->list; ptok; ptok = ptok->next)
    {
        /* current file to match */
        d = (DATUM *) ptok->data;

        /* make sure each search token listed in `words' is present for
        * each member of this list.  i am assuming the number of search
        * tokens is smaller than the number of tokens for a given file.
        * each element of `words' is an FLIST containing all the matching
        * files
        */
        is_match = 1;
        for (pWords = words; pWords; pWords = pWords->next)
        {
            /* each DATUM contains a list of all the tokens it contains.
            * check to make sure the current search term is a member
            * of the list.  skip the word we are matching on since we
            * know its there.
            */
            if(pWords->data != flist && !sContainsFileList(d, pWords->data))
            {
                is_match = 0;
                break;
            }
        }

        if(!is_match)
            continue;

        /* check to make sure this file doesn't contain any of the excluded
        * words
        */
        for (pWords = exclude_words; pWords; pWords = pWords->next)
        {
            if(sContainsFileList(d, pWords->data))
            {
                /* file contains a bad word */
                is_match = 0;
                break;
            }
        }

        if(!is_match)
            continue;

        /* don't return matches for a user's own files */
        if(d->user == crit->user)
            continue;
        /* ignore match if both parties are firewalled */
        if(crit->user->port == 0 && d->user->port == 0)
            continue;
        if(BitRate[d->bitrate] < crit->minbitrate)
            continue;
        if(BitRate[d->bitrate] > crit->maxbitrate)
            continue;
        if(d->user->speed < crit->minspeed)
            continue;
        if(d->user->speed > crit->maxspeed)
            continue;
        if(d->size < crit->minsize)
            continue;
        if(d->size > crit->maxsize)
            continue;
        if(d->duration < crit->minduration)
            continue;
        if(d->duration > crit->maxduration)
            continue;
        if(SampleRate[d->frequency] < crit->minfreq)
            continue;
        if(SampleRate[d->frequency] > crit->maxfreq)
            continue;
        if(crit->type != -1 && crit->type != d->type)
            continue;       /* wrong content type */

        /* Look for the search in the cached list and add the search results to that list.
        FIXME
        */

        /* Buf contains the search string.
        FIXME
        */

        /* Append the result to the cached list if it does not already exist there.
        FIXME
        */

        /* send the result to the server that requested it */
        if(crit->id)
        {
            ASSERT(ISSERVER(crit->con));
            ASSERT(validate_user(d->user));
            /* 10016 <id> <user> "<filename>" <md5> <size> <bitrate> <frequency> <duration> */
            send_cmd(crit->con, MSG_SERVER_REMOTE_SEARCH_RESULT, "%s %s \"%s\" %s %u %d %d %d", crit->id, d->user->nick, d->filename,
#if RESUME
                d->hash,
#else
                "00000000000000000000000000000000",
#endif
                d->size, BitRate[d->bitrate], SampleRate[d->frequency], d->duration);
        }
        /* if a local user issued the search, notify them of the match */
        else
        {
            send_cmd(crit->con, MSG_SERVER_SEARCH_RESULT,"\"%s\" %s %u %d %d %d %s %u %d", d->filename,
#if RESUME
                d->hash,
#else
                "00000000000000000000000000000000",
#endif
                d->size, BitRate[d->bitrate], SampleRate[d->frequency], d->duration, d->user->nick, d->user->ip, d->user->speed);
        }

        /* filename matches, check other criteria */
        if(++hits == maxhits)
            break;
    }

    list_free(words, 0);

    return hits;
}

static void generate_qualifier(char *d, int dsize, char *attr, unsigned int min, unsigned int max, unsigned int hardmax)
{
    if(min > 0)
        snprintf(d, dsize, " %s \"%s\" %d", attr, (min == max) ? "EQUAL TO" : "AT LEAST", min);
    else if(max < hardmax)
        snprintf(d, dsize, " %s \"AT BEST\" %d", attr, max);
}

#define MAX_SPEED 10
#define MAX_BITRATE 0xffff
#define MAX_FREQUENCY 0xffff
#define MAX_DURATION 0xffff
#define MAX_SIZE 0xffffffff

static void generate_request(char *d, int dsize, int results, LIST * contains, LIST * excludes, SEARCH * parms)
{
    int     l;

    snprintf(d, dsize, "FILENAME CONTAINS \"");
    l = strlen(d);
    d += l;
    dsize -= l;
    for (; contains; contains = contains->next)
    {
        snprintf(d, dsize, "%s ", (char *) contains->data);
        l = strlen(d);
        d += l;
        dsize -= l;
    }
    snprintf(d, dsize, "\" MAX_RESULTS %d", results);
    l = strlen(d);
    d += l;
    dsize -= l;
    if(parms->type != CT_MP3)
    {
        snprintf(d, dsize, " TYPE %s", parms->type != -1 ? Content_Types[parms->type] : "ANY");
        l = strlen(d);
        d += l;
        dsize -= l;
    }
    generate_qualifier(d, dsize, "BITRATE", parms->minbitrate, parms->maxbitrate, MAX_BITRATE);
    l = strlen(d);
    d += l;
    dsize -= l;
    generate_qualifier(d, dsize, "FREQ", parms->minfreq, parms->maxfreq, MAX_FREQUENCY);
    l = strlen(d);
    d += l;
    dsize -= l;
    generate_qualifier(d, dsize, "LINESPEED", parms->minspeed, parms->maxspeed, MAX_SPEED);
    l = strlen(d);
    d += l;
    dsize -= l;
    generate_qualifier(d, dsize, "SIZE", parms->minsize, parms->maxsize, MAX_SIZE);
    l = strlen(d);
    d += l;
    dsize -= l;
    generate_qualifier(d, dsize, "DURATION", parms->minduration, parms->maxduration, MAX_DURATION);
    l = strlen(d);
    d += l;
    dsize -= l;

    if(excludes)
    {
        snprintf(d, dsize, " FILENAME EXCLUDES \"");
        l = strlen(d);
        d += l;
        dsize -= l;
        for (; excludes; excludes = excludes->next)
        {
            snprintf(d, dsize, "%s ", (char *) excludes->data);
            l = strlen(d);
            d += l;
            dsize -= l;
        }
        snprintf(d, dsize, "\"");
        l = strlen(d);
        d += l;
        dsize -= l;
    }
}

static int set_compare(CONNECTION * con, const char *op, int val, int *min, int *max)
{
    ASSERT(validate_connection(con));
    ASSERT(min != NULL);
    ASSERT(max != NULL);
    if(!strcasecmp(op, "equal to"))
        *min = *max = val;
    else if(!strcasecmp(op, "at least"))
        *min = val;
    else if(!strcasecmp(op, "at best"))
        *max = val;
    else if(ISUSER(con))
    {
        send_cmd(con, MSG_SERVER_NOSUCH, "%s: invalid comparison for search", op);
        return 1;
    }
    return 0;
}


/* Destroy a cache entry disposing all data dangling from the cache record */
void free_cache(SEARCHCACHE *q)
{

    if(q)
	{
        if(q->unifiedsearch)
            FREE(q->unifiedsearch);
        /* FIXME Resultlist does not expire! */ 
        FREE(q);
    }
}


/* Seek for a unified search in the search cache and pass back the 
pointer to it - pass 0 when not found.
*/
SEARCHCACHE *seek_cache_entry(char *search) 
{

    SEARCHCACHE *p=NULL;
    LIST        *list;

    list=global.searchCacheList;

    if( list ) 
		p=list->data;

    while (list && strcmp(p->unifiedsearch,search)) 
	{ 
        list=list->next;
        if( list ) 
			p=list->data;
    }
    return( list?list->data:0);
}


/* Seek and create an entry for the search cache
Expects a normalized search string
Returns a pointer to the list entry.
Returns 0 when an error occurred.
*/
SEARCHCACHE *seek_and_create_cache_entry(char *search) 
{
    SEARCHCACHE  *sc,*p=NULL;
    LIST         *list,*q;

    /* This points to the list entry which has least usage
    A sc which is least used has a very long idle time ( >>> ) and
    a very small usage count ( <<< ) 
    So we rank the usage by doing a ( deltat / usage )
    The higher the rank the higher the possibility to expire the record. */
    LIST         *leastused, *prevleastused;
    double       highest;

    short int    ok;    /* Just a flag to say "hi - all's fine here" :-) */

    /* We are traversing the list once. In this traversal
    all parameters are gained to expire a searchrec
    if neccessary. */

    do 
	{
        highest=-1.0;
        leastused=0;
        prevleastused=0;
        list = global.searchCacheList;
        q=0;
        if( list )
			p=list->data;
        while (list && strcmp(p->unifiedsearch,search)) 
		{ 
            /* We only have to calculate the ranking if we have to expire a record. */
            if( global.searchCacheEntries >= global.search_max_cache_entries) 
			{
                p->rank = ((float) global.current_time - (float)p->lastused) / (float) p->used;
                if( p->rank > highest ) 
				{
                    highest=p->rank;
                    prevleastused=q;
                    leastused=list;
                }
            }
            /* The next in lane please ... */
            q=list;
            list=list->next;
            if( list ) 
				p=list->data;
        }

        /* The max_cache_entries variable has changed ...
        We have to adjust the cache records asap.
        But we must not purge the found list entry! */
        if( leastused && ( leastused != list) && ( global.searchCacheEntries > global.search_max_cache_entries ) ) 
		{
            /* Free the data part of the list. */
            sc=leastused->data;

            /* To prevent segfaults - these should not happen - but who knows? */
            if( sc && sc->unifiedsearch) 
				FREE(sc->unifiedsearch);
            if( sc ) 
				FREE(sc);

            /* Searchresults are not existant yet - but they are soon. 
            So we have to free Searchresults as well.
            FIXME
            */
            if( prevleastused ) 
			{
                /* The item is inmidst or before the end of the list. */
                prevleastused->next=leastused->next;
            }
			else 
			{
                /* The item is the start of the list */
                global.searchCacheList=leastused->next;
            }
            global.searchCacheEntries--;
            FREE(leastused);
            leastused=0;  /* just to be sure ...  */
        }
        /* We do a break in the loop when we found a list entry. The next run of
        the purge loop will probably purge some more.
        */
    } while ( (( global.searchCacheEntries > global.search_max_cache_entries) && !list) && ( leastused != list ));

    if( !list ) 
	{
        /* we found no search in the cachelist.
        So we have to create a new cache entry. */
        ok=0;

        /* This is not a loop - this is some kind of errorhandler :-) */
        do 
		{
            sc = CALLOC(1, sizeof(SEARCHCACHE));
            if(!sc )
                break;
            sc->unifiedsearch = STRDUP(search);
            if(!sc->unifiedsearch)
                break;

            /* All went fine so we can initialize some statics. */
            sc->firstused=global.current_time;
            sc->lastused=0;
            sc->used=0;
            sc->SearchResults=0;
            sc->rank=0.0;

            /* Do we have to expire a searchrec? */
            if( leastused ) 
			{

                /* dealloc memory of the to-expire-searchrecord */
                p=leastused->data;
                free_cache(p);

                /* Assign the newly created record to the cache data */
                leastused->data=sc;

                /* To give the errorhandler a better state... */
                list=leastused;
            }
			else
			{
                /* Nope - nothing to expire yet - just add a new record to the list. */
                list = CALLOC(1, sizeof(LIST));
                if(!list)
                    break;

                /* The head of the list ist now the new record ... */
                list->next=global.searchCacheList;
                global.searchCacheList=list;

                /* Assign the newly created record to the list entry */
                list->data=sc;
                global.searchCacheEntries++;

            }
            /* and say "Cheese" to everyone around. */
            ok = 1;
            break;

        } while (1);

        if( ! ok ) 
		{
            /* This point is only reached when something fscked up.
            There has been no sc created - so we simply return.
            */
            free_cache(sc);
            return 0;
        }
    }
	else
	{
        /* initialize the return value */
        sc=list->data;
    }

    /* All went fine and we return a pointer to the searchrec... */
    return sc;
}





/* common code for local and remote searching */
static void search_internal(CONNECTION * con, USER * user, char *id, char *pkt)
{
    int     i, n, max_results = global.maxSearchResults, done = 1, local = 0;
    int     invalid = 0;
    LIST   *contains = 0;
    LIST   *excludes = 0;
    SEARCH  parms;
    /*    SEARCHCACHE *sc; */
    char   *arg, *arg1, *ptr;

    ASSERT(validate_connection(con));

    /* set defaults */
    memset(&parms, 0, sizeof(parms));
    parms.con = con;
    parms.user = user;
    parms.maxspeed = MAX_SPEED;
    parms.maxbitrate = MAX_BITRATE;
    parms.maxfreq = MAX_FREQUENCY;
    parms.maxsize = MAX_SIZE;
    parms.maxduration = MAX_DURATION;
    parms.type = CT_MP3;    /* search for audio/mp3 by default */
    parms.id = id;

    /* prime the first argument */
    arg = next_arg(&pkt);
    while (arg)
    {
        if(!strcasecmp("filename", arg))
        {
            arg = next_arg(&pkt);
            arg1 = next_arg(&pkt);
            if(!arg || !arg1)
            {
                invalid = 1;
                goto done;
            }
            /* do an implicit AND operation if multiple FILENAME CONTAINS
            clauses are specified */
            if(!strcasecmp("contains", arg))
            {
                contains = list_append(contains, tokenize (arg1, &excludes));
            }
            else 
            {
                if(!strcasecmp("excludes", arg))
                    /* ignore `-' prefix here */
                    excludes = list_append(excludes, tokenize (arg1, NULL));

                else
                {
                    invalid = 1;
                    goto done;
                }
            }
        }
        else if(!strcasecmp("max_results", arg))
        {
            arg = next_arg(&pkt);
            if(!arg)
            {
                invalid = 1;
                goto done;
            }
            max_results = strtol(arg, &ptr, 10);
            if(*ptr)
            {
                /* not a number */
                invalid = 1;
                goto done;
            }
            if((global.maxSearchResults > 0 && max_results > global.maxSearchResults)
                /* don't let the user pick 0 to force unlimited results! */
                || max_results == 0)
                max_results = global.maxSearchResults;
        }
        else if(!strcasecmp("type", arg))
        {
            arg = next_arg(&pkt);
            if(!arg)
            {
                invalid = 1;
                goto done;
            }
            parms.type = -1;
            if(strcasecmp("any", arg))
            {
                for (n = CT_MP3; n < CT_UNKNOWN; n++)
                {
                    if(!strcasecmp(arg, Content_Types[n]))
                    {
                        parms.type = n;
                        break;
                    }
                }
                if(parms.type == -1)
                {
                    if(ISUSER(con))
                        send_cmd(con, MSG_SERVER_NOSUCH,
                        "%s: invalid type for search", arg);
                    goto done;
                }
            }
        }
        else if((!strcasecmp("linespeed", arg) && (i = 1)) ||
            (!strcasecmp("bitrate", arg) && (i = 2)) ||
            (!strcasecmp("freq", arg) && (i = 3)) ||
            (!strcasecmp("size", arg) && (i = 4)) ||
            (!strcasecmp("duration", arg) && (i = 5)))
        {
            int    *min, *max;

            arg = next_arg(&pkt);  /* comparison operation */
            arg1 = next_arg(&pkt); /* value */
            if(!arg || !arg1)
            {
                invalid = 1;
                goto done;
            }
            n = strtol(arg1, &ptr, 10);
            if(*ptr)
            {
                /* not a number */
                invalid = 1;
                goto done;
            }
            if(i == 1)
            {
                min = &parms.minspeed;
                max = &parms.maxspeed;
            }
            else if(i == 2)
            {
                min = &parms.minbitrate;
                max = &parms.maxbitrate;
            }
            else if(i == 3)
            {
                min = &parms.minfreq;
                max = &parms.maxfreq;
            }
            else if(i == 4)
            {
                min = (int *) &parms.minsize;
                max = (int *) &parms.maxsize;
            }
            else if(i == 5)
            {
                min = &parms.minduration;
                max = &parms.maxduration;
            }
            else
            {
                log_message_level(LOG_LEVEL_SEARCH, "fdb_search: ERROR, drscholl fscked up if you see this");
                goto done;
            }

            if(set_compare(con, arg, n, min, max))
                goto done;
        }
        else if(!strcasecmp("local", arg) || !strcasecmp("local_only", arg))
        {
            local = 1;      /* only search for files from users on the same server */
        }
        else
        {
            log_message_level(LOG_LEVEL_SEARCH, "search: %s: unknown search argument", arg);
            invalid = 1;
            goto done;
        }
        arg = next_arg(&pkt);  /* skip to next token */
    }

    if(!contains)
    {
        if(ISUSER(con))
            send_cmd(con, MSG_SERVER_NOSUCH, "search failed: request contained no valid words");
        goto done;
    }

    /* On repeated request of a single person ( howdy Moni ) resume searches
    are handled a bit different than open searches.
    Resume searches are different because:
    - they likely to have much less results than open searches
    - they are not that server thrashing
    - they are coming from lopster mostly ;-)
    local searches are not thrashing the hub either - so we'll sort them out as well. 
    */
    if( ISUSER(con) && ! local && ( parms.minsize != parms.maxsize) )
    {
        con->user->count200++;
        if( notify_abuse(con, con->user, 200, con->user->count200, 1) )
        {
            send_cmd(con, MSG_SERVER_NOSUCH,
                "search failed: Your client is thrashing on the network ( %.1f searches per minute %d max)",
                ( ((float) global.current_time == (float) con->user->connected) ? -1 : 
                    (60.0* (float) con->user->count200 / ( (float) global.current_time - (float) con->user->connected)) ),
                global.max_searches_per_minute );
            /* As a user who gets an error has a higher search rate the counter has to be decremented again. */
            con->user->count200--;
        }
    }


    /* Search the local database first whether to see if 
    the request can fully satisfied by a local search. */
    n = fdb_search(contains, excludes, max_results, &parms);

    if((n < max_results) && !local &&
        ((ISSERVER(con) && list_count (global.serversList) > 1) ||
        (ISUSER(con) && global.serversList)))
    {
        char   *request;
        /* reform the search request to send to the remote servers */
        generate_request(Buf, sizeof(Buf), max_results - n, contains, excludes, &parms);

        /* Buf contains a standardized search request now. 
        This search request is searched in the cache, increased and optionally added to the search list ...
        */

        /* We really don't use search cache at this time, so why call it.        
        sc = seek_and_create_cache_entry(Buf);
        */

        /* We simply ignore the fact that a none existant cache entry means that an error occurred.
        FIXME */
        /*        if( sc ) 
		{
        sc->used++;
        sc->lastused=global.current_time;
        }
        */
        /* and search 'em locally.
        FIXME */

        /* And if the request still cannot be fulfilled then 
        the request is passed to the other servers.
        FIXME */

        /* make a copy since pass_message_args() uses Buf[] */
        request = STRDUP(Buf);

        if(dsearch_alloc(con, user, id, request))
        {
            FREE(request);
            goto done;
        }

        FREE(request);
        done = 0;       /* delay sending the end-of-search message */
    }

done:

    if(invalid)
    {
        if(ISUSER(con))
            send_cmd(con, MSG_SERVER_NOSUCH, "invalid search request");
    }

    list_free(contains, 0);
    list_free(excludes, 0);

    if(done)
        search_end(con, id);
}

/* 200 ... */
HANDLER(search)
{

    (void) tag;
    (void) len;


    ASSERT(validate_connection(con));
    CHECK_USER_CLASS("search");


    /* if global.maxSearches is > 0, we only allow clients to have a certain small
    * number of pending search requests.  Some abusive clients will tend
    * to issues multiple search requests at a time.
    */
    if(con->uopt->searches < 0)
    {
        log_message_level(LOG_LEVEL_ERROR, "search: ERROR, con->uopt->searches < 0!!!");
        send_cmd(con, MSG_SERVER_NOSUCH, "search failed: server error");
        con->uopt->searches = 0;
        return;
    }

    if(! option(ON_ALLOW_SHARE))
    {
        /* sharing is not allowed on this server */
        send_cmd(con, MSG_SERVER_SEARCH_END, "");
        return;
    }

    /* NO SOUP FOR YOU!!! */
    if(con->user->level == LEVEL_LEECH)
    {
        send_cmd(con, MSG_SERVER_SEARCH_END, "");
        return;
    }


    /* if global.maxSearches is > 0, we only allow clients to have a certain small
    * number of pending search requests.  Some abusive clients will tend
    * to issues multiple search requests at a time.
    */
    if(global.maxSearches > 0 && con->uopt->searches >= global.maxSearches)
    {
        send_cmd(con, MSG_SERVER_NOSUCH, "search failed: too many pending searches");
        return;
    }
    if(con->uopt->searches == 0x7fffffff)
    {
        log_message_level(LOG_LEVEL_ERROR, "search: ERROR, con->uopt->searches will overflow!!!");
        send_cmd(con, MSG_SERVER_NOSUCH, "search failed: server error");
        return;
    }
    con->uopt->searches++;

    search_internal(con, con->user, 0, pkt);
}
#endif /* ! ROUTING_ONLY */

static DSEARCH *find_search(const char *id)
{
    LIST   *list;
    DSEARCH *ds;

    for (list = Remote_Search; list; list = list->next)
    {
        ASSERT(list->data != 0);
        ds = list->data;
        if(!strcmp(ds->id, id))
            return ds;
    }
    return 0;
}

/* 10015 <sender> <id> ...
remote search request */
HANDLER(remote_search)
{
    USER   *user;
    char   *nick, *id;

    (void) tag;
    (void) len;
    ASSERT(validate_connection(con));
    CHECK_SERVER_CLASS("remote_search");
    nick = next_arg(&pkt); /* user that issued the search */
    id = next_arg(&pkt);
    if(!nick || !id || !pkt)
    {
        /* try to terminate the search anyway */
        if(id)
            send_cmd(con, MSG_SERVER_REMOTE_SEARCH_END, "%s", id);
        log_message_level( LOG_LEVEL_SEARCH, "remote_search: too few parameters");
        return;
    }
    user = hash_lookup(global.usersHash, nick);
    if(!user)
    {
        log_message_level( LOG_LEVEL_SEARCH, "remote_search: could not locate user %s (from %s)", nick, con->host);
        /* imediately notify the peer that we don't have any matches */
        send_cmd(con, MSG_SERVER_REMOTE_SEARCH_END, "%s", id);
        return;
    }

    /* If we're a hub we DON'T want to check this, as it will
    end a search! */

#ifndef ROUTING_ONLY
    /* This has been a really silly one.
    A router is a server where by definition sharing is not allowed.
    So all searches in a remote search would be killed when having
    this code compiled into a router */
    if(! option(ON_ALLOW_SHARE))
    {
        /* sharing is not allowed on this server */
        send_cmd(con, MSG_SERVER_REMOTE_SEARCH_END, "%s", id);
        return;
    }
#endif

    if(user->level == LEVEL_LEECH)
    {
        /* user is not allowed to search this server */
        send_cmd(con, MSG_SERVER_REMOTE_SEARCH_END, "%s", id);
        return;
    }

#ifdef ROUTING_ONLY
    stats.search_total++;
    global.search_count++;
    /* no local files, just pass this request to the peer servers and
    * wait for the reponses
    */
    if(dsearch_alloc(con, user, id, pkt))
    {
        /* failed, send the ACK back immediately */
        send_cmd(con, MSG_SERVER_REMOTE_SEARCH_END, "%s", id);
    }
#else
    search_internal(con, user, id, pkt);
#endif
}

/* 10016 <id> <user> "<filename>" <md5> <size> <bitrate> <frequency> <duration>
send a search match to a remote user */
HANDLER(remote_search_result)
{
    DSEARCH *search;
    char   *av[8];
    int     ac;
    USER   *user;

    (void) con;
    (void) tag;
    (void) len;
    ASSERT(validate_connection(con));
    CHECK_SERVER_CLASS("remote_search_result");
    ac = split_line(av, sizeof(av) / sizeof(char *), pkt);

    if(ac != 8)
    {
        log_message_level( LOG_LEVEL_SEARCH, "remote_search_result: wrong number of args");
        /* print_args (ac, av); debug only - leodav */
        return;
    }
    search = find_search(av[0]);
    if(!search)
    {
        log_message_level( LOG_LEVEL_SEARCH, "remote_search_result: could not find search id %s", av[0]);
        return;
    }
    if(ISUSER(search->con))
    {
        /* deliver the match to the client */
        user = hash_lookup(global.usersHash, av[1]);
        if(!user)
        {
            log_message_level( LOG_LEVEL_SEARCH, "remote_search_result: could not find user %s (from %s)",  av[1], con->host);
            return;
        }
        send_cmd(search->con, MSG_SERVER_SEARCH_RESULT, "\"%s\" %s %s %s %s %s %s %u %d", av[2], av[3], av[4], av[5], av[6], av[7], user->nick, user->ip, user->speed);
    }
    else
    {
        /* pass the message back to the server we got the request from */
        ASSERT(ISSERVER(search->con));
        /* should not send it back to the server we just recieved it from */
        ASSERT(con != search->con);
        send_cmd(search->con, tag, "%s %s \"%s\" %s %s %s %s %s", av[0], av[1], av[2], av[3], av[4], av[5], av[6], av[7]);
    }
}

/* consolodated code for removing a pending search struct from the list.
* this needs to be done from several points, so aggregate the command code
* here.  Note that *list gets updated, so its perfectly fine to loop on
* it when calling this routine.
*/
static void unlink_search(LIST ** list, int send_ack)
{
    DSEARCH *s = (*list)->data;
    LIST   *tmp;

    ASSERT(validate_connection(s->con));
    if(send_ack)
        search_end(s->con, s->id);
    free_dsearch(s);
    tmp = *list;
    *list = (*list)->next;
    /* if there are no more entries in the list, we have to update the
    * tail pointer
    */
    if(!*list)
        Remote_Search_Tail = list;
    FREE(tmp);

    if(Pending_Searches == 0)
        log_message_level(LOG_LEVEL_ERROR,  "search_end: ERROR, Pending_Searches == 0!!!");
    else
        Pending_Searches--;
}

/* 10017 <id>
indicates end of search results for <id> */
HANDLER(remote_search_end)
{
    DSEARCH *search;
    LIST  **list;
    char   *id = next_arg(&pkt);

    CHECK_SERVER_CLASS("remote_search_end");

    ASSERT(validate_connection(con));
    (void) con;
    (void) tag;
    (void) len;

    list = &Remote_Search;
    while (*list)
    {
        if(!strcmp(((DSEARCH *) (*list)->data)->id, id))
            break;
        list = &(*list)->next;
    }
    if(!*list)
    {
        stats.search_nosuch++;
        log_message_level( LOG_LEVEL_SEARCH, "remote_end_match: could not find entry for search id %s", id);
        return;
    }
    search = (*list)->data;
    ASSERT(search->numServers <= list_count (global.serversList));
    search->count++;
    if(search->count == search->numServers)
    {
        /* got the end of the search matches from all our peers, clean up */
        unlink_search(list, 1);
    }
}

/* if a user logs out before the search is complete, we need to cancel
the search so that we don't try to send the result to the client */
void cancel_search(CONNECTION * con)
{
    LIST  **list;
    DSEARCH *d;
    int     isServer = ISSERVER(con);

    ASSERT(validate_connection(con));
    list = &Remote_Search;
    while (*list)
    {
        d = (*list)->data;
        if(isServer)
            d->numServers--;
        if(d->con == con || d->count >= d->numServers) 
		{
            /* this call updates *list, so we don't have to worry about an
            * inifinite loop
            */
            unlink_search(list, (d->con != con));
            stats.search_cancelled++;
        }
		else
		{
            list = &(*list)->next;
        }
    }
}

void expire_searches(void)
{
    LIST  **list = &Remote_Search;
    DSEARCH *search;
    int     expired = 0;

    while (*list)
    {
        search = (*list)->data;
        if(search->timestamp + global.searchTimeout > global.current_time)
            break;      /* everything else in the list is older, so we
                        can safely stop here */
        /* this call updates *list, so we don't have to worry about an
        * inifinite loop
        */
        unlink_search(list, 1);
        expired++;
        stats.search_expired++;
    }
    if(expired)
        log_message_level( LOG_LEVEL_SEARCH, "expire_searches: %d stale entries", expired);
}



int  search_compare_rank( SEARCHCACHE *p, SEARCHCACHE *q) 
{
    return( (p && q)?(p->rank < q->rank):1  ) ;
}


/* 10116 report statistics for the search cache
* Format:
* Entry, Usage, Firstused, Lastused, Searchstring
*/
HANDLER(search_cache_stats)
{
    LIST    *list;
    SEARCHCACHE *sc;
    unsigned int i;
    unsigned int cachedsearches;
    time_t lifetime;

    ( void ) tag;
    ( void ) len; 
    ( void ) pkt;


    /*    CHECK_USER_CLASS("searchcachestats"); */
    if(con->user->level < LEVEL_USER )
    {
        permission_denied(con);
        return;
    }

    /* Sort the global.searchCacheList by rank descending */
    global.searchCacheList = list_sort( global.searchCacheList, (list_cmp_callback_t) search_compare_rank );

    i=0;
    list=global.searchCacheList;
    cachedsearches=0;
    lifetime=0;
    while ( list ) 
	{
        sc=list->data;
        if( sc ) 
            send_cmd(con, MSG_SERVER_NOSUCH, "%lu %.1f %lu %lu %lu %lu %s", ++i, sc->rank, sc->used, sc->firstused, sc->lastused, sc->ResultCount, sc->unifiedsearch);
        cachedsearches+=sc->used;
        lifetime+=(sc->lastused - sc->firstused);
        list=list->next;
    }
    send_cmd(con, MSG_SERVER_NOSUCH, "SUM: %lu cached  %lu total  %.1f secs", i, cachedsearches, (i?(float)lifetime/(float)i:0.0) );
}
