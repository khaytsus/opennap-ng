/* Copyright (C) 2000 drscholl@users.sourceforge.net
This is free software distributed under the terms of the
GNU Public License.  See the file COPYING for details.

$Id: hashlist.h 434 2006-09-03 17:48:47Z reech $ */

#define MAGIC_HASHLIST 0xdb983112

struct hashlist
{
#if ONAP_DEBUG
    u_int   magic;
#endif
    void   *key;
    int     count;
    LIST   *list;
};

typedef struct hashlist hashlist_t;

hashlist_t *hashlist_add(HASH * h, void *key, void *data);
int hashlist_remove(HASH * h, void *key, void *data);
int hashlist_count(HASH *h, void *key);
LIST *hashlist_lookup(HASH *h, void *key);
void hashlist_free(hashlist_t *);
int hashlist_validate(hashlist_t *);
