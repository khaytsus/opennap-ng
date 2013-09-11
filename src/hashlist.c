/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
This is free software distributed under the terms of the
GNU Public License.  See the file COPYING for details.

$Id: hashlist.c 434 2006-09-03 17:48:47Z reech $ */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include "list.h"
#include "hash.h"
#include "hashlist.h"
#include "opennap.h"
#include "debug.h"

hashlist_t *
hashlist_add(HASH * h, void *key, void *data)
{
    hashlist_t *hl;

    ASSERT(key != 0);
    hl = hash_lookup(h, key);
    if(!hl)
    {
        hl = CALLOC(1, sizeof(hashlist_t));
        if(!hl)
        {
            OUTOFMEMORY("hashlist_add");
            return 0;
        }
#if ONAP_DEBUG
        hl->magic = MAGIC_HASHLIST;
#endif
        /* TODO: this should probably be user-configurable */
        if(h->hash_key == hash_string)
        {
            hl->key = STRDUP(key);
            if(!hl->key)
            {
                OUTOFMEMORY("hashlist_add");
                memset(hl, 0xff, sizeof(hashlist_t));
                FREE(hl);
                return 0;
            }
        }
        else
            hl->key = key;
        if(hash_add(h, hl->key, hl))
        {
            FREE(hl->key);
            memset(hl, 0xff, sizeof(hashlist_t));
            FREE(hl);
            return 0;
        }
    }
    ASSERT(hashlist_validate(hl));
    if(data)
    {
        LIST   *list;

        if(list_find(hl->list, data))
        {
            /* already present */
            return 0;
        }

        list = CALLOC(1, sizeof(LIST));
        if(!list)
        {
            OUTOFMEMORY("hashlist_add");
            if(hl->count == 0)
            {
                ASSERT(hl->list == 0);
                hash_remove(h, hl->key);
            }
            if(h->hash_key == hash_string)
                FREE(hl->key);
            memset(hl, 0xff, sizeof(hashlist_t));
            FREE(hl);
            return 0;
        }
        list->data = data;
        hl->list = list_push(hl->list, list);
    }
    hl->count++;
    return hl;
}

int hashlist_remove(HASH * h, void *key, void *data)
{
    hashlist_t *hl;

    ASSERT(key != 0);
    if((hl = hash_lookup(h, key)) == 0)
        return -1;

    ASSERT(hashlist_validate(hl));
    ASSERT(hl->count > 0);
    if(data)
    {
        LIST  **cur;
        LIST   *tmp = 0;

        ASSERT(hl->list != 0);
        /* don't use list_delete() here since we need to ensure that
        * the member was actually part of the list in order to
        * succeed.
        */
        for (cur = &hl->list; *cur;)
        {
            if((*cur)->data == data)
            {
                tmp = *cur;
                *cur = (*cur)->next;
                FREE(tmp);
                break;
            }
            cur = &(*cur)->next;
        }
        if(!tmp)
        {
            /* element was not found on the list */
            return -1;
        }
    }
    hl->count--;
    if(hl->count == 0)
    {
        ASSERT(hl->list == NULL);
        hash_remove(h, hl->key);
        if(h->hash_key == hash_string)
            FREE(hl->key);
        /* for debugging.. */
        memset(hl, 0xff, sizeof(hashlist_t));
        FREE(hl);
    }
    return 0;
}

int hashlist_count(HASH * h, void *key)
{
    hashlist_t *hl;

    ASSERT(key != 0);
    hl = hash_lookup(h, key);
#if ONAP_DEBUG
    if(hl)
        ASSERT(hashlist_validate(hl));
#endif
    return(hl ? hl->count : 0);
}

LIST   *hashlist_lookup(HASH * h, void *key)
{
    hashlist_t *hl;

    ASSERT(key != 0);
    hl = hash_lookup(h, key);
#if ONAP_DEBUG
    if(hl)
        ASSERT(hashlist_validate(hl));
#endif
    return hl ? hl->list : 0;
}

void hashlist_free(hashlist_t * l)
{
    ASSERT(hashlist_validate(l));
    /* TODO: currently this should only be called for hash tables which end
    * up with leftover entries AND use strings as hash keys
    */
    FREE(l->key);
    FREE(l);
}

#if ONAP_DEBUG
int hashlist_validate(hashlist_t * l)
{
    ASSERT_RETURN_IF_FAIL(VALID_LEN(l, sizeof(hashlist_t)), 0);
    ASSERT_RETURN_IF_FAIL(l->magic == MAGIC_HASHLIST, 0);
    /* if there are members of the list, the count should be greater than
    * zero.  nonzero count with null list is allowed.
    */
    ASSERT_RETURN_IF_FAIL((l->list && l->count > 0) || l->list == 0, 0);
    return 1;
}
#endif
