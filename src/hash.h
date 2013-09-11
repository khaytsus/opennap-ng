/* Copyright (C) 2000 drscholl@users.sourceforge.net
This is free software distributed under the terms of the
GNU Public License.  See the file COPYING for details.

$Id: hash.h 415 2005-05-14 14:21:35Z reech $ */

#ifndef hash_h
#define hash_h

#include <sys/types.h>

typedef void (*hash_destroy) (void *);

typedef unsigned int (*hash_key_t) (void *key);
typedef int (*hash_compare_t) (void *, void *);

typedef struct _hashent
{
    void   *key;
    void   *data;
    struct _hashent *next;
}
HASHENT;

typedef struct _hash
{
    HASHENT **bucket;
    int     numbuckets;
    int     dbsize;     /* # of elements in the table */
    hash_key_t hash_key;
    hash_compare_t compare_key;
    hash_destroy destroy;
}
HASH;

typedef void (*hash_callback_t) (void *, void *);

void    hash_init_real(void);
HASH   *hash_init (int, hash_destroy);
int     hash_add (HASH *, void *key, void *);
void   *hash_lookup (HASH *, void *key);
int     hash_remove (HASH *, void *key);
void    free_hash (HASH *);
void    hash_foreach (HASH * h, hash_callback_t, void *funcdata);
void    hash_set_hash_func (HASH * h, hash_key_t, hash_compare_t);

unsigned int   hash_pointer (void *key);
unsigned int   hash_string (void *key);
unsigned int   hash_u_int (void *key);

int     hash_compare_string (void *, void *);
int     hash_compare_string_insensitive (void *, void *);
int     hash_compare_u_int (void *, void *);

#endif /* hash_h */
