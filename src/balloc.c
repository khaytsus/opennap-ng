/*
*  ircd-hybrid: an advanced Internet Relay Chat Daemon(ircd).
*  balloc.c: A block allocator.
*
*  Copyright (C) 2002 by the past and present ircd coders, and others.
*  Original credit lines follow:
*
*  File:   balloc.c
*  Owner:  Wohali (Joan Touzet)
*  
*  Modified 2001/11/29 for mmap() support by Aaron Sethman <androsyn@ratbox.org>
*
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2 of the License, or
*  (at your option) any later version.
*
*  This program is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*  GNU General Public License for more details.
*
*  You should have received a copy of the GNU General Public License
*  along with this program; if not, write to the Free Software
*  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
*  USA
*
*  $Id: balloc.c,v 7.51 2005/03/29 19:25:47 michael Exp $
*/

/* 
* About the block allocator
*
* Basically we have three ways of getting memory off of the operating
* system. Below are this list of methods and the order of preference.
*
* 1. mmap() anonymous pages with the MMAP_ANON flag.
* 2. mmap() via the /dev/zero trick.
* 3. malloc() 
*
* The advantages of 1 and 2 are this.  We can munmap() the pages which will
* return the pages back to the operating system, thus reducing the size 
* of the process as the memory is unused.  malloc() on many systems just keeps
* a heap of memory to itself, which never gets given back to the OS, except on
* exit.  This of course is bad, if say we have an event that causes us to allocate
* say, 200MB of memory, while our normal memory consumption would be 15MB.  In the
* malloc() case, the amount of memory allocated to our process never goes down, as
* malloc() has it locked up in its heap.  With the mmap() method, we can munmap()
* the block and return it back to the OS, thus causing our memory consumption to go
* down after we no longer need it.
*/

#define WE_ARE_MEMORY_C
//#include "stdinc.h"
//#include "ircd_defs.h"          /* DEBUG_BLOCK_ALLOCATOR */
//#include "ircd.h"
//#include "memory.h"
//#include "balloc.h"
//#include "irc_string.h"
//#include "tools.h"
//#include "s_log.h"
//#include "client.h"
//#include "fdlist.h"
//#include "event.h"
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif
#include <stdlib.h>
#include <stdio.h>
#include "opennap.h"
#include "debug.h"
static BlockHeap *heap_list = NULL;

static int newblock(BlockHeap *);
static void heap_garbage_collection(void *);

void outofmemory(void)
{
	printf("out of memory...");
    exit(-99);
}

#ifdef HAVE_MMAP /* We've got mmap() that is good */
#include <sys/mman.h>

/* HP-UX sucks */
#ifdef MAP_ANONYMOUS
# ifndef MAP_ANON
#  define MAP_ANON MAP_ANONYMOUS
# endif
#endif /* MAP_ANONYMOUS */
#endif /* HAVE_MMAP */

/*
* static inline void free_block(void *ptr, size_t size)
*
* Inputs: The block and its size
* Output: None
* Side Effects: Returns memory for the block back to the OS
*/
void free_block(void *ptr, size_t size)
{
#ifdef HAVE_MMAP
    munmap(ptr, size);
#else
    free(ptr);
#endif
    log_message_level(LOG_LEVEL_DEBUG, "balloc: free_block: %d bytes", size);
}

#ifndef MAP_ANON /* But we cannot mmap() anonymous pages */
/* So we mmap() /dev/zero, which is just as good */
static int zero_fd = -1;
#endif
/*
* void initBlockHeap(void)
* Note: This is the /dev/zero version of getting pages 
* 
* Inputs: None
* Outputs: None
* Side Effects: Opens /dev/zero and saves the file handle for
*		 future allocations.
*/

void initBlockHeap(void)
{
#ifdef HAVE_MMAP
#ifndef MAP_ANON
    zero_fd = open("/dev/zero", O_RDWR);

    if(zero_fd < 0)
        outofmemory();
    fd_open(zero_fd, FD_FILE, "Anonymous mmap()");
#endif /* MAP_ANON */
#endif /* HAVE_MMAP */
    add_timer(119, -1, (timer_cb_t) heap_garbage_collection, 0);
    log_message_level(LOG_LEVEL_DEBUG, "balloc: initBlockHeap: using: %s",
#ifndef HAVE_MMAP
        "malloc()"
#else
#ifdef MAP_ANON
        "mmap() w/MAP_ANON"
#else
        "mmap() w/dev/zero"
#endif
#endif
        );
}

/*
* static inline void *get_block(size_t size)
* 
* Note: This is the /dev/zero version
* Input: Size of block to allocate
* Output: Pointer to new block
* Side Effects: None
*/
void *get_block(size_t size)
{

    void *ptr;

#ifdef HAVE_MMAP
#ifndef MAP_ANON
    ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE, zero_fd, 0);
#else
    ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
#endif
    if(ptr == MAP_FAILED)
    {
        ptr = NULL;
    }
#else
    ptr = calloc(1, size);
#endif
    log_message_level(LOG_LEVEL_DEBUG, "balloc: get_block: %d bytes", size);
    return(ptr);
}

static int BlockHeapGarbageCollect(BlockHeap *bh);

static void heap_garbage_collection(void *arg)
{
    BlockHeap *bh;

    for (bh = heap_list; bh != NULL; bh = bh->next)
        BlockHeapGarbageCollect(bh);
}

/* ************************************************************************ */
/* FUNCTION DOCUMENTATION:                                                  */
/*    newblock                                                              */
/* Description:                                                             */
/*    Allocates a new block for addition to a blockheap                     */
/* Parameters:                                                              */
/*    bh (IN): Pointer to parent blockheap.                                 */
/* Returns:                                                                 */
/*    0 if successful, 1 if not                                             */
/* ************************************************************************ */

static int newblock(BlockHeap * bh)
{
    MemBlock *newblk;
    Block *b;
    int i;
    void *offset;

    /* Setup the initial data structure. */
    b = (Block *) calloc(1, sizeof(Block));
    if(b == NULL)
    {
        return(1);
    }
    b->freeElems = bh->elemsPerBlock;
    b->free_list.head = b->free_list.tail = NULL;
    b->used_list.head = b->used_list.tail = NULL;
    b->next = bh->base;

    b->alloc_size = (bh->elemsPerBlock + 1) * (bh->elemSize + sizeof(MemBlock));

    b->elems = get_block(b->alloc_size);
    if(b->elems == NULL)
    {
        return(1);
    }
    offset = b->elems;
    /* Setup our blocks now */
    for (i = 0; i < bh->elemsPerBlock; i++)
    {
        void *data;
        newblk = (void *)offset;
        newblk->block = b;
        data = (void *)((size_t)offset + sizeof(MemBlock));
        dlinkAdd(data, &newblk->self, &b->free_list);
        offset = (unsigned char *)((unsigned char *)offset + bh->elemSize + sizeof(MemBlock));
    }

    ++bh->blocksAllocated;
    bh->freeElems += bh->elemsPerBlock;
    bh->base = b;

    return(0);
}


/* ************************************************************************ */
/* FUNCTION DOCUMENTATION:                                                  */
/*    BlockHeapCreate                                                       */
/* Description:                                                             */
/*   Creates a new blockheap from which smaller blocks can be allocated.    */
/*   Intended to be used instead of multiple calls to malloc() when         */
/*   performance is an issue.                                               */
/* Parameters:                                                              */
/*   elemsize (IN):  Size of the basic element to be stored                 */
/*   elemsperblock (IN):  Number of elements to be stored in a single block */
/*         of memory.  When the blockheap runs out of free memory, it will  */
/*         allocate elemsize * elemsperblock more.                          */
/* Returns:                                                                 */
/*   Pointer to new BlockHeap, or NULL if unsuccessful                      */
/* ************************************************************************ */
BlockHeap *BlockHeapCreate(size_t elemsize, int elemsperblock)
{
    BlockHeap *bh = NULL;
    ASSERT(elemsize > 0 && elemsperblock > 0);

    /* Catch idiotic requests up front */
    if((elemsize <= 0) || (elemsperblock <= 0))
        outofmemory();    /* die.. out of memory */

    /* Allocate our new BlockHeap */
    if((bh = calloc(1, sizeof(BlockHeap))) == NULL)
        outofmemory();    /* die.. out of memory */

    if((elemsize % sizeof(void *)) != 0)
    {
        /* Pad to even pointer boundary */
        elemsize += sizeof(void *);
        elemsize &= ~(sizeof(void *) - 1);
    }

    bh->elemSize = elemsize;
    bh->elemsPerBlock = elemsperblock;

    /* Be sure our malloc was successful */
    if(newblock(bh))
    {
        if(bh != NULL)
            free(bh);

        outofmemory();    /* die.. out of memory */
    }

    ASSERT(bh);

    bh->next = heap_list;
    heap_list = bh;

    return(bh);
}

/* ************************************************************************ */
/* FUNCTION DOCUMENTATION:                                                  */
/*    BlockHeapAlloc                                                        */
/* Description:                                                             */
/*    Returns a pointer to a struct within our BlockHeap that's free for    */
/*    the taking.                                                           */
/* Parameters:                                                              */
/*    bh (IN):  Pointer to the Blockheap.                                   */
/* Returns:                                                                 */
/*    Pointer to a structure (void *), or NULL if unsuccessful.             */
/* ************************************************************************ */

void *BlockHeapAlloc(BlockHeap * bh)
{
    Block *walker;
    dlink_node *new_node;

    ASSERT(bh != NULL);
    if(bh == NULL)
    {
        outofmemory();
    }

    if(bh->freeElems == 0)
    {   
        /* Allocate new block and assign */
        /* newblock returns 1 if unsuccessful, 0 if not */

        if(newblock(bh))
        {
            /* That didn't work..try to garbage collect */
            BlockHeapGarbageCollect(bh);  
            if(bh->freeElems == 0)
            {
                outofmemory(); /* Well that didn't work either...bail */
            }
        }
    }

    for (walker = bh->base; walker != NULL; walker = walker->next)
    {
        if(walker->freeElems > 0)
        {
            bh->freeElems--;
            walker->freeElems--;
            new_node = walker->free_list.head;
            dlinkDelete(new_node, &walker->free_list);
            dlinkAdd(new_node->data, new_node, &walker->used_list);
            ASSERT(new_node->data != NULL);
            if(new_node->data == NULL)
                outofmemory();
            return(new_node->data);
        }
    }
    ASSERT(0 == 1);
    outofmemory();
    return(NULL);
}


/* ************************************************************************ */
/* FUNCTION DOCUMENTATION:                                                  */
/*    BlockHeapFree                                                         */
/* Description:                                                             */
/*    Returns an element to the free pool, does not free()                  */
/* Parameters:                                                              */
/*    bh (IN): Pointer to BlockHeap containing element                      */
/*    ptr (in):  Pointer to element to be "freed"                           */
/* Returns:                                                                 */
/*    0 if successful, 1 if element not contained within BlockHeap.         */
/* ************************************************************************ */
int BlockHeapFree(BlockHeap * bh, void *ptr)
{
    Block *block;
    struct MemBlock *memblock;

    ASSERT(bh != NULL);
    ASSERT(ptr != NULL);

    if(bh == NULL)
    {

        log_message_level(LOG_LEVEL_ERROR, "balloc.c:BlockHeapFree() bh == NULL");
        return(1);
    }

    if(ptr == NULL)
    {
        log_message_level(LOG_LEVEL_ERROR, "balloc.BlockHeapFree() ptr == NULL");
        return(1);
    }

    memblock = (void *)((size_t)ptr - sizeof(MemBlock));
    ASSERT(memblock->block != NULL);
    if(memblock->block == NULL)
    {
        outofmemory();
    }
    /* Is this block really on the used list? */
    ASSERT(dlinkFind(&memblock->block->used_list, memblock) == NULL); 

    block = memblock->block;
    bh->freeElems++;
    block->freeElems++;
    mem_frob(ptr, bh->elemSize);
    dlinkDelete(&memblock->self, &block->used_list);
    dlinkAdd(ptr, &memblock->self, &block->free_list);
    return(0);
}

/* ************************************************************************ */
/* FUNCTION DOCUMENTATION:                                                  */
/*    BlockHeapGarbageCollect                                               */
/* Description:                                                             */
/*    Performs garbage collection on the block heap.  Any blocks that are   */
/*    completely unallocated are removed from the heap.  Garbage collection */
/*    will never remove the root node of the heap.                          */
/* Parameters:                                                              */
/*    bh (IN):  Pointer to the BlockHeap to be cleaned up                   */
/* Returns:                                                                 */
/*   0 if successful, 1 if bh == NULL                                       */
/* ************************************************************************ */
static int BlockHeapGarbageCollect(BlockHeap *bh)
{
    Block *walker, *last;

    if(bh == NULL)
    {
        return(1);
    }

    if(bh->freeElems < bh->elemsPerBlock || bh->blocksAllocated == 1)
    {
        /* There couldn't possibly be an entire free block.  Return. */
        return(0);
    }

    last = NULL;
    walker = bh->base;

    while (walker != NULL)
    {
        if((walker->freeElems == bh->elemsPerBlock) != 0)
        {
            free_block(walker->elems, walker->alloc_size);
            if(last != NULL)
            {
                last->next = walker->next;
                if(walker != NULL)
                    free(walker);
                walker = last->next;
            }
            else
            {
                bh->base = walker->next;
                if(walker != NULL)
                    free(walker);
                walker = bh->base;
            }
            bh->blocksAllocated--;
            bh->freeElems -= bh->elemsPerBlock;
        }
        else
        {
            last = walker;
            walker = walker->next;
        }
    }
    return(0);
}

/* ************************************************************************ */
/* FUNCTION DOCUMENTATION:                                                  */
/*    BlockHeapDestroy                                                      */
/* Description:                                                             */
/*    Completely free()s a BlockHeap.  Use for cleanup.                     */
/* Parameters:                                                              */
/*    bh (IN):  Pointer to the BlockHeap to be destroyed.                   */
/* Returns:                                                                 */
/*   0 if successful, 1 if bh == NULL                                       */
/* ************************************************************************ */
int BlockHeapDestroy(BlockHeap * bh)
{
    Block *walker, *next;

    if(bh == NULL)
    {
        return(1);
    }

    for (walker = bh->base; walker != NULL; walker = next)
    {
        next = walker->next;
        free_block(walker->elems, walker->alloc_size);
        if(walker != NULL)
            free(walker);
    }

    if(heap_list == bh)
        heap_list = bh->next;
    else 
    {
        BlockHeap *prev;

        for (prev = heap_list; prev->next != bh; prev = prev->next);
        prev->next = bh->next;
    }

    free(bh);
    return(0);
}

/*
* block_heap_get_used()
*
* inputs       - Pointer to a BlockHeap
* output       - Number of bytes being used
* side effects - NONE
*/
size_t block_heap_get_used(const BlockHeap *const bh)
{
    return(((bh->blocksAllocated * bh->elemsPerBlock)-bh->freeElems) * (bh->elemSize + sizeof(MemBlock)));
}

/*
* block_heap_get_free()
*
* inputs       - Pointer to a BlockHeap
* output       - Number of bytes being free for further allocations
* side effects - NONE
*/
size_t block_heap_get_free(const BlockHeap *const bh)
{
    return(bh->freeElems * (bh->elemSize + sizeof(MemBlock)));
}

/*
* block_heap_get_size()
*
* inputs       - Pointer to a BlockHeap
* output       - Total number of bytes of memory belonging to a heap
* side effects - NONE
*/
size_t block_heap_get_size(const BlockHeap *const bh)
{
    return(((bh->blocksAllocated * bh->elemsPerBlock)) * (bh->elemSize + sizeof(MemBlock)));
}
