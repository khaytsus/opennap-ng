/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
This is free software distributed under the terms of the
GNU Public License.  See the file COPYING for details.

$Id: list.c 434 2006-09-03 17:48:47Z reech $ */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>
#include "list.h"
#include "debug.h"

//BlockHeap *list_heap;

LIST   *list_new(void *p)
{
	LIST   *list = CALLOC(1, sizeof(LIST));

	if(list)
		list->data = p;
	return list;
}

/* remove the element matching `data' from the list */
LIST   *list_delete(LIST * list, void *data)
{
	LIST  **ptr, *tmp;

	ASSERT(list != 0);
	ASSERT(data != 0);
	for (ptr = &list; *ptr; ptr = &(*ptr)->next)
	{
		ASSERT(VALID_LEN(*ptr, sizeof(LIST)));
		if((*ptr)->data == data)
		{
			tmp = *ptr;
			*ptr = (*ptr)->next;
			FREE(tmp);
			break;
		}
	}
	return list;
}

LIST   *list_append(LIST * l, LIST * b)
{
	LIST  **r = &l;

	while (*r)
	{
		ASSERT(VALID_LEN(*r, sizeof(LIST)));
		r = &(*r)->next;
	}
	*r = b;
	return l;
}

LIST   *list_append_data(LIST * l, void *d)
{
	LIST   *list;

	ASSERT(d != 0);
	LIST_NEW(list, d);
	return(list_append (l, list));
}

void list_free(LIST * l, list_destroy_t cb)
{
	LIST   *t;

	while (l)
	{
		ASSERT(VALID_LEN(l, sizeof(LIST)));
		t = l;
		l = l->next;
		if(cb)
			cb(t->data);
		FREE(t);
	}
}

int list_count(LIST * list)
{
	int     count = 0;

	for (; list; list = list->next)
	{
		ASSERT(VALID_LEN(list, sizeof(LIST)));
		count++;
	}
	return count;
}

LIST   *list_find(LIST * list, void *data)
{
	for (; list; list = list->next)
	{
		ASSERT(VALID_LEN(list, sizeof(LIST)));
		if(list->data == data)
			return list;
	}
	return 0;
}

#if ONAP_DEBUG
int list_validate(LIST * list)
{
	for (; list; list = list->next)
	{
		ASSERT_RETURN_IF_FAIL(VALID_LEN(list, sizeof(LIST)), 0);
	}
	return 1;
}
#endif

LIST   *list_push(LIST * head, LIST * elem)
{
	elem->next = head;
	return elem;
}

void list_foreach(LIST * list, list_callback_t func, void *arg)
{
	while (list)
	{
		func(list->data, arg);
		list = list->next;
	}
}


/* Does a mergesort of a linked list. Returns the sorted list. */
LIST *list_sort( LIST *list, list_cmp_callback_t cmpfunc) 
{
	LIST *p, *q, *e, *tail, *oldhead;
	int insize, nmerges, psize, qsize, i;


	/* We do not sort empty lists ... */
	if( ! list ) 
		return 0;

	insize = 1;

	while (1) 
	{
		p = list;
		oldhead = list;            /* only used for circular linkage */
		list = NULL;
		tail = NULL;

		nmerges = 0;  /* count number of merges we do in this pass */

		while (p) 
		{
			nmerges++;  /* there exists a merge to be done */
			/* step     nsize' places along from p */
			q = p;
			psize = 0;
			for (i = 0; i < insize; i++) 
			{
				psize++;
				q = q->next;
				if(!q) 
					break;
			}

			/* if q hasn't fallen off end, we have two lists to merge */
			qsize = insize;

			/* now we have two lists; merge them */
			while (psize > 0 || (qsize > 0 && q)) 
			{

				/* decide whether next element of merge comes from p or q */
				if(psize == 0) 
				{
					/* p is empty; e must come from q. */
					e = q; 
					q = q->next; 
					qsize--;
				} 
				else if(qsize == 0 || !q) 
				{
					/* q is empty; e must come from p. */
					e = p; 
					p = p->next; 
					psize--;
				} 
				else if(cmpfunc(p->data,q->data) ) 
				{
					/* First element of p is lower (or same);
					* e must come from p. */
					e = p; 
					p = p->next; 
					psize--;
				}
				else 
				{
					/* First element of q is lower; e must come from q. */
					e = q; 
					q = q->next; 
					qsize--;
				}

				/* add the next element to the merged list */
				if(tail) 
				{
					tail->next = e;
				} 
				else 
				{
					list = e;
				}
				tail = e;
			}

			/* now p has stepped    nsize' places along, and q has too */
			p = q;
		}
		tail->next = NULL;

		/* If we have done only one merge, we're finished. */
		if(nmerges <= 1)   /* allow for nmerges==0, the empty list case */
			return list;

		/* Otherwise repeat, merging lists twice the size */
		insize *= 2;
	}
}
