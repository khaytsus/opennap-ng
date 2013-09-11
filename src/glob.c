/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
This is free software distributed under the terms of the
GNU Public License.  See the file COPYING for details.

$Id: glob.c 434 2006-09-03 17:48:47Z reech $ */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

/* Added by winter_mute */
#if defined(USE_PROTNET) || defined(USE_INVALID_CLIENTS) || defined(USE_INVALID_NICKS)
#  include <string.h>
#  include <stdlib.h>
#endif

#include <ctype.h>
#include "opennap.h"
#include "debug.h"

/* returns >0 if the pattern matches, 0 if the pattern does not match.
* the match is case-insensitive
*/
int glob_match(const char *pattern, const char *s)
{
    const char *ptr;

    /* Added by winter_mute */
#if defined(USE_PROTNET) || defined(USE_INVALID_CLIENTS) || defined(USE_INVALID_NICKS)
    if(
#ifdef USE_PROTNET
        strcmp(pattern, global.protnet) == 0
#endif
        /* global.invalidClients is not alone, add the || */
#if defined(USE_PROTNET) && defined(USE_INVALID_CLIENTS)
        || strcmp(pattern, global.invalidClients) == 0
#elif defined(USE_INVALID_CLIENTS)
        strcmp(pattern, global.invalidClients) == 0
#endif
        /* global.invalidNicks is not alone, add the || */
#if(defined(USE_PROTNET) || defined(USE_INVALID_CLIENTS)) && defined(USE_INVALID_NICKS)
        || strcmp(pattern, global.invalidNicks) == 0
#elif defined(USE_INVALID_NICKS)
        strcmp(pattern, global.invalidNicks) == 0
#endif
#if(defined(USE_PROTNET) || defined(USE_INVALID_CLIENTS)) && defined(USE_INVALID_NICKS)
        || strcmp(pattern, global.setServerNicks) == 0
#elif defined(USE_INVALID_NICKS)
        strcmp(pattern, global.setServerNicks) == 0
#endif
        )
    {  
        const char *delim = ",";
        char *p_tmp = STRDUP(pattern);
        /* In order to preserve the pointer, we now assign it to another var */
        char *p_tmpptr = p_tmp;
        /* Seperate the string into either , or SPACE, and loop throug each one */
        char *val = strsep(&p_tmp, delim);

        if(p_tmp)
        {  
            do
            {  
                if(glob_match(val, s)) 
				{
                    /* Might be a leak when not freed */
                    FREE(p_tmpptr);
                    return 1;
                }
            } while ((val = strsep(&p_tmp, delim)) != NULL);
            /* No match, free mem and return 0 */

            if(p_tmpptr != NULL)
                FREE(p_tmpptr);

            return 0;
        }
        /* Wouldn't split it up, so free mem and let normal glob take care of it */
        else if(p_tmpptr != NULL)
            FREE(p_tmpptr);
    }
#endif /* either identifier exists */

    while (*pattern || *s)
    {
        if(*pattern == '*')
        {
            while (*pattern == '*' || *pattern == '?')
                pattern++;
            if(!*pattern)
            {
                /* match to end of string */

                return 1;
            }
            /* recursively attempt to match the rest of the string, using the
            * longest match first
            */
            ptr = s + strlen(s);
            for (;;)
            {
                while (ptr > s && tolower (*(ptr - 1)) != tolower (*pattern))
                    ptr--;
                if(ptr == s)
                    return 0;   /* no match */
                if(glob_match(pattern + 1, ptr))
                    return 1;
                ptr--;
            }
            /* not reached */
        }
        else if(*pattern == '?' || tolower (*pattern) == tolower (*s))
        {
            pattern++;
            s++;
        }
        else
            return 0;       /* no match */
    }
    return((*pattern || *s) ? 0 : 1);
}
