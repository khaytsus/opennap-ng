/* $Id: win32-support.h 438 2006-10-04 10:48:08Z khaytsus $
*
*    Open Source Napster Server - Peer-To-Peer Indexing/Chat Daemon
*    Copyright (C) 2001  drscholl@users.sourceforge.net
*
*    This program is free software; you can redistribute it and/or modify
*    it under the terms of the GNU General Public License as published by
*    the Free Software Foundation; either version 2 of the License, or
*    (at your option) any later version.
*
*    This program is distributed in the hope that it will be useful,
*    but WITHOUT ANY WARRANTY; without even the implied warranty of
*    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*    GNU General Public License for more details.
*
*    You should have received a copy of the GNU General Public License
*    along with this program; if not, write to the Free Software
*    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

/* This file contains definitions useful for porting UNIX code to the Win32
* platform using the Microsoft Visual C++ compiler.
*/

#define FD_SETSIZE 8192
#include <winsock2.h>
#include <windows.h>

/* the next #define is needed for zlib */
#define ZLIB_WINAPI

#include <zlib.h>
#include <io.h>
#include <errno.h>
#include <psapi.h>
#include <stdarg.h>

#define PACKAGE "opennap-ng"
#define VERSION "0.50-beta2"
#define SHAREDIR "."
#define VARDIR "."

#define getopt _getopt
#define READ(a,b,c) recv(a,b,c,0)
#define WRITE(a,b,c) send(a,b,c,0)
#define CLOSE closesocket
#undef SOCKOPTCAST
#define SOCKOPTCAST (char*)
#define EINPROGRESS WSAEINPROGRESS
#define EWOULDBLOCK WSAEWOULDBLOCK
#define ENOBUFS WSAENOBUFS
#define ENOTSOCK WSAENOTSOCK
#define _POSIX_PATH_MAX _MAX_PATH
#define strcasecmp _stricmp
#define strncasecmp _strnicmp
#define vsnprintf _vsnprintf
#define snprintf _snprintf
#define getuid() 0          /* just fake it */
#define getpid() _getpid()  /* just fake it, no need to */
#define S_IRUSR _S_IREAD
#define S_IWUSR _S_IWRITE
#define strerror win32_strerror
#define gettimeofday win32_gettimeofday
#define getpagesize() 4096
#define dup2 _dup2
#define open _open
#define close _close
#define unlink _unlink
#define write _write
#define read _read
#define lseek _lseek
#define access _access
#define fdopen _fdopen


/* manual options from configure.in */
#define CSC 1
#define USE_INVALID_CLIENTS 1
#define USE_INVALID_NICKS 1
#define USE_PROTNET 1
#define LOG_CHANNEL 1
#define PID 1
#define RESUME 1
#undef ROUTING_ONLY
#undef EMAIL

extern char *optarg;
extern int optind;

extern int _getopt (int, char **, char *);
extern int _getpid( void );
extern int win32_gettimeofday( struct timeval* tv, void* timezone );
