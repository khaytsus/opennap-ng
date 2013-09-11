/* Copyright (C) 2000 drscholl@users.sourceforge.net
This is free software distributed under the terms of the
GNU Public License.  See the file COPYING for details.

$Id: opennap.h 436 2006-09-04 14:56:32Z reech $ */

#ifndef opennap_h
#define opennap_h

#ifdef WIN32
#   include "win32-support.h"
#endif

#ifdef WIN32
# define LE "\r\n"
#else
# define LE "\n"
#endif

#if defined(HAVE_POLL)
#   include <sys/poll.h>
#endif

#include <stdarg.h>
#include <sys/types.h>
#ifndef WIN32
#   include <zlib.h>
#endif
#include "balloc.h"
#include "hash.h"
#include "list.h"
#include "subversionrev.h"

#ifndef SOCKET
# define SOCKET int
#endif
#ifndef INVALID_SOCKET
# define INVALID_SOCKET -1
#endif

/* added printf and exit to OUTOFMEMORY rhk */
#define OUTOFMEMORY(f) log_message("%s: OUT OF MEMORY at %s:%d", f, __FILE__, __LINE__); printf("%s: OUT OF MEMORY at %s:%d", f, __FILE__, __LINE__); exit(-99)
#define _logerr(f,s,e) log_message("%s: %s: %s (errno %d)", f, s, strerror(e), e)
#define logerr(f,s) _logerr(f,s,errno)

#define MAGIC_USER 0xeaee402a
#define MAGIC_CHANNEL 0xa66544cb
#define MAGIC_CONNECTION 0x3c4474a3
#define MAGIC_BUFFER 0xe5a7a3be
#define MAGIC_CHANUSER 0x728dc736
#define MAGIC_OPS 0xa28e453f
#define MAGIC_FLIST 0xff496a95

#define MAX_NICKLEN 50
#define MAX_PASSLEN 33

#if WORDS_BIGENDIAN
#   define BSWAP16(c) (((((c) & 0xff) << 8) | (((c) >> 8) & 0xff)))
#   define BSWAP32(c) ((((c)>>24)&0xff)|(((c)>>8)&0xff00)|(((c)<<8)&0xff0000)|((c)<<24))
#else
#   define BSWAP16(c) c
#   define BSWAP32(c) c
#endif

#define ISSPACE(c) isspace((unsigned char)(c))
#define ISPRINT(c) isprint((unsigned char)(c))

#define FIELDS(p) sizeof(p)/sizeof(char*)

typedef struct _buffer BUFFER;

/* to avoid copying a lot of data around with memmove() we use the following
structure for output buffers */
struct _buffer
{
#if ONAP_DEBUG
    unsigned int magic;
#endif
    char   *data;           /* allocated data */
    int     datasize;       /* total bytes used in `data' */
    int     datamax;        /* size of allocated memory block */
    int     consumed;       /* how many bytes of data consumed from this buffer */
    BUFFER *next;
};

#define RECVBUF_INITAL_SIZE 2048   /* was hardcoded to 5 which is just the size of len+tag then would realloc up to what was needed.  
                                    * this should save a lot of reallocs w/o really wasting much memory
									* -- should this be coded as max_command_length?  (defaults to 2048, no real diff)
                                    */
#define BUFFER_SIZE 8192     /* default buffer length for output queues (bumped from 4k to 16k to match the tcp buffer 
                              * (why have 4 BUFFERS in a list when only one is needed? 
							  * ok, ok, a server is horking up on allocation of buffers, let's half this... (8k)
                              */

typedef struct _connection CONNECTION;
typedef struct _user USER;
typedef struct _channel CHANNEL;
typedef struct _chanuser CHANUSER;
typedef struct _class CLASS;
typedef struct _global GLOBAL;

/* bitmasks for the `flags' member of struct _chanuser */
#define ON_CHANNEL_OPERATOR (1<<0)
#define ON_CHANNEL_VOICE    (1<<1)
#define ON_CHANNEL_MUZZLED  (1<<2)

struct _chanuser
{
#ifdef ONAP_DEBUG
    unsigned int magic;
#endif
    int     flags;
    USER   *user;
};

/* bitmask values for the channel flags */
#define ON_CHANNEL_REGISTERED   (1<<0)  /* channel is registered */
#define ON_CHANNEL_PRIVATE      (1<<1)  /* private (hidden) channel */
#define ON_CHANNEL_MODERATED    (1<<2)  /* moderated channel */
#define ON_CHANNEL_INVITE       (1<<3)  /* invitation required */
#define ON_CHANNEL_TOPIC        (1<<4)  /* topic can be set by any member */
#define ON_CHANNEL_QUIET        (1<<5)  /* quiet channel */

struct _channel
{
#ifdef ONAP_DEBUG
    unsigned int magic;
#endif
    char   *name;           /* name of the channel */
    char   *topic;          /* current topic of discussion */
    LIST   *users;          /* list of users on the channel */
    LIST   *bans;           /* channel specific bans */
    LIST   *invited;        /* invited users */
    time_t  timestamp;      /* when channel was created, used to sync servers */
    unsigned short limit;   /* max number of users allowed */
    unsigned int flags:12;  /* channel flags */
    unsigned int level:3;   /* minimum level to enter channel */
    unsigned int local:1;   /* channel is local to server */
};

/* user level */
enum
{
    LEVEL_LEECH,
    LEVEL_USER,
    LEVEL_MODERATOR,
    LEVEL_ADMIN,
    LEVEL_ELITE
};

/* connection class */
struct _class
{
    unsigned int target;
    unsigned int mask;
    int     limit;
};

struct _user
{
#ifdef ONAP_DEBUG
    unsigned int magic;
#endif
    char   *nick;
    char   *pass;           /* password for this user, needed for sync */
    char   *clientinfo;     /* DO NOT FREE.  This is a ref to
                            *  an entry in the Client_Versions hash
                            *  table */
    char   *server;         /* which server the user is connected to.
                            *  NOTE. this is a pointer to an entry in
                            *  Server_Names, and not malloc'd. */

    time_t  connected;      /* time at which the user connected */
    LIST   *channels;       /* channels of which this user is a member */
    CONNECTION *con;        /* local connection, or server which this
                            *  user is behind */

    unsigned int libsize;       /* approximate size of shared files in kB */
    unsigned int ip;            /* ip of user in network byte order */

    unsigned short uploads;     /* no. of uploads in progress */
    unsigned short downloads;   /* no. of downloads in progress */
    unsigned short port;        /* data port client is listening on */
    unsigned short conport;     /* remote port for connection to server */
    unsigned short totalup;     /* total number of uploads */
    unsigned short totaldown;   /* total number of downloads */

    unsigned int   shared;      /* # of shared files */
    unsigned short wantPong;    /* # of outstanding PONGs */

    unsigned short yyy;         /* unused */

    /* Added by Davide Scola <davide.gnu@disi.unige.it> */
    unsigned int warned;       /* stop flooding users when his share is greater than Max_Shared */

    /* Added by winter_mute */
    unsigned short desynced;    /* nonzero if user is desynced */
    unsigned int level:3;       /* user level */
    unsigned int speed:4;       /* link speed */

    /* These vars are to abolish abusive behavior of these tags which cause a lot 
    of bandwidth to be consumed. Some annoying client uses this quite abusively */
    unsigned int count218;      /* Counter of download-Start-Requests */
    unsigned int count219;      /* Counter of Download-End-Requests */
    unsigned int count700;      /* Counter of Change linkspeed requests */
    unsigned int count200;      /* Counter of search requests */
    unsigned int did640browse;  /* Did the user ever issue a 640 browse? This is to prevent privmsgs when browsing otherwise */

    unsigned int local:1;   /* nonzero if locally connected */
    unsigned int flags;     /* contains information if this user is
                            * muzzled or a friend */
    unsigned int sharing:1;
    unsigned int unsharing:1;
    unsigned int cloaked:1;
    unsigned int xxx:4;     /* unused */
    HASH        *tagCountHash; /* keeps track of how many times the user has issued a tag */
};

typedef struct
{
    unsigned long   count;
    time_t          lastInterval; /* time when we last reported */
    unsigned short  flag; /* if 1 dump packets */
}tag_count_t;

enum
{
    CLASS_UNKNOWN,
    CLASS_USER,
    CLASS_SERVER
};

#define ISSERVER(c) ((c)->class==CLASS_SERVER)
#define ISUSER(c)   ((c)->class==CLASS_USER)
#define ISUNKNOWN(c)    ((c)->class==CLASS_UNKNOWN)

typedef struct
{
    z_streamp   zin;      /* input stream decompressor */
    z_streamp   zout;     /* output stream compressor */
    BUFFER     *outbuf;     /* compressed output buffer */
    HASH       *tagCountHash; /* keeps track of how many times the server has issued a tag */

}
SERVER;

typedef struct
{
    char   *nonce;
    char   *sendernonce;
}
AUTH;

/* this struct contains options on a per user basis.  They are not included
* in the USER struct since they only apply to local connections */
typedef struct
{
    /* bitmask of which server messages a user wishes to receive */
    unsigned int usermode;
    /* hotlist for user.  this is the list of users they wish to be
    * notified about when they log in or out.  note that this is just
    * a pointer to the _single_ global entry stored in the Hotlist
    * hash table.  the actual HOTLIST* pointer should only be freed
    * when hotlist->numusers is zero.  */
    LIST     *hotlist;
    HASH     *files;        /* db entries for this user's shared files */
    BlockHeap *files_heap;
    LIST     *ignore;       /* server side ignore list */
    int       searches;     /* number of pending searches */
#ifdef CSC
    z_streamp zin;      /* input stream decompressor */
    z_streamp zout;     /* output stream compressor */
    BUFFER   *outbuf;   /* compressed output buffer */
    int       csc;      /* flag for CSC */
#endif
}
USEROPT;

struct _connection
{
#ifdef ONAP_DEBUG
    unsigned int magic;
#endif
    int     id;         /* index into the Clients[] and Poll[] array */
    SOCKET  fd;         /* socket for this connection */
    unsigned int ip;    /* ip for this connection */
    char   *host;       /* host from which this connection originates */
    USER   *user;       /* pointer to the user associated with this
                        * connection, if CLASS_USER */
    BUFFER *sendbuf;        /* output buffer */
    BUFFER *recvbuf;        /* input buffer */

    union
    {
        /* parameters for use when the connection is a server.  items which
        * only apply to users on the local server are placed here in order
        * to reduce memory consumption */
#define uopt opt.useropt
        USEROPT *useropt;
        /* parameters for server->server connection */
#define sopt opt.server
        SERVER *server;
        /* this field is used for the authentication phase of server links */
        AUTH   *auth;
    }
    opt;

    time_t  timer;      /* timer to detect idle connections */
    time_t  flood_start;/* flood protection counter */

    unsigned short flood_commands;
    unsigned short port;    /* remote port */

    unsigned short unused;

    unsigned int connecting:1;
    unsigned int destroy:1;     /* connection should be destoyed in
                                * handle_connection().  because h_c() caches
                                * a copy of the CONNECTION pointer, we can't
                                * remove it from inside a handler, so we mark
                                * it here and have it removed at a later time 
                                * when it is safe */
    unsigned int killed:1;      /* set when the user was killed so free_user()
                                * knows not to generate a QUIT message */
    unsigned int quit:1;        /* used to detect manual server disconnects */
    unsigned int server_login:1;
    unsigned int compress:4;    /* compression level for this connection */
    unsigned int class:2;       /* connection class (unknown, user, server) */
    unsigned int numerics:1;    /* use real numerics for opennap extensions */
    unsigned int xxx:4;         /*unused */

};

/* doubly linked list */
typedef struct _DList {
    struct _DList *prev;
    struct _DList *next;
    void *data;
} DList;

/* list of DATUM entries, used in the global file list */
typedef struct
{
#if ONAP_DEBUG
    unsigned int magic;
#endif
    char   *key;        /* keyword */
    DList   *list;      /* list of files containing this keyword */
    int     count;      /* number of files in the list */
}
FileList;

/* Each DATUM contains a list of all the `tokens' it contains.  Since the
* list of files in each token can be very large (~thousands on a busy
* server), deletion of a particular DATUM from the FileList would involve
* scanning the entire list.  Instead, we store a pointer to the element
* itself so we can remove it quickly.  Previously, when a user with a large
* shared collection quit the server, there would be a noticeable pause
* with all the list scanning that occurred.
*/
typedef struct {
    FileList *flist;    /* bin in which this file resides */
    DList *dlist;       /* reference to this file for quick deletion */
} TokenRef;

/* content-type */
enum
{
    CT_MP3,         /* default */
    CT_AUDIO,
    CT_VIDEO,
    CT_APPLICATION,
    CT_IMAGE,
    CT_TEXT,
    CT_UNKNOWN
};

/* maximum number of words a file can be indexed under.  currently we have 5-bits of storage for
* the number of tokens.
*/
#define kOMaxTokens 31 /* 0 , 2^5 - 1 */

typedef struct
{
    USER   *user;       /* user who possesses this file */
    char   filename[_POSIX_PATH_MAX + 3];
#if RESUME
    char   hash[33];       /* the md5 hash of the file */
#endif
    TokenRef   *tokens;     /* array of keywords for this file */

    unsigned int size;      /* size of file in bytes.  set to -1 if
                            the structure is invalid */
    unsigned short duration;
    /* next 4 fields make up 16 bits */
    unsigned int bitrate:5; /* offset into BitRate[] */
    unsigned int frequency:3;   /* offset into SampleRate[] */
    unsigned int type:3;    /* content type */
    unsigned int numTokens:5;       /* # of entries in the TokenRef array */
}
DATUM;

typedef struct _ban
{
    /* target[maxnicklen + ! + strlen("111.222.333.444") + \0 ]  */
    char    target[MAX_NICKLEN + 16];     /* target of the ban */
    char    setby[MAX_NICKLEN + 1];      /* user/server that set the ban */
    char    reason[256];     /* reason for the ban */
    time_t  when;       /* when the ban was set */
    int     timeout;        /* how many secs the ban is active for */
    int     connect_counter;    /* How many times the user tried to connect */
    time_t  firstconnect;       /* When did the first connect occur? */
    time_t  when_deleted;   /* What had been the deletion time? ( if deleted != 0 ) */
}
BAN;


/* This one has two aspects 
It should contain a statistics on searches 
and it later increases the list of files found.
This struct is used whenever a search request
is about to be transmitted to a remote server.
*/
typedef struct _searchcache
{
    int    used;        /* How often has this search been used? */
    time_t lastused;        /* When has this search been used for the last time? */
    time_t firstused;       /* When has this search been used for the first time? */
    float  rank;                /* Which rank has been calculated for this record? */
    int    ResultCount;         /* How many results are connected to this cache entry? */
    LIST   *SearchResults;  /* LIST containing the results for this search */
    char   *unifiedsearch;  /* Containing the search-string to gain these results. */
} SEARCHCACHE;

/* bitmask for use in USERDB .flags member */
#define ON_MUZZLED  0x0001  /* To represent a muzzled user */
#define ON_FRIEND   0x0002  /* To avoid setting someone to mod when just allowing chatting */
#define ON_CRIMINAL 0x0004  /* A user with this flag gets banned as soon as he finishes sharing */


/* 20 (+4) bytes */
typedef struct
{
    char   nick[MAX_NICKLEN + 1];
    char   password[MAX_PASSLEN + 1];
#if EMAIL
    char   *email;
#endif
    unsigned short level;
    unsigned short flags;
    time_t  created;        /* when the record was created */
    time_t  lastSeen;
}
USERDB;

typedef struct link
{
    char   *server;
    char   *peer;
    unsigned short port;
    unsigned short peerport;
    int     hops;
}
LINK;

/* structure to hold the server-link authentications */

typedef struct
{
    char   *name;
    char   *alias;      /* name which will be displayed (optional) */
    unsigned short     port;       /* port to connect to */
    char   *their_pass;
    char   *my_pass;
}
server_auth_t;

/* who-was entry */
typedef struct
{
    char   *nick;
    char   *server;
    unsigned int ip;        /* client's ip address */
    time_t  when;           /* when the user logged out */
    char   *clientinfo;     /* client version string */
}
whowas_t;

/* information per ip address to help curb abuse of reconnecting to fast
* or registering a lot of nicknames.
*/
typedef struct
{
    unsigned int ip;        /* ip address */
    time_t  last_connect;   /* time at which last connect occurred */
    time_t  last_register;  /* time at which last was registered */
    unsigned int users;     /* current number of users from this ip */
    unsigned int connects;  /* total number of connects from this ip */
}
ip_info_t;

typedef struct
{
    unsigned int ip;
    unsigned int mask;
    unsigned count;
}
access_t;

typedef struct {
    unsigned int  tag;
    unsigned int  count;
    unsigned long len;
} histogram_t;

/* bitmask used for new_tcp_socket() call */
#define ON_NONBLOCKING  1
#define ON_REUSEADDR    2
#define ON_LISTEN       4

typedef void (*timer_cb_t) (void *);

/* define a namespace for global variables */
struct _global
{
    HASH   *usersHash;
#if HAVE_POLL
    struct pollfd *poll;
    int     poll_num;
    int     poll_max;
    int    *fdmap;
#else
    fd_set  read_fds;
    fd_set  write_fds;
#endif
    SOCKET  max_fd;

    CONNECTION **clients;
    int     clients_num;
    int     clients_max;

    /* Contains the last called functioncall */
    unsigned int     current_tag;

    double  bytes_in;
    double  bytes_out;
    double  total_bytes_in;
    double  total_bytes_out;

    time_t  current_time;
    time_t  last_click;
    int     min_read;
    int     max_tags_per_minute;
    int     max_searches_per_minute;
    int     max_new_users_per_minute;
    int     evaluate_search_abuse_after_tags;
    int     evaluate_search_abuse_after_secs;
    int     notify_user_abuse_frequency;
    int     notify_mod_abuse_frequency;
    int     abuse_bans_ip;
    int     eject_ban_ttl;
    int     ibl_ttl;
#ifdef HAVE_LIBPTHREAD
    int     proxycheck;
#endif
    int     stat_click;
    int     search_count;
    int     count205mx;
    int     count205;
    int     size205;
    int     size205mx;
    int     ghost_kill_timer;
    int     search_max_cache_entries;
    int     discipline_ignorers_ban_ttl;
    int     level_to_set_flags;
    int     discipline_block_ban_ttl;
    int     hlc;    /* Hoshi  Hash Loop Count */
    int     frc;    /* Free Count */
    int     logfile;
    int     BlockWinMX;
    int     clientQueueLen;
    int     compressionLevel;
    int     ejectAfter;
    int     floodCommands;
    int     floodTime;
    int     loginTimeout;
    int     loginInterval;
    unsigned short     logLevel;
    int     maxBrowseResult;
    int     maxClientString;
    int     maxClones;
    int     maxCommandLen;
    int     maxConnections;
    int     maxHotlist;
    int     maxIgnore;
    int     maxReason;
    int     maxTopic;
    int     maxSearchResults;
    int     maxSearches;
    int     maxTimeDelta;
    int     maxUserChannels;
    int     nickExpire;
    double  fileLibSize; /* in KB */
    int     fileLibCount;
    LIST   *modList;
    char   *Listen_Addr;
    int     pingInterval;
    int     registerInterval;
    int     searchTimeout;
    int     serverChunk;
    u_int   serverIP;
    u_int   serverFlags;
    int     maxShared;
    int     maxNickLen;
    int     maxChanLen;
    int     whoWasTime;
    u_int   iface;
    int     warnTimeDelta;
    LIST   *banList;
    LIST   *serverAliasList;
    LIST   *internalBanList;
    LIST   *destroyList;
    LIST   *flooderList;
    char   *serverAlias;
    char   *serverName;
    LIST   *serverPortList;
    time_t  serverStartTime;
    int     serverQueueMaxLen;
    int     sigCaught;
    int     userDBSaveFreq;
    LIST   *searchCacheList;
    int     searchCacheEntries;
    HASH   *channelHash;
    HASH   *clientVersionHash;
    HASH   *clonesHash;
    HASH   *hotlistHash;
    HASH   *whoWasHash;
    LIST   *serversList;
    LIST   *serverLinksList;
    LIST   *serverNamesList;
    HASH   *userDbHash;
    LIST   *histOutList;
    char   *shareDir;
    char   *varDir;
    HASH   *filterHash;
    LIST   *blockList;
    unsigned short     statsPort2;


#ifdef USE_INVALID_CLIENTS
    char   *invalidClients;
#endif
#ifdef USE_INVALID_NICKS
    char   *invalidNicks;
#endif
#ifdef USE_PROTNET
    char   *protnet;
#endif
#if defined(USE_INVALID_CLIENTS) || defined(USE_INVALID_NICKS)
    char   *setServerNicks;
#endif

#ifndef WIN32
    int     hardConnLimit;
    int     maxDataSize;
    int     maxRssSize;
#endif

#ifndef ROUTING_ONLY
    int     eject_limit_files;
    unsigned int     eject_limit_libsize;
    unsigned int     min_file_size;
    int     eject_limit;
    int     eject_grace_time;
    SOCKET  stat_server_fd;
    char   *stat_pass;
    char   *stat_server;
    unsigned short     stat_server_port;
    char   *stat_user;
    char   *report_ip;
    int     report_port;
    char   *report_name;
    int     fileCountThreshold;
    int     localSharedFiles;
    int     fileIndexPathDepth;
    unsigned short     statsPort;
    HASH   *FileHash;
#   ifdef RESUME
      HASH   *MD5Hash;
#   endif
#endif
};

extern GLOBAL global;

/* a structure to hold all login/logout stats */
typedef struct
{
    unsigned long  connects;
    unsigned long  disconnects;
#ifdef CSC
    unsigned long  zusers;
#endif
    float          load_avg;
    unsigned long  mem_usage;
#ifdef WIN32
    unsigned long max_mem_usage;
#endif
    unsigned long  logins;
    unsigned long  login_ce_already;
    unsigned long  login_ce_params;
    unsigned long  login_se_params;
    unsigned long  login_ce_autoreg_off;
    unsigned long  login_ce_too_fast;
    unsigned long  login_ce_invalid_nick;
#if ROUTING_ONLY
    unsigned long  login_ce_not_admin;
#endif
    unsigned long  login_ce_clone;
    unsigned long  login_ce_banned;
    unsigned long  login_ce_max_connections;
    unsigned long  login_ce_client_banned;
    unsigned long  login_ce_speed;
    unsigned long  login_ce_port;
    unsigned long  login_ce_restricted;
    unsigned long  login_ce_nick_already_registered;
    unsigned long  login_ce_password;
    unsigned long  search_total;
    unsigned long  search_cancelled;
    unsigned long  search_expired;
    unsigned long  search_nosuch;
    unsigned long  ibl_db;
    unsigned long  con_104;
    unsigned long  con_110;
    unsigned long  con_113;
    unsigned long  con_032;
    unsigned long  flood_db;
    unsigned long  tags;
}
stats_t;
extern stats_t stats;

#define LOG_LEVEL_SERVER    1           /*  1    */
#define LOG_LEVEL_CLIENT    (1<<1)      /*  2    */
#define LOG_LEVEL_LOGIN     (1<<2)      /*  4    */
#define LOG_LEVEL_FILES     (1<<3)      /*  8    */
#define LOG_LEVEL_SHARE     (1<<4)      /*  16   */
#define LOG_LEVEL_SEARCH    (1<<5)      /*  32   */
#define LOG_LEVEL_DEBUG     (1<<6)      /*  64   */
#define LOG_LEVEL_ERROR     (1<<7)      /*  128  */
#define LOG_LEVEL_SECURITY  (1<<8)      /*  256  */
#define LOG_LEVEL_CHANNEL   (1<<9)      /*  512  */
#define LOG_LEVEL_STATS     (1<<10)     /*  1024 */

#define LOG_LEVEL_ALL (LOG_LEVEL_SERVER|LOG_LEVEL_CLIENT|LOG_LEVEL_LOGIN|\
    LOG_LEVEL_FILES|LOG_LEVEL_SHARE|LOG_LEVEL_SEARCH|LOG_LEVEL_DEBUG|\
    LOG_LEVEL_ERROR|LOG_LEVEL_SECURITY|LOG_LEVEL_CHANNEL|LOG_LEVEL_STATS)



extern unsigned int Pending_Searches;
extern unsigned int UserMode_int;   /* Default UserMode to use when mod logs in */
extern char *UserMode;

extern const int BitRate[];
extern const int SampleRate[];


#define option(x) ((global.serverFlags & (x))!=0)

#define ON_STRICT_CHANNELS          1       /* only mods+ can create channels */
#define ON_REGISTERED_ONLY          (1<<1)  /* only registered users are allowed */
#define ON_AUTO_REGISTER            (1<<2)  /* automatically register users */
#define ON_LOCK_MEMORY              (1<<3)  /* prevent process from being swapped */
#define ON_NO_LISTEN                (1<<4)  /* don't listen on port 8889 */
#define ON_BACKGROUND               (1<<5)  /* run in daemon mode */
#define ON_EJECT_WHEN_FULL          (1<<6)  /* eject nonsharing clients when full */
#define ON_IRC_CHANNELS             (1<<7)  /* irc-style channels */
#define ON_LOGLEVEL_CHANGE          (1<<8)  /* log level changes to clients */
#define ON_REMOTE_BROWSE            (1<<9)  /* allow server->server browsing */
#define ON_AUTO_LINK                (1<<10) /* auto-link servers */
#define ON_GHOST_KILL               (1<<11) /* enable auto ghost kill */
#define ON_ALLOW_SHARE              (1<<12) /* allow file sharing */
#define ON_REMOTE_CONFIG            (1<<13) /* is remote configuration allowed ? */
#define ON_IGNORE_SUFFIX            (1<<14) /* ignore file suffix when indexing? */
#define ON_RESTRICT_REGISTRATION    (1<<15) /* disallow auto client registration */
#define ON_LOG_STDOUT               (1<<16) /* output the log to disk? */
#define ON_EJECT_LEECHES            (1<<17) /* eject leeches? */
#define ON_EJECT_ALSO_BANS          (1<<18) 
#define ON_EJECT_NOCHANNELS         (1<<19) 
#define ON_NOTIFY_MOD_ABUSE         (1<<20)
#define ON_NOTIFY_USER_ABUSE        (1<<21)
#define ON_BREAK_MX_QUEUE           (1<<22)
#define ON_DISCIPLINE_IGNORERS      (1<<23)
#define ON_DISCIPLINE_BLOCK         (1<<24)
#define ON_DISCIPLINE_BLOCK_MOD     (1<<25)
#define ON_NOTIFY_MOD_BLOCK         (1<<26)
#define ON_BROWSE_NAG               (1<<27)
#define ON_NO_MOD_ANNOYING          (1<<28)
#define ON_ALLOW_DYNAMIC_GHOSTS     (1<<29)

extern char Buf[2048];
extern BlockHeap *user_heap;
extern BlockHeap *useropt_heap;
extern BlockHeap *destroy_list_heap;
extern BlockHeap *userdb_heap;

extern char *Levels[LEVEL_ELITE + 1];
extern char *Content_Types[CT_UNKNOWN];
extern char *User_Flags[];

#define set_tag(b,n) set_val(b+2,n)
#define set_len set_val
void    set_val (char *d, unsigned short val);

/* message types */
/* MSG_CLIENT_* are messages sent by the client to the server
MSG_SERVER_* are messages sent by the server to the client

note that in some cases CLIENT messages are sent to peer servers
by the receiving server */

#define MSG_SERVER_ERROR                    0
#define MSG_CLIENT_LOGIN                    2
#define MSG_SERVER_EMAIL                    3
#define MSG_CLIENT_VERSION_CHECK            4
#define MSG_CLIENT_LOGIN_REGISTER           6
#define MSG_CLIENT_REGISTER                 7
#define MSG_SERVER_REGISTER_OK              8
#define MSG_SERVER_REGISTER_FAIL            9
#define MSG_SERVER_BAD_NICK                 10
#define MSG_CLIENT_CHECK_PASS               11
#define MSG_SERVER_PASS_OK                  12
#define MSG_SERVER_ECHO                     13
#define MSG_CLIENT_REGISTRATION_INFO        14
#define MSG_CLIENT_ADD_FILE                 100
#define MSG_CLIENT_REMOVE_FILE              102
#define MSG_CLIENT_UNSHARE_ALL              110
#define MSG_CLIENT_SEARCH                   200
#define MSG_SERVER_SEARCH_RESULT            201
#define MSG_SERVER_SEARCH_END               202
#define MSG_CLIENT_DOWNLOAD                 203
#define MSG_SERVER_FILE_READY               204
#define MSG_CLIENT_PRIVMSG                  205
#define MSG_SERVER_SEND_ERROR               206
#define MSG_CLIENT_ADD_HOTLIST              207
#define MSG_CLIENT_ADD_HOTLIST_SEQ          208
#define MSG_SERVER_USER_SIGNON              209
#define MSG_SERVER_USER_SIGNOFF             210
#define MSG_CLIENT_BROWSE                   211
#define MSG_SERVER_BROWSE_RESPONSE          212
#define MSG_SERVER_BROWSE_END               213
#define MSG_SERVER_STATS                    214
#define MSG_CLIENT_RESUME_REQUEST           215
#define MSG_SERVER_RESUME_MATCH             216
#define MSG_SERVER_RESUME_MATCH_END         217
#define MSG_CLIENT_DOWNLOAD_START           218
#define MSG_CLIENT_DOWNLOAD_END             219
#define MSG_CLIENT_UPLOAD_START             220
#define MSG_CLIENT_UPLOAD_END               221
#define MSG_CLIENT_CHECK_PORT               300
#define MSG_SERVER_HOTLIST_ACK              301
#define MSG_SERVER_HOTLIST_ERROR            302
#define MSG_CLIENT_REMOVE_HOTLIST           303
#define MSG_SERVER_DISCONNECTING            316
#define MSG_CLIENT_IGNORE_LIST              320
#define MSG_SERVER_IGNORE_ENTRY             321
#define MSG_CLIENT_IGNORE_USER              322
#define MSG_CLIENT_UNIGNORE_USER            323
#define MSG_SERVER_NOT_IGNORED              324
#define MSG_SERVER_ALREADY_IGNORED          325
#define MSG_CLIENT_CLEAR_IGNORE             326
#define MSG_CLIENT_JOIN                     400
#define MSG_CLIENT_PART                     401
#define MSG_CLIENT_PUBLIC                   402
#define MSG_SERVER_PUBLIC                   403
#define MSG_SERVER_NOSUCH                   404
#define MSG_SERVER_JOIN_ACK                 405
#define MSG_SERVER_JOIN                     406
#define MSG_SERVER_PART                     407
#define MSG_SERVER_CHANNEL_USER_LIST        408 /* list of users in a channel */
#define MSG_SERVER_CHANNEL_USER_LIST_END    409
#define MSG_SERVER_TOPIC                    410 /* server and client */
#define MSG_CLIENT_CHANNEL_BAN_LIST         420
#define MSG_SERVER_CHANNEL_BAN_LIST         421
#define MSG_CLIENT_CHANNEL_BAN              422
#define MSG_CLIENT_CHANNEL_UNBAN            423
#define MSG_CLIENT_CHANNEL_CLEAR_BANS       424
#define MSG_CLIENT_DOWNLOAD_FIREWALL        500
#define MSG_SERVER_UPLOAD_FIREWALL          501
#define MSG_CLIENT_USERSPEED                600
#define MSG_SERVER_USER_SPEED               601
#define MSG_CLIENT_WHOIS                    603 /* whois query */
#define MSG_SERVER_WHOIS_RESPONSE           604
#define MSG_SERVER_WHOWAS                   605
#define MSG_CLIENT_SETUSERLEVEL             606
#define MSG_SERVER_UPLOAD_REQUEST           607
#define MSG_CLIENT_UPLOAD_OK                608
#define MSG_CLIENT_ACCEPT_FAILED            609     /* added leodav */
#define MSG_CLIENT_KILL                     610
#define MSG_CLIENT_NUKE                     611
#define MSG_CLIENT_BAN                      612
#define MSG_CLIENT_ALTER_PORT               613
#define MSG_CLIENT_UNBAN                    614
#define MSG_CLIENT_BANLIST                  615
#define MSG_SERVER_IP_BANLIST               616
#define MSG_CLIENT_LIST_CHANNELS            617
#define MSG_SERVER_CHANNEL_LIST_END         617
#define MSG_SERVER_CHANNEL_LIST             618
#define MSG_CLIENT_LIMIT                    619
#define MSG_SERVER_LIMIT                    620
#define MSG_CLIENT_MOTD                     621 /* client request for motd */
#define MSG_SERVER_MOTD                     621
#define MSG_CLIENT_MUZZLE                   622
#define MSG_CLIENT_UNMUZZLE                 623
#define MSG_CLIENT_UNNUKE                   624
#define MSG_CLIENT_ALTER_SPEED              625
#define MSG_CLIENT_DATA_PORT_ERROR          626
#define MSG_SERVER_DATA_PORT_ERROR          626 /* same as client message */
#define MSG_CLIENT_WALLOP                   627
#define MSG_SERVER_WALLOP                   627 /* same as client message */
#define MSG_CLIENT_ANNOUNCE                 628
#define MSG_SERVER_ANNOUNCE                 628 /* same as client message */
#define MSG_SERVER_NICK_BANLIST             629
#define MSG_CLIENT_BROWSE_DIRECT            640
#define MSG_SERVER_BROWSE_DIRECT_OK         641
#define MSG_SERVER_BROWSE_DIRECT_ERR        642
#define MSG_CLIENT_CLOAK                    652
#define MSG_CLIENT_CHANGE_SPEED             700
#define MSG_CLIENT_CHANGE_PASS              701
#define MSG_CLIENT_CHANGE_EMAIL             702
#define MSG_CLIENT_CHANGE_DATA_PORT         703
#define MSG_SERVER_GHOST                    748
#define MSG_CLIENT_PING_SERVER              750
#define MSG_CLIENT_PING                     751
#define MSG_SERVER_PING                     751
#define MSG_CLIENT_PONG                     752
#define MSG_SERVER_PONG                     752
#define MSG_CLIENT_ALTER_PASS               753 /* admin pass change */
#define MSG_CLIENT_SERVER_RECONFIG          800
#define MSG_CLIENT_SERVER_VERSION           801
#define MSG_CLIENT_SERVER_CONFIG            810
#define MSG_CLIENT_CLEAR_CHANNEL            820
#define MSG_CLIENT_REDIRECT                 821
#define MSG_CLIENT_CYCLE                    822
#define MSG_CLIENT_SET_CHAN_LEVEL           823
#define MSG_CLIENT_EMOTE                    824
#define MSG_SERVER_NAMES_LIST               825
#define MSG_CLIENT_CHANNEL_LIMIT            826
#define MSG_CLIENT_FULL_CHANNEL_LIST        827
#define MSG_SERVER_FULL_CHANNEL_INFO        828
#define MSG_CLIENT_KICK                     829
#define MSG_SERVER_NAMES_LIST_END           830
#define MSG_CLIENT_NAMES_LIST               830
#define MSG_CLIENT_GLOBAL_USER_LIST         831
#define MSG_SERVER_GLOBAL_USER_LIST         832
#define MSG_CLIENT_ADD_DIRECTORY            870

/* non-standard message unique to this server */
#define MSG_CLIENT_ADD_SERVER           9998
#define MSG_CLIENT_LIST_SERVER          9999
#define MSG_CLIENT_QUIT                 10000   /* user has quit */
#define MSG_SERVER_LOGIN                10010   /* server login request */
#define MSG_SERVER_LOGIN_ACK            10011   /* server login response */
#define MSG_SERVER_USER_SHARING         10012
#define MSG_SERVER_USER_IP              10013   /* deprecated, ip for user */
#define MSG_SERVER_REGINFO              10014   /* registration info */
#define MSG_SERVER_REMOTE_SEARCH        10015
#define MSG_SERVER_REMOTE_SEARCH_RESULT 10016
#define MSG_SERVER_REMOTE_SEARCH_END    10017
#define MSG_SERVER_ENCAPSULATED         10018
#define MSG_SERVER_LINK_INFO            10019
#define MSG_SERVER_QUIT                 10020
#define MSG_SERVER_NOTIFY_MODS          10021
#define MSG_SERVER_SERVER_PONG          10022   /* server->server pong */
#define MSG_SERVER_TIME_CHECK           10023   /* server time check */
#define MSG_SERVER_WHOIS_NOTIFY         10024
#define MSG_CLIENT_USERFLAGS            10050   /* changing of userflags */
#define MSG_CLIENT_CONNECT              10100
#define MSG_CLIENT_DISCONNECT           10101
#define MSG_CLIENT_KILL_SERVER          10110
#define MSG_CLIENT_REMOVE_SERVER        10111
#define MSG_CLIENT_LINKS                10112
#define MSG_SERVER_LINKS                10112
#define MSG_CLIENT_USAGE_STATS          10115   /* server usage stats */
#define MSG_SERVER_USAGE_STATS          10115
#define MSG_SERVER_SEARCH_STATS         10116   /* Show search cache stats */
#define MSG_CLIENT_REHASH               10117   /* reload config file */
#define MSG_CLIENT_VERSION_STATS        10118   /* client version stats */
#define MSG_CLIENT_WHICH_SERVER         10119   /* which server a user is on */
#define MSG_CLIENT_PING_ALL_SERVERS     10120
#define MSG_CLIENT_WHO_WAS              10121
#define MSG_CLIENT_MASS_KILL            10122
#define MSG_CLIENT_HISTOGRAM            10123   /* request/response show incoming stats */
#define MSG_SERVER_HISTOGRAM            10124   /* end of response on 10123 */
#define MSG_CLIENT_SHISTOGRAM           10125   /* request/response show outgoing stats */
#define MSG_SERVER_SHISTOGRAM           10126   /* end of response on 10125 */
#define MSG_CLIENT_REGISTER_USER        10200
#define MSG_CLIENT_CHANNEL_LEVEL        10201   /* deprecated, use 823 instead */
#define MSG_CLIENT_KICK_USER            10202   /* deprecated, use 829 instead */
#define MSG_CLIENT_USER_MODE            10203   /* set a user mode */
#define MSG_SERVER_USER_MODE            10203
#define MSG_CLIENT_OP                   10204
#define MSG_CLIENT_DEOP                 10205
#define MSG_CLIENT_OP_LIST              10206
#define MSG_CLIENT_DROP_CHANNEL         10207
#define MSG_CLIENT_CHANNEL_WALLOP       10208
#define MSG_CLIENT_CHANNEL_MODE         10209
#define MSG_CLIENT_CHANNEL_INVITE       10210
#define MSG_CLIENT_CHANNEL_VOICE        10211
#define MSG_CLIENT_CHANNEL_UNVOICE      10212
#define MSG_CLIENT_CHANNEL_MUZZLE       10213
#define MSG_CLIENT_CHANNEL_UNMUZZLE     10214
#define MSG_CLIENT_CLASS_ADD            10250
#define MSG_CLIENT_CLASS_DEL            10251
#define MSG_CLIENT_CLASS_LIST           10252
#define MSG_CLIENT_DLINE_ADD            10253
#define MSG_CLIENT_DLINE_DEL            10254
#define MSG_CLIENT_DLINE_LIST           10255
#define MSG_CLIENT_ILINE_ADD            10256
#define MSG_CLIENT_ILINE_DEL            10257
#define MSG_CLIENT_ILINE_LIST           10258
#define MSG_CLIENT_ELINE_ADD            10259
#define MSG_CLIENT_ELINE_DEL            10260
#define MSG_CLIENT_ELINE_LIST           10261
#define MSG_SERVER_SYNC_END             10262  /* server sends this at the end of syncing with another server - informational only */
#define MSG_SERVER_SYNC_END_ACK         10263  /* server responds to above with this */
#define MSG_CLIENT_LOG_LEVEL            10264  /* change log_level */

#define MSG_CLIENT_SHARE_FILE           10300   /* generic media type */
#define MSG_CLIENT_BROWSE_NEW           10301
#define MSG_SERVER_BROWSE_RESULT_NEW    10302
/* Added by winter_mute */
#ifdef USE_PROTNET
#   define MSG_CLIENT_RESYNC_USER          10303   /* resync user */
#   define MSG_CLIENT_DESYNC_USER          10304   /* desync user */
#endif

/* utility routines */

#if HAVE_POLL
    void    remove_fd(SOCKET fd);
#endif

int     acl_connection_allowed(unsigned int);
void    acl_init(void);
void    acl_destroy(void);
void    acl_save(void);
void    acl_sync(CONNECTION *);
int     add_client(CONNECTION *, int is_server);
void    add_fd(SOCKET fd);
int     add_timer(int, int, timer_cb_t, void *);
void    add_shist( unsigned int tag, unsigned int len );
char   *append_string(char *in, const char *fmt, ...);
void    auto_link(void);
void    ban_user_internal(CONNECTION *con, char *user, time_t btimeout, char *reason);
int     bind_interface(SOCKET, unsigned int, unsigned short);
BUFFER *buffer_append(BUFFER *, BUFFER *);
BUFFER *buffer_consume(BUFFER *, int);
void    buffer_free(BUFFER *);
int     buffer_size(BUFFER *);
int     buffer_decompress(BUFFER *, z_streamp, char *, int);
int     buffer_validate(BUFFER *);
void    cancel_search(CONNECTION * con);
int     check_ban(CONNECTION *, const char *, const char *);
int     check_class(CONNECTION *, ip_info_t *);
int     check_connect_status(SOCKET);
int     check_pass(const char *info, const char *pass);
int     check_eject_limits( USER *user );
void    cleanup_ip_info(void);
void    clear_read(SOCKET);
void    clear_write(SOCKET);
void    close_db(void);
void    complete_connect(CONNECTION * con);
int     config(int);
void    config_defaults(void);
BAN    *create_ban(char *target, char *issuer, char *reason, time_t starttime, time_t timeout);
USERDB *create_db(USER *);
void    destroy_connection(CONNECTION *);
void    discipline_user(USER *);
int     notify_abuse(CONNECTION *con, USER *user, int tag, int counter, int ignoretag);
void    send_self(CONNECTION * con, USER * user, char *message);
void    dump_channels(void);
void    dump_state(void);
void    eject_internal( CONNECTION *con, USER *user);
void    exec_timers(time_t);
void    expand_hex(char *, int);
void    expire_bans(void);
void    expire_searches(void);
void    expire_whowas(void);
#ifdef WIN32
    SIZE_T  CurrentMemUsage( void );
    SIZE_T  MaxMemUsage( void );
#endif
char   *fake_fgets(char *buf, int max_len, int fd);
int     fake_fputs(const char *buf, int fd);
void    finalize_compress(SERVER *);
#ifdef CSC
    void    finalize_client_compress(USEROPT *);
#endif
CHANNEL        *find_channel(LIST *, const char *);
CHANUSER       *find_chanuser(LIST *, USER *);
server_auth_t  *find_server_auth(const char *);
int     form_message(char *, int, int, const char *, ...);
void    free_ban(BAN *);
void    free_cache(SEARCHCACHE *p);
void    free_channel(CHANNEL *);
void    free_config(void);
void    free_datum(DATUM *);
void    free_pointer(void *);
void    free_server_auth(server_auth_t *);
void    free_timers(void);
void    free_user(USER *);
void    free_whowas(whowas_t *);
char   *generate_nonce(void);
char   *generate_pass(const char *pass);
int     get_level(const char *);
unsigned short get_local_port(SOCKET);
void    get_random_bytes(char *d, int);
char   *get_user(CONNECTION *con, int mode);
int     glob_match(const char *, const char *);
void    handle_connection(CONNECTION *);
void    ibl_expire(void);
int     ibl_check(unsigned int ip);
int     ibl_kill(CONNECTION * con, unsigned int msgtype, const char *fmt, ...);
#ifdef CSC
    int     init_client_compress(CONNECTION *, unsigned int);
#endif
int     init_compress(CONNECTION *, int);
int     init_db(void);
void    init_random(void);
int     init_server(void);
int     invalid_channel(const char *);
void    invalid_channel_msg(CONNECTION *);
/* Added by winter_mute */
#ifdef USE_INVALID_CLIENTS
    int     invalid_client(const char *s);
#endif
int     invalid_host(const char *);
int     invalid_nick(const char *);
void    invalid_nick_msg(CONNECTION *);
void    TagCountFree(tag_count_t *info);
void    ip_info_free(ip_info_t *);
int     is_address(char *, unsigned int *, unsigned int *);
int     is_blocked(char *);
int     is_chanop(CHANNEL *, USER *);
int     is_filtered(char *);
int     filter_dump(void);
int     is_ignoring(LIST *, const char *);
int     is_linked(const char *);
int     is_server(const char *);
void    kill_user_internal(CONNECTION *, USER *, const char *, USER *,const char *, ...);
void    kill_client(CONNECTION * con, const char *user, const char *reason);
void    lag_detect(void *);
int     load_bans(void);
void    load_block(void);
void    load_channels(void);
int     load_class(void);
void    load_filter(void);
void    load_server_auth(void);
void    log_message(const char *fmt, ...);
void    log_message_level(int level, const char *fmt, ...);
unsigned int lookup_ip(const char *host);
SOCKET     make_tcp_connection(const char *host, unsigned short port, unsigned int *ip);
void    motd_init(void);
void    motd_close(void);
char   *my_ntoa(unsigned int);
CHANNEL *new_channel(void);
CONNECTION *new_connection(void);
SOCKET     new_tcp_socket(int);
char   *next_arg(char **);
char   *next_arg_noskip(char **);
time_t  next_timer(void);
char   *normalize_ban(char *, char *, int);
void    nosuchuser(CONNECTION *);
void    nosuchchannel(CONNECTION *);
void    notify_mods(unsigned int, const char *, ...);
void    notify_ops(CHANNEL *, const char *, ...);
void    part_channel(CHANNEL *, USER *);
void    pass_message(CONNECTION *, char *, size_t);
void    pass_message_args(CONNECTION * con, unsigned int msgtype, const char *fmt, ...);
void    permission_denied(CONNECTION * con);
int     pop_user(CONNECTION * con, char **pkt, USER ** user);
int     pop_user_server(CONNECTION * con, int tag, char **pkt, char **nick, USER ** user);
void    print_args(int, char **);
char   *print_size(char *str, int strlen, double bytes);
void    queue_data(CONNECTION *, char *, int);
void    reload_config(void);
void    cycle_files(void);
void    remove_connection(CONNECTION *);
void    remove_links(const char *);
void    remove_user(CONNECTION *);
#ifdef USE_PROTNET
    void    resync_user(USER * user, CONNECTION * con);
#endif
int     safe_realloc(void **, int);
int     save_bans(void);
int     save_class(void);
SEARCHCACHE *seek_and_create_cache_entry(char *search);
SEARCHCACHE *seek_cache_entry(char *search);
void    send_all_clients(int, const char *, ...);
void    send_cmd(CONNECTION *, unsigned int msgtype, const char *fmt, ...);
void    send_cmd_pre(CONNECTION *, unsigned int msgtype, const char *pre, const char *fmt, ...);
int     send_queued_data(CONNECTION * con);
int     send_to_channel(char *, char *, int);
void    send_user(USER *, int, char *fmt, ...);
int     set_keepalive(SOCKET, int);
int     set_data_size(int);
/*void    set_fd(int, int);*/
int     set_max_connections(int);
int     set_nonblocking(SOCKET);
void    set_read(SOCKET);
int     set_rss_size(int);
int     set_tcp_buffer_len(SOCKET, int);
void    set_write(SOCKET);
int     split_line(char **template, int templatecount, char *pkt);
char   *split_filename(char *fqfn);
void    stat_server_push(void);
void    stat_server_read(void);
char   *strfcpy(char *, const char *, size_t);
char   *strlower(char *);
#ifndef HAVE_STRSEP
    char   *strsep(char **pp, const char *delim);
#endif
void    sync_channel_bans(CONNECTION *, CHANNEL *);
void    sync_channel_user(CONNECTION *, CHANNEL *, CHANUSER *);
void    synch_server(CONNECTION *);
char   *tag2hrf(int tag);
void    timer_set_interval(unsigned int, int);
LIST   *tokenize(char *, LIST **);
void    truncate_reason(char *);
void    unparsable(CONNECTION *);
void    unshare_all_internal(USER *);
int     userdb_dump(void);
int     userdb_init(void);
void    userdb_free(USERDB *);
void    logmode_change(char *, char *, int, int);
unsigned int set_usermode (char *, unsigned int);
void    config_user_level(char *);
void zap_local_user(CONNECTION * con, const char *reason);

#ifdef CSC
    void buf_print(char *s, size_t ssize, char *reason );
#endif

#ifdef HAVE_LIBPTHREAD
    void ProxyCheck( USER *user);
#endif

#if ONAP_DEBUG
    int     validate_user(USER *);
    int     validate_channel(CHANNEL *);
    int     validate_connection(CONNECTION *);
    int     validate_flist(FileList *);
#endif
#ifdef WIN32
    char    *win32_strerror(int WSAErr);
#endif

#define HANDLER(f) void f (CONNECTION *con, unsigned short tag, u_short len, char *pkt)
/* this is not a real handler, but has the same arguments as one */
HANDLER(dispatch_command);

/* protocol handlers */
HANDLER(accept_failed);
HANDLER(add_class);
HANDLER(add_file);
HANDLER(add_directory);
HANDLER(add_hotlist);
HANDLER(add_server);
HANDLER(alter_pass);
HANDLER(alter_port);
HANDLER(alter_speed);
HANDLER(announce);
HANDLER(ban);
HANDLER(banlist);
HANDLER(browse);
HANDLER(browse_direct);
HANDLER(browse_direct_ok);
HANDLER(browse_new);
HANDLER(change_data_port);
HANDLER(change_email);
HANDLER(change_speed);
HANDLER(change_pass);
HANDLER(change_userflags);
HANDLER(channel_ban);
HANDLER(channel_banlist);
HANDLER(channel_clear_bans);
HANDLER(channel_invite);
HANDLER(channel_level);
HANDLER(channel_limit);
HANDLER(channel_mode);
HANDLER(channel_muzzle);
HANDLER(channel_op);
HANDLER(channel_unban);
HANDLER(channel_wallop);
HANDLER(check_password);
HANDLER(class_list);
HANDLER(clear_channel);
HANDLER(clear_ignore);
HANDLER(client_quit);
HANDLER(client_version_stats);
HANDLER(cloak);
HANDLER(cycle_client);
HANDLER(data_port_error);
HANDLER(download);
HANDLER(download_end);
HANDLER(download_start);
HANDLER(emote);
HANDLER(encapsulated);
HANDLER(full_channel_list);
HANDLER(generic_acl_add);
HANDLER(generic_acl_del);
HANDLER(generic_acl_list);
HANDLER(global_user_list);
HANDLER(ignore);
HANDLER(ignore_command);
HANDLER(ignore_list);
HANDLER(join);
HANDLER(kick);
HANDLER(kill_user);
HANDLER(kill_server);
HANDLER(level);
HANDLER(link_info);
HANDLER(list_channels);
HANDLER(list_users);
HANDLER(list_server);
HANDLER(login);
HANDLER(mass_kill);
HANDLER(muzzle);
HANDLER(nuke);
HANDLER(part);
HANDLER(ping);
HANDLER(ping_all_servers);
HANDLER(ping_server);
HANDLER(privmsg);
HANDLER(public);
HANDLER(queue_limit);
HANDLER(redirect_client);
HANDLER(reginfo);
HANDLER(register_nick);
HANDLER(register_user);
HANDLER(rehash);
HANDLER(remote_notify_mods);
HANDLER(remote_search);
HANDLER(remote_search_result);
HANDLER(remote_search_end);
HANDLER(remove_file);
HANDLER(remove_hotlist);
HANDLER(remove_server);
HANDLER(resume);
HANDLER(search);
HANDLER(search_cache_stats);
HANDLER(server_config);
HANDLER(server_connect);
HANDLER(server_disconnect);
HANDLER(server_error);
HANDLER(server_links);
HANDLER(server_login);
HANDLER(server_login_ack);
HANDLER(server_pong);
HANDLER(server_reconfig);
HANDLER(server_stats);
HANDLER(server_usage);
HANDLER(server_version);
HANDLER(share_file);
HANDLER(show_motd);
HANDLER(upload_ok);
HANDLER(upload_start);
HANDLER(upload_end);
HANDLER(time_check);
HANDLER(topic);
HANDLER(unban);
HANDLER(unignore);
HANDLER(unnuke);
HANDLER(unshare_all);
HANDLER(upload_request);
HANDLER(user_ip);
HANDLER(user_sharing);
HANDLER(user_speed);
HANDLER(wallop);
HANDLER(whois);
HANDLER(user_mode_cmd);
HANDLER(which_server);
HANDLER(who_was);
HANDLER(whois_notify);
HANDLER(server_sync_end);
HANDLER(server_sync_end_ack);
HANDLER(log_level_cmd);
/* Added by winter_mute */
#ifdef USE_PROTNET
    HANDLER(my_resync_user);
    HANDLER(desync_user);
#endif

#define CHECK_USER_CLASS(f) if(con->class != CLASS_USER) { log_message ("%s: not USER class", f); return; }
#define CHECK_SERVER_CLASS(f) if(con->class != CLASS_SERVER) { log_message ("%s: not SERVER class", f); return; }

#define NONULL(p) (p!=0?p:"")

#ifndef HAVE_SOCKLEN_T
#   ifdef __sun__
/* solaris 2.6 uses a signed int for the 4th arg to accept() */
        typedef int socklen_t;
#   else
#       ifndef __CYGWIN__
            typedef unsigned int socklen_t;
#       endif
#   endif
#endif

#ifdef __sun__
#   define SOCKOPTCAST (char*)
#elif !defined SOCKOPTCAST
#   define SOCKOPTCAST
#endif /* __sun__ */

/* fast, inlined strcmp (only if using GCC) */
#ifdef __GNUC__
#   define strcmpfast(s1,s2) ({ \
    int     _result = 0; \
    char   *_s1; \
    char   *_s2; \
    _s1 = (s1); \
    _s2 = (s2); \
    while (*_s1) { \
    if(*_s1++ != *_s2++) { \
    _result = 1; \
    break; \
    } \
    } \
    _result; })
#else /* Standard strcmp if not using GCC */
#   define strcmpfast(s1, s2) strcmp(s1, s2)
#endif

/*
** Macros to use to aid in porting code to Win32
*/
#ifndef WIN32
#   define READ read
#   define WRITE write
#   define CLOSE close
/* use N_ERRNO instead of `errno' when checking the error code for network
related functions */
#   define N_ERRNO errno
/* log message for errors with socket related system calls */
#   define nlogerr logerr

#else

/* winsock uses h_errno so we have to wrap the test for it here */
#   define N_ERRNO h_errno
#   define nlogerr(f,s) _logerr(f,s,h_errno)

#endif /* !WIN32 */

#define ERROR_MODE      (1<<0)
#define BANLOG_MODE     (1<<1)
#define CHANGELOG_MODE  (1<<2)
#define KILLLOG_MODE    (1<<3)
#define LEVELLOG_MODE   (1<<4)
#define SERVERLOG_MODE  (1<<5)
#define MUZZLELOG_MODE  (1<<6)
#define PORTLOG_MODE    (1<<7)
#define WALLOPLOG_MODE  (1<<8)
#define CLOAKLOG_MODE   (1<<9)
#define FLOODLOG_MODE   (1<<10)
#define PINGLOG_MODE    (1<<11)
#define MSGLOG_MODE     (1<<12)
#define WHOISLOG_MODE   (1<<13)
#define ABUSE_MODE      (1<<14)

#define LOGALL_MODE (ERROR_MODE|BANLOG_MODE|CHANGELOG_MODE|\
    KILLLOG_MODE|LEVELLOG_MODE|SERVERLOG_MODE|MUZZLELOG_MODE|PORTLOG_MODE|\
    WALLOPLOG_MODE|CLOAKLOG_MODE|FLOODLOG_MODE|PINGLOG_MODE|MSGLOG_MODE|\
    WHOISLOG_MODE|ABUSE_MODE)

#endif /* opennap_h */
