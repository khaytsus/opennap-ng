/* Copyright(C) 2000-1 drscholl@users.sourceforge.net
This is free software distributed under the terms of the
GNU Public License.  See the file COPYING for details.

$Id: main.c 435 2006-09-03 18:57:03Z reech $ */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <sys/stat.h>
#ifdef HAVE_SYS_RESOURCE_H
# include <sys/resource.h>
#endif
#include <ctype.h>

#ifndef WIN32
# include <sys/types.h>
# include <sys/stat.h>
# include <fcntl.h>
# include <errno.h>
# include <unistd.h>
# include <sys/socket.h>
# include <netinet/in.h>
# include <arpa/inet.h>
# include <string.h>
# include <sys/time.h>
# include <limits.h>
#endif /* !WIN32 */

#include "opennap.h"
#include "debug.h"

#if ONAP_DEBUG
# define dprint0(a)      printf(a);
# define dprint1(a,b)    printf(a,b);
#else
# define dprint0(a)
# define dprint1(a,b)
#endif

#define CLICK FD_SETSIZE /* 64 */

/* offset into global.poll[] for the given file descriptor */
#define POFF(fd)    global.fdmap[fd]

#if defined(WIN32) && !defined(CYGWIN)
# define SOFT_ERROR(e)  ((e) == WSAEINTR || \
	(e) == WSAEWOULDBLOCK || \
	(e) == EWOULDBLOCK || \
	(e) == EINTR || \
	(e) == EAGAIN || \
	(e) == 0)

#else
# define SOFT_ERROR(e)  ((e) == EINTR || \
	(e) == EWOULDBLOCK || \
	(e) == EAGAIN || \
	(e) == 0)
#endif

/*
* Global Variables
*/

GLOBAL global;

BlockHeap *user_heap;
BlockHeap *useropt_heap;
BlockHeap *destroy_list_heap;
BlockHeap *userdb_heap;

char    Buf[2048];      /* global scratch buffer */

stats_t stats;

/*
* setup_corefile
*
* inputs       - nothing
* output       - nothing
* side effects - setups corefile to system limits.
* -kre
*
* this code is from ircd-ratbox - reech
*/
static void setup_corefile(void)
{
#ifdef HAVE_SYS_RESOURCE_H
	struct rlimit rlim;     /* resource limits */

	/* Set corefilesize to maximum */
	if(!getrlimit(RLIMIT_CORE, &rlim))
	{
		rlim.rlim_cur = rlim.rlim_max;
		setrlimit(RLIMIT_CORE, &rlim);
	}
#endif
}

void set_write(SOCKET fd)
{
#if HAVE_POLL
	global.poll[POFF(fd)].events |= POLLOUT;
#else
	FD_SET(fd, &global.write_fds);
#endif
}

void clear_write(SOCKET fd)
{
#if HAVE_POLL
	global.poll[POFF(fd)].events &= ~POLLOUT;
#else
	FD_CLR(fd, &global.write_fds);
#endif
}

void set_read(SOCKET fd)
{
#if HAVE_POLL
	global.poll[POFF(fd)].events |= POLLIN;
#else
	FD_SET(fd, &global.read_fds);
#endif
}

void clear_read(SOCKET fd)
{
#if HAVE_POLL
	global.poll[POFF(fd)].events &= ~POLLIN;
#else
	FD_CLR(fd, &global.read_fds);
#endif
}


void add_fd(SOCKET fd)
{
#if HAVE_POLL
	int     off;

	if(global.poll_max == global.poll_num)
	{
		global.poll_max += CLICK;
		global.poll = REALLOC(global.poll, sizeof(struct pollfd) * global.poll_max);
		for(off = global.poll_num; off < global.poll_max; off++)
		{
			global.poll[off].fd = INVALID_SOCKET;
			global.poll[off].events = 0;
			global.poll[off].revents = 0;
		}
	}
#endif

	/* keep track of the biggest fd we've seen */
	if(fd > global.max_fd)
	{
#if HAVE_POLL
		global.fdmap = REALLOC(global.fdmap, sizeof(int) *(fd + 1));

		for(off = global.max_fd + 1; off < fd + 1; off++)
			global.fdmap[off] = INVALID_SOCKET;
#endif
		global.max_fd = fd;
	}

#if HAVE_POLL
	off = global.fdmap[fd] = global.poll_num++;

	global.poll[off].fd = fd;
	global.poll[off].events = 0;
	global.poll[off].revents = 0;
#endif
}

#if HAVE_POLL
void remove_fd(SOCKET fd)
{
	if(fd == INVALID_SOCKET)
	{
		ASSERT(0);
		return;
	}

	if(global.fdmap[fd] == INVALID_SOCKET)
	{
		ASSERT(0);
		return;
	}

	if(global.fdmap[fd] < global.poll_num - 1)
	{
		/* swap with the last client */
		int     i = global.poll[global.poll_num - 1].fd;

		ASSERT(i != -1);
		ASSERT(global.poll[POFF(fd)].fd == fd);
		ASSERT(global.poll[POFF(i)].fd == i);

		memcpy(&global.poll[POFF(fd)], &global.poll[POFF(i)], sizeof(struct pollfd));
		global.fdmap[i] = POFF(fd);
	}

	/* mark as unused */
	global.fdmap[fd] = INVALID_SOCKET;
	global.poll_num--;

	/* reset the pollfd struct */
	global.poll[global.poll_num].fd = INVALID_SOCKET;
	global.poll[global.poll_num].events = 0;
	global.poll[global.poll_num].revents = 0;
}
#endif /* HAVE_POLL */

int add_client(CONNECTION * con, int is_server)
{
	/* allocate more space if required */
	if(global.clients_max == global.clients_num)
	{
		global.clients_max += CLICK;
		global.clients = REALLOC(global.clients, sizeof(CONNECTION *) * global.clients_max);
	}
	con->id = global.clients_num++;
	global.clients[con->id] = con;

	add_fd(con->fd);

	con->class = CLASS_UNKNOWN;
	con->timer = global.current_time;   /* set a login timer */

	set_nonblocking(con->fd);
	set_keepalive(con->fd, 1); /* enable tcp keepalive messages */

	if(is_server)
	{
		/* we are doing a non-blocking connect, wait for the socket to become
		* writable
		*/
		con->connecting = 1;
		set_write(con->fd);
	}
	else
	{
		/* user connection, wait for some input */
		set_read(con->fd);
	}
	return 0;
}

void send_all_clients(int tag, const char *fmt, ...)
{
	va_list ap;
	unsigned short     len;
	int     i;

	va_start(ap, fmt);
	vsnprintf(Buf + 4, sizeof(Buf) - 4, fmt, ap);
	va_end(ap);
	len = strlen(Buf + 4);
	set_tag(Buf, tag);
	set_len(Buf, len);
	len += 4;
	for(i = 0; i < global.clients_num; i++)
		if(ISUSER(global.clients[i])) 
		{
			queue_data(global.clients[i], Buf, len);
		}
}

#ifndef ROUTING_ONLY

static void report_stats(SOCKET fd)
{
	SOCKET    n;
	struct    sockaddr_in sin;
	socklen_t sinsize = sizeof(sin);

	n = accept(fd,(struct sockaddr *) &sin, &sinsize);
	if(n == INVALID_SOCKET)
	{
		nlogerr("report_stats", "accept");
		return;
	}
	log_message_level(LOG_LEVEL_STATS, "report_stats: connection from %s:%d", inet_ntoa(sin.sin_addr), htons(sin.sin_port));

	snprintf(Buf, sizeof(Buf), "%d %d %0.2f %.0f %d\n", global.usersHash->dbsize, global.fileLibCount, stats.load_avg, global.fileLibSize * 1024., global.clients_num - list_count(global.serversList));

	WRITE(n, Buf, strlen(Buf));
	CLOSE(n);
}
#endif /* ROUTING_ONLY */

static void report_stats2(SOCKET fd)
{
	SOCKET    n;
	int       numServers = list_count(global.serversList);
	struct    sockaddr_in sin;
	socklen_t sinsize = sizeof(sin);
	time_t    delta;

	delta = global.current_time - global.last_click;
	if(0==delta)
		delta = 1;


	n = accept(fd,(struct sockaddr *) &sin, &sinsize);
	if(n == INVALID_SOCKET)
	{
		nlogerr("report_stats", "accept");
		return;
	}
	log_message_level(LOG_LEVEL_STATS, "report_stats: connection from %s:%d", inet_ntoa(sin.sin_addr), htons(sin.sin_port));

	snprintf(Buf, sizeof(Buf), "%d %d %lu %d %d %.0f %d %.0f %d %lu %.0f %lu %lu %lu %d %u\n",
		global.usersHash->dbsize, 
		global.clients_num - numServers, 
#ifdef CSC
		stats.zusers, 
#else
		0,
#endif
		global.fileLibCount,
#ifndef ROUTING_ONLY
		global.localSharedFiles, 
#else
		0,
#endif
		global.total_bytes_out, 
		(int)(global.bytes_out / delta / 1024),  
		global.total_bytes_in, 
		(int)(global.bytes_in / delta / 1024), 
		stats.mem_usage,
		global.fileLibSize,
		stats.connects / delta,
		stats.tags / delta,
		stats.ibl_db,
		global.search_count / delta, 
		Pending_Searches);

	WRITE(n, Buf, strlen(Buf));
	CLOSE(n);
}

static void update_stats(void)
{
	int     numServers = list_count(global.serversList);
	time_t  delta;
	char   *tin, *tout;

#if defined(HAVE_SYS_RESOURCE_H)
	struct rusage rus;
	time_t secs;
#if defined(LINUX)
	int     fd;
	char    path[_POSIX_PATH_MAX];
	char    inbuf[128];
#endif /* LINUX */

#endif /* HAVE_SYS_RESOURCE_H */

	delta = global.current_time - global.last_click;
	if(0==delta)
		delta = 1;

	strcpy(Buf, ctime(&global.serverStartTime));
	Buf[strlen(Buf) - 1] = 0; 
	log_message_level(LOG_LEVEL_STATS, "stats: server was started on %s", Buf);
	strcpy(Buf, ctime(&global.current_time));
	Buf[strlen(Buf) - 1] = 0; 
	log_message_level(LOG_LEVEL_STATS, "stats: current time is %s", Buf);
	log_message_level(LOG_LEVEL_STATS, "stats: library is %d GB, %d files, %d users", (int)(global.fileLibSize / 1048576.), global.fileLibCount, global.usersHash->dbsize);
#ifdef CSC
	log_message_level(LOG_LEVEL_STATS, "stats: %d local clients, %d z-clients, %d linked servers", global.clients_num - numServers, stats.zusers, numServers);
#else
	log_message_level(LOG_LEVEL_STATS, "stats: %d local clients, %d linked servers", global.clients_num - numServers, numServers);
#endif
#ifndef ROUTING_ONLY
	log_message_level(LOG_LEVEL_STATS, "stats: %d local files", global.localSharedFiles);
	log_message_level(LOG_LEVEL_STATS, "stats: File_Table contains %d entries", global.FileHash->dbsize);
	log_message_level(LOG_LEVEL_STATS, "stats: Search Filter contains %d entries", global.filterHash->dbsize);
#endif
	log_message_level(LOG_LEVEL_STATS, "stats: %d searches/sec - %d pending", global.search_count / delta, Pending_Searches);
	log_message_level(LOG_LEVEL_STATS, "stats: User_Db %d, IBL %d, Flooders %d", global.userDbHash ->dbsize, stats.ibl_db, stats.flood_db);
	log_message_level(LOG_LEVEL_STATS, "stats: %d channels", global.channelHash->dbsize);
	log_message_level(LOG_LEVEL_STATS, "stats: %d kbytes/sec in, %d kbytes/sec out", (int)(global.bytes_in / 1024 / delta),  (int)(global.bytes_out / delta / 1024));
	global.total_bytes_in += global.bytes_in;
	global.bytes_in = 0;
	global.total_bytes_out += global.bytes_out;
	global.bytes_out = 0;
	tin = print_size( Buf, sizeof(Buf), global.total_bytes_in );
	tout = print_size( Buf + 16, sizeof(Buf) - 16, global.total_bytes_out );
	log_message_level(LOG_LEVEL_STATS, "stats: %.0f(%s) bytes sent, %.0f(%s) bytes received", global.total_bytes_out, tout, global.total_bytes_in, tin);

#ifdef WIN32
	stats.mem_usage = (unsigned long)CurrentMemUsage() / 1024;
	stats.max_mem_usage = (unsigned long)MaxMemUsage() / 1024;
	log_message_level(LOG_LEVEL_STATS, "stats: %d kB memory used, %d kB max", stats.mem_usage, stats.max_mem_usage);
#elif defined(HAVE_SYS_RESOURCE_H) /* taken from ircd-ratpack - for the mostpart */
	if(getrusage(RUSAGE_SELF, &rus) == -1)
		log_message_level(LOG_LEVEL_STATS, "stats: rusage_error - some stats not available");
	else
	{
		secs = rus.ru_utime.tv_sec + rus.ru_stime.tv_sec;
		if(0 == secs)
			secs = 1;
#ifdef LINUX
		snprintf(path, sizeof(path), "/proc/%d/status", getpid());
		if((fd = open(path, O_RDONLY))==-1) 
		{
			log_message_level(LOG_LEVEL_ERROR, "update_stats: ERROR: can't open %s: %s (erno %d)", path, strerror(errno), errno);
		} 
		else 
		{
			while ((fake_fgets(inbuf,127,fd))!=NULL) 
			{
				if(strncmp("VmSize:", inbuf,7)==0) 
				{
					rus.ru_maxrss = atol(inbuf+7);
					break;
				}

			}
			close(fd);
		}
#endif
		stats.mem_usage = rus.ru_maxrss;
		log_message_level(LOG_LEVEL_STATS, "stats: CPU Secs %d:%02d User %d:%02d System %d:%02d", (int) (secs / 60), (int) (secs % 60), (int) (rus.ru_utime.tv_sec / 60), (int) (rus.ru_utime.tv_sec % 60), (int) (rus.ru_stime.tv_sec / 60), (int) (rus.ru_stime.tv_sec % 60));
		log_message_level(LOG_LEVEL_STATS, "stats: RSS %ld ShMem %ld Data %ld Stack %ld", rus.ru_maxrss, (rus.ru_ixrss / delta), (rus.ru_idrss / delta), (rus.ru_isrss / delta));
		log_message_level(LOG_LEVEL_STATS, "stats: Swaps %d Reclaims %d Faults %d", (int) rus.ru_nswap, (int) rus.ru_minflt, (int) rus.ru_majflt);
		log_message_level(LOG_LEVEL_STATS, "stats: Block in %d out %d", (int) rus.ru_inblock, (int) rus.ru_oublock);
		log_message_level(LOG_LEVEL_STATS, "stats: Msg Rcv %d Send %d", (int) rus.ru_msgrcv, (int) rus.ru_msgsnd);
		log_message_level(LOG_LEVEL_STATS, "stats: Signals %d Context Vol. %d Invol %d", (int) rus.ru_nsignals, (int) rus.ru_nvcsw, (int) rus.ru_nivcsw);
	}
#endif

	log_message_level(LOG_LEVEL_STATS, "stats: %d total logins, %d disconnects", stats.logins, stats.disconnects );
	log_message_level(LOG_LEVEL_STATS, "stats: %d connects(%d/sec)", stats.connects, stats.connects / delta);
	stats.connects = 0;
	log_message_level(LOG_LEVEL_STATS, "stats: %d tags(%d/sec)", stats.tags, stats.tags / delta);
	stats.tags = 0;
	log_message_level(LOG_LEVEL_STATS, "stats: %d connection reset, %d timeouts, %d no route, %d broken pipe", stats.con_104, stats.con_110, stats.con_113, stats.con_032 );
	log_message_level(LOG_LEVEL_STATS, "stats: wrong parameters %d client, %d server", stats.login_ce_params, stats.login_se_params );
	log_message_level(LOG_LEVEL_STATS, "stats: %d auto reg is off, %d already logged in", stats.login_ce_autoreg_off, stats.login_ce_already );
	log_message_level(LOG_LEVEL_STATS, "stats: %d connecting too fast", stats.login_ce_too_fast );
#if ROUTING_ONLY
	log_message_level(LOG_LEVEL_STATS | LOG_LEVEL_SECURITY, "stats: %d error not admin+", stats.login_ce_not_admin );
#endif
	if(stats.login_ce_restricted > 0) 
	{
		log_message_level(LOG_LEVEL_STATS, "stats: %d error server is restricted", stats.login_ce_restricted );
	}
	if(stats.login_ce_nick_already_registered > 0) 
	{
		log_message_level(LOG_LEVEL_STATS, "stats: %d error nick already registered", stats.login_ce_nick_already_registered );
	}
	/*    log_message_level(LOG_LEVEL_STATS, "stats: %d opennap clients banned", stats.login_ce_client_banned ); */
	log_message_level(LOG_LEVEL_STATS, "stats: %d clones detected, %d banned, %d max_connections reached", stats.login_ce_clone, stats.login_ce_banned, stats.login_ce_max_connections );
	log_message_level(LOG_LEVEL_STATS, "stats: login invalid: %d nick, %d client, %d password, %d speed, %d port", stats.login_ce_invalid_nick, stats.login_ce_client_banned, stats.login_ce_password, stats.login_ce_speed, stats.login_ce_port );
	log_message_level(LOG_LEVEL_STATS, "stats: %d searches, %d cancelled, %d expired, %d not found", stats.search_total, stats.search_cancelled, stats.search_expired, stats.search_nosuch );

	/* reset counters */
	global.search_count = 0;
	global.last_click = global.current_time;

	/* since we send the same data to many people, optimize by forming
	the message once then writing it out */
	send_all_clients(MSG_SERVER_STATS, "%d %d %d", global.usersHash->dbsize, global.fileLibCount,(int)(global.fileLibSize / 1048576.));

#ifndef ROUTING_ONLY
	/* send live stats to stat server */
	stat_server_push();
#endif
}

/* accept all pending connections */
static void accept_connection(SOCKET s)
{
	CONNECTION *cli = 0;
	socklen_t   sinsize;
	struct      sockaddr_in sin;
	SOCKET      f;

	for(;;)
	{
		sinsize = sizeof(sin);
#if HAVE_ALARM
		/* set an alarm just in case we end up blocking when a client
		* disconnects before we get to the accept()
		*/
		alarm(3);
#endif
		f = accept(s,(struct sockaddr *) &sin, &sinsize);
		if(f == INVALID_SOCKET)
		{
#if HAVE_ALARM
			alarm(0);
#endif
			if(N_ERRNO != EWOULDBLOCK)
#ifdef WIN32
				log_message_level(LOG_LEVEL_LOGIN, "accept_connection: accept: %s(%d)", win32_strerror(N_ERRNO), N_ERRNO);
#else
				nlogerr("accept_connection", "accept");
#endif
			return;
		}
#if HAVE_ALARM
		alarm(0);
#endif
		// connections are connections to this server
		// count them all (could be a user or another server...)
		stats.connects++;
		if(ibl_check(BSWAP32(sin.sin_addr.s_addr))) 
		{
			CLOSE(f);
			continue;
		}

		if(!acl_connection_allowed(BSWAP32(sin.sin_addr.s_addr)))
		{
			log_message_level(LOG_LEVEL_SECURITY | LOG_LEVEL_ERROR, "accept_connection: connection from %s denied by ACLs", inet_ntoa(sin.sin_addr));
			/*      CLOSE(f); 
			continue;  */
		}
		cli = new_connection();
		if(!cli)
			goto error;
		cli->fd = INVALID_SOCKET;

		/* if we have a local connection, use the external
		interface so others can download from them */
		if(sin.sin_addr.s_addr == inet_addr("127.0.0.1"))
		{
			cli->ip = BSWAP32(global.serverIP);
			cli->host = STRDUP(global.serverName);
		}
		else
		{
			cli->ip = BSWAP32(sin.sin_addr.s_addr);
			cli->host = STRDUP(inet_ntoa(sin.sin_addr));
		}

		if(!cli->host)
		{
			OUTOFMEMORY("accept_connection");
			goto error;
		}

		cli->port = ntohs(sin.sin_port);
		cli->fd = f;

		if(add_client(cli, 0))
			goto error;
	}

	/* not reached */
	ASSERT(0);
	return;
error:
	if(cli)
	{
		if(cli->fd != INVALID_SOCKET)
			CLOSE(cli->fd);
		if(cli->host)
			FREE(cli->host);
		FREE(cli);
	}
	else
		CLOSE(f);
}

static void usage(void)
{
	fprintf(stderr, "usage: %s [ -bhrsv ] [ -c DIR ] [ -e DIR ] [ -p PORT ] [ -l IP ]\n", PACKAGE);
	fprintf(stderr, "  -c DIR  read config files from DIR(default: %s)\n", SHAREDIR);
	fprintf(stderr, "  -e DIR  read log files from DIR(default: %s)\n", VARDIR);
	fprintf(stderr, "  -b      run as a background process(daemon)\n");
	fprintf(stderr, "  -h      print this help message\n");
	fprintf(stderr, "  -l IP   listen only on IP instead of all interfaces\n");
	fprintf(stderr, "  -p PORT listen on PORT for connections(default: 8888)\n");
	fprintf(stderr, "  -r      disable remote configuration commands\n");
	fprintf(stderr, "  -s      channels may only be created by privileged users\n");
	fprintf(stderr, "  -v      display version information\n");
	exit(0);
}

static void version(void)
{
	fprintf(stderr, "%s %s%s%s%s%s%s\n", PACKAGE, VERSION, SUBVERSIONREV,
#ifdef WIN32
		".win32",
#else
		"",
#endif
#ifdef ROUTING_ONLY
		".rt",
#else
		"",
#endif
#ifdef HAVE_POLL
		".poll",
#else
		"",
#endif
#ifdef HAVE_LIBPTHREAD
		".thread"
#else
		""
#endif
		);
	fprintf(stderr, "Copyright(C) 2000-2001 drscholl@users.sourceforge.net\n");
	fprintf(stderr, "Copyright(C) 2002-2005 Whole Opennap-ng Team http://opennap-ng.org\n");
	exit(0);
}

static SOCKET *args(int argc, char **argv, int *sockfdcount)
{
	int     i;
	LIST   *ports = 0, *tmpList;
	int     iface = -1;
	SOCKET *sockfd;
	int     not_root = 1;
	unsigned short     port;
	int     disable_remote = 0;

#ifndef WIN32
	not_root =(getuid() != 0);
#else
	/* set the priority to high */
	/* people are complaining that opennap is "taking over their system"...
	* comment this for now...
	HANDLE proc;
	proc = OpenProcess(  PROCESS_SET_INFORMATION, FALSE, GetCurrentProcessId() );
	if(proc)
	{
	SetPriorityClass( proc, HIGH_PRIORITY_CLASS);
	CloseHandle( proc );
	}
	*/
#endif

	setup_corefile();

	while ((i = getopt(argc, argv, "bc:hl:p:e:rsvD")) != -1)
	{
		switch(i)
		{
		case 'b':
			global.serverFlags |= ON_BACKGROUND;
			break;
		case 'D':
			global.serverFlags |= ON_NO_LISTEN;   /* dont listen on stats port */
			break;
		case 'c':
			/* ignore the command line option if we're running as root.
			* we don't allow non-root users to specify their own config
			* files to avoid possible security problems.
			*/
			if(not_root)
				global.shareDir = optarg;
			else
			{
				/*      log_message_level(LOG_LEVEL_SECURITY | LOG_LEVEL_ERROR, "args: can't use -c when run as root");
				exit(1); */
				global.shareDir = optarg;
			}
			break;
		case 'e':
			/* ignore the command line option if we're running as root.
			* we don't allow non-root users to specify their own config
			* files to avoid possible security problems.
			*/
			if(not_root)
				global.varDir = optarg;
			else
			{
				/*      log_message_level(LOG_LEVEL_SECURITY | LOG_LEVEL_ERROR, "args: can't use -c when run as root");
				exit(1); */
				global.varDir = optarg;
			}
			break;
		case 'l':
			iface = inet_addr(optarg);
			break;
		case 'p':
			/* don't allow a privileged port to be used from the command line
			* if running as root.  this can only be specified in the
			* configuration file defined at compile time.
			*/
			port = (unsigned short)atoi(optarg);
			if(not_root || port > 1024)
			{
				tmpList = CALLOC(1, sizeof(LIST));
				tmpList->data = STRDUP(optarg);
				tmpList->next = ports;
				ports = tmpList;
			}
			else
			{
				log_message_level(LOG_LEVEL_ERROR, "args: privileged ports not allowed on command line");
				exit(1);
			}
			break;
		case 'r':
			disable_remote = 1;
			break;
		case 's':
			global.serverFlags |= ON_STRICT_CHANNELS;
			break;
		case 'v':
			version();
			break;
		default:
			usage();
		}
	}

#if USE_CHROOT
	/* we always use the compiled directory instead of the one on the command
	* line here to avoid problems.
	*/
	if(chroot(SHAREDIR))
	{
		perror("chroot");
		exit(1);
	}
	if(chdir("/"))
	{
		perror("chdir");
		exit(1);
	}
	/* force the config files to be relative to the chroot jail */
	global.shareDir = "/";
	global.varDir = "/";
	/* privs will be dropped later.  we still need them to read the the
	* config file and set resources.
	*/
#endif

#if !defined(WIN32) && !defined(__EMX__)
	/* check whether to run in the background */
	if(global.serverFlags & ON_BACKGROUND)
	{
		if(fork() == 0)
			setsid();
		else
			exit(0);
	}
#endif

	if(init_server())
		exit(1);

	/* if requested, disable remote configuration */
	if(disable_remote)
		global.serverFlags &= ~ON_REMOTE_CONFIG;
	if(!(global.serverFlags & ON_REMOTE_CONFIG))
		log_message_level(LOG_LEVEL_SECURITY, "args: remote configuration disabled");

	/* if the interface was specified on the command line, override the
	* value from the config file
	*/
	if(iface != -1)
	{
		global.iface = iface;
		global.serverIP = iface;
	}

	/* if port(s) were specified on the command line, override the values
	specified in the config file */
	if(!ports)
		ports = global.serverPortList;

	/* create the incoming connections socket(s) */
	*sockfdcount = list_count(ports);
	/* ensure at least one valid port */
	if(*sockfdcount < 1)
	{
		log_message_level(LOG_LEVEL_ERROR, "args: no server ports defined");
		exit(1);
	}
	sockfd = CALLOC(*sockfdcount, sizeof(SOCKET));

	log_message_level(LOG_LEVEL_STATS, "args: listening on %d sockets", *sockfdcount);
	for(i = 0, tmpList = ports; i < *sockfdcount; i++, tmpList = tmpList->next)
	{
		if((sockfd[i] = new_tcp_socket(ON_NONBLOCKING | ON_REUSEADDR)) == INVALID_SOCKET)
			exit(1);
		if(bind_interface(sockfd[i], global.iface, (unsigned short)atoi(tmpList->data)) == -1)
			exit(1);
		if(listen(sockfd[i], SOMAXCONN) < 0)
		{
			nlogerr("args", "listen");
			exit(1);
		}
		log_message_level(LOG_LEVEL_STATS, "args: listening on %s port %d", my_ntoa(global.iface), atoi(tmpList->data));
		if(sockfd[i] > global.max_fd)
			global.max_fd = sockfd[i];
	}
	if(ports != global.serverPortList)
		list_free(ports, free_pointer);
	return sockfd;
}

/* sync in-memory state to disk so we can restore properly */
void dump_state(void)
{
	userdb_dump();     /* write out the user database */
#ifndef ROUTING_ONLY
	save_bans();       /* write out server bans */
	dump_channels();       /* write out persistent channels file */
	acl_save();        /* save acls */
#endif
}

#ifndef ROUTING_ONLY
static SOCKET init_stats_port(void)
{
	SOCKET     sp = INVALID_SOCKET;

	if(!option(ON_NO_LISTEN) && global.statsPort != 0)
	{
		/* listen on port 8889 for stats reporting */
		if((sp = new_tcp_socket(ON_REUSEADDR)) == INVALID_SOCKET)
			exit(1);
		if(bind_interface(sp, global.iface, global.statsPort))
			exit(1);
		if(listen(sp, SOMAXCONN))
		{
			logerr("main", "listen");
			exit(1);
		}
		if(sp > global.max_fd)
			global.max_fd = sp;
	}
	return sp;
}
#endif

static SOCKET init_stats_port2(void)
{
	SOCKET     sp2 = INVALID_SOCKET;

	if(!option(ON_NO_LISTEN) && global.statsPort2 != 0)
	{
		/* listen on port 8889 for stats reporting */
		if((sp2 = new_tcp_socket(ON_REUSEADDR)) == INVALID_SOCKET)
			exit(1);
		if(bind_interface(sp2, global.iface, global.statsPort2))
			exit(1);
		if(listen(sp2, SOMAXCONN))
		{
			logerr("main", "listen");
			exit(1);
		}
		if(sp2 > global.max_fd)
			global.max_fd = sp2;
	}
	return sp2;
}


int     num_reaped = 0;

/* puts the specified connection on the destroy list to be reaped at the
* end of the main event loop
*/
void destroy_connection(CONNECTION * con)
{
	LIST   *list;

	ASSERT(validate_connection(con));

	/* already destroyed */
	if(con->fd == -1)
		return;

	// disconnects could be a user or a server, we count them all the same....
	stats.disconnects++;

	dprint1("destroy_connection: destroying fd %d\n", con->fd);
	/*    log_message("%d:KILL", con->fd); */

	if(con->destroy)
	{
		list = list_find(global.destroyList, con);
		if(list)
			return;     /* already destroyed */
		log_message_level(LOG_LEVEL_ERROR, "destroy_connection: error, destroyed connection not on global.destroyList");
		log_message_level(LOG_LEVEL_ERROR, "destroy_connection: con->host = %s", con->host);
		if(ISUSER(con))
			log_message_level(LOG_LEVEL_CLIENT, "destroy_connection: con->user->nick = %s", con->user->nick);
	}
	else
		num_reaped++;

	/* append to the list of connections to destroy */
	list = BlockHeapAlloc(destroy_list_heap); /*CALLOC(1, sizeof(LIST));*/
	if(!list)
	{
		OUTOFMEMORY("destroy_connection");
		return;
	}
	memset(list, 0, sizeof(LIST));
	list->data = con;
	ASSERT(list_validate(global.destroyList));
	global.destroyList = list_push(global.destroyList, list);
	ASSERT(global.destroyList->data == con);
	con->destroy = 1;

	/* we don't want to read/write anything furthur to this fd */
#if HAVE_POLL
	remove_fd(con->fd);
#else
	FD_CLR(con->fd, &global.read_fds);
	FD_CLR(con->fd, &global.write_fds);
#endif /* HAVE_POLL */

	ASSERT(list_count(global.destroyList) == num_reaped);
}

static void reap_dead_connection(CONNECTION * con)
{
#if ONAP_DEBUG
	int     i;
#endif
	ASSERT(validate_connection(con));

#if HAVE_POLL
	ASSERT(global.fdmap[con->fd] == -1);

#if ONAP_DEBUG
	/* be certain the fd isn't being polled */
	for(i = 0; i < global.poll_num; i++)
		ASSERT(global.poll[i].fd != con->fd);
#endif /* ONAP_DEBUG */

#else
	/* this should have already happened, but to it here just to be safe */
	FD_CLR(con->fd, &global.read_fds);
	FD_CLR(con->fd, &global.write_fds);
#endif

	if(con->id < global.clients_num - 1)
	{
		/* swap this place with the last connection in the array */
		global.clients[con->id] = global.clients[global.clients_num - 1];
		global.clients[con->id]->id = con->id;
	}

	global.clients_num--;
	global.clients[global.clients_num] = 0;

	/* close either the current descriptor */
	CLOSE(con->fd);

	/* mark that the descriptor has been closed */
	con->fd = INVALID_SOCKET;

	/* remove from flood list(if present) */
	if(global.flooderList)
		global.flooderList = list_delete(global.flooderList, con);

	/* this call actually free's the memory associated with the connection */
	remove_connection(con);
}

/* we can't use list_free(global.destroyList, reap_dead_connection) here because
* reap_dead_connection might try to access `global.destroyList', which will be pointed
* to free'd memory.  so this function updates `global.destroyList' in an atomic
* fashion such that if `global.destroyList' is updated, we have the correct new value.
*/
static void reap_connections(void)
{
	LIST   *tmp;

	while (global.destroyList)
	{
		tmp = global.destroyList;
		global.destroyList = global.destroyList->next;
		num_reaped--;
		reap_dead_connection(tmp->data);
		BlockHeapFree(destroy_list_heap, tmp); /*FREE(tmp);*/
	}
	ASSERT(num_reaped == 0);
}

static void flood_expire(void)
{
	LIST  **list, *tmp;
	CONNECTION *con;

	stats.flood_db = 0;
	for(list = &global.flooderList; *list;) 
	{
		con =(*list)->data;
		if(con->flood_start + global.floodTime < global.current_time) 
		{
			/* flood timer expired, resume reading commands */
			set_read(con->fd);
			tmp = *list;
			*list =(*list)->next;
			FREE(tmp);
		}
		else
		{
			list = &(*list)->next;
			stats.flood_db++;
		}
	}
}

/* since server->server data is always queued up so it can be compressed
* in one shot, we have to explicitly call send_queued_data() for each
* server here.
*/
static void flush_server_data(CONNECTION * con, void *unused)
{
	(void) unused;
	ASSERT(validate_connection(con));
	if(send_queued_data(con) == -1)
		destroy_connection(con);
}

#if HAVE_POLL
#define TIMEOUT timeout
#define READABLE(c)(global.poll[global.fdmap[c]].revents & POLLIN)
#define WRITABLE(c)(global.poll[global.fdmap[c]].revents & POLLOUT)
#else
#define TIMEOUT tv.tv_sec
#define READABLE(c) FD_ISSET(c,&read_fds)
#define WRITABLE(c) FD_ISSET(c,&write_fds)
#endif

static void server_input(CONNECTION * con, void *arg)
{
#if HAVE_POLL
	(void) arg;
	ASSERT(global.fdmap[con->fd] != -1);

	ASSERT((global.poll[POFF(con->fd)].events & POLLIN) !=0);
	if(global.poll[POFF(con->fd)].revents & POLLIN)
		handle_connection(con);
#else
	fd_set *read_fds =(fd_set *) arg;

	if(FD_ISSET(con->fd, read_fds))
		handle_connection(con);
#endif
}

int main(int argc, char **argv)
{
	SOCKET    *sockfd;     /* server sockets */
	int     sockfdcount;    /* number of server sockets */
	int     i;          /* generic counter */
	int     numfds;

#ifndef HAVE_POLL 
	int     sel_error; /* select error number */
#endif

#ifndef ROUTING_ONLY
	SOCKET     sp;
#endif
	SOCKET     sp2;
#if HAVE_POLL
	int     timeout;
#else
	struct timeval tv;
	fd_set  read_fds, write_fds;
#endif

#ifdef WIN32
	WSADATA wsaData;
	int wsaErr;

	wsaErr = WSAStartup(MAKEWORD(2, 0), &wsaData);
	if(wsaErr != 0) 
	{
		logerr("main", "WSAStartup error!!!");
		exit(1);
	}

#endif /* !WIN32 */

	memset(&global, 0, sizeof(GLOBAL));
	global.shareDir = SHAREDIR;
	global.varDir = VARDIR;
	global.logLevel = 2047; /* so we log things off the bat, else it is 0 and nothing gets logged until we read the config file */

	/* minimize the stack space for the main loop by moving the command line
	parsing code to a separate routine */
	sockfd = args(argc, argv, &sockfdcount);

#ifndef ROUTING_ONLY
	sp = init_stats_port();
#endif
	sp2 = init_stats_port2();

#if HAVE_POLL
	global.poll_max = global.max_fd + 1;
	global.poll = CALLOC(global.poll_max, sizeof(struct pollfd));
	for(i = 0; i < global.poll_max; i++)
		global.poll[i].fd = -1;
	global.fdmap = CALLOC(global.poll_max, sizeof(int) *(global.max_fd + 1));
	memset(global.fdmap, -1, sizeof(int) *(global.max_fd + 1));
#endif

	for(i = 0; i < sockfdcount; i++)
	{
#if HAVE_POLL
		struct pollfd *p;

		global.fdmap[sockfd[i]] = global.poll_num++;
		p = &global.poll[global.fdmap[sockfd[i]]];

		p->fd = sockfd[i];
		p->events = POLLIN;
#else
		FD_SET(sockfd[i], &global.read_fds);
#endif
	}

#ifndef ROUTING_ONLY
	if(sp != -1)
	{
#if HAVE_POLL
		global.fdmap[sp] = global.poll_num++;
		global.poll[POFF(sp)].fd = sp;
		global.poll[POFF(sp)].events = POLLIN;
#else
		FD_SET(sp, &global.read_fds);
#endif
	}
#endif
	if(sp2 != -1)
	{
#if HAVE_POLL
		global.fdmap[sp2] = global.poll_num++;
		global.poll[POFF(sp2)].fd = sp2;
		global.poll[POFF(sp2)].events = POLLIN;
#else
		FD_SET(sp2, &global.read_fds);
#endif
	}

	/* schedule periodic events */
	add_timer(global.stat_click, -1,(timer_cb_t) update_stats, 0);

	add_timer(global.userDBSaveFreq, -1,(timer_cb_t) dump_state, 0);
	add_timer(60, -1,(timer_cb_t) expire_bans, 0);
	add_timer(60, -1,(timer_cb_t) ibl_expire, 0);
	add_timer(global.pingInterval, -1,(timer_cb_t) lag_detect, 0);
	add_timer(global.whoWasTime, -1,(timer_cb_t) expire_whowas, 0);

	/* initialize so we get the correct delta for the first call to
	update_stats() */
	global.last_click = global.current_time;

	/* auto connect remote servers if requested */
	if(option(ON_AUTO_LINK))
		auto_link();

	/* main event loop */
	while (!global.sigCaught)
	{
		global.current_time = time(0);

		TIMEOUT = next_timer();
		/* if we have a flood list and the timeout is greater than when
		* the flood expires, reset the timeout
		*/
		if(global.flooderList && global.floodTime > 0 && TIMEOUT > global.floodTime)
			TIMEOUT = global.floodTime;

#if HAVE_POLL

#if ONAP_DEBUG
		/* check to make sure the poll[] array looks kosher */
		for(i = 0; i < global.poll_num; i++)
		{
			ASSERT(global.poll[i].fd != -1);
			ASSERT(global.fdmap[global.poll[i].fd] == i);
		}
		for(i = global.poll_num; i < global.poll_max; i++)
		{
			ASSERT(global.poll[i].fd == -1);
			ASSERT(global.poll[i].events == 0);
			ASSERT(global.poll[i].revents == 0);
		}
#endif /* ONAP_DEBUG */

		numfds = poll(global.poll, global.poll_num, (TIMEOUT<1?1000:1000*TIMEOUT));

		if(numfds == -1)
		{
			nlogerr("main", "poll");
			continue;
		}
#else
		read_fds = global.read_fds;
		write_fds = global.write_fds;
		tv.tv_sec = (TIMEOUT<1?1:TIMEOUT);
		tv.tv_usec = 0;

		for(;;) 
		{
			numfds = select((int)global.max_fd + 1, &read_fds, 
#ifdef WIN32
				/* dont't pass empty fd set */
				( write_fds.fd_count > 0 ? &write_fds : NULL),
#else
				&write_fds,
#endif /* WIN32 */
				NULL, &tv);
			if(numfds >= 0)
				break;
			else
			{
				sel_error = 
#ifdef WIN32
					WSAGetLastError();
#else
					errno;
#endif
				if(!SOFT_ERROR(sel_error) &&
#ifdef WIN32
					sel_error != WSAEINVAL) 
#else
					sel_error != EINVAL)
#endif
				{
					log_message_level(LOG_LEVEL_ERROR, "select had an error... sel_error is %d", sel_error);
					logerr("main", "select loop - bombed");
					exit(1);
				}
			}
		}

#endif
		if(numfds > 0)
		{
			/* pre-read server links */
			list_foreach(global.serversList,(list_callback_t) server_input,
#ifndef HAVE_POLL
				&read_fds
#else
				NULL
#endif
				);

			/* do client i/o */
			if(global.clients_num != 0)
			{
				for(i = 0; i < global.clients_num; i++)
				{
#if HAVE_POLL
					int     off = POFF(global.clients[i]->fd);

					if(global.poll[off].revents &(POLLNVAL | POLLHUP | POLLERR))
					{
						if(global.poll[off].revents & POLLERR)
						{
							int     err;
							socklen_t errlen = sizeof(err);

							/* error */
							if(getsockopt(global.poll[off].fd, SOL_SOCKET, SO_ERROR, &err, &errlen))
							{
								logerr("main", "getsockopt");
							}
							else
							{
								if(err == 104) 
								{
									stats.con_104++;
								} 
								else if(err == 110) 
								{
									stats.con_110++;
								} 
								else if(err == 113) 
								{
									stats.con_113++;
								} 
								else if(err == 32) 
								{
									stats.con_032++;
								} 
								else 
								{
									log_message_level(LOG_LEVEL_ERROR, "main: fd %d(%s): %s(errno %d)", global.poll[off].fd, global.clients[i]->host, strerror(err), err);
								}
							}
						}
						else
						{
							log_message_level(LOG_LEVEL_ERROR, "main: fd %d %s", global.poll[off].fd, (global.poll[off].revents & POLLNVAL) ? "is invalid" : "got hangup");
						}
						log_message_level(LOG_LEVEL_ERROR, "main: fd: %d - destroying (%s)", global.poll[off].fd, ISSERVER(global.clients[i])?"server":ISUSER(global.clients[i])?"user":"unknown");
						destroy_connection(global.clients[i]);
						continue;
					}
#endif
					if(READABLE(global.clients[i]->fd))
					{
						if(!global.clients[i]->destroy) 
						{
							handle_connection(global.clients[i]);
						}
					}
					if(!global.clients[i]->destroy) 
					{
						if(WRITABLE(global.clients[i]->fd)) 
						{
							if(global.clients[i]->connecting) 
							{
								complete_connect(global.clients[i]);
								printf("back from complete_connect\n");
							} 
							else 
							{
#if HAVE_POLL
								/* sanity check - make sure there was actually data to
								* write.
								*/
								if(!ISSERVER(global.clients[i]) && !global.clients[i]->sendbuf )
								{
									log_message_level(LOG_LEVEL_ERROR, "main: ERROR, fd %d(id %d) was writable with no pending data",
										global.clients[i]->fd, global.clients[i]->id);
									clear_write(global.clients[i]->fd);
								}
#endif

								if(send_queued_data(global.clients[i]) == -1)
									destroy_connection(global.clients[i]);
							}
						}
					}

					/* reap connections which have not logged in after
					* `global.loginTimeout' seconds
					*/
					if(ISUNKNOWN(global.clients[i]) && global.current_time - global.clients[i]->timer > global.loginTimeout)
					{
						log_message_level( LOG_LEVEL_LOGIN, "main: terminating %s(login timeout)", global.clients[i]->host);
						send_cmd(global.clients[i], MSG_SERVER_ERROR, "Idle timeout");
						destroy_connection(global.clients[i]);
					}
#ifndef ROUTING_ONLY
					else
					{
						if(!global.clients[i]->destroy && ISUSER(global.clients[i]) && check_eject_limits(global.clients[i]->user))
							eject_internal(global.clients[i], global.clients[i]->user);
					}
#endif
				}
			}
			/* handle timed-out remote searches */
			expire_searches();

#ifndef ROUTING_ONLY
			/* check for stat server i/o */
			if(global.stat_server_fd != INVALID_SOCKET)
			{
				if(WRITABLE(global.stat_server_fd))
				{
					int code;
					socklen_t codesize = sizeof(code);

					clear_write(global.stat_server_fd);
					/* nonblocking connect complete - check connection code */
					if(getsockopt(global.stat_server_fd, SOL_SOCKET, SO_ERROR, SOCKOPTCAST &code, &codesize))
					{
						logerr("main","getsockopt");
#if HAVE_POLL
						remove_fd(global.stat_server_fd);
#endif
						CLOSE(global.stat_server_fd);
						global.stat_server_fd = INVALID_SOCKET;
					}
					else if(code)
					{
						log_message_level(LOG_LEVEL_ERROR, "main: connection to stat server failed(%s)",
							strerror(code));
#if HAVE_POLL
						remove_fd(global.stat_server_fd);
#endif
						CLOSE(global.stat_server_fd);
						global.stat_server_fd = INVALID_SOCKET;
					}
					else
						set_read(global.stat_server_fd);
				}
				else if(READABLE(global.stat_server_fd))
					stat_server_read();
			}

			/* check for stats port connections */
			if(sp != INVALID_SOCKET)
			{
#if HAVE_POLL
				if(global.poll[POFF(sp)].revents & POLLIN)
#else
				if(FD_ISSET(sp, &read_fds))
#endif /* HAVE_POLL */
					report_stats(sp);
			}
#endif
			/* check for stats port2 connections */
			if(sp2 != INVALID_SOCKET)
			{
#if HAVE_POLL
				if(global.poll[POFF(sp2)].revents & POLLIN)
#else
				if(FD_ISSET(sp2, &read_fds))
#endif /* HAVE_POLL */
					report_stats2(sp2);
			}

			/* check for new clients */
			for(i = 0; i < sockfdcount; i++)
			{
#if HAVE_POLL
				if(global.poll[POFF(sockfd[i])].revents & POLLIN)
#else
				if(FD_ISSET(sockfd[i], &read_fds))
#endif /* HAVE_POLL */
				{
					accept_connection(sockfd[i]);
				}
			}

			list_foreach(global.serversList,(list_callback_t) flush_server_data, 0);
		} /* if(numfds >0) */
		flood_expire();

		/* execute any pending events now */
		exec_timers(global.current_time);

		/* remove destroyed connections from the client list.  this
		* MUST be the last operation in the loop since all the previous
		* can cause connections to be terminated.
		*/
		reap_connections();
	} /* while (!global.sigCaught) */

	/* close all open file descriptors properly */
	for(i = 0; i <= global.max_fd; i++)
		CLOSE(i);

	dump_state();

#if ONAP_DEBUG

#if HAVE_POLL
	FREE(global.poll);
	FREE(global.fdmap);
#endif
	for(i = 0; i < global.clients_num; i++)
	{
		global.clients[i]->fd = -1;
		remove_connection(global.clients[i]);
	}
	FREE(global.clients);

	FREE(sockfd);

#ifndef ROUTING_ONLY
	free_hash(global.filterHash);
	free_hash(global.FileHash);
#endif

	free_hash(global.usersHash);
	free_hash(global.channelHash);
	global.channelHash = 0;
	free_hash(global.hotlistHash);
	free_hash(global.userDbHash );
	free_hash(global.whoWasHash);
	free_hash(global.clonesHash);
	free_hash(global.clientVersionHash);
	free_timers();

	list_free(global.banList,(list_destroy_t) free_ban);
	list_free(global.internalBanList,(list_destroy_t) free_ban);
	list_free(global.serverAliasList,(list_destroy_t) free_server_auth);
	list_free(global.serverNamesList, free_pointer);
	list_free(global.destroyList, 0);
	/* list_free(global.histOutHash, free_pointer); */
	list_free(global.searchCacheList,(list_destroy_t) free_cache);


	/* free up memory associated with global configuration variables */
	free_config();
	acl_destroy();

	/* this displays a list of leaked memory.  pay attention to this. */
	CLEANUP();
#endif

#ifdef WIN32
	WSACleanup();
#endif

	global.current_time = time(0);
	log_message_level(LOG_LEVEL_SERVER, "main: server ended at %s", ctime(&global.current_time));

	exit(0);
}
