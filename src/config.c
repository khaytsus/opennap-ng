/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
This is free software distributed under the terms of the
GNU Public License.  See the file COPYING for details.

$Id: config.c 434 2006-09-03 17:48:47Z reech $ */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stddef.h>
#include <ctype.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#ifndef WIN32
# include <unistd.h>
#endif
#include "opennap.h"
#include "debug.h"

typedef enum
{
	VAR_TYPE_INT,
	VAR_TYPE_STR,
	VAR_TYPE_BOOL,
	VAR_TYPE_LIST
}
VAR_TYPE;

#define CF_ONCE 1       /* may only be set in config file or command line */
#define CF_HIDDEN 2     /* can't be queried by a client */

struct config
{
	char   *name;
	VAR_TYPE type;
	unsigned long val;
	unsigned long def;      /* default value */
	unsigned int flags;
};

#define UL (unsigned long)

static struct config Vars[] = {
#ifndef ROUTING_ONLY
	{"allow_share", VAR_TYPE_BOOL, ON_ALLOW_SHARE, 1, 0},
	{"eject_after", VAR_TYPE_INT, UL & global.ejectAfter, 120, 0},
	{"eject_leeches", VAR_TYPE_BOOL, ON_EJECT_LEECHES, 0, 0},
	{"eject_nochannels", VAR_TYPE_BOOL, ON_EJECT_NOCHANNELS, 1, 0},
	{"eject_when_full", VAR_TYPE_BOOL, ON_EJECT_WHEN_FULL, 0, 0},
	{"eject_limit_files", VAR_TYPE_INT, UL & global.eject_limit_files, 0, 0},
	{"eject_limit_libsize", VAR_TYPE_INT, UL & global.eject_limit_libsize, 0, 0},
	{"eject_also_bans", VAR_TYPE_BOOL, ON_EJECT_ALSO_BANS, 0, 0},
	{"abuse_bans_ip", VAR_TYPE_INT, UL & global.abuse_bans_ip, 1, 0},
	{"eject_ban_ttl", VAR_TYPE_INT, UL & global.eject_ban_ttl, 1800, 0},
	{"eject_grace_time", VAR_TYPE_INT, UL & global.eject_grace_time, 600, 0},
	{"min_file_size", VAR_TYPE_INT, UL & global.min_file_size, 0, 0},
	{"index_ignore_suffix", VAR_TYPE_BOOL, ON_IGNORE_SUFFIX, 1, 0},
	{"index_path_depth", VAR_TYPE_INT, UL & global.fileIndexPathDepth, 2, 0},
	{"file_count_threshold", VAR_TYPE_INT, UL & global.fileCountThreshold, 5000, 0},
	{"max_results", VAR_TYPE_INT, UL & global.maxSearchResults, 100, 0},
	{"max_searches", VAR_TYPE_INT, UL & global.maxSearches, 3, 0},
	{"max_new_users_per_minute", VAR_TYPE_INT, UL & global.max_new_users_per_minute, 0, 0},
	{"report_name", VAR_TYPE_STR, UL & global.report_name, 0, 0},
	{"report_ip", VAR_TYPE_STR, UL & global.report_ip, 0, 0},
	{"report_port", VAR_TYPE_INT, UL & global.report_port, 0, 0},
	{"stat_server_host", VAR_TYPE_STR, UL & global.stat_server,UL "stats.napigator.com", 0},
	/*    {"stat_server_pass", VAR_TYPE_STR, UL & global.stat_pass, 0, CF_HIDDEN}, */
	{"stat_server_pass", VAR_TYPE_STR, UL & global.stat_pass, UL "", CF_HIDDEN},
	{"stat_server_port", VAR_TYPE_INT, UL & global.stat_server_port, 8890, 0},
	/*    {"stat_server_user", VAR_TYPE_STR, UL & global.stat_user, 0, CF_HIDDEN}, */
	{"stat_server_user", VAR_TYPE_STR, UL & global.stat_user, UL "", CF_HIDDEN},
	{"stats_port", VAR_TYPE_INT, UL & global.statsPort, 8889, CF_ONCE},
#endif

	{"stats_port2", VAR_TYPE_INT, UL & global.statsPort2, 8892, CF_ONCE},
	{"ibl_ttl", VAR_TYPE_INT, UL & global.ibl_ttl, 0, 0},
	{"notify_mod_abuse", VAR_TYPE_BOOL, ON_NOTIFY_MOD_ABUSE, 0, 0},
	{"notify_mod_abuse_frequency", VAR_TYPE_INT, UL & global.notify_mod_abuse_frequency, 100, 0},

	{"notify_user_abuse", VAR_TYPE_BOOL, ON_NOTIFY_USER_ABUSE, 0, 0},
	{"notify_user_abuse_frequency", VAR_TYPE_INT, UL & global.notify_user_abuse_frequency, 1000, 0},

	{"evaluate_search_abuse_after_secs", VAR_TYPE_INT, UL & global.evaluate_search_abuse_after_secs, 120, 0},
	{"evaluate_search_abuse_after_tags", VAR_TYPE_INT, UL & global.evaluate_search_abuse_after_tags, 100, 0},
	{"max_searches_per_minute", VAR_TYPE_INT, UL & global.max_searches_per_minute, 2, 0},
	{"break_mx_queue", VAR_TYPE_BOOL, ON_BREAK_MX_QUEUE, 0, 0},
	{"level_to_set_flags", VAR_TYPE_INT, UL & global.level_to_set_flags,UL 2, 0},
	{"discipline_ignorers", VAR_TYPE_BOOL, ON_DISCIPLINE_IGNORERS, 1, 0},
	{"discipline_ignorers_ban_ttl", VAR_TYPE_INT, UL & global.discipline_ignorers_ban_ttl,UL 2592000, 0},
	{"discipline_block", VAR_TYPE_BOOL, ON_DISCIPLINE_BLOCK, 0, 0},
	{"discipline_block_ban_ttl", VAR_TYPE_INT, UL & global.discipline_block_ban_ttl,UL 259200, 0},
	{"discipline_block_mod", VAR_TYPE_BOOL, ON_DISCIPLINE_BLOCK_MOD, 1, 0},
	{"notify_mod_block", VAR_TYPE_BOOL, ON_NOTIFY_MOD_BLOCK, 0, 0},
	{"browse_nag", VAR_TYPE_BOOL, ON_BROWSE_NAG, 1, 0},
	/* Search cacheing settings from here on 500 cache entries should be sufficient for 
	a quick'n dirty proof of concept. */
	{"search_max_cache_entries", VAR_TYPE_INT, UL & global.search_max_cache_entries, 500, 0},

	{"no_mod_annoying", VAR_TYPE_BOOL, ON_NO_MOD_ANNOYING, 0, 0},
	{"max_tags_per_minute", VAR_TYPE_INT, UL & global.max_tags_per_minute, 2, 0},

	{"max_shared", VAR_TYPE_INT, UL & global.maxShared, 5000, 0},
	{"auto_link", VAR_TYPE_BOOL, ON_AUTO_LINK, 0, 0},
	{"auto_register", VAR_TYPE_BOOL, ON_AUTO_REGISTER, 0, 0},
	{"block_winmx", VAR_TYPE_INT, UL & global.BlockWinMX, 0, 0},
	{"client_queue_length", VAR_TYPE_INT, UL & global.clientQueueLen, 102400,0},
	{"compression_level", VAR_TYPE_INT, UL & global.compressionLevel, 1, CF_ONCE},
	{"flood_commands", VAR_TYPE_INT, UL & global.floodCommands, 0, 0},
	{"flood_time", VAR_TYPE_INT, UL & global.floodTime, 0, 0},
	{"ghost_kill", VAR_TYPE_BOOL, ON_GHOST_KILL, 1, 0},
	{"allow_dynamic_ghosts", VAR_TYPE_BOOL, ON_ALLOW_DYNAMIC_GHOSTS, 0, 0},
	{"ghost_kill_timer", VAR_TYPE_INT, UL & global.ghost_kill_timer, 450, 0},

	{"irc_channels", VAR_TYPE_BOOL, ON_IRC_CHANNELS, 1, 0},
	{"listen_addr", VAR_TYPE_STR, UL & global.Listen_Addr, UL "0.0.0.0", CF_ONCE},
	{"log_mode", VAR_TYPE_BOOL, ON_LOGLEVEL_CHANGE, 0, 0},
	{"log_level", VAR_TYPE_INT, UL & global.logLevel, (LOG_LEVEL_SERVER | LOG_LEVEL_CLIENT | LOG_LEVEL_LOGIN | LOG_LEVEL_FILES | LOG_LEVEL_ERROR | LOG_LEVEL_SECURITY | LOG_LEVEL_STATS), 0},

	{"log_stdout", VAR_TYPE_BOOL, ON_LOG_STDOUT, 1, 0},
	{"login_interval", VAR_TYPE_INT, UL & global.loginInterval, 0, 0},
	{"login_timeout", VAR_TYPE_INT, UL & global.loginTimeout, 60, 0},
	{"max_browse_result", VAR_TYPE_INT, UL & global.maxBrowseResult, 500, 0},
	{"max_channel_length", VAR_TYPE_INT, UL & global.maxChanLen, 32, 0},
	{"max_client_string", VAR_TYPE_INT, UL & global.maxClientString, 32, 0},
	{"max_clones", VAR_TYPE_INT, UL & global.maxClones, 0, 0},
	{"max_command_length", VAR_TYPE_INT, UL & global.maxCommandLen, 2048, 0},
	{"max_connections", VAR_TYPE_INT, UL & global.maxConnections, 1000, 0},
	{"max_hotlist", VAR_TYPE_INT, UL & global.maxHotlist, 32, 0},
	{"max_ignore", VAR_TYPE_INT, UL & global.maxIgnore, 32, 0},
	{"max_nick_length", VAR_TYPE_INT, UL & global.maxNickLen, 19, 0},
	{"max_reason", VAR_TYPE_INT, UL & global.maxReason, 96, 0},
	{"max_time_delta", VAR_TYPE_INT, UL & global.maxTimeDelta, 90, 0},
	{"max_topic", VAR_TYPE_INT, UL & global.maxTopic, 64, 0},
	{"max_user_channels", VAR_TYPE_INT, UL & global.maxUserChannels, 5, 0},
	{"min_read", VAR_TYPE_INT, UL & global.min_read, 0, 0},
	{"nick_expire", VAR_TYPE_INT, UL & global.nickExpire, 2678400 /* 31 days */ , 0},
	{"ping_interval", VAR_TYPE_INT, UL & global.pingInterval, 600, 0},
	{"register_interval", VAR_TYPE_INT, UL & global.registerInterval, 0, 0},
	{"registered_only", VAR_TYPE_BOOL, ON_REGISTERED_ONLY, 0, 0},
	{"restrict_registration", VAR_TYPE_BOOL, ON_RESTRICT_REGISTRATION, 0, 0},
	{"remote_browse", VAR_TYPE_BOOL, ON_REMOTE_BROWSE, 1, 0},
	{"remote_config", VAR_TYPE_BOOL, ON_REMOTE_CONFIG, 1, 0},
	{"search_timeout", VAR_TYPE_INT, UL & global.searchTimeout, 180, 0},
	{"server_alias", VAR_TYPE_STR, UL & global.serverAlias, 0, CF_ONCE},
	{"server_chunk", VAR_TYPE_INT, UL & global.serverChunk, 0, 0},
	{"server_name", VAR_TYPE_STR, UL & global.serverName, 0, CF_ONCE},
	{"server_ports", VAR_TYPE_LIST, UL & global.serverPortList, UL "8888", CF_ONCE},
	{"server_queue_length", VAR_TYPE_INT, UL & global.serverQueueMaxLen, 1048576, 0},
	{"stat_click", VAR_TYPE_INT, UL & global.stat_click, 60, 0},
	{"strict_channels", VAR_TYPE_BOOL, ON_STRICT_CHANNELS, 0, 0},
	{"user_db_interval", VAR_TYPE_INT, UL & global.userDBSaveFreq, 1200, 0},
	{"usermode", VAR_TYPE_STR, UL & UserMode, UL "ALL", CF_ONCE},
	{"warn_time_delta", VAR_TYPE_INT, UL & global.warnTimeDelta, 30, 0},
	{"who_was_time", VAR_TYPE_INT, UL & global.whoWasTime, 300, 0},
#ifdef USE_INVALID_CLIENTS
	{"invalid_clients", VAR_TYPE_STR, UL & global.invalidClients, UL "", 0}, /* Add by winter_mute */
#endif
#ifdef USE_INVALID_NICKS
	{"invalid_nicks", VAR_TYPE_STR, UL & global.invalidNicks, UL "", 0}, /* Add by winter_mute */
#endif
#ifdef USE_PROTNET
	{"protnet", VAR_TYPE_STR, UL & global.protnet, UL "*", 0}, /* Add by winter_mute */
#endif
#ifdef HAVE_LIBPTHREAD
	{"proxycheck", VAR_TYPE_INT, UL & global.proxycheck, 0, 0},
#endif
#if defined (USE_INVALID_CLIENTS) || defined (USE_INVALID_NICKS)
	{"set_server_nicks", VAR_TYPE_STR, UL & global.setServerNicks, UL "", 0},
#endif
#ifndef WIN32
	{"connection_hard_limit", VAR_TYPE_INT, UL & global.hardConnLimit, FD_SETSIZE, CF_ONCE},
	{"max_data_size", VAR_TYPE_INT, UL & global.maxDataSize, -1, CF_ONCE},
	{"max_rss_size", VAR_TYPE_INT, UL & global.maxRssSize, -1, CF_ONCE},
	{"lock_memory", VAR_TYPE_BOOL, ON_LOCK_MEMORY, 0, CF_ONCE},
#endif
};

static int Vars_Size = sizeof(Vars) / sizeof(struct config);

/* Added by winter_mute
returns 1 if none of the comma delimited strings in arg have a low ratio 
of meta-chars (* ?) with respect to it's length.
*/
#if defined (USE_INVALID_CLIENTS) || defined (USE_INVALID_NICKS)
static int check_meta_chars(const char* arg)
{ 
	unsigned short count = 0;
	const char *delim = ",";
	char *val, *tmp, *ptr, *ptrtmp;

	ptr = STRDUP( arg );
	ptrtmp = ptr;

	/* Seperate the string by , and loop throug each one */
	val = strsep(&ptr, delim);

	if(ptr)
	{
		do
		{
			tmp = val;
			while (*val != 0)
			{
				if(*val == '*' || *val == '?')
					count++;
				val++;
			}
			if((strlen(tmp) - count) <= 2) 
			{
				FREE(ptr);
				return 0;
			}
			count = 0;
		} while ((val = strsep(&ptr, delim)) != NULL);
	}
	else
	{  
		while (*val != 0)
		{  
			if(*val == '*' || *val == '?')
				count++;
			val++;
		}
		if((strlen(arg) - count) <= 2)
		{
			if(ptrtmp) 
			{
				FREE(ptrtmp);
			}
			return 0;
		}
	}
	if(ptrtmp) 
	{
		FREE(ptrtmp);
	}
	return 1;
}
#endif

static void set_int_var(struct config *v, int val)
{
	ASSERT(v->type == VAR_TYPE_INT);
	*(int *) v->val = val;
}

static void set_str_var(struct config *v, const char *s)
{
	char  **ptr;

	ASSERT(v->type == VAR_TYPE_STR);
	ptr = (char **) v->val;
	if(*ptr)
		FREE(*ptr);
	*ptr = STRDUP(s);
}

static void set_list_var(struct config *v, const char *s)
{
	int     ac, i;
	char   *av[32];
	LIST   *tmpList, *list = 0;


	ASSERT(v->type == VAR_TYPE_LIST);
	strncpy(Buf, s, sizeof(Buf) - 1);
	Buf[sizeof(Buf) - 1] = 0;
	ac = split_line(av, FIELDS(av), Buf);
	for (i = 0; i < ac; i++)
	{
		tmpList = CALLOC(1, sizeof(LIST));
		tmpList->data = STRDUP(av[i]);
		tmpList->next = list;
		list = tmpList;
	}
	list_free(*(LIST **) v->val, free_pointer);
	*(LIST **) v->val = list;
}

static void set_bool_var(struct config *v, int on)
{
	ASSERT(v->type == VAR_TYPE_BOOL);
	if(on)
		global.serverFlags |= v->val;
	else
		global.serverFlags &= ~v->val;
}

static int set_var(const char *var, const char *val, int init)
{
	int     i, n;
	char   *ptr;

	for (i = 0; i < Vars_Size; i++)
	{
		if(!strcmp (Vars[i].name, var))
		{
			if(!init && (Vars[i].flags & CF_ONCE))
			{
				log_message_level(LOG_LEVEL_SERVER, "set_var: %s may not be reset/only set in the config file", Vars[i].name);
				return -1;
			}
			if(Vars[i].type == VAR_TYPE_INT)
			{
				n = strtol(val, &ptr, 10);
				if(*ptr)
				{
					log_message_level(LOG_LEVEL_ERROR, "set_var: invalid integer value: %s", val);
					return -1;
				}
				/* FIXME: If max_connections is changed to a bigger value
				then the increase should be done in little steps for 
				not to overload the bandwidth of low-bandwidth servers */

				set_int_var (&Vars[i], n);
			}
			else if(Vars[i].type == VAR_TYPE_STR)
			{

				/* Added by winter_mute */
#if defined USE_PROTNET && (defined (USE_INVALID_CLIENTS) || defined (USE_INVALID_NICKS))
				if(!strcasecmp("protnet", var) && !check_meta_chars(val))
					return -1;
#endif
#ifdef USE_INVALID_CLIENTS
				if(!strcasecmp("invalid_clients", var) && !check_meta_chars(val))
					return -1;
#endif
#ifdef USE_INVALID_NICKS
				if(!strcmp("invalid_nicks", var) && !check_meta_chars(val))
					return -1;
#endif
				set_str_var (&Vars[i], val);
			}
			else if(Vars[i].type == VAR_TYPE_BOOL)
			{
				if(!strcasecmp("yes", val) || !strcasecmp("on", val))
					n = 1;
				else if(!strcasecmp("no", val) || !strcasecmp("off", val))
					n = 0;
				else
				{
					n = strtol(val, &ptr, 10);
					if(*ptr)
					{
						log_message_level(LOG_LEVEL_ERROR, "set_var: invalid boolean value: %s", val);
						return -1;
					}
				}
				set_bool_var(&Vars[i], n);
			}
			else if(Vars[i].type == VAR_TYPE_LIST)
				set_list_var(&Vars[i], val);
			else
			{
				ASSERT(0);
			}
			return 0;
		}
	}
	log_message_level(LOG_LEVEL_ERROR, "set_var: unknown variable %s", var);
	return -1;
}

static char *get_str_var(char *name)
{
	int     ac;

	for (ac = 0; ac < Vars_Size; ac++)
	{
		if(!strcasecmp(name, Vars[ac].name)
			&& Vars[ac].type == VAR_TYPE_STR)
			return *(char **) Vars[ac].val;
	}
	return NULL;
}

int config(int init)
{
	int     fd;
	char   *ptr, *var;
	int     len, line = 0;
	char    path[_POSIX_PATH_MAX];
	char    buf[1024];

	snprintf(path, sizeof(path), "%s/config", global.shareDir);

	fd = open(path, O_RDONLY);
	if(fd)
	{
		log_message_level(LOG_LEVEL_DEBUG, "config: reading %s", path);
		buf[sizeof buf - 1] = 0;
		while (fake_fgets(buf, sizeof(buf) - 1, fd))
		{
			line++;
			ptr = buf;
			while (isspace((int)*ptr))
				ptr++;
			if(!*ptr || *ptr == '#')
				continue;
			len = strlen(ptr);
			while (len > 0 && isspace((int)*(ptr + len - 1)))
				len--;
			*(ptr + len) = 0;

			var = next_arg(&ptr);
			if(!ptr)
			{
				log_message_level(LOG_LEVEL_ERROR, "config: error in %s:%d: missing value", path, line);
				continue;
			}
			if(set_var(var, ptr, init) != 0)
			{
				log_message_level(LOG_LEVEL_ERROR, "config: error in %s, line %d", path, line);
			}
		}
		close(fd);
	}
	else if(errno != ENOENT)
	{
		logerr("config", path);
		return -1;
	}
	if(init) 
	{
		config_user_level(get_str_var("usermode"));
		/*  config_log_level(get_str_var("loglevel")); */
	}
	return 0;
}

static void query_var(CONNECTION * con, struct config *v)
{
	if(v->type == VAR_TYPE_INT)
		send_cmd(con, MSG_SERVER_NOSUCH, "%s = %d", v->name, *(int *) v->val);
	else if(v->type == VAR_TYPE_BOOL)
	{
		send_cmd(con, MSG_SERVER_NOSUCH, "%s = %s", v->name, (global.serverFlags & v->val) ? "on" : "off");
	}
	else if(v->type == VAR_TYPE_LIST)
	{
		char    buf[1024];
		LIST   *tmpList = 0;

		buf[0] = 0;
		for (tmpList = *(LIST **) v->val; tmpList; tmpList = tmpList->next)
			snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "%s ", (char *) tmpList->data);
		send_cmd(con, MSG_SERVER_NOSUCH, "%s = %s", v->name, buf);
	}
	else
	{
		ASSERT(v->type == VAR_TYPE_STR);
		send_cmd(con, MSG_SERVER_NOSUCH, "%s = %s", v->name, *(char **) v->val);
	}
}

/* 810 [ <var> [ <value> ] ] */
HANDLER(server_config)
{
	char   *av[2];
	int     ac;

	(void) tag;
	(void) len;
	ASSERT(validate_connection(con));
	/* only local users should be able to config the server.  this is still
	* problematic as currently user levels are shared across all servers
	* meaning an Elite from another server could still log in and alter the
	* settings.
	*/
	CHECK_USER_CLASS("server_config");

	if(!option(ON_REMOTE_CONFIG))
	{
		send_cmd(con, MSG_SERVER_NOSUCH, "remote configuration is disabled");
		return;
	}
	/* allow mods+ to query the config values, only elites can set them */
	if(con->user->level < LEVEL_MODERATOR)
	{
		permission_denied(con);
		return;
	}

	ac = split_line(av, FIELDS(av), pkt);
	if(ac == 0)
	{
		/* user requests all config variables */
		for (ac = 0; ac < Vars_Size; ac++)
		{
			if(!(Vars[ac].flags & CF_HIDDEN))
				query_var(con, &Vars[ac]);
		}
	}
	else if(ac == 1)
	{
		/* user requests the value of a specific variable */
		for (ac = 0; ac < Vars_Size; ac++)
			if(!strcasecmp(av[0], Vars[ac].name))
			{
				if(Vars[ac].flags & CF_HIDDEN)
					break;  /* hide this variable */
				query_var(con, &Vars[ac]);
				return;
			}
			send_cmd(con, MSG_SERVER_NOSUCH, "no such variable %s", pkt);
	}
	else
	{
		if(con->user->level < LEVEL_ELITE)
		{
			permission_denied(con);
			return;
		}

		/* Added by winter_mute */
#ifdef USE_PROTNET
		if(!strcasecmp(av[0], "protnet"))
		{  
			send_cmd(con, MSG_SERVER_NOSUCH, "protnet is only hashable");
			return;
		}
#endif
		/* Added by winter_mute */
#ifdef USE_INVALID_CLIENTS
		if(!strcasecmp(av[0], "invalid_clients"))
		{  
			send_cmd(con, MSG_SERVER_NOSUCH, "invalid_clients is only hashable");
			return;
		}
		if(!strcasecmp(av[0], "set_server_nicks"))
		{  
			send_cmd(con, MSG_SERVER_NOSUCH, "set_server_nicks is only hashable");
			return;
		}
#endif
		/* Added by winter_mute */
#ifdef USE_INVALID_NICKS
		if(!strcasecmp(av[0], "invalid_nicks"))
		{  send_cmd(con, MSG_SERVER_NOSUCH, "invalid_nicks is only hashable");
		return;
		}
		if(!strcasecmp(av[0], "set_server_nicks"))
		{  
			send_cmd(con, MSG_SERVER_NOSUCH, "set_server_nicks is only hashable");
			return;
		}
#endif

		/* user changes the value of a specific variable */
		if(set_var(av[0], av[1], 0) != 0)
		{
			send_cmd(con, MSG_SERVER_NOSUCH, "error setting variable %s", av[0]);
		}
		else
			notify_mods(CHANGELOG_MODE, "%s set %s to %s", con->user->nick, av[0], av[1]);
	}
}

void free_config(void)
{
	int     i;

	for (i = 0; i < Vars_Size; i++)
		if(Vars[i].type == VAR_TYPE_STR && *(char **) Vars[i].val)
			FREE(*(char **) Vars[i].val);
		else if(Vars[i].type == VAR_TYPE_LIST)
			list_free(*(LIST **) Vars[i].val, free_pointer);
}

/* load the default settings of the server */
void config_defaults(void)
{
	int     i;

	for (i = 0; i < Vars_Size; i++)
	{
		if(Vars[i].def)
		{
			if(Vars[i].type == VAR_TYPE_STR)
				set_str_var(&Vars[i], (char *) Vars[i].def);
			else if(Vars[i].type == VAR_TYPE_INT)
				set_int_var(&Vars[i], Vars[i].def);
			else if(Vars[i].type == VAR_TYPE_LIST)
				set_list_var(&Vars[i], (char *) Vars[i].def);
			else if(Vars[i].type == VAR_TYPE_BOOL)
				set_bool_var(&Vars[i], Vars[i].def);
#if ONAP_DEBUG
			else
				ASSERT(0);
#endif
		}
	}
}

/* 800 [ :<user> ] <var>
reset `var' to its default value */
HANDLER(server_reconfig)
{
	int     i;

	(void) tag;
	(void) len;
	ASSERT(validate_connection(con));
	CHECK_USER_CLASS("server_reconfig");
	ASSERT(validate_user(con->user));
	if(con->user->level < LEVEL_ELITE)
	{
		permission_denied(con);
		return;
	}
	if(!option(ON_REMOTE_CONFIG))
	{
		send_cmd(con, MSG_SERVER_NOSUCH, "remote configuration is disabled");
		return;
	}

	for (i = 0; i < Vars_Size; i++)
		if(!strcmp (pkt, Vars[i].name))
		{
			if(!(Vars[i].flags & CF_ONCE))
			{
				send_cmd(con, MSG_SERVER_NOSUCH,
					"reconfig failed: %s may not be changed",
					Vars[i].name);
			}
			else if(Vars[i].def)
			{
				if(Vars[i].type == VAR_TYPE_STR)
					set_str_var(&Vars[i], (char *) Vars[i].def);
				else if(Vars[i].type == VAR_TYPE_INT)
					set_int_var(&Vars[i], Vars[i].def);
				else if(Vars[i].type == VAR_TYPE_BOOL)
					set_bool_var(&Vars[i], Vars[i].def);
				else if(Vars[i].type == VAR_TYPE_BOOL)
					set_list_var(&Vars[i], (char *) Vars[i].def);
				notify_mods(CHANGELOG_MODE, "%s reset %s",
					con->user->nick, Vars[i].name);
			}
			else
			{
				send_cmd(con, MSG_SERVER_NOSUCH, "no default value for %s", pkt);
			}
			return;
		}
		send_cmd(con, MSG_SERVER_NOSUCH, "no such variable %s", pkt);
}

static void nick_check(server_auth_t * auth, void *unused)
{
	USER   *user;
	USERDB *userdb;

	(void) unused;
	if(auth->alias)
	{
		user = hash_lookup(global.usersHash, auth->alias);
		if(user)
		{
			kill_user_internal(0, user, global.serverName, 0, "you may not use this nickname");
		}
		/* if the nick is registered, drop it now */
		userdb = hash_lookup(global.userDbHash , auth->alias);
		if(userdb)
		{
			log_message_level(LOG_LEVEL_SECURITY, "nick_check: nuking account %s", userdb->nick);
			hash_remove(global.userDbHash , userdb->nick);
		}
	}
}

/* Added by winter_mute */
#ifdef USE_INVALID_NICKS
static void my_nick_check(USER *user, void *unused)
{  
	USERDB *userdb;
	(void) unused;

	if(glob_match(global.invalidNicks, user->nick) && ISUSER(user->con) )
	{  
		kill_user_internal(0, user, global.serverName, 0, "you may not use this nickname");

		log_message_level(LOG_LEVEL_DEBUG, "config: my_nick_check: nick: %s", user->nick);
		/* if the nick is registered, drop it now */
		userdb = hash_lookup(global.userDbHash , user->nick);
		if(userdb)
		{
			log_message_level(LOG_LEVEL_SECURITY, "config: nick_check: nuking account %s", userdb->nick);
			hash_remove(global.userDbHash , userdb->nick);
		}
	}
}
#endif

/* Added by winter_mute */
#ifdef USE_INVALID_CLIENTS
static void my_client_check(USER *user, void *unused)
{  
	(void) unused;

	if(glob_match(global.invalidClients, user->clientinfo) && ISUSER(user->con) )
		kill_user_internal(0, user, global.serverName, 0, "your client, %s, is not welcome here.", user->clientinfo);
}
#endif

/*
#if defined (USE_INVALID_CLIENTS) || defined (USER_INVALID_NICKS)
static void
set_server_check(USER *user, void *unused)
{  
(void) unused;

if(glob_match(global.setServerNicks, user->clientinfo) && ISUSER(user->con) )
return 0;
return 1;
}
#endif
*/

void reload_config(void)
{
	log_message_level(LOG_LEVEL_SERVER, "reload_config: reloading configuration files");
	config(0);
	/* since the motd is stored in memory, reread it */
	motd_close();
	motd_init();
#ifndef ROUTING_ONLY
	/* reread filter file */
	load_filter();
	load_block();
#endif
	load_server_auth();

	/* since the servers file may have changed, ensure that there is
	* no nickname that matches an alias for a server.
	*/
	list_foreach(global.serverAliasList, (list_callback_t) nick_check, 0);

	/* Added by winter_mute */
	/* remove any nicks that are now not valid */
#ifdef USE_INVALID_NICKS
	hash_foreach(global.usersHash, (list_callback_t) my_nick_check, 0);
#endif
	/* remove any clients that are now not valid */

	/*  This seems to be bad for rehash, kills *globally*.
	#ifdef USE_INVALID_CLIENTS
	hash_foreach(global.usersHash, (list_callback_t) my_client_check, 0);
	#endif
	*/

	/*
	#if defined (USE_INVALID_CLIENTS) || defined (USE_INVALID_NICKS)
	hash_foreach(global.usersHash, (list_callback_t) set_server_check, 0);
	#endif
	*/
}

/* 10117 [ :user ] [server]
* reload configuration file
*/
HANDLER(rehash)
{
	USER   *sender;

	(void) len;
	if(pop_user(con, &pkt, &sender))
		return;
	if(sender->level < LEVEL_ELITE)
	{
		permission_denied(con);
		return;
	}
	notify_mods(SERVERLOG_MODE, "%s reloaded configuration on %s", sender->nick, pkt && *pkt ? pkt : global.serverName);
	if(!pkt || !*pkt || !strcasecmp(global.serverName, pkt))
		reload_config();

	/* pass the message even if this is the server we are reloading so that
	* everyone sees the message
	*/
	pass_message_args(con, tag, ":%s %s", sender->nick, pkt && *pkt ? pkt : global.serverName);
}
