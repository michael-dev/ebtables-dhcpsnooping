#include "config.h"
#include "debug.h"
#include "cmdline.h"
#include <unistd.h>
#include <syslog.h>
#include <stdio.h>
#include <string.h>

static int debug = DEBUG_ERROR;

void set_debug_flag(int c) {
	debug |= c;
}

void edprint(int level, char* msg)
{
#ifdef DEBUG
	static int open = 0;
	if (!open) {
		openlog ("dhcpsnoopingd", LOG_CONS | LOG_PID | LOG_NDELAY | LOG_PERROR, LOG_DAEMON);
		open = 1;
	}
	if (level & debug) {
		syslog(LOG_INFO, msg, strlen(msg));
	};
#endif
}

static __attribute__((constructor)) void debug_init()
{
	{
		struct option long_option = {"debug", no_argument, 0, DEBUG_GENERAL};
		add_option_cb(long_option, set_debug_flag);
	}
	{
		struct option long_option = {"debug-udp", no_argument, 0, DEBUG_UDP};
		add_option_cb(long_option, set_debug_flag);
	}
	{
		struct option long_option = {"debug-nflog", no_argument, 0, DEBUG_NFLOG};
		add_option_cb(long_option, set_debug_flag);
	}
	{
		struct option long_option = {"debug-neigh", no_argument, 0, DEBUG_NEIGH};
		add_option_cb(long_option, set_debug_flag);
	}
	{
		struct option long_option = {"debug-all",  no_argument, 0, DEBUG_ALL};
		add_option_cb(long_option, set_debug_flag);
	}
}

