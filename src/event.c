/**
 *  This file is part of ebtables-dhcpsnoopingd.
 *
 *  Ebtables-dhcpsnoopingd is free software: you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Ebtables-dhcpsnoopingd is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with ebtables-dhcpsnoopingd.
 *  If not, see <http://www.gnu.org/licenses/>.
 *
 *  (C) 2013, Michael Braun <michael-dev@fami-braun.de>
 */

#include "config.h"
#include "event.h"
#include "debug.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <assert.h>
#include <sys/select.h>

struct packet_cb_list_entry {
	packet_cb cb;
	struct packet_cb_list_entry* next;
};
struct packet_cb_list_entry* packet_cb_list = NULL;

struct handle_cb_list_entry {
	handle_cb cb;
	int h;
	void *ctx;
	struct handle_cb_list_entry* next;
};
struct handle_cb_list_entry* handle_cb_list = NULL;

struct signal_cb_list_entry {
	signal_cb cb;
	int s;
	int called;
	struct signal_cb_list_entry* next;
};
struct signal_cb_list_entry* signal_cb_list = NULL;

int signalCalled = 0;

void cb_add_packet_cb(packet_cb cb) {
	struct packet_cb_list_entry* entry = malloc(sizeof(struct packet_cb_list_entry));
	if (!entry) {
		eprintf(DEBUG_ERROR, "out of memory");
		exit(1);
	}
	memset(entry, 0, sizeof(struct packet_cb_list_entry));
	entry->cb = cb;
	entry->next = packet_cb_list;
	packet_cb_list = entry;
};

void cb_call_packet_cb(const int ptype, const uint8_t *packet, const int len, const char* ifname, const uint16_t vlanid) {
	for (struct packet_cb_list_entry* entry = packet_cb_list; entry; entry = entry->next) {
		entry->cb(ptype, packet, len, ifname, vlanid);
	}
};

void cb_add_handle(int h, void* ctx, handle_cb cb) {
	struct handle_cb_list_entry* entry = malloc(sizeof(struct handle_cb_list_entry));
	if (!entry) {
		eprintf(DEBUG_ERROR, "out of memory");
		exit(1);
	}
	if(!h) {
		eprintf(DEBUG_ERROR, "no handle given");
		exit(1);
	}
	if (!cb) {
		eprintf(DEBUG_ERROR, "no cb given");
		exit(1);
	}
	memset(entry, 0, sizeof(struct handle_cb_list_entry));
	entry->h = h;
	entry->cb = cb;
	entry->ctx = ctx;
	entry->next = handle_cb_list;
	handle_cb_list = entry;
};

void signal_cb_int(int s) {
	for (struct signal_cb_list_entry* entry = signal_cb_list; entry; entry = entry->next) {
		if (entry->s == s) {
			entry->called++;
			signalCalled = 1;
		}
	}
};

void cb_add_signal(int s, signal_cb cb) {
	struct signal_cb_list_entry* entry = malloc(sizeof(struct signal_cb_list_entry));
	if (!entry) {
		eprintf(DEBUG_ERROR, "out of memory");
		exit(1);
	}
	memset(entry, 0, sizeof(struct signal_cb_list_entry));
	if(!s) {
		eprintf(DEBUG_ERROR, "no signal given");
		exit(1);
	}
	if (!cb) {
		eprintf(DEBUG_ERROR, "no cb given");
		exit(1);
	}
	entry->s = s;
	entry->cb = cb;
	entry->next = signal_cb_list;
	signal_cb_list = entry;
	signal(s, signal_cb_int);
};

void event_runloop() {
	fd_set rfds;
	int maxfd, retval;

        // Block SIGALRM and SIGUSR1
        sigset_t sigset, oldset;
        sigemptyset(&sigset);
	for (struct signal_cb_list_entry* entry = signal_cb_list; entry; entry = entry->next) {
        	sigaddset (&sigset, entry->s);
	}
        sigprocmask(SIG_BLOCK, &sigset, &oldset);

	while (1) {
		FD_ZERO(&rfds);
		maxfd = -1;
		for (struct handle_cb_list_entry* entry = handle_cb_list; entry; entry = entry->next) {
			FD_SET(entry->h, &rfds);
			if (maxfd < entry->h) {
				maxfd = entry->h;
			}
		}
		signalCalled = 0;
		retval = pselect(maxfd+1, &rfds, NULL, NULL, NULL, &oldset);
		if (retval < 0 && errno != EINTR)
			break;
		if (retval > 0) {
			for (struct handle_cb_list_entry* entry = handle_cb_list; entry; entry = entry->next) {
				if (FD_ISSET(entry->h, &rfds)) {
					entry->cb(entry->h, entry->ctx);
				}
			}
		}
		if (signalCalled > 0) {
			for (struct signal_cb_list_entry* entry = signal_cb_list; entry; entry = entry->next) {
				if (entry->called > 0) {
					entry->called = 0;
					entry->cb(entry->s);
				}
			}
		}
	}
	eprintf(DEBUG_ERROR, "exit due to: %s (%d)", strerror(errno), errno);
};
