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

#include "timer.h"
#include "event.h"
#include "debug.h"
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <time.h>

#define SLOT_INTERVAL 1

struct timer_cb_list_entry {
	int lastcalled;
	int timeout;
	int repeat;
	int deleted;
	void* ctx;
	timer_cb cb;
	struct timer_cb_list_entry* next;
};
struct timer_cb_list_entry* timer_cb_list = NULL;

void cb_add_timer(int timeout, int repeat, void* ctx, timer_cb cb)
{
	struct timer_cb_list_entry* entry = malloc(sizeof(struct timer_cb_list_entry));
	if (!entry) {
		eprintf(DEBUG_ERROR, "out of memory");
		exit(1);
	}
	memset(entry, 0, sizeof(struct timer_cb_list_entry));
	entry->cb = cb;
	entry->ctx = ctx;
	entry->timeout = timeout;
	entry->repeat = repeat;
	entry->lastcalled = time(NULL);
	entry->next = timer_cb_list;
	timer_cb_list = entry;
};

void cb_del_timer(void* ctx, timer_cb cb)
{
	struct timer_cb_list_entry* entry = NULL;
	for (entry = timer_cb_list; entry; entry = entry->next) {
		if (entry->cb != cb)
			continue;
		if (entry->ctx != ctx)
			continue;
		entry->deleted = 1;
	}
}

void timer(int s)
{
	alarm (SLOT_INTERVAL);

	struct timer_cb_list_entry* entry = NULL, *prev = NULL, *next = NULL;
	int now = time(NULL);
	timer_cb cb;
	void *ctx = NULL;

	next = timer_cb_list;
	while (next) {
		prev = entry;
		entry = next;
		next = entry->next;

		if (entry->deleted) {
			/* delete entry */
			if (prev) {
				prev->next = next;
			} else {
				timer_cb_list = next;
			}
			free(entry);
			entry = prev;
			continue;
		}

		if (entry->lastcalled + entry->timeout > now)
			continue;

		cb = entry->cb;
		ctx = entry->ctx;

		/* timer needs to fire */
		if (entry->repeat) {
			entry->lastcalled = now;
		} else {
			entry->deleted = 1;
		}

		/* call cb */
		cb(ctx);
	}
}

static __attribute__((constructor)) void timer_init()
{
	cb_add_signal(SIGALRM, timer);
	alarm (SLOT_INTERVAL);
}

