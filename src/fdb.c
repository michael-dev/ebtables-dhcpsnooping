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
#ifdef __USE_ROAMING__

#include "fdb.h"
#include "dhcp.h"
#include "debug.h"
#include "event.h"
#include "timer.h"

#include <netinet/ether.h>
#include "ether_ntoa.h"

#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define FDBMAXSIZE 4096

static struct cache_fdb_entry* globalFdbCache = NULL;
static int globalFdbCacheSize = 0;

struct cache_fdb_entry* get_fdb_entry(const uint8_t* mac, const char* bridge, const int vlanid, const unsigned int portidx)
{
	struct cache_fdb_entry* entry = globalFdbCache;
	while (entry != NULL) {
		if (memcmp(entry->mac, mac, ETH_ALEN) == 0 &&
		    entry->vlanid == vlanid &&
		    ((bridge && strncmp(entry->bridge, bridge, IF_NAMESIZE) == 0) || entry->portidx == portidx)
		   ) {
			break;
		}
		entry = entry->next;
	}
	return entry;
}

void* get_fdb_entry_wrp(const uint8_t* mac, const char* bridge, const int vlanid) {
	return get_fdb_entry(mac, bridge, vlanid, 0);
}

struct cache_fdb_entry* add_fdb_entry(const uint8_t* mac, const char* ifname, const int vlanid, uint8_t enabled, unsigned int portidx) {
	if (globalFdbCacheSize > FDBMAXSIZE) return NULL;
	struct cache_fdb_entry* entry = malloc(sizeof(struct cache_fdb_entry));
	if (!entry) {
		eprintf(DEBUG_ERROR, "out of memory");
		return NULL;
	}
	memset(entry, 0, sizeof(struct cache_fdb_entry));
	memcpy(entry->mac, mac, ETH_ALEN);
	strncpy(entry->bridge, ifname, IF_NAMESIZE);
	entry->vlanid = vlanid;
	entry->enabled = enabled;
	entry->portidx = portidx;
	entry->next = globalFdbCache;
	globalFdbCache = entry;
	globalFdbCacheSize++;
	return entry;
}

void update_fdb(update_fdb_cb cb, void* ctx) {
	struct cache_fdb_entry* entry;
	for (entry = globalFdbCache; entry; entry = entry->next) {
		cb(entry, ctx);
	}
}

void check_expired_fdb(void *ctx)
{
	struct cache_fdb_entry* entry = globalFdbCache;
	struct cache_fdb_entry* prev = NULL;
	while (entry != NULL) {
		if (!entry->enabled) {
			if (prev == NULL) {
				globalFdbCache = entry->next;
			} else {
				prev->next = entry->next;
			}
			free(entry);
			globalFdbCacheSize--;
			if (prev == NULL) {
				entry = globalFdbCache;
			} else {
				entry = prev->next;
			}
		} else {
			prev = entry;
			entry = entry->next;
		}
	}
}

void dump_fdb(int s)
{
	struct cache_fdb_entry* entry = globalFdbCache;
	while (entry != NULL) {
		eprintf(DEBUG_GENERAL | DEBUG_VERBOSE,  "fdb: MAC: %s BRIDGE: %s VLANID: %d %s" , ether_ntoa_z((struct ether_addr *)entry->mac), entry->bridge, (int) entry->vlanid, (entry->enabled ? "enabled" : "disabled"));
		entry = entry->next;
	}
}

static __attribute__((constructor)) void fdb_init()
{
	cb_add_timer(PRUNE_INTERVAL, 1, NULL, check_expired_fdb);
	cb_add_signal(SIGUSR1, dump_fdb);
	add_is_local_hook(get_fdb_entry_wrp);
}

#endif
