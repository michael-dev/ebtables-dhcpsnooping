#include "config.h"
#ifdef __USE_ROAMING__

#include "fdb.h"
#include "dhcp.h"
#include "debug.h"
#include "event.h"

#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define FDBMAXSIZE 4096

static struct cache_fdb_entry* globalFdbCache = NULL;
static int globalFdbCacheSize = 0;

struct cache_fdb_entry* get_fdb_entry(const uint8_t* mac, const char* bridge, const unsigned int portidx) 
{
	struct cache_fdb_entry* entry = globalFdbCache;
	while (entry != NULL) {
		if (memcmp(entry->mac, mac, ETH_ALEN) == 0 &&
		    ((bridge && strncmp(entry->bridge, bridge, IF_NAMESIZE) == 0) || entry->portidx == portidx)
		   ) {
			break;
		}
		entry = entry->next;
	}
	return entry;
}

void* get_fdb_entry_wrp(const uint8_t* mac, const char* bridge) {
	return get_fdb_entry(mac, bridge, 0);
}

struct cache_fdb_entry* add_fdb_entry(const uint8_t* mac, const char* ifname, uint8_t enabled, unsigned int portidx) {
	if (globalFdbCacheSize > FDBMAXSIZE) return NULL;
	struct cache_fdb_entry* entry = malloc(sizeof(struct cache_fdb_entry));
	if (!entry) {
		eprintf(DEBUG_ERROR, "out of memory at %s:%d in %s", __FILE__, __LINE__, __PRETTY_FUNCTION__);
		return NULL;
	}
	memset(entry, 0, sizeof(struct cache_fdb_entry));
	memcpy(entry->mac, mac, ETH_ALEN);
	strncpy(entry->bridge, ifname, IF_NAMESIZE);
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

void check_expired_fdb(int s)
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
		eprintf(DEBUG_GENERAL,  "fdb: MAC: %s BRIDGE: %s %s\n" , ether_ntoa((struct ether_addr *)entry->mac), entry->bridge, (entry->enabled ? "enabled" : "disabled"));
		entry = entry->next;
	}
}

static __attribute__((constructor)) void fdb_init()
{
	cb_add_signal(SIGALRM, check_expired_fdb);
	cb_add_signal(SIGUSR1, dump_fdb);
	add_is_local_hook(get_fdb_entry_wrp);
}

#endif
