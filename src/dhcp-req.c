#include "config.h"
#include "dhcp-req.h"
#include "dhcp.h"
#include "debug.h"
#include "event.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <signal.h>

static struct cache_req_entry* globalReqCache = NULL;

struct cache_req_entry* get_req_entry(const uint8_t* mac, const char* ifname) 
{
	struct cache_req_entry* entry = globalReqCache;
	while (entry != NULL) {
		if (memcmp(entry->mac, mac, ETH_ALEN) == 0
		    && strncmp(entry->bridge, ifname, IF_NAMESIZE) == 0) {
			break;
		}
		entry = entry->next;
	}
	return entry;
}

void* get_req_entry_wrp(const uint8_t* mac, const char* ifname) {
	return get_req_entry(mac, ifname);
}

struct cache_req_entry* add_req_entry(const uint8_t* mac, const char* ifname, const uint32_t expiresAt) 
{
	struct cache_req_entry* entry = malloc(sizeof(struct cache_req_entry));
	if (!entry) {
		eprintf(DEBUG_ERROR, "out of memory at %s:%d in %s", __FILE__, __LINE__, __PRETTY_FUNCTION__);
		return NULL;
	}
	memset(entry, 0, sizeof(struct cache_req_entry));
	memcpy(entry->mac, mac, ETH_ALEN);
	strncpy(entry->bridge, ifname, IF_NAMESIZE);
	entry->expiresAt = expiresAt;
	entry->next = globalReqCache;
	globalReqCache = entry;
	return entry;
}

void check_expired_req(int s)
{
	uint32_t now = time(NULL);
	struct cache_req_entry* entry = globalReqCache;
	struct cache_req_entry* prev = NULL;
	while (entry != NULL) {
		if (entry->expiresAt < now) {
			if (prev == NULL) {
				globalReqCache = entry->next;
			} else {
				prev->next = entry->next;
			}
			free(entry);
			if (prev == NULL) {
				entry = globalReqCache;
			} else {
				entry = prev->next;
			}
		} else {
			prev = entry;
			entry = entry->next;
		}
	}
}

void dump_req(int s)
{
	uint32_t now = time(NULL);
	struct cache_req_entry* entry = globalReqCache;
	while (entry != NULL) {
		eprintf(DEBUG_GENERAL,  "req: MAC: %s BRIDGE: %s expires in %d\n" , ether_ntoa((struct ether_addr *)entry->mac), entry->bridge, (int) entry->expiresAt - (int) now);
		entry = entry->next;
	}
}

static __attribute__((constructor)) void dhcp_req_init()
{
	cb_add_signal(SIGALRM, check_expired_req);
	cb_add_signal(SIGUSR1, dump_req);
	add_is_local_hook(get_req_entry_wrp);
}

