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
#include "dhcp-ack.h"
#include "ebtables.h"
#include "signal.h"
#include "debug.h"
#include "event.h"
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>

/* global cache of dhcp acks (linked list)
 * fields: bridge name, mac, ip, lifetime
 */

struct cache_ack_update_cb_entry {
	ack_update_cb cb;
	void* ctx;
	struct cache_ack_update_cb_entry* next;
};

static struct cache_ack_entry* globalAckCache = NULL;
static struct cache_ack_update_cb_entry* globalAckUpdatCbList = NULL;

struct cache_ack_entry* get_ack_entry(const struct in_addr* yip, const uint8_t* mac, const char* ifname) 
{
	struct cache_ack_entry* entry = globalAckCache;
	while (entry != NULL) {
		if (memcmp(&entry->ip, yip, sizeof(struct in_addr)) == 0
		    && memcmp(entry->mac, mac, ETH_ALEN) == 0
		    && strncmp(entry->bridge, ifname, IF_NAMESIZE) == 0) {
			break;
		}
		entry = entry->next;
	}
	return entry;
}

struct cache_ack_entry* add_ack_entry(const struct in_addr* yip, const uint8_t* mac, const char* ifname, const uint32_t expiresAt) 
{
	struct cache_ack_entry* entry = malloc(sizeof(struct cache_ack_entry));
	if (!entry) {
		eprintf(DEBUG_ERROR, "out of memory at %s:%d in %s", __FILE__, __LINE__, __PRETTY_FUNCTION__);
		return NULL;
	}
	memset(entry, 0, sizeof(struct cache_ack_entry));
	memcpy(entry->mac, mac, ETH_ALEN);
	memcpy(&entry->ip,yip,sizeof(struct in_addr));
	strncpy(entry->bridge, ifname, IF_NAMESIZE);
	entry->expiresAt = expiresAt;
	entry->next = globalAckCache;
	globalAckCache = entry;
	return entry;
}

void add_ack_entry_if_not_found(const struct in_addr* yip, const uint8_t* mac, const char* ifname, const uint32_t expiresAt) 
{
	assert(yip); assert(mac); assert(ifname);
	struct cache_ack_entry* entry = get_ack_entry(yip, mac, ifname);
	if (entry == NULL) {
		entry = add_ack_entry(yip, mac, ifname, expiresAt);
		ebtables_add(yip, mac, ifname);
	} else {
		entry->expiresAt = expiresAt;
	}
}

void ack_update(ack_update_cb cb, void* ctx) {
	for(struct cache_ack_entry* entry = globalAckCache; entry; entry = entry->next) {
		cb(entry, ctx);
	}
}

void add_ack_update_cb(ack_update_cb cb, void* ctx) {
	struct cache_ack_update_cb_entry* entry = malloc(sizeof(struct cache_ack_update_cb_entry));
	if (!entry) {
		eprintf(DEBUG_ERROR, "out of memory at %s:%d in %s", __FILE__, __LINE__, __PRETTY_FUNCTION__);
		exit(1);
	}
	memset(entry, 0, sizeof(struct cache_ack_update_cb_entry));
	entry->next = globalAckUpdatCbList;
	entry->cb = cb;
	entry->ctx = ctx;
	globalAckUpdatCbList = entry;
}

void check_expired_ack(int s)
{
	uint32_t now =time(NULL);

	eprintf(DEBUG_DHCP, "check for expired dhcp ack");
	struct cache_ack_entry* entry = globalAckCache;
	struct cache_ack_entry* prev = NULL;
	while (entry != NULL) {
		eprintf(DEBUG_DHCP, "check for expired dhcp ack: mac: %s ip: %s bridge: %s expiresIn: %d", ether_ntoa((struct ether_addr *)entry->mac), inet_ntoa(entry->ip), entry->bridge, entry->expiresAt - now);
		for(struct cache_ack_update_cb_entry* cb_entry = globalAckUpdatCbList; cb_entry; cb_entry = cb_entry->next) {
			cb_entry->cb(entry, cb_entry->ctx);
		}
		eprintf(DEBUG_DHCP, "check for expired dhcp ack after update cb: mac: %s ip: %s bridge: %s expiresIn: %d", ether_ntoa((struct ether_addr *)entry->mac), inet_ntoa(entry->ip), entry->bridge, entry->expiresAt - now);
		if (entry->expiresAt < now) {
			ebtables_del(&entry->ip, entry->mac, entry->bridge);
			if (prev == NULL) {
				globalAckCache = entry->next;
			} else {
				prev->next = entry->next;
			}
			free(entry);
			if (prev == NULL) {
				entry = globalAckCache;
			} else {
				entry = prev->next;
			}
		} else {
			prev = entry;
			entry = entry->next;
		}
	}
}

void dump_ack(int s)
{
	uint32_t now = time(NULL);
	struct cache_ack_entry* entry = globalAckCache;
	while (entry != NULL) {
		eprintf(DEBUG_GENERAL,  "ack: MAC: %s IP: %s BRIDGE: %s expires in %d\n" , ether_ntoa((struct ether_addr *)entry->mac), inet_ntoa(entry->ip), entry->bridge, (int) entry->expiresAt - (int) now);
		entry = entry->next;
	}
}

static __attribute__((constructor)) void dhcp_ack_init()
{
	cb_add_signal(SIGALRM, check_expired_ack);
	cb_add_signal(SIGUSR1, dump_ack);
}
