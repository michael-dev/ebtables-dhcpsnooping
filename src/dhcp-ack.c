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
#include "dhcp.h"
#include "dhcp-ack.h"
#include "ebtables.h"
#include "signal.h"
#include "debug.h"
#include "event.h"
#include "timer.h"
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>

#include <net/if.h>
#include <netinet/ether.h>
#include "ether_ntoa.h"
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


struct cache_ack_entry 
{
	char bridge[IF_NAMESIZE];
	uint8_t mac[ETH_ALEN];
	struct in_addr ip;
	uint32_t expiresAt;
	struct cache_ack_entry* next;
};

/* global cache of dhcp acks (linked list)
 * fields: bridge name, mac, ip, lifetime
 */

static struct cache_ack_entry* globalAckCache = NULL;

void check_expired_ack(void *ctx);

void update_ack_timeout(struct cache_ack_entry* entry) {
       int now = time(NULL);
       int timeout = (entry->expiresAt < now) ? 0 : (entry->expiresAt - time(NULL));

       cb_del_timer(entry, check_expired_ack);
       cb_add_timer(timeout + 1, 0, entry, check_expired_ack);
}

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

void dhcp_update_ack(const uint8_t* mac, const struct in_addr* yip, const char* ifname, const uint32_t expiresAt, const enum t_lease_update_src reason)
{
	int modified = 0;
	uint32_t now =time(NULL);
	assert(yip); assert(mac); assert(ifname);
	struct cache_ack_entry* entry = get_ack_entry(yip, mac, ifname);
	if (entry != NULL) {
		modified = (entry->expiresAt != expiresAt);
		entry->expiresAt = expiresAt;
	} else if (expiresAt > now) {
		entry = add_ack_entry(yip, mac, ifname, expiresAt);
		ebtables_add(yip, mac, ifname);
		modified = 1;
	}
	if (modified) {
		update_ack_timeout(entry);
	}
}

void check_expired_ack(void *ctx)
{
	uint32_t now =time(NULL);
	uint32_t expiresAt;

	if (ctx) {
		eprintf(DEBUG_DHCP | DEBUG_VERBOSE, "check for expired dhcp ack (single)");
	} else {
		eprintf(DEBUG_DHCP | DEBUG_VERBOSE, "check for expired dhcp ack");
	}
	struct cache_ack_entry* entry = globalAckCache;
	struct cache_ack_entry* prev = NULL;
	while (entry != NULL) {
		if (ctx != NULL && entry != ctx)
			goto next;
		expiresAt = entry->expiresAt;

		if (ctx && !(expiresAt < now)) {
			eprintf(DEBUG_ERROR, "check for expired dhcp ack (single): mac: %s ip: %s bridge: %s expiresIn: %d has not yet expired", ether_ntoa_z((struct ether_addr *)entry->mac), inet_ntoa(entry->ip), entry->bridge, expiresAt - now);
		}

		eprintf(DEBUG_DHCP, "check for expired dhcp ack: mac: %s ip: %s bridge: %s expiresIn: %d", ether_ntoa_z((struct ether_addr *)entry->mac), inet_ntoa(entry->ip), entry->bridge, expiresAt - now);
		if (update_lease(entry->bridge, entry->mac, &entry->ip, &expiresAt) >= 0)
		{
			if (expiresAt != entry->expiresAt)
			{
				updated_lease(entry->mac, &entry->ip, entry->bridge,entry-> expiresAt, UPDATED_LEASE_FROM_EXTERNAL);
			}
		}

		if (ctx && !(expiresAt < now)) {
			eprintf(DEBUG_VERBOSE, "check for expired dhcp ack (single): mac: %s ip: %s bridge: %s expiresIn: %d was updated remotely and has not yet expired (we likely missed a UDP packet)", ether_ntoa_z((struct ether_addr *)entry->mac), inet_ntoa(entry->ip), entry->bridge, expiresAt - now);
		}

		eprintf(DEBUG_DHCP, "check for expired dhcp ack after update cb: mac: %s ip: %s bridge: %s expiresIn: %d", ether_ntoa_z((struct ether_addr *)entry->mac), inet_ntoa(entry->ip), entry->bridge, expiresAt - now);
		if (expiresAt < now) {
			ebtables_del(&entry->ip, entry->mac, entry->bridge);
			if (prev == NULL) {
				globalAckCache = entry->next;
			} else {
				prev->next = entry->next;
			}
			cb_del_timer(entry, check_expired_ack);
			free(entry); entry = NULL;
			if (prev == NULL) {
				entry = globalAckCache;
			} else {
				entry = prev->next;
			}
			continue;
		}
next:
		prev = entry;
		entry = entry->next;
	}
}

void dump_ack(int s)
{
	uint32_t now = time(NULL);
	struct cache_ack_entry* entry = globalAckCache;
	while (entry != NULL) {
		eprintf(DEBUG_GENERAL | DEBUG_VERBOSE,  "ack: MAC: %s IP: %s BRIDGE: %s expires in %d" , ether_ntoa_z((struct ether_addr *)entry->mac), inet_ntoa(entry->ip), entry->bridge, (int) entry->expiresAt - (int) now);
		entry = entry->next;
	}
}

static __attribute__((constructor)) void dhcp_ack_init()
{
	cb_add_timer(PRUNE_INTERVAL, 1, NULL, check_expired_ack);
	cb_add_signal(SIGUSR1, dump_ack);
	add_updated_lease_hook(dhcp_update_ack);
}

