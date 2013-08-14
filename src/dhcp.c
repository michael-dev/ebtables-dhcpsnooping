#include "config.h"
#include "dhcp.h"
#include "debug.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

struct is_local_entry 
{
	is_local_cb cb;
	struct is_local_entry *next;
};
static struct is_local_entry* globalIsLocalHook = NULL;

struct update_lease_entry 
{
	update_lease_cb cb;
	struct update_lease_entry *next;
};
static struct update_lease_entry* globalUpdateLeaseHook = NULL;

struct updated_lease_entry 
{
	updated_lease_cb cb;
	struct updated_lease_entry *next;
};
static struct updated_lease_entry* globalUpdatedLeaseHook = NULL;

struct lease_lookup_by_mac_entry
{
	lease_lookup_by_mac_cb cb;
	struct lease_lookup_by_mac_entry *next;
};
static struct lease_lookup_by_mac_entry* globalLookupLeaseHook = NULL;

void add_is_local_hook(is_local_cb cb) 
{
	struct is_local_entry *entry = malloc(sizeof(struct is_local_entry));
	if (!entry) {
		eprintf(DEBUG_ERROR, "out of memory at %s:%d in %s", __FILE__, __LINE__, __PRETTY_FUNCTION__);
		exit(1);
	}
	memset(entry, 0, sizeof(struct is_local_entry));
	entry->cb = cb;
	entry->next = globalIsLocalHook;
	globalIsLocalHook = entry;
}

int is_local (const uint8_t* mac, const char* ifname) 
{
	for (struct is_local_entry* entry = globalIsLocalHook; entry; entry = entry->next) {
		if (entry->cb(mac, ifname)) return 1;
	}
	return 0;
}

void add_update_lease_hook(update_lease_cb cb) 
{
	struct update_lease_entry *entry = malloc(sizeof(struct update_lease_entry));
	if (!entry) {
		eprintf(DEBUG_ERROR, "out of memory at %s:%d in %s", __FILE__, __LINE__, __PRETTY_FUNCTION__);
		exit(1);
	}
	memset(entry, 0, sizeof(struct update_lease_entry));
	entry->cb = cb;
	entry->next = globalUpdateLeaseHook;
	globalUpdateLeaseHook = entry;
}

int update_lease(const char* ifname, const uint8_t* mac, const struct in_addr* ip, uint32_t* expiresAt)
{
	for (struct update_lease_entry *entry = globalUpdateLeaseHook; entry; entry = entry->next) {
		if (entry->cb(ifname, mac, ip, expiresAt)) return 1;
	}
	return 0;
}

void add_updated_lease_hook(updated_lease_cb cb) 
{
	struct updated_lease_entry *entry = malloc(sizeof(struct updated_lease_entry));
	if (!entry) {
		eprintf(DEBUG_ERROR, "out of memory at %s:%d in %s", __FILE__, __LINE__, __PRETTY_FUNCTION__);
		exit(1);
	}
	memset(entry, 0, sizeof(struct updated_lease_entry));
	entry->cb = cb;
	entry->next = globalUpdatedLeaseHook;
	globalUpdatedLeaseHook = entry;
}

void updated_lease(const uint8_t* mac, const struct in_addr* yip, const char* ifname, const uint32_t expiresAt)
{
	for (struct updated_lease_entry *entry = globalUpdatedLeaseHook; entry; entry = entry->next) {
		entry->cb(mac, yip, ifname, expiresAt);
	}
}

void add_lease_lookup_by_mac(lease_lookup_by_mac_cb cb)
{
	struct lease_lookup_by_mac_entry *entry = malloc(sizeof(struct lease_lookup_by_mac_entry));
	if (!entry) {
		eprintf(DEBUG_ERROR, "out of memory at %s:%d in %s", __FILE__, __LINE__, __PRETTY_FUNCTION__);
		exit(1);
	}
	memset(entry, 0, sizeof(struct lease_lookup_by_mac_entry));
	entry->cb = cb;
	entry->next = globalLookupLeaseHook;
	globalLookupLeaseHook = entry;
}

void lease_lookup_by_mac(const char* ifname, const uint8_t* mac, lease_cb cb)
{
	for (struct lease_lookup_by_mac_entry *entry = globalLookupLeaseHook; entry; entry = entry->next) {
		entry->cb(ifname, mac, cb);
	}
}

