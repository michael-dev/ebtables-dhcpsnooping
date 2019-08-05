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

#ifdef __USE_ROAMING__

#include <net/if.h>
#include <netinet/ether.h>
#include <stdint.h>

struct cache_fdb_entry
{
	char bridge[IF_NAMESIZE];
	int vlanid;
	uint8_t mac[ETH_ALEN];
	uint8_t enabled;
	unsigned int portidx;
	struct cache_fdb_entry* next;
};

typedef void (*update_fdb_cb)(struct cache_fdb_entry* entry, void* ctx);

struct cache_fdb_entry* get_fdb_entry(const uint8_t* mac, const char* bridge, const int vlanid, const unsigned int portidx);
struct cache_fdb_entry* add_fdb_entry(const uint8_t* mac, const char* ifname, const int vlanid, uint8_t enabled, unsigned int portidx);
void update_fdb(update_fdb_cb, void* ctx);
#endif
