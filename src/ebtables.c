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

#ifdef __USE_EBTABLES__

#include "config.h"
#include "debug.h"
#include "cmdline.h"
#include "dhcp.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include "ether_ntoa.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef CHAINNAME
#define CHAINNAME "dhcpsnooping"
#endif
#ifndef EBTABLES
#define EBTABLES "ebtables"
#endif

static int disabled = 0;

static void ebtables_run(const char* cmd) {
	eprintf(DEBUG_GENERAL, "run \"%s\"", cmd);
	if (system(cmd)) {
		eprintf(DEBUG_ERROR, "cmd \"%s\" failed", cmd);
	} else {
		eprintf(DEBUG_GENERAL, "cmd \"%s\" ok", cmd);
	}
}

static void ebtables_novlan(const char* op, const struct in_addr* yip, const uint8_t* mac, const char* ifname) {
	char cmd[65535];

	snprintf(cmd, sizeof(cmd), EBTABLES " %s " CHAINNAME " -s %s --proto ipv4 --ip-source %s --logical-in %s -j ACCEPT",
	         op, ether_ntoa_z((struct ether_addr *)mac), inet_ntoa(*yip), ifname);
	ebtables_run(cmd);

	snprintf(cmd, sizeof(cmd), EBTABLES " %s " CHAINNAME " -s %s --proto arp --arp-ip-src %s --logical-in %s -j ACCEPT",
	         op, ether_ntoa_z((struct ether_addr *)mac), inet_ntoa(*yip), ifname);
	ebtables_run(cmd);

	snprintf(cmd, sizeof(cmd), EBTABLES " -t nat %s " CHAINNAME " --proto arp --arp-ip-dst %s --logical-in %s -j dnat --to-destination %s --dnat-target CONTINUE",
	         op, inet_ntoa(*yip), ifname, ether_ntoa_z((struct ether_addr *)mac));
	ebtables_run(cmd);
}

static void ebtables_add_vlan(const char* op, const struct in_addr* yip, const uint8_t* mac, const char* ifname, const uint16_t vlanid) {
	char cmd[65535];

	snprintf(cmd, sizeof(cmd), EBTABLES " %s " CHAINNAME " -s %s --proto 802_1Q --vlan-id %d --vlan-encap ipv4 --ip-source %s --logical-in %s -j ACCEPT",
	         op, ether_ntoa_z((struct ether_addr *)mac), (int) vlanid, inet_ntoa(*yip), ifname);
	ebtables_run(cmd);

	snprintf(cmd, sizeof(cmd), EBTABLES " %s " CHAINNAME " -s %s --proto 802_1Q --vlan-id %d --vlan-encap arp --arp-ip-src %s --logical-in %s -j ACCEPT",
	         op, ether_ntoa_z((struct ether_addr *)mac), (int) vlanid, inet_ntoa(*yip), ifname);
	ebtables_run(cmd);

	snprintf(cmd, sizeof(cmd), EBTABLES " -t nat %s " CHAINNAME " --proto 802_1Q --vlan-id %d --vlan-encap arp --arp-ip-dst %s --logical-in %s -j dnat --to-destination %s --dnat-target CONTINUE",
	         op, (int) vlanid, inet_ntoa(*yip), ifname, ether_ntoa_z((struct ether_addr *)mac));
	ebtables_run(cmd);
}

static void ebtables_do(const char* ifname, const uint16_t vlanid, const uint8_t* mac, const struct in_addr* ip, const int start)
{
	assert(yip); assert(mac); assert(ifname);
	if (disabled)
		return;

	eprintf(DEBUG_VERBOSE, "%s ebtables rule: MAC: %s IP: %s BRIDGE: %s VLAN: %d", (start ? "add" : "delete"), ether_ntoa_z((struct ether_addr *)mac), inet_ntoa(*yip), ifname, (int) vlanid);

	const char* op = start ? "-A" : "-D";

	if (vlanid == 0)
		ebtables_novlan(op, yip, mac, ifname);
	else
		ebtables_vlan(op, yip, mac, ifname, vlanid);
}

static void disable_ebtables(int c)
{
	disabled = 1;
}

static __attribute__((constructor)) void ebtables_init()
{
        static struct option de_option = {"disable-ebtables", no_argument, 0, 0};
        add_option_cb(de_option, disable_ebtables);
	add_lease_start_stop_hook(ebtables_do);
}

#endif
