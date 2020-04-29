/**
 *  This file is part of nftables-dhcpsnoopingd.
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
 *  along with nftables-dhcpsnoopingd.
 *  If not, see <http://www.gnu.org/licenses/>.
 *
 *  (C) 2013, Michael Braun <michael-dev@fami-braun.de>
 */


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

#ifndef CHAINNAME1
#define CHAINNAME1 "dhcpsnooping"
#endif
#ifndef CHAINNAME2
#define CHAINNAME2 "dhcpsnooping"
#endif
#ifndef TBL1
#define TBL1 "nat"
#endif
#ifndef TBL2
#define TBL2 "nat"
#endif
#ifndef SETNAME
#define SETNAME "leases-s"
#endif
#ifndef MAPNAME
#define MAPNAME "leases-m"
#endif
#ifndef NFTABLES
#define NFTABLES "nft"
#endif

#ifdef __USE_NFTABLES__

static int disabled = 0;
static int legacy = 0;
static int dry = 0;

static const char *nftcmd = NFTABLES;
static const char *chain1 = CHAINNAME1;
static const char *chain2 = CHAINNAME2;
static const char *tbl1 = TBL1;
static const char *tbl2 = TBL2;
static const char *setname = SETNAME;
static const char *mapname = MAPNAME;

enum {
	CFG_NFTCMD,
	CFG_CHAIN1,
	CFG_CHAIN2,
	CFG_TBL1,
	CFG_TBL2,
	CFG_SET,
	CFG_MAP
};

static void set_nftables(int c, void *arg)
{

	if (!optarg) {
		eprintf(DEBUG_ERROR, "missing arg");
		exit(254);
	}

	switch (c) {
	case CFG_NFTCMD:
		nftcmd = optarg;
		break;
	case CFG_CHAIN1:
		chain1 = optarg;
		break;
	case CFG_CHAIN2:
		chain2 = optarg;
		break;
	case CFG_TBL1:
		tbl1 = optarg;
		break;
	case CFG_TBL2:
		tbl2 = optarg;
		break;
	case CFG_SET:
		setname = optarg;
		break;
	case CFG_MAP:
		mapname = optarg;
		break;
	};
}

static void nftables_run(const char* cmd) {
	eprintf(DEBUG_GENERAL, "run \"%s\"", cmd);
	if (dry) return;

	if (system(cmd)) {
		eprintf(DEBUG_ERROR, "cmd \"%s\" failed", cmd);
	} else {
		eprintf(DEBUG_GENERAL, "cmd \"%s\" ok", cmd);
	}
}

static void nftables_novlan(const int add, const struct in_addr* ip, const uint8_t* mac, const char* ifname) {
	char cmd[65535];

	if (legacy) {
		/* this needs to use insert (add rule to beginning) because non-base chains cannot have a policy (default-rule)
		 * so we have a drop rule in the end of the chain and do want to insert before not after that
		 */
		snprintf(cmd, sizeof(cmd),"%s %s rule bridge %s %s ether saddr %s ip saddr %s meta ibrname \"%s\" return",
			 nftcmd, add ? "insert" : "delete", tbl1, chain1, ether_ntoa_z((struct ether_addr *)mac), inet_ntoa(*ip), ifname);
		nftables_run(cmd);
		snprintf(cmd, sizeof(cmd), "%s %s rule bridge %s %s ether saddr %s arp saddr ip %s meta ibrname \"%s\" return",
			 nftcmd, add ? "insert" : "delete", tbl1, chain1, ether_ntoa_z((struct ether_addr *)mac), inet_ntoa(*ip), ifname);
		nftables_run(cmd);
		snprintf(cmd, sizeof(cmd), "%s %s rule bridge %s %s arp daddr ip %s meta ibrname %s dnat %s return",
			 nftcmd, add ? "insert" : "delete", tbl2, chain2, inet_ntoa(*ip), ifname, ether_ntoa_z((struct ether_addr *)mac));
		nftables_run(cmd);
	} else {
		snprintf(cmd, sizeof(cmd), "%s %s element bridge %s %s { \"%s\" . %s . %s }",
			 nftcmd, add ? "add" : "delete", tbl1, setname, ifname, ether_ntoa_z((struct ether_addr *)mac), inet_ntoa(*ip));
		nftables_run(cmd);
		snprintf(cmd, sizeof(cmd), "%s %s element bridge %s %s { \"%s\" . %s : %s }",
			 nftcmd, add ? "add" : "delete", tbl2, mapname, ifname, inet_ntoa(*ip), ether_ntoa_z((struct ether_addr *)mac));
		nftables_run(cmd);
	}
}

static void nftables_vlan(const int add, const struct in_addr* ip, const uint8_t* mac, const char* ifname, const int vlanid) {
	char cmd[65535];

	if (legacy) {
		/* this needs to use insert (add rule to beginning) because non-base chains cannot have a policy (default-rule)
		 * so we have a drop rule in the end of the chain and do want to insert before not after that
		 */
		snprintf(cmd, sizeof(cmd), "%s %s rule bridge %s %s ether saddr %s vlan id %d ip saddr %s meta ibrname \"%s\" return",
			 nftcmd, add ? "insert" : "delete", tbl1, chain1, ether_ntoa_z((struct ether_addr *)mac), vlanid, inet_ntoa(*ip), ifname);
		nftables_run(cmd);
		snprintf(cmd, sizeof(cmd), "%s %s rule bridge %s %s ether saddr %s vlan id %d arp saddr ip %s meta ibrname \"%s\" return",
			 nftcmd, add ? "insert" : "delete", tbl1, chain1, ether_ntoa_z((struct ether_addr *)mac), vlanid, inet_ntoa(*ip), ifname);
		nftables_run(cmd);
		snprintf(cmd, sizeof(cmd), "%s %s rule bridge %s %s vlan id %d arp daddr ip %s meta ibrname %s dnat %s return",
			 nftcmd, add ? "insert" : "delete", tbl2, chain2, vlanid, inet_ntoa(*ip), ifname, ether_ntoa_z((struct ether_addr *)mac));
		nftables_run(cmd);
	} else {
		snprintf(cmd, sizeof(cmd), "%s %s element bridge %s %s { \"%s\" . %s . %d . %s }",
			 nftcmd, add ? "add" : "delete", tbl1, setname, ifname, ether_ntoa_z((struct ether_addr *)mac), vlanid, inet_ntoa(*ip));
		nftables_run(cmd);
		snprintf(cmd, sizeof(cmd), "%s %s element bridge %s %s { \"%s\" . %d . %s : %s }",
			 nftcmd, add ? "add" : "delete", tbl2, mapname, ifname, vlanid, inet_ntoa(*ip), ether_ntoa_z((struct ether_addr *)mac));
		nftables_run(cmd);
	}
}

static void nftables_do(const char* ifname, const int vlanid, const uint8_t* mac, const struct in_addr* ip, const int start)
{
	if (disabled)
		return;

	assert(ip); assert(mac); assert(ifname);
	eprintf(DEBUG_VERBOSE, "%s nftables rule: MAC: %s IP: %s BRIDGE: %s VLAN: %d", start ? "add" : "delete", ether_ntoa_z((struct ether_addr *)mac), inet_ntoa(*ip), ifname, vlanid);
	if (vlanid == 0)
		nftables_novlan(start, ip, mac, ifname);
	else
		nftables_vlan(start, ip, mac, ifname, vlanid);
}

static void disable_nftables(int c, void *arg)
{
	disabled = 1;
}

static void enable_nftables_legacy(int c, void *arg)
{
	/* delete rules by statement is not yet implemented by nft, but we do not have a cache here so just ignore it for now
	 * see https://wiki.nftables.org/wiki-nftables/index.php/Simple_rule_management
	 */
	legacy = 1;
}

static void dry_nftables(int c, void *arg)
{
	dry = 1;
}

static __attribute__((constructor)) void nftables_init()
{
        static struct option de_option = {"disable-nftables", no_argument, 0, 0};
        add_option_cb(de_option, disable_nftables, NULL);
        static struct option le_option = {"nftables-legacy", no_argument, 0, 0};
        add_option_cb(le_option, enable_nftables_legacy, NULL);
        static struct option dry_option = {"dry-nftables", no_argument, 0, 0};
        add_option_cb(dry_option, dry_nftables, NULL);
	struct option CFG_NFTCMD_option = {"nft-cmd", required_argument, 0, CFG_NFTCMD };
	add_option_cb(CFG_NFTCMD_option, set_nftables, NULL);
	struct option CFG_CHAIN1_option = {"nft-chain1", required_argument, 0, CFG_CHAIN1 };
	add_option_cb(CFG_CHAIN1_option, set_nftables, NULL);
	struct option CFG_CHAIN2_option = {"nft-chain2", required_argument, 0, CFG_CHAIN2 };
	add_option_cb(CFG_CHAIN2_option, set_nftables, NULL);
	struct option CFG_TBL1_option = {"nft-tbl1", required_argument, 0, CFG_TBL1 };
	add_option_cb(CFG_TBL1_option, set_nftables, NULL);
	struct option CFG_TBL2_option = {"nft-tbl2", required_argument, 0, CFG_TBL2 };
	add_option_cb(CFG_TBL2_option, set_nftables, NULL);
	struct option CFG_SET_option = {"nft-setname", required_argument, 0, CFG_SET };
	add_option_cb(CFG_SET_option, set_nftables, NULL);
	struct option CFG_MAP_option = {"nft-mapname", required_argument, 0, CFG_MAP };
	add_option_cb(CFG_MAP_option, set_nftables, NULL);
	add_lease_start_stop_hook(nftables_do);
}

#endif
