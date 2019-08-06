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

#include <assert.h>
#include <sys/types.h>
#include <net/if.h>
#define _LINUX_IF_H
#include <linux/netfilter/nfnetlink_log.h>
#include <linux/netfilter/nfnetlink_log.h>
#include <netlink/netfilter/nfnl.h>
#include <netlink/netfilter/log.h>
#include <netlink/netfilter/log_msg.h>
#include <netlink/route/neighbour.h>
#include <netlink/route/link.h>
#include <netlink/route/rtnl.h>
#include <netlink/cache.h>
#include <netlink/msg.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <libnet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fdb.h"
#include "debug.h"
#include "dhcp.h"
#include "dhcp-ack.h"
#include "event.h"
#include "cmdline.h"
#include "timer.h"

#define ROAMIFPREFIX "wl"
static int numRoamIfPrefix = 0;
static char **roamIfPrefix = NULL;

struct helper2 {
	char* ifname;
	int ifidx;
};

void fdb_del_by_ifname_and_port(struct cache_fdb_entry* entry, void* ctx) {
	struct helper2* tmp = (struct helper2* ) ctx;

	/* DELLINK does not care for VLANID */
	if (strncmp(entry->bridge, tmp->ifname, IF_NAMESIZE) != 0 && entry->portidx != tmp->ifidx) {
		return;
	}
	entry->enabled = 0;
}

void obj_input_dellink(struct rtnl_link *link)
{
	char *ifname = rtnl_link_get_name(link);
	unsigned int ifidx = rtnl_link_get_ifindex(link);

	eprintf(DEBUG_NEIGH,  "DELLINK message for %s (%d) received, pruning", ifname, ifidx);

	struct helper2 tmp = { ifname, ifidx };
	update_fdb(fdb_del_by_ifname_and_port, &tmp);
}

int get_lladdr(struct rtnl_neigh *neigh, char *lladdr, int size)
{
	struct nl_addr* addr = rtnl_neigh_get_lladdr(neigh);
	if (nl_addr_get_family(addr) != AF_LLC) {
		eprintf(DEBUG_NEIGH,  "addr family %d != AF_LLC (%d), ignore", nl_addr_get_family(addr), AF_LLC);
		addr = NULL;
		return 1;
	}
	nl_addr2str(addr, lladdr, size);
	addr = NULL;
	return 0;
}

int get_link_by_idx(int ifidx, struct rtnl_link **link)
{
	*link = NULL;

	if (ifidx <= 0)
		return 1;

	static struct nl_sock *sock = NULL;
	if (!sock) {
		sock = nl_socket_alloc();
		if (sock < 0) {
			eprintf(DEBUG_ERROR, "cannot alloc socket (III): %s", strerror(errno));
			sock = NULL;
			return 1;
		}
		if (nl_connect(sock, NETLINK_ROUTE) < 0) {
			eprintf(DEBUG_ERROR, "cannot conncet socket (III): %s", strerror(errno));
			nl_socket_free(sock);
			sock = NULL;
			return 1;
		}
	}

	if (rtnl_link_get_kernel(sock, ifidx, NULL, link) < 0) {
		eprintf(DEBUG_ERROR, "failed to fetch link %d from kernel", ifidx);
		*link = NULL;
		return 1;
	}

	return 0;
}

void obj_input_neigh(int type, struct rtnl_neigh *neigh)
{
	int family = rtnl_neigh_get_family(neigh);
	if (family != AF_BRIDGE) {
		eprintf(DEBUG_NEIGH,  "family %d != AF_BRIDGE (%d), ignore", family, AF_BRIDGE);
		return;
	}

	char lladdr[32];
	if (get_lladdr(neigh, lladdr, 32))
		return;

	// need brige and at best port
	int ifidx = rtnl_neigh_get_ifindex(neigh);
	struct rtnl_link *link = NULL, *bridge = NULL;

	if (get_link_by_idx(ifidx, &link)) {
		if (type == RTM_NEWNEIGH) {
			eprintf(DEBUG_ERROR, "failed to fetch link when handling %s, lladdr = %s, family=AF_BRIDGE ifidx=%d", (type == RTM_NEWNEIGH ? "NEWNEIGH" : "DELNEIGH" ), lladdr, ifidx);
			goto out;
		}
		/* RTM_DELNEIGH also works without interface resolution */
	}
	if (type == RTM_NEWNEIGH)
		assert(link);

	char *linkifname = NULL;
	char *bridgeifname = NULL;
	if (link) {
		linkifname = rtnl_link_get_name(link);
		if (!linkifname) {
			eprintf(DEBUG_ERROR, "missing link ifname: ifidx=%d", ifidx);
			goto out;
		}

		unsigned int bridgeidx = rtnl_link_get_master(link);
		if (bridgeidx == 0) {
			eprintf(DEBUG_ERROR, "missing bridge idx: link %s(%d) has no master", linkifname, ifidx);
			goto out;
		}

		if (get_link_by_idx(bridgeidx, &bridge)) {
			eprintf(DEBUG_ERROR,  "failed to fetch bridge link %d from kernel, aborting", bridgeidx);
			goto out;
		}
		assert(bridge);

		bridgeifname = rtnl_link_get_name(bridge);
		if (!bridgeifname) {
			eprintf(DEBUG_ERROR, "missing bridge ifname: %s (%d)", strerror(errno), errno);
			goto out;
		}
		eprintf(DEBUG_NEIGH, "got %s, lladdr = %s, family=AF_BRIDGE iface=%s br-iface=%s", (type == RTM_NEWNEIGH ? "NEWNEIGH" : "DELNEIGH" ), lladdr, linkifname, bridgeifname);

		int match = 0;
		for (int i = 0; i < numRoamIfPrefix; i++)
			match |= (strncmp(linkifname, roamIfPrefix[i], strlen(roamIfPrefix[i])) == 0);

		if (!match)
			type = RTM_DELNEIGH;
	}

#ifdef __USE_VLAN__
       	int vlanid = rtnl_neigh_get_vlan(neigh);
#else
	const int vlanid = -1;
#endif
	struct ether_addr *mac = ether_aton(lladdr);
	int exists;
	{
		struct cache_fdb_entry* entry = get_fdb_entry((uint8_t*) mac, bridgeifname, vlanid, ifidx);
		exists = (entry && entry->enabled);
		switch (type) {
			case RTM_DELNEIGH:
				if (exists) {
					eprintf(DEBUG_GENERAL | DEBUG_VERBOSE, "delete neigh %s on %s vlan %d", lladdr, entry->bridge, vlanid);
					entry->enabled = 0;
				}
			break;
			case RTM_NEWNEIGH:
				if (!exists) {
					assert(bridgeifname);
					eprintf(DEBUG_GENERAL | DEBUG_VERBOSE, "add neigh %s on %s on %s vlan %d", lladdr, (bridgeifname ? bridgeifname : "NULL"), (linkifname ? linkifname : "NULL"), vlanid);
					if (!entry)
						add_fdb_entry((uint8_t*) mac, bridgeifname, vlanid, 1, ifidx);
					else
						entry->enabled = 1;
				}
			break;
		}
	}

	if (type == RTM_NEWNEIGH && !exists) {
		lease_lookup_by_mac(bridgeifname, vlanid, (uint8_t*) mac, updated_lease);
	}
out:
	if (link)
		rtnl_link_put(link);
	if (bridge)
		rtnl_link_put(bridge);
}

void obj_input_route(struct nl_object *obj, void *arg)
{
	if (isdebug(DEBUG_NEIGH)) {
		char buf[4096];
		nl_object_dump_buf(obj, buf, sizeof(buf));
		eprintf(DEBUG_NEIGH,  "received %s", buf);
	}

	int type = nl_object_get_msgtype(obj);
	switch (type) {
	case RTM_NEWNEIGH:
	case RTM_DELNEIGH:
		obj_input_neigh(type, (struct rtnl_neigh *) obj);
		break;
	case RTM_DELLINK:
		obj_input_dellink((struct rtnl_link *) obj);
		break;
	case RTM_NEWLINK:
		break;
	default:
		eprintf(DEBUG_NEIGH,  "type %d != RTM_NEWNEIGH (%d), RTM_DELNEIGH (%d), RTM_NEWLINK (%d), RTM_DELLINK (%d) ignore", type, RTM_NEWNEIGH, RTM_DELNEIGH, RTM_NEWLINK, RTM_DELLINK);
		break;
	}
}

int event_input_route(struct nl_msg *msg, void *arg)
{
	if (isdebug(DEBUG_NEIGH)) {
		char buf[4096] = {0};
		FILE *ofd;

		ofd = fmemopen(buf, sizeof(buf), "w");
		if (ofd) {
			nl_msg_dump(msg, ofd);
			fclose(ofd);
			eprintf(DEBUG_NEIGH,  "received message: %s", buf);
		} else {
			eprintf(DEBUG_NEIGH,  "received message");
		}
	}

        if (nl_msg_parse(msg, &obj_input_route, NULL) < 0)
		eprintf(DEBUG_NEIGH,  "<<EVENT:Route>> Unknown message type");
	return NL_OK;
}

void bridge_receive(int s, void* ctx)
{
	struct nl_sock *nf_sock_route = (struct nl_sock *) ctx;
	int ret;
	ret = nl_recvmsgs_default(nf_sock_route);
	if (ret < 0) {
		eprintf(DEBUG_ERROR,  "receiving ROUTE->NEIGH failed on %d error %s", s, strerror(errno));
	}
}

void add_roamifprefix(char* ifname) {
	char** tmp = realloc(roamIfPrefix, (numRoamIfPrefix+1) * sizeof(*roamIfPrefix));
	if (!tmp) {
		eprintf(DEBUG_ERROR, "%s:%d %s error parsing command line", __FILE__, __LINE__, __PRETTY_FUNCTION__);
		exit(1);
	}

	tmp[numRoamIfPrefix] = calloc(strlen(ifname)+1, sizeof(char));
	if (!tmp[numRoamIfPrefix]) {
		eprintf(DEBUG_ERROR, "%s:%d %s error parsing command line", __FILE__, __LINE__, __PRETTY_FUNCTION__);
		exit(1);
	}
	strcpy(tmp[numRoamIfPrefix], ifname);
	roamIfPrefix = tmp;
	numRoamIfPrefix++;
}

void set_roamifprefix(int c) {
	static int called = 0;

	if (!optarg)
		return;

	if (!called) {
		called++;
		numRoamIfPrefix = 0;
	}

	fprintf(stderr, "roaming if prefix %s\n", optarg);
	add_roamifprefix(optarg);
}

static __attribute__((constructor)) void bridge_init()
{
	add_roamifprefix(ROAMIFPREFIX);

	{
		struct option long_option = {"roamifprefix", required_argument, 0, 0};
		add_option_cb(long_option, set_roamifprefix);
	}

	eprintf(DEBUG_ERROR,  "Listen to ROUTE->NEIGH notifications");
	/* connect to netlink route to get notified of bridges learning new addresses */
	struct nl_sock *nf_sock_route;
	nf_sock_route = nl_socket_alloc();
	if (nf_sock_route < 0) {
		eprintf(DEBUG_ERROR, "cannot alloc socket (II): %s", strerror(errno));
		exit(254);
	}
	nl_socket_disable_seq_check(nf_sock_route);
	nl_socket_modify_cb(nf_sock_route, NL_CB_VALID, NL_CB_CUSTOM, event_input_route, NULL);

	if (nl_connect(nf_sock_route, NETLINK_ROUTE) < 0) {
		eprintf(DEBUG_ERROR, "cannot connect II: %s", strerror(errno));
		exit(254);
	}

        if (nl_socket_add_membership(nf_sock_route, RTNLGRP_NEIGH)) {
		eprintf(DEBUG_ERROR, "cannot bind to GRPNEIGH: %s", strerror(errno));
		exit(254);
	}

        if (nl_socket_add_membership(nf_sock_route, RTNLGRP_LINK)) {
		eprintf(DEBUG_ERROR, "cannot bind to GRPLINK: %s", strerror(errno));
		exit(254);
	}

	int rffd = nl_socket_get_fd(nf_sock_route);
	cb_add_handle(rffd, nf_sock_route, bridge_receive);

	/* connect to netlink route to get notified of all known bridge addresses */
	nf_sock_route = nl_socket_alloc();
	if (nf_sock_route < 0) {
		eprintf(DEBUG_ERROR, "cannot alloc socket (II): %s", strerror(errno));
		exit(254);
	}
	nl_socket_disable_seq_check(nf_sock_route);
	nl_socket_modify_cb(nf_sock_route, NL_CB_VALID, NL_CB_CUSTOM, event_input_route, NULL);
	nl_socket_disable_auto_ack(nf_sock_route);

	if (nl_connect(nf_sock_route, NETLINK_ROUTE) < 0) {
		eprintf(DEBUG_ERROR, "cannot connect II: %s", strerror(errno));
		exit(254);
	}

	/* nl_rtgen_request(nf_sock_route, RTM_GETNEIGH, AF_BRIDGE, NLM_F_DUMP)
	 * produces an undersized payload and thus gets discarded by the kernel.
	 */
	struct ndmsg msg = { 0 };
	msg.ndm_family = AF_BRIDGE;
	if (nl_send_simple(nf_sock_route, RTM_GETNEIGH, NLM_F_DUMP, &msg, sizeof(msg)) < 0) {
		eprintf(DEBUG_ERROR, "cannot request fdb dump: %s", strerror(errno));
		exit(254);
	}

	rffd = nl_socket_get_fd(nf_sock_route);
	cb_add_handle(rffd, nf_sock_route, bridge_receive);
}

#endif
