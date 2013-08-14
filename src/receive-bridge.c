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
#include <netlink/cache.h>
#include <netlink/msg.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <libnet.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#include "fdb.h"
#include "debug.h"
#include "dhcp-ack.h"
#include "dhcp.h"
#include "event.h"

#define ROAMIFPREFIX "wl"
struct helper2 {
	char* ifname;
	int ifidx;
};

void fdb_del_by_ifname_and_port(struct cache_fdb_entry* entry, void* ctx) {
	struct helper2* tmp = (struct helper2* ) ctx;

	if (strncmp(entry->bridge, tmp->ifname, IF_NAMESIZE) != 0 && entry->portidx != tmp->ifidx) {
		return;
	}
	entry->enabled = 0;
}

void obj_input_dellink(struct rtnl_link *link)
{
	char *ifname = rtnl_link_get_name(link);
	unsigned int ifidx = rtnl_link_get_ifindex(link);

	eprintf(DEBUG_NEIGH,  "DELLINK message for %s (%d) received, pruning\n", ifname, ifidx);

	struct helper2 tmp = { ifname, ifidx };
	update_fdb(fdb_del_by_ifname_and_port, &tmp);
}

int get_lladdr(struct rtnl_neigh *neigh, char *lladdr, int size)
{
	struct nl_addr* addr = rtnl_neigh_get_lladdr(neigh);
	if (nl_addr_get_family(addr) != AF_LLC) {
		eprintf(DEBUG_NEIGH,  "addr family %d != AF_LLC (%d), ignore\n", nl_addr_get_family(addr), AF_LLC);
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

	static struct nl_sock *sock = NULL;
	if (!sock) {
		sock = nl_socket_alloc();
		if (sock < 0) {
			eprintf(DEBUG_ERROR, "cannot alloc socket (III): %s\n", strerror(errno));
			sock = NULL;
			return 1;
		}
		if (nl_connect(sock, NETLINK_ROUTE) < 0) {
			eprintf(DEBUG_ERROR, "cannot conncet socket (III): %s\n", strerror(errno));
			nl_socket_free(sock);
			sock = NULL;
			return 1;
		}
	}

	if (rtnl_link_get_kernel(sock, ifidx, NULL, link) < 0) {
		*link = NULL;
		return 1;
	}

	return 0;
}

void obj_input_neigh(int type, struct rtnl_neigh *neigh)
{
	int family = rtnl_neigh_get_family(neigh);
	if (family != AF_BRIDGE) {
		eprintf(DEBUG_NEIGH,  "family %d != AF_BRIDGE (%d), ignore\n", family, AF_BRIDGE);
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
			eprintf(DEBUG_NEIGH,  "failed to fetch link %d from kernel\n", ifidx);
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
			eprintf(DEBUG_ERROR, "missing link ifname: %s\n", strerror(errno));
			goto out;
		}

		unsigned int bridgeidx = rtnl_link_get_master(link);
		if (bridgeidx == 0) {
			eprintf(DEBUG_ERROR, "missing bridge idx: %s\n", strerror(errno));
			goto out;
		}

		if (get_link_by_idx(bridgeidx, &bridge)) {
			eprintf(DEBUG_NEIGH,  " failed to fetch bridge link %d from kernel\n", bridgeidx);
			goto out;
		}
		assert(bridge);

		bridgeifname = rtnl_link_get_name(bridge);
		if (!bridgeifname) {
			eprintf(DEBUG_ERROR, "missing bridge ifname: %s\n", strerror(errno));
			goto out;
		}
		eprintf(DEBUG_NEIGH, "got %s, lladdr = %s, family=AF_BRIDGE iface=%s br-iface=%s", (type == RTM_NEWNEIGH ? "NEWNEIGH" : "DELNEIGH" ), lladdr, linkifname, bridgeifname);

		if (strncmp(linkifname, ROAMIFPREFIX, strlen(ROAMIFPREFIX)) != 0) {
//			eprintf(DEBUG_NEIGH, "\nprefix of ifname is not %s -> DELETE\n", ROAMIFPREFIX);
			type = RTM_DELNEIGH;
		}
	}

	struct ether_addr *mac = ether_aton(lladdr);
	{
		struct cache_fdb_entry* entry = get_fdb_entry((uint8_t*) mac, bridgeifname, ifidx);
		switch (type) {
			case RTM_DELNEIGH:
				if (entry) {
					eprintf(DEBUG_GENERAL, "delete neigh %s on %s on %s", lladdr, (bridgeifname ? bridgeifname : "NULL"), (linkifname ? linkifname : "NULL"));
					entry->enabled = 0;
				}
			break;
			case RTM_NEWNEIGH:
				assert(bridgeifname);
				eprintf(DEBUG_GENERAL, "add neigh %s on %s on %s", lladdr, (bridgeifname ? bridgeifname : "NULL"), (linkifname ? linkifname : "NULL"));
				if (!entry)
					add_fdb_entry((uint8_t*) mac, bridgeifname, 1, ifidx);
				else
					entry->enabled = 1;
			break;
		}
	}

	if (type == RTM_NEWNEIGH) {
		lease_lookup_by_mac(bridgeifname, (uint8_t*) mac, add_ack_entry_if_not_found);
	}
out:
	if (link)
		rtnl_link_put(link);
	if (bridge)
		rtnl_link_put(bridge);
}

void obj_input_route(struct nl_object *obj, void *arg)
{
//	eprintf(DEBUG_NEIGH,  "obj_input_route...\n");

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
		eprintf(DEBUG_NEIGH,  "type %d != RTM_NEWNEIGH (%d), RTM_DELNEIGH (%d), RTM_NEWLINK (%d), RTM_DELLINK (%d) ignore\n", type, RTM_NEWNEIGH, RTM_DELNEIGH, RTM_NEWLINK, RTM_DELLINK);
		break;
	}
}

int event_input_route(struct nl_msg *msg, void *arg)
{
        if (nl_msg_parse(msg, &obj_input_route, NULL) < 0)
		eprintf(DEBUG_NEIGH,  "<<EVENT:Route>> Unknown message type\n");
	return NL_STOP;
}

void bridge_receive(int s, void* ctx)
{
	struct nl_sock *nf_sock_route = (struct nl_sock *) ctx;
	nl_recvmsgs_default(nf_sock_route);
}

static __attribute__((constructor)) void bridge_init()
{
	eprintf(DEBUG_ERROR,  "Listen to ROUTE->NEIGH notifications\n");
	/* connect to netlink route to get notified of bridges learning new addresses */
	struct nl_sock *nf_sock_route;
	nf_sock_route = nl_socket_alloc();
	if (nf_sock_route < 0) {
		eprintf(DEBUG_ERROR, "cannot alloc socket (II): %s\n", strerror(errno));
		exit(254);
	}
	nl_socket_disable_seq_check(nf_sock_route);
	nl_socket_modify_cb(nf_sock_route, NL_CB_VALID, NL_CB_CUSTOM, event_input_route, NULL);

	if (nl_connect(nf_sock_route, NETLINK_ROUTE) < 0) {
		eprintf(DEBUG_ERROR, "cannot connect II: %s\n", strerror(errno));
		exit(254);
	}

        if (nl_socket_add_membership(nf_sock_route, RTNLGRP_NEIGH)) {
		eprintf(DEBUG_ERROR, "cannot bind to GRPNEIGH: %s\n", strerror(errno));
		exit(254);
	}

        if (nl_socket_add_membership(nf_sock_route, RTNLGRP_LINK)) {
		eprintf(DEBUG_ERROR, "cannot bind to GRPLINK: %s\n", strerror(errno));
		exit(254);
	}

	int rffd = nl_socket_get_fd(nf_sock_route);
	cb_add_handle(rffd, nf_sock_route, bridge_receive);
}

#endif
