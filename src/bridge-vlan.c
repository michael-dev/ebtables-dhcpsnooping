/**
 *  This file is part of mvrpd.
 *
 *  mvrpd is free software: you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  mvrpd is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with mvrpd.
 *  If not, see <http://www.gnu.org/licenses/>.
 *
 *  (C) 2019, Michael Braun <michael-dev@fami-braun.de>
 */

#include "config.h"
#ifdef __USE_VLAN__

#include <assert.h>
#include <linux/if_bridge.h>
#include <netlink/route/link.h>
#include <fnmatch.h>
#include <errno.h>
#include <net/if.h>

#include "debug.h"
#include "event.h"
#include "cmdline.h"
#include "timer.h"

#ifndef VLAN_VID_MASK
#define VLAN_VID_MASK		0x0fff /* VLAN Identifier */
#endif

struct my_array {
	int num;
	char** item;
};

static struct my_array bridge = { 0, NULL };
static int *bridgeIfIdx = NULL;
static struct nl_sock *nf_sock_bcast = NULL;
static struct nl_sock *nf_sock_dump = NULL;
static struct nl_sock *nf_sock_vlan = NULL;
static int dumpNetlink = 0;

struct nf_obj_cb {
	struct nl_msg *msg;
	int fromDump;
};

struct port_info {
	int ifidx;
	char ifname[IFNAMSIZ];
	uint16_t pvid;
	struct port_info *next; 
};

static struct port_info *ports;

static void bridge_dump_links();

static int is_bridge_if(int ifidx) {
	for (int i = 0; i < bridge.num; i++) {
		if (bridgeIfIdx[i] == ifidx)
			return 1;
	}
	return 0;
}

static int
_port_find(const int ifidx, struct port_info **result, struct port_info **pred)
{
	for (struct port_info *cur = ports, *prev = NULL; cur; prev = cur, cur = cur->next) {
		if (cur->ifidx != ifidx)
			continue;
		if (pred)
			*pred = prev;
		if (result)
			*result = cur;
		return 1;
	}
	return 0;
}

int
port_pvid(int ifidx, const char *ifname) 
{
	struct port_info *cur;
	if (_port_find(ifidx, &cur, NULL) == 0)
		return -1;
	if (strncmp(cur->ifname, ifname, sizeof(cur->ifname)) != 0) {
		eprintf(DEBUG_ERROR, "port: ifidx: %d name: %s does not match %s", cur->ifidx, cur->ifname, ifname);
	}
	return cur->pvid;
}

static void
port_del(const int ifidx)
{
	struct port_info *cur, *prev;
	if (_port_find(ifidx, &cur, &prev) == 0)
		return;

	if (prev)
		prev->next = cur->next;
	else
		ports = cur->next;
	free(cur);
}

static void
port_upsert(const int ifidx, const char *ifname, const int pvid)
{
	struct port_info *cur;
	if (_port_find(ifidx, &cur, NULL) == 0) {
		cur = malloc(sizeof(*cur));
		cur->next = ports;
		ports = cur;
	}

	cur->pvid = pvid;
	strncpy(cur->ifname, ifname, sizeof(cur->ifname));
	cur->ifname[sizeof(cur->ifname)-1] = '\0';
}

static void
obj_input_newlink(struct rtnl_link *link, struct nl_msg *msg, int fromDump)
{
	const int ifidx = rtnl_link_get_ifindex(link);
	if (!is_bridge_if(rtnl_link_get_master(link)) &&
	    !is_bridge_if(ifidx)) {
		port_del(ifidx);
		return;
	}

	const char *ifname = rtnl_link_get_name(link);

	eprintf(DEBUG_BRIDGE, "NEWLINK: %s(%d)", ifname, ifidx);

	struct ifinfomsg *ifi = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *a_af_spec = NULL;
	if (ifi->ifi_family != AF_BRIDGE) {
		eprintf(DEBUG_BRIDGE, "msg is not of family bridge, so discard IFLA_AF_SPEC");
		/* it might have IFLA_AF_SPEC, but this has a different content */
		if (!fromDump)
			bridge_dump_links(); // pass ifidx once the kernel supports it ;)
		return;
	}
	a_af_spec = nlmsg_find_attr(nlmsg_hdr(msg), sizeof(struct ifinfomsg), IFLA_AF_SPEC);

	uint16_t pvid = 0;

	eprintf(DEBUG_BRIDGE, "got IFLA_AF_SPEC type %d len %d, expecting type %d, fromDump %d", (int) nla_type(a_af_spec), (int) nla_len(a_af_spec), (int) IFLA_AF_SPEC, fromDump);

	int remaining;
	struct nlattr *attr;

	nla_for_each_nested(attr, a_af_spec, remaining) {
		eprintf(DEBUG_BRIDGE, "got anoter IFLA_AF_SPEC entry type %d len %d, expecting type %d and len %zd", (int) nla_type(attr), (int) nla_len(attr), (int) IFLA_BRIDGE_VLAN_INFO, sizeof(struct bridge_vlan_info));
		if (nla_type(attr) != IFLA_BRIDGE_VLAN_INFO)
			continue;
		if (nla_len(attr) != sizeof(struct bridge_vlan_info))
			continue;
		struct bridge_vlan_info *vinfo = nla_data(attr);
		if (!vinfo->vid || vinfo->vid >= VLAN_VID_MASK)
			continue;
		if (!(vinfo->flags & BRIDGE_VLAN_INFO_PVID))
			continue;
		eprintf(DEBUG_BRIDGE, "found vlan %d on %s(%d)", vinfo->vid, ifname, ifidx);
		pvid = vinfo->vid;
	}

	if (!pvid) {
		eprintf(DEBUG_ERROR, "port: ifidx: %d name: %s no pvid", ifidx, ifname);
		return;
	}

	eprintf(DEBUG_BRIDGE, "port: ifidx: %d name: %s pvid:%d", ifidx, ifname, pvid);
	eprintf(DEBUG_VERBOSE, "port: ifidx: %d name: %s pvid:%d", ifidx, ifname, pvid);

	port_upsert(ifidx, ifname, pvid);
}

static void
obj_input_dellink(struct rtnl_link *link, struct nl_msg *msg)
{
	const int ifidx = rtnl_link_get_ifindex(link);
	if (is_bridge_if(ifidx)) {
		eprintf(DEBUG_ERROR, "my bridge %s removed", rtnl_link_get_name(link));
		exit(254);
	}
	port_del(ifidx);
}

static void
obj_input_route(struct nl_object *obj, void *arg)
{
	struct nf_obj_cb *ctx = arg;
	struct nl_msg *msg = ctx->msg;
	if (isdebug(DEBUG_BRIDGE)) {
		char buf[4096];
		nl_object_dump_buf(obj, buf, sizeof(buf));
		eprintf(DEBUG_BRIDGE,  "received fromDump=%d %s", ctx->fromDump, buf);
	}

	int type = nl_object_get_msgtype(obj);
	switch (type) {
	case RTM_NEWLINK:
		obj_input_newlink((struct rtnl_link *) obj, msg, ctx->fromDump);
		break;
	case RTM_DELLINK:
		obj_input_dellink((struct rtnl_link *) obj, msg);
		break;
	}
}

static int
event_input_route(struct nl_msg *msg, void *arg)
{
	if (isdebug(DEBUG_BRIDGE)) {
		char buf[256] = {0};
		FILE *ofd;

		ofd = fmemopen(buf, sizeof(buf), "w");
		if (ofd && dumpNetlink) {
			nl_msg_dump(msg, ofd);
			eprintf(DEBUG_BRIDGE,  "received message: %s", buf);
			nl_msg_dump(msg, stderr);
		} else {
			eprintf(DEBUG_BRIDGE,  "received message");
		}
		if (ofd)
			fclose(ofd);
	}

	struct nf_obj_cb ctx;
	ctx.msg = msg;
	ctx.fromDump = (arg == nf_sock_dump);

        if (nl_msg_parse(msg, &obj_input_route, &ctx) < 0)
		eprintf(DEBUG_BRIDGE,  "<<EVENT:Route>> Unknown message type");
	return NL_OK;
}

static void
bridge_receive(int s, void* ctx)
{
	struct nl_sock *nf_sock_route = (struct nl_sock *) ctx;
	int ret;
	ret = nl_recvmsgs_default(nf_sock_route);
	if (ret < 0) {
		eprintf(DEBUG_ERROR,  "receiving ROUTE->NEIGH failed on %d error %s", s, strerror(errno));
	}
}

static void
array_append(struct my_array *arr, char* ifname)
{
	char** tmp = realloc(arr->item, (arr->num+1) * sizeof(*arr->item));
	if (!tmp) {
		eprintf(DEBUG_ERROR, "%s:%d %s error parsing command line", __FILE__, __LINE__, __PRETTY_FUNCTION__);
		exit(1);
	}

	tmp[arr->num] = calloc(strnlen(ifname,IFNAMSIZ-1)+1, sizeof(char));
	if (!tmp[arr->num]) {
		eprintf(DEBUG_ERROR, "%s:%d %s error parsing command line", __FILE__, __LINE__, __PRETTY_FUNCTION__);
		exit(1);
	}
	strcpy(tmp[arr->num], ifname);
	arr->item = tmp;
	arr->num++;
}

static void
add_if(int c, void *if_list)
{

	if (!optarg)
		return;

	eprintf(DEBUG_BRIDGE, "add if %s\n", optarg);
	array_append(if_list, optarg);
}

static void
bridge_start_listen()
{
	assert(nf_sock_bcast == NULL);
	nf_sock_bcast = nl_socket_alloc();
	if (!nf_sock_bcast) {
		eprintf(DEBUG_ERROR, "cannot alloc socket (I): %s", strerror(errno));
		exit(254);
	}
	nl_socket_disable_seq_check(nf_sock_bcast);
	nl_socket_modify_cb(nf_sock_bcast, NL_CB_VALID, NL_CB_CUSTOM, event_input_route, nf_sock_bcast);

	if (nl_connect(nf_sock_bcast, NETLINK_ROUTE) < 0) {
		eprintf(DEBUG_ERROR, "cannot connect I: %s", strerror(errno));
		exit(254);
	}

        if (nl_socket_add_membership(nf_sock_bcast, RTNLGRP_LINK)) {
		eprintf(DEBUG_ERROR, "cannot bind to GRPLINK: %s", strerror(errno));
		exit(254);
	}

	int rffd = nl_socket_get_fd(nf_sock_bcast);
	cb_add_handle(rffd, nf_sock_bcast, bridge_receive);
}

static void
bridge_dump_init()
{
	assert(nf_sock_dump == NULL);
	nf_sock_dump = nl_socket_alloc();
	if (!nf_sock_dump) {
		eprintf(DEBUG_ERROR, "cannot alloc socket (II): %s", strerror(errno));
		exit(254);
	}

	nl_socket_disable_seq_check(nf_sock_dump);
	nl_socket_modify_cb(nf_sock_dump, NL_CB_VALID, NL_CB_CUSTOM, event_input_route, nf_sock_dump);
	nl_socket_disable_auto_ack(nf_sock_dump);

	if (nl_connect(nf_sock_dump, NETLINK_ROUTE) < 0) {
		eprintf(DEBUG_ERROR, "cannot connect II: %s", strerror(errno));
		exit(254);
	}

	int rffd = nl_socket_get_fd(nf_sock_dump);
	cb_add_handle(rffd, nf_sock_dump, bridge_receive);
}

static void
bridge_vlan_init()
{
	assert(nf_sock_vlan == NULL);
	nf_sock_vlan = nl_socket_alloc();
	if (!nf_sock_vlan) {
		eprintf(DEBUG_ERROR, "cannot alloc socket (III): %s", strerror(errno));
		exit(254);
	}

	if (nl_connect(nf_sock_vlan, NETLINK_ROUTE) < 0) {
		eprintf(DEBUG_ERROR, "cannot connect III: %s", strerror(errno));
		exit(254);
	}
}

static void
bridge_dump_links()
{
	/* nl_rtgen_request(nf_sock_dump, RTM_GETNEIGH, AF_BRIDGE, NLM_F_DUMP)
	 * produces an undersized payload and thus gets discarded by the kernel.
	 */
	/*
	 * getting vlan information is only supported for AF_BRIDGE w NLM_F_DUMP RTM_GETLINK requests.
	 * All others do not have it.
	 * Sadly, AF_BRIGE+NLM_F_DUMP->kernel:rtnl_bridge_getlink does not allow to filter for master device or ifidx.
	 */
	struct ifinfomsg msg = { 0 };
	struct nl_msg *nlmsg = NULL;

	msg.ifi_family = AF_BRIDGE;
	//msg.ifi_index = ifidx;	

	nlmsg = nlmsg_alloc_simple(RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP);
	//nlmsg = nlmsg_alloc_simple(RTM_GETLINK, NLM_F_REQUEST | (ifidx ? 0 : NLM_F_DUMP));
	if (!nlmsg) {
		eprintf(DEBUG_ERROR, "out of memory");
		exit(254);
	}
	if (nlmsg_append(nlmsg, &msg, sizeof(msg), NLMSG_ALIGNTO) < 0) {
		eprintf(DEBUG_ERROR, "out of memory");
		exit(254);
	}
	/*
	if (!ifidx &&
	    nla_put_u32(nlmsg, IFLA_MASTER, bridgeIfIdx) < 0) {
		eprintf(DEBUG_ERROR, "out of memory");
		exit(254);
	}
	*/
	if (nla_put_u32(nlmsg, IFLA_EXT_MASK, RTEXT_FILTER_BRVLAN) < 0) {
		eprintf(DEBUG_ERROR, "out of memory");
		exit(254);
	}

	if (isdebug(DEBUG_BRIDGE)) {
		char buf[1024] = {0};
		FILE *ofd;

		ofd = fmemopen(buf, sizeof(buf), "w");
		if (ofd && dumpNetlink) {
			nl_msg_dump(nlmsg, ofd);
			eprintf(DEBUG_BRIDGE,  "send message: %s", buf);
			//nl_msg_dump(nlmsg, stderr);
		} else {
			eprintf(DEBUG_BRIDGE,  "send message");
		}
		if (ofd)
			fclose(ofd);
	}

	if (nl_send_auto(nf_sock_dump, nlmsg) < 0) { /* ACK was disabled above */
		eprintf(DEBUG_ERROR, "netlink error");
		exit(254);
	}

	nlmsg_free(nlmsg);
}

static void
bridge_start(void *ctx)
{
	eprintf(DEBUG_BRIDGE,  "Listen to ROUTE->LINK notifications");

	if (!bridge.num) {
		eprintf(DEBUG_ERROR, "no bridge set");
		exit(254);
	}

	bridgeIfIdx = calloc(bridge.num, sizeof(*bridgeIfIdx));
	if (!bridgeIfIdx) {
		eprintf(DEBUG_ERROR, "malloc failure");
		exit(254);
	}
	for (int i = 0; i < bridge.num; i++) {
		bridgeIfIdx[i] = if_nametoindex(bridge.item[i]);

		if (!bridgeIfIdx[i]) {
			eprintf(DEBUG_ERROR, "bridge %s does not exist", bridge.item[i]);
			exit(254);
		}
	}

	/* connect to netlink route to get notified of new bridge ports */
	bridge_start_listen();

	/* connect to netlink route to dump all known bridge ports */
	bridge_dump_init();
	//bridge_dump_links(bridgeIfIdx[0..n-1]);
	bridge_dump_links();

	/* socket or vlan_add or vlan_del */
	bridge_vlan_init();
}

static void
setDumpNetlink(int c, void *arg)
{
	dumpNetlink = 1;
}

static __attribute__((constructor)) void
bridge_init()
{
	{
		struct option long_option = {"bridge", required_argument, 0, 0};
		add_option_cb(long_option, add_if, &bridge);
	}
	{
		struct option long_option = {"bridge-dump-netlink", no_argument, 0, 0};
		add_option_cb(long_option, setDumpNetlink, NULL);
	}
	cb_add_timer(0, 0, NULL, bridge_start);
}

#endif
