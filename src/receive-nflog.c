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
#include "event.h"
#include "debug.h"

#include <sys/types.h>
#include <net/if.h>
#define _LINUX_IF_H
#include <linux/netfilter/nfnetlink_log.h>
#include <netlink/netfilter/nfnl.h>
#include <netlink/netfilter/log.h>
#include <netlink/netfilter/log_msg.h>
#include <netlink/msg.h>
#include <errno.h>

void obj_input_nflog(struct nl_object *obj, void *arg)
{
        struct nfnl_log_msg *msg = (struct nfnl_log_msg *) obj;
	char buf[IF_NAMESIZE];

	uint32_t  indev = nfnl_log_msg_get_indev(msg);
	uint32_t  outdev = nfnl_log_msg_get_outdev(msg);

	if (indev != outdev) {
		eprintf(DEBUG_NFLOG,  "obj_input_nflog...err indev!=outdev");
		return;
	}
	memset(buf,0,sizeof(buf));
	if (!if_indextoname(indev, buf)) {
		eprintf(DEBUG_ERROR,  "obj_input_nlog: failed to fetch interface name of ifidx %d: %s (%d)", indev, strerror(errno), errno);
		return;
	}

	uint16_t hwproto = ntohs(nfnl_log_msg_get_hwproto(msg));
	int len = 0;
	const u_char* data = (const u_char*) nfnl_log_msg_get_payload(msg, (int*) &len);

	eprintf(DEBUG_NFLOG,  "obj_input...packet received");
	cb_call_packet_cb(hwproto, data, len, buf);
}

int event_input_nflog(struct nl_msg *msg, void *arg)
{
        if (nl_msg_parse(msg, &obj_input_nflog, NULL) < 0)
                eprintf(DEBUG_NFLOG,  "<<EVENT:nflog>> Unknown message type");
        return NL_STOP;
}

void nflog_receive(int s, void* ctx)
{
	int ret;
	struct nl_sock *nf_sock_nflog = (struct nl_sock *) ctx;
	ret = nl_recvmsgs_default(nf_sock_nflog);
	if (ret < 0) {
		eprintf(DEBUG_ERROR, "receiving nflog socket %d failed %s", s, strerror(errno));
	}
}

static __attribute__((constructor)) void nflog_init()
{
	eprintf(DEBUG_ERROR, "listen to NFLOG packets for group %d", NFLOG_GROUP);
	/* connect to netfilter / NFLOG */
	struct nl_sock *nf_sock_nflog;
	struct nfnl_log *log;
	int nffd;
	
	nf_sock_nflog = nl_socket_alloc();
	if (nf_sock_nflog < 0) {
		eprintf(DEBUG_ERROR, "cannot alloc socket: %s", strerror(errno));
		exit(254);
	}
	nl_socket_disable_seq_check(nf_sock_nflog);
	nl_socket_modify_cb(nf_sock_nflog, NL_CB_VALID, NL_CB_CUSTOM, event_input_nflog, NULL);

	if (nl_connect(nf_sock_nflog, NETLINK_NETFILTER) < 0) {
		eprintf(DEBUG_ERROR, "cannot connect: %s", strerror(errno));
		exit(254);
	}

	if (nfnl_log_pf_bind(nf_sock_nflog, AF_BRIDGE) < 0) {
		eprintf(DEBUG_ERROR, "cannot bind: %s", strerror(errno));
		exit(254);
	}

	log = nfnl_log_alloc();
	nfnl_log_set_group(log, NFLOG_GROUP);

	nfnl_log_set_copy_mode(log, NFNL_LOG_COPY_PACKET);

	nfnl_log_set_copy_range(log, 0xFFFF);

	if (nfnl_log_create(nf_sock_nflog, log) < 0) {
		eprintf(DEBUG_ERROR, "cannot create log: %s", strerror(errno));
		exit(254);
	}

	nffd = nl_socket_get_fd(nf_sock_nflog);
	if (nffd < 0) {
		eprintf(DEBUG_ERROR, "nflog socket %d is error", nffd);
		exit(254);
	}
	eprintf(DEBUG_ERROR, "nflog socket %d", nffd);
	
	cb_add_handle(nffd, nf_sock_nflog, nflog_receive);
}
