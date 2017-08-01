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
#include "dhcp.h"
#include "dhcp-req.h"
#include "dhcp-ack.h"
#include "timer.h"

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
#include "ether_ntoa.h"
#include <libnet.h>
#include <stdio.h>
#include <stdlib.h>

#define REQ_LIFETIME 300

/**
 * This method handles IPv4 packets.
 */
void dhcpv4_got_packet(const int ptype, const u_char *packet, const int len, const char* ifname)
{
	const int c_dhcp_req = 1;
	const int c_dhcp_ack = 2;
	int dhcp_mode = 0;

	if (ptype != ETH_P_IP) {
		eprintf(DEBUG_DHCP,  "packet is not IP");
		return;
	}

	/** Parse packet */
	const u_char* packet_end = packet + len;
	/** check IPv4 **/
	struct iphdr* ip = ((struct iphdr*) packet);
	if (((u_char*) ip) + sizeof(struct iphdr) >= packet_end) {
		eprintf(DEBUG_DHCP, "packet is short of ip header");
		return;
	}
	if (ip->protocol != IPPROTO_UDP) {
		eprintf(DEBUG_DHCP, "packet is not udp");
		return;
	}
	struct in_addr* saddr = (struct in_addr*) &ip->saddr;
	struct in_addr* daddr = (struct in_addr*) &ip->daddr;
	/** check UDP ports for  **/
	struct udphdr *udp = (struct udphdr *) ( (u_char *) ip + sizeof(struct iphdr) );
	if (((u_char*) udp) + sizeof(struct udphdr) >= packet_end) {
		eprintf(DEBUG_DHCP, "packet is short of udp header");
		return;
	}
	eprintf(DEBUG_DHCP,  "source %s:%d", inet_ntoa(*saddr), ntohs(udp->source));
	eprintf(DEBUG_DHCP,  "dest %s:%d", inet_ntoa(*daddr), ntohs(udp->dest));
	if (udp->source == htons(67)) {
		dhcp_mode = c_dhcp_ack;
	} else if (udp->source == htons(68)) {
		dhcp_mode = c_dhcp_req;
	} else {
		eprintf(DEBUG_DHCP, "not udp sport 67-68");
		return;
	}
	if (!((udp->dest == htons(68) && dhcp_mode == c_dhcp_ack) || (udp->dest == htons(67) && dhcp_mode == c_dhcp_req))) {
		eprintf(DEBUG_DHCP, "not udp dport 67/68");
		return;
	}
	/** check DHCP **/
	struct libnet_dhcpv4_hdr* dhcp = (struct libnet_dhcpv4_hdr*) ((u_char*) udp + sizeof(struct udphdr));
	if (((u_char*) dhcp) + sizeof(struct libnet_dhcpv4_hdr) >= packet_end) {
		eprintf(DEBUG_DHCP, "packet short of bootp header");
		return;
	}
	if (!(
	      (dhcp->dhcp_opcode == LIBNET_DHCP_REPLY && dhcp_mode == c_dhcp_ack)
	   || (dhcp->dhcp_opcode == LIBNET_DHCP_REQUEST && dhcp_mode == c_dhcp_req)
	     )
	  ) {
		eprintf(DEBUG_DHCP, "dhcp no reply/request matching ports: opcode %x rep %x req %x", dhcp->dhcp_opcode, LIBNET_DHCP_REPLY, LIBNET_DHCP_REQUEST);
		return;
	}
	if (dhcp->dhcp_htype != 0x01) {
		eprintf(DEBUG_DHCP, "dhcp invalid htype");
		return;
	}
	if (dhcp->dhcp_hlen != ETH_ALEN) {
		eprintf(DEBUG_DHCP, "dhcp invalid hlen");
		return;
	}
    	if (dhcp->dhcp_magic != htonl(DHCP_MAGIC)) {
		eprintf(DEBUG_DHCP, "dhcp missing magic");
		return;
	}
	// fields
	uint32_t leaseTime = 0; // no default when DHCP ACK generated in reply to DHCP INFORM
	uint32_t tmp_yip = dhcp->dhcp_yip;
	struct in_addr yip;
	memcpy(&yip, &tmp_yip, sizeof(yip));
	uint8_t mac[ETH_ALEN]; memcpy(mac, dhcp->dhcp_chaddr, ETH_ALEN);
	/* check DHCP options */
	u_char* dhcpoptp = ((u_char*) dhcp + sizeof(struct libnet_dhcpv4_hdr));
	uint8_t dhcpmsgtype = 0;
	while (dhcpoptp < packet_end) {
		uint8_t dhcpopt = * dhcpoptp;
		dhcpoptp++;
		if (dhcpopt == LIBNET_DHCP_PAD) {
			continue;
		}
		if (dhcpopt == LIBNET_DHCP_END) {
			break;
		}
		uint8_t dhcpoptlen = *dhcpoptp;
		dhcpoptp++;
		u_char* dhcpdata = dhcpoptp;
		dhcpoptp += dhcpoptlen;
		switch (dhcpopt) {
			case LIBNET_DHCP_MESSAGETYPE:
				dhcpmsgtype = *dhcpdata;
				break;
			case LIBNET_DHCP_LEASETIME:
				leaseTime = ntohl(*((uint32_t*) dhcpdata));
				break;
			default:
				break;
		}
	}
	char* dhcpmsgtypestr = "UNKNOWN";
	switch (dhcpmsgtype) {
		case 0x01: dhcpmsgtypestr = "DISCOVER"; break;
		case 0x02: dhcpmsgtypestr = "OFFER"; break;
		case 0x03: dhcpmsgtypestr = "REQUEST"; break;
		case 0x04: dhcpmsgtypestr = "DECLINE"; break;
		case 0x05: dhcpmsgtypestr = "ACK"; break;
		case 0x06: dhcpmsgtypestr = "NACK"; break;
		case 0x07: dhcpmsgtypestr = "RELEASE"; break;
		case 0x08: dhcpmsgtypestr = "INFORM"; break;
	}
	if (!(
	          (dhcpmsgtype == LIBNET_DHCP_MSGACK && dhcp_mode == c_dhcp_ack && leaseTime > 0) // RFC 2131: when leaseTime = 0, this is a DHCPINFORM reply not assigning any lease
	       || (dhcpmsgtype == LIBNET_DHCP_MSGREQUEST && dhcp_mode == c_dhcp_req)
	       || (dhcpmsgtype == LIBNET_DHCP_MSGRELEASE && dhcp_mode == c_dhcp_req)
	     )
	   ) {
	   	char* mode = "UNKNOWN";
		if (dhcp_mode == c_dhcp_req) mode = "c2s";
		if (dhcp_mode == c_dhcp_ack) mode = "s2c";
		eprintf(DEBUG_DHCP, "dhcp no ack from server / no request-release from client / missing lease time");
		eprintf(DEBUG_DHCP, "msgtype = %s, mode = %s, leaseTime = %d", dhcpmsgtypestr, mode, leaseTime);
		return;
	}

	if (dhcpmsgtype == LIBNET_DHCP_MSGACK) {
		eprintf(DEBUG_DHCP| DEBUG_VERBOSE,  "DHCP ACK MAC: %s IP: %s BRIDGE: %s LeaseTime: %d" , ether_ntoa_z((struct ether_addr *)mac), inet_ntoa(yip), ifname, leaseTime);
		if (tmp_yip == 0) {
			eprintf(DEBUG_DHCP, "DHCP ACK IP 0.0.0.0 ignored");
			return;
		}
	} else if (dhcpmsgtype == LIBNET_DHCP_MSGREQUEST) {
		eprintf(DEBUG_DHCP | DEBUG_VERBOSE,  "DHCP REQ MAC: %s BRIDGE: %s" , ether_ntoa_z((struct ether_addr *)mac), ifname);
	} else if (dhcpmsgtype == LIBNET_DHCP_MSGRELEASE) {
		eprintf(DEBUG_DHCP | DEBUG_VERBOSE,  "DHCP REL MAC: %s BRIDGE: %s" , ether_ntoa_z((struct ether_addr *)mac), ifname);
	} else {
		eprintf(DEBUG_DHCP,  "ERROR - dhcp_mode is invalid");
		return;
	}

	/** update cache */
	if (dhcpmsgtype == LIBNET_DHCP_MSGREQUEST) {
		uint32_t expiresAt = reltime() + REQ_LIFETIME;
		add_req_entry_if_not_found(mac, ifname, expiresAt);
	} else if (dhcpmsgtype == LIBNET_DHCP_MSGACK
	           && is_local(mac, ifname)
		  ) {
		uint32_t now = reltime();
		uint32_t expiresAt = now + leaseTime;
		updated_lease(mac, &yip, ifname, expiresAt, UPDATED_LEASE_FROM_DHCP);
	} else if (dhcpmsgtype == LIBNET_DHCP_MSGACK) {
		eprintf(DEBUG_DHCP,  " * unsoliciated DHCP ACK");
	} else if (dhcpmsgtype == LIBNET_DHCP_MSGRELEASE) {
		char str_ifname[IFNAMSIZ];
		strncpy(str_ifname, ifname, IFNAMSIZ);
		updated_lease(mac, &yip, ifname, 0, UPDATED_LEASE_FROM_DHCP);
	} else {
		eprintf(DEBUG_DHCP,  "ERR: invalid dhcp_mode");
	}

	eprintf(DEBUG_DHCP,  "DHCP ACK processing finished");
}

static __attribute__((constructor)) void dhcpv4_init()
{
	eprintf(DEBUG_ERROR,  "register DHCPv4 handler");
	cb_add_packet_cb(dhcpv4_got_packet);
}

