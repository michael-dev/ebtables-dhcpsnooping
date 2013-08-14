#include "config.h"
#include "event.h"
#include "debug.h"
#include "dhcp.h"
#include "dhcp-req.h"
#include "dhcp-ack.h"

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

#define REQ_LIFETIME 300

struct helper1 {
	char* ifname;
	uint8_t* mac;
};

void upd(struct cache_ack_entry* entry, void* ctx)
{
	struct helper1* tmp = (struct helper1*) ctx;
	
	if (memcmp(entry->mac, tmp->mac, ETH_ALEN) == 0 && strncmp(entry->bridge, tmp->ifname, IF_NAMESIZE) == 0) {
		entry->expiresAt = 0;
		updated_lease(entry->mac, &entry->ip, entry->bridge, 0);
	}
}

/**
 * This method handles IPv4 packets.
 */
void dhcpv4_got_packet(const int ptype, const u_char *packet, const int len, const char* ifname)
{
	const int c_dhcp_req = 1;
	const int c_dhcp_ack = 2;
	int dhcp_mode = 0;

	if (ptype != ETH_P_IP) {
		eprintf(DEBUG_DHCP,  "%s:%d packet is not IP\n", __FILE__, __LINE__);
		return;
	}

	/** Parse packet */
	const u_char* packet_end = packet + len;
	/** check IPv4 **/
	struct iphdr* ip = ((struct iphdr*) packet);
	if (((u_char*) ip) + sizeof(struct iphdr) >= packet_end) {
		eprintf(DEBUG_DHCP, "%s:%d packet short\n", __FILE__, __LINE__);
		return;
	}
	if (ip->protocol != IPPROTO_UDP) {
		eprintf(DEBUG_DHCP, "%s:%d not udp\n", __FILE__, __LINE__);
		return;
	}
	struct in_addr* saddr = (struct in_addr*) &ip->saddr;
	struct in_addr* daddr = (struct in_addr*) &ip->daddr;
	/** check UDP ports for  **/
	struct udphdr *udp = (struct udphdr *) ( (u_char *) ip + sizeof(struct iphdr) );
	if (((u_char*) udp) + sizeof(struct udphdr) >= packet_end) {
		eprintf(DEBUG_DHCP, "%s:%d packet short\n", __FILE__, __LINE__);
		return;
	}
	eprintf(DEBUG_DHCP,  "source %s:%d\n", inet_ntoa(*saddr), ntohs(udp->source));
	eprintf(DEBUG_DHCP,  "dest %s:%d\n", inet_ntoa(*daddr), ntohs(udp->dest));
	if (udp->source == htons(67)) {
		dhcp_mode = c_dhcp_ack;
	} else if (udp->source == htons(68)) {
		dhcp_mode = c_dhcp_req;
	} else {
		eprintf(DEBUG_DHCP, "%s:%d not udp sport 67-68\n", __FILE__, __LINE__);
		return;
	}
	if (!((udp->dest == htons(68) && dhcp_mode == c_dhcp_ack) || (udp->dest == htons(67) && dhcp_mode == c_dhcp_req))) {
		eprintf(DEBUG_DHCP, "%s:%d not udp dport 67/68\n", __FILE__, __LINE__);
		return;
	}
	/** check DHCP **/
	struct libnet_dhcpv4_hdr* dhcp = (struct libnet_dhcpv4_hdr*) ((u_char*) udp + sizeof(struct udphdr));
	if (((u_char*) dhcp) + sizeof(struct libnet_dhcpv4_hdr) >= packet_end) {
		eprintf(DEBUG_DHCP, "%s:%d packet short\n", __FILE__, __LINE__);
		return;
	}
	if (!(
	      (dhcp->dhcp_opcode == htons(LIBNET_DHCP_REPLY) && dhcp_mode == c_dhcp_ack)
	   || (dhcp->dhcp_opcode == htons(LIBNET_DHCP_REQUEST) && dhcp_mode == c_dhcp_req)
	     )
	  ) {
		eprintf(DEBUG_DHCP, "%s:%d dhcp no reply/request matching ports\n", __FILE__, __LINE__);
		return;
	}
	if (dhcp->dhcp_htype != 0x01) {
		eprintf(DEBUG_DHCP, "%s:%d dhcp invalid htype\n", __FILE__, __LINE__);
		return;
	}
	if (dhcp->dhcp_hlen != ETH_ALEN) {
		eprintf(DEBUG_DHCP, "%s:%d dhcp invalid hlen\n", __FILE__, __LINE__);
		return;
	}
    	if (dhcp->dhcp_magic != htonl(DHCP_MAGIC)) {
		eprintf(DEBUG_DHCP, "%s:%d dhcp missing magic\n", __FILE__, __LINE__);
		return;
	}
	// fields
	uint32_t leaseTime = 0; // no default when DHCP ACK generated in reply to DHCP INFORM
	uint32_t tmp_yip = ntohl(dhcp->dhcp_yip);
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
		eprintf(DEBUG_DHCP, "%s:%d dhcp no ack from server / no request-release from client / missing lease time\n", __FILE__, __LINE__);
		eprintf(DEBUG_DHCP, "msgtype = %s, mode = %s, leaseTime = %d\n", dhcpmsgtypestr, mode, leaseTime);
		return;
	}

	if (dhcpmsgtype == LIBNET_DHCP_MSGACK) {
		eprintf(DEBUG_DHCP,  "DHCP ACK MAC: %s IP: %s BRIDGE: %s LeaseTime: %d\n" , ether_ntoa((struct ether_addr *)mac), inet_ntoa(yip), ifname, leaseTime);
		if (tmp_yip == 0) {
			eprintf(DEBUG_DHCP, "DHCP ACK IP 0.0.0.0 ignored\n");
			return;
		}
	} else if (dhcpmsgtype == LIBNET_DHCP_MSGREQUEST) {
		eprintf(DEBUG_DHCP,  "DHCP REQ MAC: %s BRIDGE: %s\n" , ether_ntoa((struct ether_addr *)mac), ifname);
	} else if (dhcpmsgtype == LIBNET_DHCP_MSGRELEASE) {
		eprintf(DEBUG_DHCP,  "DHCP REL MAC: %s BRIDGE: %s\n" , ether_ntoa((struct ether_addr *)mac), ifname);
	} else {
		eprintf(DEBUG_DHCP,  "ERROR - dhcp_mode is invalud\n");
		return;
	}

	/** update cache */
	if (dhcpmsgtype == LIBNET_DHCP_MSGREQUEST) {
		struct cache_req_entry* entry = get_req_entry(mac, ifname);
		uint32_t expiresAt = time(NULL) + REQ_LIFETIME;
		if (entry == NULL) {
			add_req_entry(mac, ifname, expiresAt);
		} else {
			entry->expiresAt = expiresAt;
		}
	} else if (dhcpmsgtype == LIBNET_DHCP_MSGACK
	           && is_local(mac, ifname)
		  ) {
		uint32_t now = time(NULL);
		uint32_t expiresAt = now + leaseTime;
		add_ack_entry_if_not_found(&yip, mac, ifname, expiresAt);
		updated_lease(mac, &yip, ifname, expiresAt);
	} else if (dhcpmsgtype == LIBNET_DHCP_MSGACK) {
		eprintf(DEBUG_DHCP,  " * unsoliciated DHCP ACK\n");
	} else if (dhcpmsgtype == LIBNET_DHCP_MSGRELEASE) {
		char str_ifname[IFNAMSIZ];
		strncpy(str_ifname, ifname, IFNAMSIZ);
		struct helper1 tmp = { str_ifname, mac };
		ack_update(upd, &tmp);
		updated_lease(mac, &yip, ifname, -1);
	} else {
		eprintf(DEBUG_DHCP,  "ERR: invalid dhcp_mode\n");
	}

	eprintf(DEBUG_DHCP,  "DHCP ACK processing finished\n");
}

static __attribute__((constructor)) void dhcpv4_init()
{
	eprintf(DEBUG_ERROR,  "register DHCPv4 handler\n");
	cb_add_packet_cb(dhcpv4_got_packet);
}

