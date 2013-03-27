/*
 * This program reads dhcp ack packets from nflog using libnl and creates a
 * temporary table of all authenticated MAC/IP pairs + their lifetime.
 * When a new entry is added, an ebtables accept rule is added,
 * when the entry expires, it is removed.
 * DHCP requests are used to filter dhcp broadcast acks for unseen dhcp requests,
 * i.e. non-local stations.
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 *  gcc -I /usr/include/libnl3/ dhcpsnoopingd.c -l nl-3 -l nl-genl-3 -l nl-nf-3 -l nl-route-3 -o dhcpsnoopingd
 *
 * Copyright (c) 2012 Michael Braun <michael-dev@fami-braun.de>
 * forked from nf-log.c (libnl):
 *   Copyright (c) 2003-2008 Thomas Graf <tgraf@suug.ch>
 *   Copyright (c) 2007 Philip Craig <philipc@snapgear.com>
 *   Copyright (c) 2007 Secure Computing Corporation
 */

#include <sys/types.h>
#include <linux/netfilter/nfnetlink_log.h>
#include <linux/netfilter/nfnetlink_log.h>
#include <netlink/netfilter/nfnl.h>
#include <netlink/netfilter/log.h>
#include <netlink/netfilter/log_msg.h>
#include <netlink/msg.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <libnet.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define CHAINNAME "dhcpsnooping"
#define EBTABLES "ebtables"
#define PRUNE_INTERVAL 300
#define DEBUG 1
#define REQ_LIFETIME 300

#if DEBUG
#define fprintf fprintf
#else
#define fprintf if (0) fprintf
#endif

/* global cache of dhcp acks (linked list)
 * fields: bridge name, mac, ip, lifetime
 */

struct cache_ack_entry {
	char bridge[IF_NAMESIZE];
	uint8_t mac[ETH_ALEN];
	struct in_addr ip;
	uint32_t expiresAt;
	struct cache_ack_entry* next;
};

struct cache_req_entry {
	char bridge[IF_NAMESIZE];
	uint8_t mac[ETH_ALEN];
	uint32_t expiresAt;
	struct cache_req_entry* next;
};

static struct cache_ack_entry* globalAckCache = NULL;
static struct cache_req_entry* globalReqCache = NULL;

struct cache_req_entry* get_req_entry(const uint8_t* mac, const char* ifname) {
	struct cache_req_entry* entry = globalReqCache;
	while (entry != NULL) {
		if (memcmp(entry->mac, mac, ETH_ALEN) == 0
		    && strncmp(entry->bridge, ifname, IF_NAMESIZE) == 0) {
			break;
		}
		entry = entry->next;
	}
	return entry;
}

struct cache_ack_entry* get_ack_entry(const struct in_addr* yip, const uint8_t* mac, const char* ifname) {
	struct cache_ack_entry* entry = globalAckCache;
	while (entry != NULL) {
		if (memcmp(&entry->ip, yip, sizeof(struct in_addr)) == 0
		    && memcmp(entry->mac, mac, ETH_ALEN) == 0
		    && strncmp(entry->bridge, ifname, IF_NAMESIZE) == 0) {
			break;
		}
		entry = entry->next;
	}
	return entry;
}

struct cache_req_entry* add_req_entry(const uint8_t* mac, const char* ifname, const uint32_t expiresAt) {
	struct cache_req_entry* entry = malloc(sizeof(struct cache_req_entry));
	memset(entry, 0, sizeof(struct cache_req_entry));
	memcpy(entry->mac, mac, ETH_ALEN);
	strncpy(entry->bridge, ifname, IF_NAMESIZE);
	entry->expiresAt = expiresAt;
	entry->next = globalReqCache;
	globalReqCache = entry;
	return entry;
}

struct cache_ack_entry* add_ack_entry(const struct in_addr* yip, const uint8_t* mac, const char* ifname, const uint32_t expiresAt) {
	struct cache_ack_entry* entry = malloc(sizeof(struct cache_ack_entry));
	memset(entry, 0, sizeof(struct cache_ack_entry));
	memcpy(entry->mac, mac, ETH_ALEN);
	memcpy(&entry->ip,yip,sizeof(struct in_addr));
	strncpy(entry->bridge, ifname, IF_NAMESIZE);
	entry->expiresAt = expiresAt;
	entry->next = globalAckCache;
	globalAckCache = entry;
	return entry;
}

/**
 * This method handles IPv4 packets.
 */
void got_packet(const u_char *packet, const int len, const char* ifname)
{
	const int c_dhcp_req = 1;
	const int c_dhcp_ack = 2;
	int dhcp_mode = 0;

	/** Parse packet */
	const u_char* packet_end = packet + len;
	/** check IPv4 **/
	struct iphdr* ip = ((struct iphdr*) packet);
	if (((u_char*) ip) + sizeof(struct iphdr) >= packet_end) {
		fprintf(stderr,"%s:%d packet short\n", __FILE__, __LINE__);
		return;
	}
	if (ip->protocol != IPPROTO_UDP) {
		fprintf(stderr,"%s:%d not udp\n", __FILE__, __LINE__);
		return;
	}
	struct in_addr* saddr = (struct in_addr*) &ip->saddr;
	struct in_addr* daddr = (struct in_addr*) &ip->daddr;
	/** check UDP ports for  **/
	struct udphdr *udp = (struct udphdr *) ( (u_char *) ip + sizeof(struct iphdr) );
	if (((u_char*) udp) + sizeof(struct udphdr) >= packet_end) {
		fprintf(stderr,"%s:%d packet short\n", __FILE__, __LINE__);
		return;
	}
	fprintf(stderr, "source %s:%d\n", inet_ntoa(*saddr), ntohs(udp->source));
	fprintf(stderr, "dest %s:%d\n", inet_ntoa(*daddr), ntohs(udp->dest));
	if (udp->source == htons(67)) {
		dhcp_mode = c_dhcp_ack;
	} else if (udp->source == htons(68)) {
		dhcp_mode = c_dhcp_req;
	} else {
		fprintf(stderr,"%s:%d not udp sport 67-68\n", __FILE__, __LINE__);
		return;
	}
	if (!((udp->dest == htons(68) && dhcp_mode == c_dhcp_ack) || (udp->dest == htons(67) && dhcp_mode == c_dhcp_req))) {
		fprintf(stderr,"%s:%d not udp dport 67/68\n", __FILE__, __LINE__);
		return;
	}
	/** check DHCP **/
	struct libnet_dhcpv4_hdr* dhcp = (struct libnet_dhcpv4_hdr*) ((u_char*) udp + sizeof(struct udphdr));
	if (((u_char*) dhcp) + sizeof(struct libnet_dhcpv4_hdr) >= packet_end) {
		fprintf(stderr,"%s:%d packet short\n", __FILE__, __LINE__);
		return;
	}
	if (!((dhcp->dhcp_opcode == htons(LIBNET_DHCP_REPLY) && dhcp_mode == c_dhcp_ack) || (dhcp->dhcp_opcode == htons(LIBNET_DHCP_REQUEST) && dhcp_mode == c_dhcp_req))) {
		fprintf(stderr,"%s:%d dhcp no reply/request matching ports\n", __FILE__, __LINE__);
		return;
	}
	if (dhcp->dhcp_htype != 0x01) {
		fprintf(stderr,"%s:%d dhcp invalid htype\n", __FILE__, __LINE__);
		return;
	}
	if (dhcp->dhcp_hlen != ETH_ALEN) {
		fprintf(stderr,"%s:%d dhcp invalid hlen\n", __FILE__, __LINE__);
		return;
	}
    	if (dhcp->dhcp_magic != htonl(DHCP_MAGIC)) {
		fprintf(stderr,"%s:%d dhcp missing magic\n", __FILE__, __LINE__);
		return;
	}
	// fields
	uint32_t leaseTime = 24 * 60 * 60; // defaults to 24h
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
	if (!((dhcpmsgtype == LIBNET_DHCP_MSGACK && dhcp_mode == c_dhcp_ack) || (dhcpmsgtype == LIBNET_DHCP_MSGREQUEST && dhcp_mode == c_dhcp_req))) {
		fprintf(stderr,"%s:%d dhcp no ack\n", __FILE__, __LINE__);
		return;
	}

	if (dhcp_mode == c_dhcp_ack) {
		fprintf(stderr, "DHCP ACK MAC: %s IP: %s BRIDGE: %s LeaseTime: %d\n" , ether_ntoa((struct ether_addr *)mac), inet_ntoa(yip), ifname, leaseTime);
	} else if (dhcp_mode == c_dhcp_req) {
		fprintf(stderr, "DHCP REQ MAC: %s BRIDGE: %s\n" , ether_ntoa((struct ether_addr *)mac), ifname);
	} else {
		fprintf(stderr, "ERROR - dhcp_mode is invalud\n");
		return;
	}

	/** update cache */
	sigset_t base_mask;
	sigemptyset (&base_mask);
	sigaddset (&base_mask, SIGALRM);
	sigaddset (&base_mask, SIGUSR1);
	sigprocmask (SIG_SETMASK, &base_mask, NULL);

	if (dhcp_mode == c_dhcp_req) {
		struct cache_req_entry* entry = get_req_entry(mac, ifname);
		uint32_t expiresAt = time(NULL) + REQ_LIFETIME;
		if (entry == NULL) {
			add_req_entry(mac, ifname, expiresAt);
		} else {
			entry->expiresAt = expiresAt;
		}
	} else if (get_req_entry(mac, ifname) != NULL && dhcp_mode == c_dhcp_ack) {
		struct cache_ack_entry* entry = get_ack_entry(&yip, mac, ifname);
		uint32_t expiresAt = time(NULL) + leaseTime;

		if (entry == NULL) {
			add_ack_entry(&yip, mac, ifname, expiresAt);
			/* run cmd */
			char cmd[65535];
			snprintf(cmd, sizeof(cmd), EBTABLES " -A " CHAINNAME " -s %s --proto ipv4 --ip-source %s --logical-in %s -j ACCEPT\n" , ether_ntoa((struct ether_addr *)mac), inet_ntoa(yip), ifname);
			fprintf(stderr,"%s", cmd);
			system(cmd);
			snprintf(cmd, sizeof(cmd), EBTABLES " -A " CHAINNAME " -s %s --proto arp --arp-ip-src %s --logical-in %s -j ACCEPT\n" , ether_ntoa((struct ether_addr *)mac), inet_ntoa(yip), ifname);
			fprintf(stderr,"%s", cmd);
			system(cmd);
		} else {
			entry->expiresAt = expiresAt;
		}
	} else if (dhcp_mode == c_dhcp_ack) {
		fprintf(stderr, " * unsoliciated DHCP ACK\n");
	} else {
		fprintf(stderr, "ERR: invalid dhcp_mode\n");
	}

	sigemptyset (&base_mask);
	sigprocmask (SIG_SETMASK, &base_mask, NULL);
	fprintf(stderr, "DHCP ACK processing finished\n");
}

void check_expired_ack()
{
	uint32_t now = time(NULL);
	struct cache_ack_entry* entry = globalAckCache;
	struct cache_ack_entry* prev = NULL;
	while (entry != NULL) {
		if (entry->expiresAt < now) {
			char cmd[65535];
			snprintf(cmd, sizeof(cmd), EBTABLES " -D " CHAINNAME " -s %s --proto ipv4 --ip-source %s --logical-in %s -j ACCEPT\n" , ether_ntoa((struct ether_addr *)entry->mac), inet_ntoa(entry->ip), entry->bridge);
			fprintf(stderr,"%s", cmd);
			system(cmd);
			snprintf(cmd, sizeof(cmd), EBTABLES " -D " CHAINNAME " -s %s --proto arp --arp-ip-src %s --logical-in %s -j ACCEPT\n" , ether_ntoa((struct ether_addr *)entry->mac), inet_ntoa(entry->ip), entry->bridge);
			fprintf(stderr,"%s", cmd);
			system(cmd);
			if (prev == NULL) {
				globalAckCache = entry->next;
			} else {
				prev->next = entry->next;
			}
			free(entry);
			if (prev == NULL) {
				entry = globalAckCache;
			} else {
				entry = prev->next;
			}
		} else {
			prev = entry;
			entry = entry->next;
		}
	}
}

void check_expired_req()
{
	uint32_t now = time(NULL);
	struct cache_req_entry* entry = globalReqCache;
	struct cache_req_entry* prev = NULL;
	while (entry != NULL) {
		if (entry->expiresAt < now) {
			if (prev == NULL) {
				globalReqCache = entry->next;
			} else {
				prev->next = entry->next;
			}
			free(entry);
			if (prev == NULL) {
				entry = globalReqCache;
			} else {
				entry = prev->next;
			}
		} else {
			prev = entry;
			entry = entry->next;
		}
	}
}

void check_expired(int signum)
{
	fprintf(stderr, "cleanup...\n");
	check_expired_ack();
	check_expired_req();
	alarm(PRUNE_INTERVAL);
	fprintf(stderr, "cleanup... done\n");
}

void dump_ack()
{
	uint32_t now = time(NULL);
	struct cache_ack_entry* entry = globalAckCache;
	while (entry != NULL) {
		fprintf(stderr, "ack: MAC: %s IP: %s BRIDGE: %s expires in %d\n" , ether_ntoa((struct ether_addr *)entry->mac), inet_ntoa(entry->ip), entry->bridge, entry->expiresAt - now);
		entry = entry->next;
	}
}

void dump_req()
{
	uint32_t now = time(NULL);
	struct cache_req_entry* entry = globalReqCache;
	while (entry != NULL) {
		fprintf(stderr, "req: MAC: %s BRIDGE: %s expires in %d\n" , ether_ntoa((struct ether_addr *)entry->mac), entry->bridge, entry->expiresAt - now);
		entry = entry->next;
	}
}

void dump(int signum)
{
	fprintf(stderr, "dump...\n");
	dump_ack();
	dump_req();
	fprintf(stderr, "dump... done\n");
}

static void obj_input(struct nl_object *obj, void *arg)
{
	fprintf(stderr, "obj_input...\n");
        struct nfnl_log_msg *msg = (struct nfnl_log_msg *) obj;
	char buf[IF_NAMESIZE];

	uint32_t  indev = nfnl_log_msg_get_indev(msg);
	uint32_t  outdev = nfnl_log_msg_get_outdev(msg);

	if (indev != outdev) {
		fprintf(stderr, "obj_input...err indev!=outdev\n");
		return;
	}

	uint16_t hwproto = ntohs(nfnl_log_msg_get_hwproto(msg));
	if (hwproto != ETH_P_IP) {
		fprintf(stderr, "obj_input...err not IP\n");
		return;
	}

	if_indextoname(indev, buf);

	int len = 0;
	const u_char* data = (const u_char*) nfnl_log_msg_get_payload(msg, (int*) &len);

	fprintf(stderr, "obj_input...calling got packet\n");
	got_packet(data, len, buf);
	fprintf(stderr, "obj_input...done\n");
}

static int event_input(struct nl_msg *msg, void *arg)
{
	fprintf(stderr, "event_input...\n");
        if (nl_msg_parse(msg, &obj_input, NULL) < 0)
                fprintf(stderr, "<<EVENT>> Unknown message type\n");

	fprintf(stderr, "event_input...done\n");
        /* Exit nl_recvmsgs_def() and return to the main select() */
        return NL_STOP;
}

int main(int argc, char *argv[])
{
	struct nl_sock *nf_sock;
	struct nfnl_log *log;
	
	signal (SIGALRM, check_expired);
	alarm (PRUNE_INTERVAL);
	signal (SIGUSR1, dump);

	nf_sock = nl_socket_alloc();
	if (nf_sock < 0) {
		perror("cannot alloc scoket");
		exit(254);
	}
	nl_socket_disable_seq_check(nf_sock);
	nl_socket_modify_cb(nf_sock, NL_CB_VALID, NL_CB_CUSTOM, event_input, NULL);

	if (nl_connect(nf_sock, NETLINK_NETFILTER) < 0) {
		perror("cannot connect");
		exit(254);
	}

	nfnl_log_pf_unbind(nf_sock, AF_BRIDGE);
	if (nfnl_log_pf_bind(nf_sock, AF_BRIDGE) < 0) {
		perror("cannot bind");
		exit(254);
	}

	log = nfnl_log_alloc();
	nfnl_log_set_group(log, 1);

	nfnl_log_set_copy_mode(log, NFNL_LOG_COPY_PACKET);

	nfnl_log_set_copy_range(log, 0xFFFF);

	if (nfnl_log_create(nf_sock, log) < 0) {
		perror("cannot create log");
		exit(254);
	}

	while (1) {
		fd_set rfds;
		int nffd, maxfd, retval;

		FD_ZERO(&rfds);

		maxfd = nffd = nl_socket_get_fd(nf_sock);
		FD_SET(nffd, &rfds);

		/* wait for an incoming message on the netlink nf_socket */
		fprintf(stderr, "wait for incoming message...\n");
		retval = select(maxfd+1, &rfds, NULL, NULL, NULL);
		fprintf(stderr, "wait for incoming message...signaled\n");
		if (retval) {
			if (FD_ISSET(nffd, &rfds))
				nl_recvmsgs_default(nf_sock);
		}
		fprintf(stderr, "wait for incoming message...processing completed\n");
	}

	return 0;
}
