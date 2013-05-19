/*
 * This program reads dhcp ack packets from nflog using libnl and creates a
 * temporary table of all authenticated MAC/IP pairs + their lifetime.
 * When a new entry is added, an ebtables accept rule is added,
 * when the entry expires, it is removed.
 * DHCP requests are used to filter dhcp broadcast acks for unseen dhcp requests,
 * i.e. non-local stations.
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License as
 *	published by the Free Software Foundation version 3 of the License.
 *
 *  gcc -I /usr/include/libnl3/ dhcpsnoopingd.c -l nl-3 -l nl-genl-3 -l nl-nf-3 -l nl-route-3 -o dhcpsnoopingd
 *
 * Roaming:
 * When using on APs, the STAs can roam around - so the DHCP request/reply pair
 * is seen on a different AP that the STA is then connected to.
 * A list of current STAs is derived from NEWNEIGH/DELNEIGH messages from
 * kernel bridge and dhcp replys that change the lease that are broadcastet
 * in the local network. See the defines below to change the network addresses.
 * Note: The roaming support only updates leases for STAs that are currently
 * marked as local by kernel bridge - i.e. they appear on a bridge port named 
 * as given below.
 * BUG: Kernel 3.8.3 does not report changes in bridge port - i.e. if an STA
 *      moves from backbone to local port.
 *      (Sent upstream)
 * Patch:
 *  https://github.com/torvalds/linux/commit/b0a397fb352e65e3b6501dca9662617a18862ef1 in v3.10-rc1
 *  (was: http://git.kernel.org/cgit/linux/kernel/git/next/linux-next.git/commit/net/bridge/br_fdb.c?id=b0a397fb352e65e3b6501dca9662617a18862ef1)
 *  (original: https://patchwork.kernel.org/patch/2444531/)
 *
 * EBTABLES FLOW: PREROUTING FILTER -> br_forward -> fdb_update [sends NEWNEIGH] -> FORWARD_FILTER -> ...
 *  --> so put your filter in ebtables FORWARDING chain
 *
 * MySQL aka MariaDB:
 * This makes all leases to be stored in a central MySQL db and ist most useful
 * to enhance roaming. When roaming occurs after a DHCP lease has been obtained,
 * database access can be used to fetch and install the current lease.
 * Expired leases are pruned from DB.
 * Restrictions:
 *  * The bridge-names need to be the same on all APs.
 *
 * Copyright (c) 2012 Michael Braun <michael-dev@fami-braun.de>
 * forked from nf-log.c (libnl):
 *   Copyright (c) 2003-2008 Thomas Graf <tgraf@suug.ch>
 *   Copyright (c) 2007 Philip Craig <philipc@snapgear.com>
 *   Copyright (c) 2007 Secure Computing Corporation
 */

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
#include <syslog.h>
#ifdef __USE_MYSQL__
#include <mysql/mysql.h>
#include <mysql/errmsg.h>
#include <sys/stat.h>
#endif
#include <getopt.h>

#define CHAINNAME "dhcpsnooping"
#define EBTABLES "ebtables"
#define PRUNE_INTERVAL 300
#define DEBUG 1
#define REQ_LIFETIME 300
#define MYCNF "/etc/mysql/fembot.cnf"
#define MYSQLDB "dhcpsnooping"
#define MYSQLLEASETABLE "leases"
#define MYSQLGROUP "dhcpsnooping"
/* prefix of wireless interfaces */
#define ROAMIFPREFIX "wl"
#define FDBMAXSIZE 4096
#define NETWORKPORT 1000
#define NETWORKADDR "10.30.255.255"
#define NETWORKPREFIX "10.30."

#define DEBUG_ERROR   1
#define DEBUG_GENERAL 2
#define DEBUG_UDP     4
#define DEBUG_NFLOG   8
#define DEBUG_NEIGH  16
#define DEBUG_DHCP   32
#define DEBUG_ALL   255
#if DEBUG
static int debug = DEBUG_ERROR;
#define eprintf(level, ...) if (level & debug) { char syslogbuf[4096]; snprintf(syslogbuf, sizeof(syslogbuf), __VA_ARGS__); syslog(LOG_INFO, syslogbuf, strlen(syslogbuf)); };
#else
#define eprintf(...)
#endif

#ifdef __USE_MYSQL__
MYSQL mysql;
static char* mysql_config_file = MYCNF;
#endif

#ifdef __USE_MYSQL__
#warning "MySQL support enabled"
#endif

#ifdef __USE_ROAMING__
#warning "Roaming support enabled"
#endif

#define MIN(a,b) (((a)<(b))?(a):(b))

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

#ifdef __USE_ROAMING__
struct cache_fdb_entry {
	char bridge[IF_NAMESIZE];
	uint8_t mac[ETH_ALEN];
	uint8_t enabled;
	unsigned int portidx;
	struct cache_fdb_entry* next;
};

static struct cache_fdb_entry* globalFdbCache = NULL;
static int globalFdbCacheSize = 0;
#endif

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

#ifdef __USE_ROAMING__
struct cache_fdb_entry* get_fdb_entry(const uint8_t* mac, const char* bridge, const unsigned int portidx) {
	struct cache_fdb_entry* entry = globalFdbCache;
	while (entry != NULL) {
		if (memcmp(entry->mac, mac, ETH_ALEN) == 0 &&
		    ((bridge && strncmp(entry->bridge, bridge, IF_NAMESIZE) == 0) || entry->portidx == portidx)
		   ) {
			break;
		}
		entry = entry->next;
	}
	return entry;
}
#endif

struct cache_req_entry* add_req_entry(const uint8_t* mac, const char* ifname, const uint32_t expiresAt) {
	struct cache_req_entry* entry = malloc(sizeof(struct cache_req_entry));
	if (!entry) {
		eprintf(DEBUG_ERROR, "out of memory at %s:%d in %s", __FILE__, __LINE__, __PRETTY_FUNCTION__);
		return NULL;
	}
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
	if (!entry) {
		eprintf(DEBUG_ERROR, "out of memory at %s:%d in %s", __FILE__, __LINE__, __PRETTY_FUNCTION__);
		return NULL;
	}
	memset(entry, 0, sizeof(struct cache_ack_entry));
	memcpy(entry->mac, mac, ETH_ALEN);
	memcpy(&entry->ip,yip,sizeof(struct in_addr));
	strncpy(entry->bridge, ifname, IF_NAMESIZE);
	entry->expiresAt = expiresAt;
	entry->next = globalAckCache;
	globalAckCache = entry;
	return entry;
}

#ifdef __USE_ROAMING__
struct cache_fdb_entry* add_fdb_entry(const uint8_t* mac, const char* ifname, uint8_t enabled, unsigned int portidx) {
	if (globalFdbCacheSize > FDBMAXSIZE) return NULL;
	struct cache_fdb_entry* entry = malloc(sizeof(struct cache_fdb_entry));
	if (!entry) {
		eprintf(DEBUG_ERROR, "out of memory at %s:%d in %s", __FILE__, __LINE__, __PRETTY_FUNCTION__);
		return NULL;
	}
	memset(entry, 0, sizeof(struct cache_fdb_entry));
	memcpy(entry->mac, mac, ETH_ALEN);
	strncpy(entry->bridge, ifname, IF_NAMESIZE);
	entry->enabled = enabled;
	entry->portidx = portidx;
	entry->next = globalFdbCache;
	globalFdbCache = entry;
	globalFdbCacheSize++;
	return entry;
}
#endif

static void ebtables_add(const struct in_addr* yip, const uint8_t* mac, const char* ifname) {
	assert(yip); assert(mac); assert(ifname);
	char cmd[65535];
	snprintf(cmd, sizeof(cmd), EBTABLES " -A " CHAINNAME " -s %s --proto ipv4 --ip-source %s --logical-in %s -j ACCEPT" , ether_ntoa((struct ether_addr *)mac), inet_ntoa(*yip), ifname);
	eprintf(DEBUG_GENERAL, "run \"%s\"", cmd);
	if (system(cmd)) {
		eprintf(DEBUG_GENERAL, "failed\n");
	} else {
		eprintf(DEBUG_GENERAL, " ok\n");
	}
	snprintf(cmd, sizeof(cmd), EBTABLES " -A " CHAINNAME " -s %s --proto arp --arp-ip-src %s --logical-in %s -j ACCEPT" , ether_ntoa((struct ether_addr *)mac), inet_ntoa(*yip), ifname);
	eprintf(DEBUG_GENERAL, "run \"%s\"", cmd);
	if (system(cmd)) {
		eprintf(DEBUG_GENERAL, "failed\n");
	} else {
		eprintf(DEBUG_GENERAL, " ok\n");
	}
}

struct cache_ack_entry* add_ack_entry_if_not_found(const struct in_addr* yip, const uint8_t* mac, const char* ifname, const uint32_t expiresAt) {
	assert(yip); assert(mac); assert(ifname);
	struct cache_ack_entry* entry = get_ack_entry(yip, mac, ifname);
	if (entry == NULL) {
		entry = add_ack_entry(yip, mac, ifname, expiresAt);
		/* run cmd */
		ebtables_add(yip, mac, ifname);
	} else {
		entry->expiresAt = expiresAt;
	}
	return entry;
}

#ifdef __USE_MYSQL__
int mysql_connected() {
	static int connected = 0;

	if (connected != 0)
		return connected;

	struct stat buf;
	if (stat(mysql_config_file, &buf) != 0) {
		eprintf(DEBUG_ERROR, "stat config file: %s\n", strerror(errno));
		eprintf(DEBUG_GENERAL, "missing %s config file\n", mysql_config_file);
		return connected;
	}
	if (!S_ISREG(buf.st_mode)) {
		eprintf(DEBUG_GENERAL, "missing %s config file\n", mysql_config_file);
		return connected;
	}

	unsigned int timeout = 2;
	my_bool reconnect = 1;
	mysql_options(&mysql, MYSQL_OPT_CONNECT_TIMEOUT, &timeout);
	mysql_options(&mysql, MYSQL_OPT_RECONNECT, &reconnect);
	mysql_options(&mysql, MYSQL_READ_DEFAULT_FILE, mysql_config_file);
	mysql_options(&mysql, MYSQL_READ_DEFAULT_GROUP, MYSQLGROUP);
	if (mysql_real_connect(&mysql, NULL, NULL, NULL, MYSQLDB, 0, NULL, CLIENT_REMEMBER_OPTIONS) == NULL) {
		eprintf(DEBUG_GENERAL,  "connection failed: %s\n", mysql_error(&mysql));
		return connected;
	}
		
	if (mysql_errno(&mysql)) {
		eprintf(DEBUG_GENERAL,  "mysql error: %s\n", mysql_error(&mysql));
		return connected;
	}

	connected = 1;

	return connected;
}
int mysql_query_errprint(const char* sql) {
	if (!mysql_connected()) {
		eprintf(DEBUG_GENERAL,  "mysql not connected, not running %s\n", sql);
		return -1;
	}

	int ret = mysql_query(&mysql, sql);
	int err = mysql_errno(&mysql);
	if (err)
		eprintf(DEBUG_GENERAL,  "mysql error: %s\nmysql query %s\n\n", mysql_error(&mysql), sql);
	if (err == CR_SERVER_GONE_ERROR) {
		eprintf(DEBUG_GENERAL,  "mysql repeat query\n");
		ret = mysql_query(&mysql, sql);
	}
	return ret;
}
#endif

#ifdef __USE_ROAMING__
static void sendBroad(const char *dstIP, const char *msg)
{
    static int broadcastSock = 0;
    struct sockaddr_in broadcastAddr; /* Broadcast address */

    /* Create socket for sending/receiving datagrams */
    if (!broadcastSock) {
        broadcastSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (broadcastSock < 0) {
           broadcastSock = 0;
           eprintf(DEBUG_ERROR, "cannot open broadcast socket: %s\n", strerror(errno));
           return;
        }
        int broadcastEnable=1;
        int ret=setsockopt(broadcastSock, SOL_SOCKET, SO_BROADCAST, &broadcastEnable, sizeof(broadcastEnable));
        if (ret < 0) {
           broadcastSock = 0;
           eprintf(DEBUG_ERROR, "cannot open broadcast socket: setting SO_BROADCAST failed: %s\n", strerror(errno));
           close(broadcastSock);
           return;
        }
    }

    /* Construct local address structure */
    memset(&broadcastAddr, 0, sizeof(broadcastAddr));
    broadcastAddr.sin_family = AF_INET;                 /* Internet address family */
    broadcastAddr.sin_addr.s_addr = inet_addr(dstIP);   /* Broadcast IP address */
    broadcastAddr.sin_port = htons(NETWORKPORT);       /* Broadcast port */

    /* send message */
    if(sendto(broadcastSock, msg, strlen(msg), 0, (struct sockaddr *)&broadcastAddr, sizeof(broadcastAddr)) < 0)
        eprintf(DEBUG_ERROR, "sendto: %s\n", strerror(errno));
}
#endif

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
	           && (get_req_entry(mac, ifname) != NULL
#ifdef __USE_ROAMING__
                       || get_fdb_entry(mac, ifname, 0) != NULL
#endif
	              )
		  ) {
		uint32_t now = time(NULL);
		uint32_t expiresAt = now + leaseTime;
		add_ack_entry_if_not_found(&yip, mac, ifname, expiresAt);

#ifdef __USE_MYSQL__
		/* the mysql commands are both run always, as the initial entry might have been created on another device. */
		/* though, we restrict ACKs to be received on APs that saw the request - no roaming between REQ/ACK */
		/* add to mysql */
		if (mysql_connected()) {
			char sql_esc_bridge[1024];
			mysql_real_escape_string(&mysql, sql_esc_bridge, ifname, MIN(strlen(ifname), sizeof(sql_esc_bridge) / 2 - 1));
			char sql[2048];
			snprintf(sql, sizeof(sql), "INSERT IGNORE INTO %s (bridge, mac, ip, validUntil) VALUES('%s', '%s', '%s', %d + UNIX_TIMESTAMP());", MYSQLLEASETABLE, sql_esc_bridge, ether_ntoa((struct ether_addr *)mac), inet_ntoa(yip), leaseTime);
			mysql_query_errprint(sql);
			/* update to mysql */
			snprintf(sql, sizeof(sql), "UPDATE %s SET validUntil = %d + UNIX_TIMESTAMP() WHERE bridge = '%s' AND mac = '%s' AND ip = '%s';", MYSQLLEASETABLE, leaseTime, sql_esc_bridge, ether_ntoa((struct ether_addr *)mac), inet_ntoa(yip));
			mysql_query_errprint(sql);
		}
#endif
#ifdef __USE_ROAMING__
		char msg[1024];
		snprintf(msg, sizeof(msg), "%s\t%s\t%s\t%d", ifname, ether_ntoa((struct ether_addr *)mac), inet_ntoa(yip), leaseTime);
		sendBroad(NETWORKADDR,msg);
#endif
	} else if (dhcpmsgtype == LIBNET_DHCP_MSGACK) {
		eprintf(DEBUG_DHCP,  " * unsoliciated DHCP ACK\n");
	} else if (dhcpmsgtype == LIBNET_DHCP_MSGRELEASE) {
		struct cache_ack_entry* entry = globalAckCache;
		while (entry != NULL) {
			if (memcmp(entry->mac, mac, ETH_ALEN) == 0 && strncmp(entry->bridge, ifname, IF_NAMESIZE) == 0) {
				entry->expiresAt = 0;
			}
			entry = entry->next;
		}
#ifdef __USE_MYSQL__
		/* update mysql */
		if (mysql_connected()) {
			char sql_esc_bridge[1024];
			mysql_real_escape_string(&mysql, sql_esc_bridge, ifname, MIN(strlen(ifname), sizeof(sql_esc_bridge) / 2 - 1));
			char sql[2048];
			snprintf(sql, sizeof(sql), "UPDATE %s SET validUntil = 0 WHERE bridge = '%s' AND mac = '%s';", MYSQLLEASETABLE, sql_esc_bridge, ether_ntoa((struct ether_addr *)mac));
			mysql_query_errprint(sql);
		}
#endif
#ifdef __USE_ROAMING__
		char msg[1024];
		snprintf(msg, sizeof(msg), "%s\t%s\t%s\t%d", ifname, ether_ntoa((struct ether_addr *)mac), inet_ntoa(yip), -1);
		sendBroad(NETWORKADDR,msg);
#endif
	} else {
		eprintf(DEBUG_DHCP,  "ERR: invalid dhcp_mode\n");
	}

	eprintf(DEBUG_DHCP,  "DHCP ACK processing finished\n");
}

int signalDump = 0, signalExpire = 0;

void check_expired_ack()
{
#ifdef __USE_MYSQL__
	char sql[1024];
	char sql_esc_bridge[1024];
	MYSQL_RES *result;
	MYSQL_ROW row;
#endif
	uint32_t now =time(NULL);

#ifdef __USE_MYSQL__
	/* update mysql */
	snprintf(sql, sizeof(sql), "DELETE FROM %s WHERE validUntil < UNIX_TIMESTAMP();", MYSQLLEASETABLE);
	mysql_query_errprint(sql);
#endif

	struct cache_ack_entry* entry = globalAckCache;
	struct cache_ack_entry* prev = NULL;
	while (entry != NULL) {
#ifdef __USE_MYSQL__
		if (mysql_connected()) {
			mysql_real_escape_string(&mysql, sql_esc_bridge, entry->bridge, MIN(strlen(entry->bridge), sizeof(sql_esc_bridge) / 2 - 1));
			snprintf(sql, sizeof(sql), "SELECT MAX(validUntil) - UNIX_TIMESTAMP() FROM %s WHERE validUntil > UNIX_TIMESTAMP() AND bridge = '%s' AND mac = '%s' AND ip = '%s';", MYSQLLEASETABLE, sql_esc_bridge, ether_ntoa((struct ether_addr *)entry->mac), inet_ntoa(entry->ip));
			if (mysql_query_errprint(sql) == 0) {
				/* mysql query sucessfull */
				result = mysql_store_result(&mysql);
				if (result) { /* Ansonsten ist ein Fehler aufgetreten */
					/* MAX(validUntil) - UNIX_TIMESTAMP() == NULL wenn keine records gefunden werden -> row[0] == NULL */
					row = mysql_fetch_row(result);
					if (row && row[0]) {
						entry->expiresAt = atoi(row[0]) + now;
					} else {
						entry->expiresAt = 0;
					}
					mysql_free_result(result);
				}
			}
		}
#endif
		if (entry->expiresAt < now) {
			char cmd[65535];
			snprintf(cmd, sizeof(cmd), EBTABLES " -D " CHAINNAME " -s %s --proto ipv4 --ip-source %s --logical-in %s -j ACCEPT" , ether_ntoa((struct ether_addr *)entry->mac), inet_ntoa(entry->ip), entry->bridge);
			eprintf(DEBUG_GENERAL, "run \"%s\"", cmd);
			if (system(cmd)) {
				eprintf(DEBUG_GENERAL, " failed\n");
			} else {
				eprintf(DEBUG_GENERAL, " ok\n");
			}
			snprintf(cmd, sizeof(cmd), EBTABLES " -D " CHAINNAME " -s %s --proto arp --arp-ip-src %s --logical-in %s -j ACCEPT" , ether_ntoa((struct ether_addr *)entry->mac), inet_ntoa(entry->ip), entry->bridge);
			eprintf(DEBUG_GENERAL, "run \"%s\"", cmd);
			if (system(cmd)) {
				eprintf(DEBUG_GENERAL, " failed\n");
			} else {
				eprintf(DEBUG_GENERAL, " ok\n");
			}
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

#ifdef __USE_ROAMING__
void check_expired_fdb()
{
	struct cache_fdb_entry* entry = globalFdbCache;
	struct cache_fdb_entry* prev = NULL;
	while (entry != NULL) {
		if (!entry->enabled) {
			if (prev == NULL) {
				globalFdbCache = entry->next;
			} else {
				prev->next = entry->next;
			}
			free(entry);
			globalFdbCacheSize--;
			if (prev == NULL) {
				entry = globalFdbCache;
			} else {
				entry = prev->next;
			}
		} else {
			prev = entry;
			entry = entry->next;
		}
	}
}
#endif

void check_expired()
{
	eprintf(DEBUG_GENERAL,  "cleanup...\n");
	check_expired_ack();
	check_expired_req();
#ifdef __USE_ROAMING__
	check_expired_fdb();
#endif
	alarm(PRUNE_INTERVAL);
	eprintf(DEBUG_GENERAL,  "cleanup... done\n");
}

void dump_ack()
{
	uint32_t now = time(NULL);
	struct cache_ack_entry* entry = globalAckCache;
	while (entry != NULL) {
		eprintf(DEBUG_GENERAL,  "ack: MAC: %s IP: %s BRIDGE: %s expires in %d\n" , ether_ntoa((struct ether_addr *)entry->mac), inet_ntoa(entry->ip), entry->bridge, (int) entry->expiresAt - (int) now);
		entry = entry->next;
	}
}

void dump_req()
{
	uint32_t now = time(NULL);
	struct cache_req_entry* entry = globalReqCache;
	while (entry != NULL) {
		eprintf(DEBUG_GENERAL,  "req: MAC: %s BRIDGE: %s expires in %d\n" , ether_ntoa((struct ether_addr *)entry->mac), entry->bridge, (int) entry->expiresAt - (int) now);
		entry = entry->next;
	}
}

#ifdef __USE_ROAMING__
void dump_fdb()
{
	struct cache_fdb_entry* entry = globalFdbCache;
	while (entry != NULL) {
		eprintf(DEBUG_GENERAL,  "fdb: MAC: %s BRIDGE: %s %s\n" , ether_ntoa((struct ether_addr *)entry->mac), entry->bridge, (entry->enabled ? "enabled" : "disabled"));
		entry = entry->next;
	}
}
#endif

void dump()
{
	eprintf(DEBUG_GENERAL,  "dump...\n");
	dump_ack();
	dump_req();
#ifdef __USE_ROAMING__
	dump_fdb();
#endif
	eprintf(DEBUG_GENERAL,  "dump... done\n");
}

static void obj_input_nflog(struct nl_object *obj, void *arg)
{
	eprintf(DEBUG_NFLOG,  "obj_input_nflog...\n");
        struct nfnl_log_msg *msg = (struct nfnl_log_msg *) obj;
	char buf[IF_NAMESIZE];

	uint32_t  indev = nfnl_log_msg_get_indev(msg);
	uint32_t  outdev = nfnl_log_msg_get_outdev(msg);

	if (indev != outdev) {
		eprintf(DEBUG_NFLOG,  "obj_input...err indev!=outdev\n");
		return;
	}

	uint16_t hwproto = ntohs(nfnl_log_msg_get_hwproto(msg));
	if (hwproto != ETH_P_IP) {
		eprintf(DEBUG_NFLOG,  "obj_input...err not IP\n");
		return;
	}

	if_indextoname(indev, buf);

	int len = 0;
	const u_char* data = (const u_char*) nfnl_log_msg_get_payload(msg, (int*) &len);

	eprintf(DEBUG_NFLOG,  "obj_input...calling got packet\n");
	got_packet(data, len, buf);
	eprintf(DEBUG_NFLOG,  "obj_input...done\n");
}

#ifdef __USE_ROAMING__
static void obj_input_dellink(struct rtnl_link *link)
{
	char *ifname = rtnl_link_get_name(link);
	unsigned int ifidx = rtnl_link_get_ifindex(link);

	eprintf(DEBUG_NEIGH,  "DELLINK message for %s (%d) received, pruning\n", ifname, ifidx);

	struct cache_fdb_entry* entry;
	for (entry = globalFdbCache; entry; entry = entry->next) {
		if (strncmp(entry->bridge, ifname, IF_NAMESIZE) != 0 && entry->portidx != ifidx) {
			continue;
		}
		entry->enabled = 0;
	}
}

static void obj_input_neigh(int type, struct rtnl_neigh *neigh)
{
	int family = rtnl_neigh_get_family(neigh);
	if (family != AF_BRIDGE) {
		eprintf(DEBUG_NEIGH,  "family %d != AF_BRIDGE (%d), ignore\n", family, AF_BRIDGE);
		return;
	}

	char lladdr[32];
	{
		struct nl_addr* addr = rtnl_neigh_get_lladdr(neigh);
		if (nl_addr_get_family(addr) != AF_LLC) {
			eprintf(DEBUG_NEIGH,  "addr family %d != AF_LLC (%d), ignore\n", nl_addr_get_family(addr), AF_LLC);
			addr = NULL;
			return;
		}
		nl_addr2str(addr, lladdr, sizeof(lladdr));
		addr = NULL;
	}

	// need brige and at best port
	int ifidx = rtnl_neigh_get_ifindex(neigh);

	static struct nl_sock *sock = NULL;
	if (!sock) {
		sock = nl_socket_alloc();
		if (sock < 0) {
			eprintf(DEBUG_ERROR, "cannot alloc socket (III): %s\n", strerror(errno));
			sock = NULL;
			return;
		}
		if (nl_connect(sock, NETLINK_ROUTE) < 0) {
			eprintf(DEBUG_ERROR, "cannot conncet socket (III): %s\n", strerror(errno));
			nl_socket_free(sock);
			sock = NULL;
			return;
		}
	}

	struct rtnl_link *link = NULL, *bridge = NULL;
	if (rtnl_link_get_kernel(sock, ifidx, NULL, &link) < 0) {
		link = NULL;
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

		if (rtnl_link_get_kernel(sock, bridgeidx, NULL, &bridge) < 0) {
			bridge = NULL;
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

#ifdef __USE_MYSQL__
	if (mysql_connected() && type == RTM_NEWNEIGH) {
		eprintf(DEBUG_NEIGH, "\nquery mysql\n");
		/* query sql for lease and add local rules*/
		char sql[1024];
		char sql_esc_bridge[1024];
		const uint32_t now = time(NULL);
		MYSQL_RES *result;
		MYSQL_ROW row;
	
		mysql_real_escape_string(&mysql, sql_esc_bridge, bridgeifname, MIN(strlen(bridgeifname), sizeof(sql_esc_bridge) / 2 - 1));
		snprintf(sql, sizeof(sql), "SELECT ip, MAX(validUntil) - UNIX_TIMESTAMP() FROM %s WHERE validUntil > UNIX_TIMESTAMP() AND bridge = '%s' AND mac = '%s' GROUP BY ip;", MYSQLLEASETABLE, sql_esc_bridge, ether_ntoa((struct ether_addr *)mac));
		eprintf(DEBUG_NEIGH, "query: %s\n", sql);
		if (mysql_query_errprint(sql) != 0) {
			goto out2;
		}
		/* mysql query sucessfull */
		result = mysql_store_result(&mysql);
		if (!result) {
			eprintf(DEBUG_NEIGH, "query mysql: cannot fetch result\n");
			goto out2;
		}
		while ((row = mysql_fetch_row(result)) != NULL) {
			eprintf(DEBUG_NEIGH, "query mysql: got row ip = %s, expiresAt = %s\n", row[0] ? row[0] : "NULL", row[1] ? row[1] : "NULL");
			if (!row[0] || !row[1])
				continue;
			struct in_addr yip;
			if (!inet_aton(row[0], &yip)) {
				eprintf(DEBUG_NEIGH, "cannot parse ip\n");
				continue;
			}
			uint32_t expiresAt = atoi(row[1]) + now;
			eprintf(DEBUG_NEIGH, "add ebtables rule...\n");
			add_ack_entry_if_not_found(&yip, (const uint8_t*) mac, bridgeifname, expiresAt);
		}
		mysql_free_result(result);
out2:
		eprintf(DEBUG_NEIGH, "mysql completed\n");
	}
#endif /* MYSQL */
out:
	if (link)
		rtnl_link_put(link);
	if (bridge)
		rtnl_link_put(bridge);
}

static void obj_input_route(struct nl_object *obj, void *arg)
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
	default:
		eprintf(DEBUG_NEIGH,  "type %d != RTM_NEWNEIGH (%d), RTM_DELNEIGH (%d), RTM_NEWLINK (%d), RTM_DELLINK (%d) ignore\n", type, RTM_NEWNEIGH, RTM_DELNEIGH, RTM_NEWLINK, RTM_DELLINK);
		break;
	}
}
#endif /* ROAMING */

static int event_input_nflog(struct nl_msg *msg, void *arg)
{
        if (nl_msg_parse(msg, &obj_input_nflog, NULL) < 0)
                eprintf(DEBUG_NFLOG,  "<<EVENT:nflog>> Unknown message type\n");
        return NL_STOP;
}

#ifdef __USE_ROAMING__
static int event_input_route(struct nl_msg *msg, void *arg)
{
        if (nl_msg_parse(msg, &obj_input_route, NULL) < 0)
		eprintf(DEBUG_NEIGH,  "<<EVENT:Route>> Unknown message type\n");
	return NL_STOP;
}

static void handle_udp_message(char* buf, int recvlen) {
	/* msg := <ifname>\t<mac>\t<ip>\t<expire> */
	/* split message by \t */
	char* pos = buf;
	char* str_ifname = pos;
	while (pos < buf + recvlen - 3 && *pos != '\t')
		pos++;
	*pos = '\0'; // terminate str_ifname
	char* str_mac = ++pos;
	while (pos < buf + recvlen - 2 && *pos != '\t')
		pos++;
	*pos = '\0'; // terminate str_mac
	char* str_ip = ++pos;
	while (pos < buf + recvlen - 1 && *pos != '\t')
		pos++;
	*pos = '\0'; // terminate str_ip
	char* str_expire = ++pos;
	while (pos < buf + recvlen - 0 && *pos != '\t')
		pos++;
	*pos = '\0'; // terminate str_expire

#ifdef __USE_MYSQL__
	/* query database for lease, goto out if not found */
	char sql[1024];
	char sql_esc_bridge[1024];
	char sql_esc_mac[1024];
	char sql_esc_ip[1024];
	MYSQL_RES *result;
	MYSQL_ROW row;
	mysql_real_escape_string(&mysql, sql_esc_bridge, str_ifname, MIN(strlen(str_ifname), sizeof(sql_esc_bridge) / 2 - 1));
	mysql_real_escape_string(&mysql, sql_esc_mac, str_mac, MIN(strlen(str_mac), sizeof(sql_esc_mac) / 2 - 1));
	mysql_real_escape_string(&mysql, sql_esc_ip, str_ip, MIN(strlen(str_ip), sizeof(sql_esc_ip) / 2 - 1));
	snprintf(sql, sizeof(sql), "SELECT MAX(validUntil) - UNIX_TIMESTAMP() FROM %s WHERE validUntil > UNIX_TIMESTAMP() AND bridge = '%s' AND mac = '%s' AND ip = '%s';", MYSQLLEASETABLE, sql_esc_bridge, sql_esc_mac, sql_esc_ip);
	eprintf(DEBUG_UDP,  "query: %s\n", sql);
	if (mysql_query_errprint(sql) != 0) {
		return;
	}
	/* mysql query sucessfull */
	result = mysql_store_result(&mysql);
	if (!result) { /* Es ist ein Fehler aufgetreten */
		return;
	}
	/* MAX(validUntil) - UNIX_TIMESTAMP() == NULL wenn keine records gefunden werden -> row[0] == NULL */
	row = mysql_fetch_row(result);
	if (!row || !row[0]) {
		eprintf(DEBUG_UDP,  "database has no lease for data given in udp packet\n");
		mysql_free_result(result);
		result = NULL;
		return;
	}
	str_expire = row[0];
	mysql_free_result(result);
	result = NULL;
#endif
	/* parse message */
	char* ifname = str_ifname;
	if (if_nametoindex(ifname) == 0) {
		eprintf(DEBUG_ERROR, "invalid interface: %s\n", strerror(errno));
		eprintf(DEBUG_UDP,  "Interface %s unknown\n", ifname);
		return;
	}
	struct ether_addr *mac = ether_aton(str_mac);
	struct in_addr yip;
	if (!inet_aton(str_ip, &yip)) {
		eprintf(DEBUG_UDP,  "invalid ip %s\n", str_ip);
		return;
	}
	int expire = time(NULL) + atoi(str_expire);

	/* check if lease exists -> exit */
	struct cache_ack_entry* ack_entry = get_ack_entry(&yip, (uint8_t*) mac, ifname);
	if (ack_entry) {
		ack_entry->expiresAt = expire;
		eprintf(DEBUG_UDP,  "mac %s on %s with ip %s has ebtables rule, update expire to %d and skip\n", str_mac, str_ifname, str_ip, expire);
		return;
	}
	/* check if in fdb, else exit */
	struct cache_fdb_entry* fdb_entry = get_fdb_entry((uint8_t*) mac, ifname, 0);
	if (!fdb_entry || !fdb_entry->enabled) {
		return;
	}
	/* add lease */
	eprintf(DEBUG_UDP,  "adding new lease\n");
	add_ack_entry(&yip, (uint8_t*) mac, ifname, expire);
	ebtables_add(&yip, (uint8_t*) mac, ifname);
}				
#endif

void signal_expire(int signum) {
	signalExpire = 1;
}

void signal_dump(int signum) {
	signalDump = 1;
}


int main(int argc, char *argv[])
{
	openlog ("dhcpsnoopingd", LOG_CONS | LOG_PID | LOG_NDELAY | LOG_PERROR, LOG_DAEMON);

	fprintf(stderr, "dhcpsnoopingd version $Id: dhcpsnoopingd.c 809 2013-05-19 14:45:40Z mbr $\n");
	/* parse args */
	int c;
     
	static struct option long_options[] = {
		/* These options set a flag. */
		{"debug",       no_argument, 0, DEBUG_GENERAL},
		{"debug-udp",   no_argument, 0, DEBUG_UDP},
		{"debug-nflog", no_argument, 0, DEBUG_NFLOG},
		{"debug-neigh", no_argument, 0, DEBUG_NEIGH},
		{"debug-all",  no_argument, 0, DEBUG_ALL},
#ifdef __USE_MYSQL__
		{"mysql-config-file", required_argument, 0, 3},
#endif
		{0, 0, 0, 0}
	};
	/* getopt_long stores the option index here. */
	int option_index = 0;
     
	while ((c = getopt_long (argc, argv, "", long_options, &option_index)) != -1) {
	   switch (c)
		 {
		 case DEBUG_GENERAL:
		 case DEBUG_UDP:
		 case DEBUG_NFLOG:
		 case DEBUG_NEIGH:
		 case DEBUG_DHCP:
		 case DEBUG_ALL:
			/* If this option set a flag, do nothing else now. */
			debug |= c;
			break;
#ifdef __USE_MYSQL__
		case 3:
			mysql_config_file = optarg;
			break;
#endif
		 default:
		   abort ();
		 }
	 }

	/* setup db */
#ifdef __USE_MYSQL__
	eprintf(DEBUG_GENERAL,  "MySQL client version: %s\n", mysql_get_client_info());
	if (!mysql_init(&mysql)) {
		eprintf(DEBUG_GENERAL,  "mysql error: %s\n", mysql_error(&mysql));
		exit(254);
	}
#endif

	signal (SIGALRM, signal_expire);
	alarm (PRUNE_INTERVAL);
	signal (SIGUSR1, signal_dump);

	/* connect to netfilter / NFLOG */
	struct nl_sock *nf_sock_nflog;
	struct nfnl_log *log;
	
	nf_sock_nflog = nl_socket_alloc();
	if (nf_sock_nflog < 0) {
		eprintf(DEBUG_ERROR, "cannot alloc socket: %s\n", strerror(errno));
		exit(254);
	}
	nl_socket_disable_seq_check(nf_sock_nflog);
	nl_socket_modify_cb(nf_sock_nflog, NL_CB_VALID, NL_CB_CUSTOM, event_input_nflog, NULL);

	if (nl_connect(nf_sock_nflog, NETLINK_NETFILTER) < 0) {
		eprintf(DEBUG_ERROR, "cannot connect: %s\n", strerror(errno));
		exit(254);
	}

	nfnl_log_pf_unbind(nf_sock_nflog, AF_BRIDGE);
	if (nfnl_log_pf_bind(nf_sock_nflog, AF_BRIDGE) < 0) {
		eprintf(DEBUG_ERROR, "cannot bind: %s\n", strerror(errno));
		exit(254);
	}

	log = nfnl_log_alloc();
	nfnl_log_set_group(log, 1);

	nfnl_log_set_copy_mode(log, NFNL_LOG_COPY_PACKET);

	nfnl_log_set_copy_range(log, 0xFFFF);

	if (nfnl_log_create(nf_sock_nflog, log) < 0) {
		eprintf(DEBUG_ERROR, "cannot create log: %s\n", strerror(errno));
		exit(254);
	}

#ifdef __USE_ROAMING__
	eprintf(DEBUG_GENERAL,  "Listen to ROUTE->NEIGH notifications\n");
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

	eprintf(DEBUG_GENERAL,  "Listen to broadcasts for dhcp notifications\n");
	int udpsocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (udpsocket < 0) {
                eprintf(DEBUG_ERROR, "udp socket: %s\n", strerror(errno));
                exit(254);
        }

        int broadcastEnable=1;
        int ret=setsockopt(udpsocket, SOL_SOCKET, SO_BROADCAST, &broadcastEnable, sizeof(broadcastEnable));
        if (ret < 0) {
           eprintf(DEBUG_ERROR, "cannot open udp socket: setting SO_BROADCAST failed: %s\n", strerror(errno));
           close(udpsocket);
           exit(254);
        }

        struct sockaddr_in my_addr;
        memset(&my_addr, 0, sizeof(my_addr));
        my_addr.sin_family = AF_INET;
        my_addr.sin_addr.s_addr = INADDR_ANY;
        my_addr.sin_port = htons(NETWORKPORT);

        if (bind(udpsocket, (struct sockaddr *)&my_addr, sizeof(struct sockaddr)) < 0) {
                eprintf(DEBUG_ERROR, "bind udp: %s\n", strerror(errno));
                exit(254);
        }

#endif

        // Block SIGALRM and SIGUSR1
        sigset_t sigset, oldset;
        sigemptyset(&sigset);
        sigaddset(&sigset, SIGTERM);
	sigaddset (&sigset, SIGALRM);
	sigaddset (&sigset, SIGUSR1);
        sigprocmask(SIG_BLOCK, &sigset, &oldset);

	/* wait for an incoming message on the netlink nf_socket */
	fd_set rfds;
	int nffd, maxfd, retval;
#ifdef __USE_ROAMING__
	int rffd;
#endif
	while (1) {

		FD_ZERO(&rfds);

		maxfd = nffd = nl_socket_get_fd(nf_sock_nflog);
		FD_SET(nffd, &rfds);

#ifdef __USE_ROAMING__
		rffd = nl_socket_get_fd(nf_sock_route);
		FD_SET(rffd, &rfds);
		if (rffd > maxfd)
			maxfd = rffd;
		FD_SET(udpsocket, &rfds);
		if (udpsocket > maxfd)
			maxfd = udpsocket;
#endif
		retval = pselect(maxfd+1, &rfds, NULL, NULL, NULL, &oldset);
		if (retval < 0 && errno != EINTR)
			break;
		// Do some processing. Note that the process will not be
		// interrupted while inside this loop.
		eprintf(DEBUG_GENERAL,  ".");
		if (retval > 0) {
			if (FD_ISSET(nffd, &rfds))
				nl_recvmsgs_default(nf_sock_nflog);
#ifdef __USE_ROAMING__
			if (FD_ISSET(rffd, &rfds))
				nl_recvmsgs_default(nf_sock_route);
			if (FD_ISSET(udpsocket, &rfds)) {
			        struct sockaddr_in their_addr;
			        socklen_t addr_len = sizeof(struct sockaddr);
				char buf[1024]; memset(&buf, 0, sizeof(buf));
				int recvlen = 0;
			        if ((recvlen = recvfrom(udpsocket, buf, sizeof(buf)-1 , MSG_DONTWAIT, (struct sockaddr*) &their_addr, &addr_len)) < 0) {
			                eprintf(DEBUG_ERROR, "recvfrom udpsocket: %s\n", strerror(errno));
       				} else if (strncmp(inet_ntoa(their_addr.sin_addr), NETWORKPREFIX, strlen(NETWORKPREFIX)) != 0) {
			        	eprintf(DEBUG_UDP,  "got packet from %s, not match prefix %s\n",inet_ntoa(their_addr.sin_addr), NETWORKPREFIX);
				} else {
				        eprintf(DEBUG_UDP,  "got packet from %s\n",inet_ntoa(their_addr.sin_addr));
				        eprintf(DEBUG_UDP,  "packet contains \"%s\"\n",buf);
					handle_udp_message(buf, recvlen);
				}
			}
#endif
		}
		if (signalExpire) {
			signalExpire = 0;
			check_expired();
		}
		if (signalDump) {
			signalDump = 0;
			dump();
		}
	}
	eprintf(DEBUG_ERROR, "exit due to: %s\n", strerror(errno));

	return 0;
}

