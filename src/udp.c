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

#include "debug.h"
#include "event.h"
#include "dhcp.h"
#include "dhcp-ack.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <net/if.h>
#include <netinet/ether.h>
#include "ether_ntoa.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#define NETWORKPORT 1000
#define NETWORKADDR "10.30.0.0"
#define NETWORKMASK "255.255.0.0"

static struct in_addr broadcastAddr;
static struct in_addr networkAddr;
static struct in_addr networkMask;

void sendLease(const uint8_t* mac, const struct in_addr* yip, const char* ifname, const uint32_t expiresAt, const enum t_lease_update_src reason)
{
	static int broadcastSock = 0;
	struct sockaddr_in sbroadcastAddr; /* Broadcast address */
	char msg[1024];

	/* only write DHCP ACK packet changes back */
	if (reason != UPDATED_LEASE_FROM_DHCP)
		return;

	snprintf(msg, sizeof(msg), "%s\t%s\t%s\t%d", ifname, ether_ntoa_z((struct ether_addr *)mac), inet_ntoa(*yip), (int) (expiresAt - time(NULL)));

	/* Create socket for sending/receiving datagrams */
	if (!broadcastSock) {
		broadcastSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (broadcastSock < 0) {
			broadcastSock = 0;
			eprintf(DEBUG_ERROR, "cannot open broadcast socket: %s", strerror(errno));
			return;
		}
		int broadcastEnable=1;
		int ret=setsockopt(broadcastSock, SOL_SOCKET, SO_BROADCAST, &broadcastEnable, sizeof(broadcastEnable));
		if (ret < 0) {
			broadcastSock = 0;
			eprintf(DEBUG_ERROR, "cannot open broadcast socket: setting SO_BROADCAST failed: %s", strerror(errno));
			close(broadcastSock);
			return;
		}
	}

	/* Construct local address structure */
	memset(&sbroadcastAddr, 0, sizeof(sbroadcastAddr));
	sbroadcastAddr.sin_family = AF_INET;				 /* Internet address family */
	sbroadcastAddr.sin_addr.s_addr = broadcastAddr.s_addr;   /* Broadcast IP address */
	sbroadcastAddr.sin_port = htons(NETWORKPORT);	   /* Broadcast port */

	/* send message */
	if(sendto(broadcastSock, msg, strlen(msg), 0, (struct sockaddr *)&sbroadcastAddr, sizeof(sbroadcastAddr)) < 0)
		eprintf(DEBUG_ERROR, "udp sendto: %s (%d)", strerror(errno), errno);
}

void handle_udp_message(char* buf, int recvlen) 
{
	/* msg := <ifname>\t<mac>\t<ip>\t<expire> */
	/* split message by \t */
	char* pos = buf;
	char* ifname = pos;
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

	uint8_t* mac = (uint8_t*) ether_aton(str_mac);
	struct in_addr yip;
	if (!inet_aton(str_ip, &yip)) {
		eprintf(DEBUG_UDP,  "invalid ip %s", str_ip);
		return;
	}
	int timedelta = atoi(str_expire);
	uint32_t expire = 0;
	if (timedelta > 0)
		expire = time(NULL) + atoi(str_expire);
		
	if (update_lease(ifname, mac, &yip, &expire) < 0) {
		eprintf(DEBUG_UDP | DEBUG_VERBOSE, "udp: sql query for lease MAC: %s IP: %s VLAN: %s failed", ether_ntoa_z((struct ether_addr *)mac), inet_ntoa(yip), ifname);
		return;
	}

	/* parse message */
	if (if_nametoindex(ifname) == 0) {
		eprintf(DEBUG_UDP,  "Interface %s unknown: %s (%d)", ifname, strerror(errno), errno);
		return;
	}

	if (!is_local(mac, ifname)) {
		eprintf(DEBUG_UDP,  "MAC %s locally unknown", str_mac);
		return;
	}

	/* add lease */
	eprintf(DEBUG_UDP | DEBUG_VERBOSE, "udp: adding new lease MAC: %s IP: %s VLAN: %s expiresAt:%d", ether_ntoa_z((struct ether_addr *)mac), inet_ntoa(yip), ifname, expire);
	updated_lease(mac, &yip, ifname, expire, UPDATED_LEASE_FROM_EXTERNAL);
}

void udp_receive(int udpsocket, void* ctx)
{
	struct sockaddr_in their_addr;
	socklen_t addr_len = sizeof(struct sockaddr);
	char buf[1024]; memset(&buf, 0, sizeof(buf));

	int recvlen = recvfrom(udpsocket, buf, sizeof(buf)-1 , MSG_DONTWAIT, (struct sockaddr*) &their_addr, &addr_len);
		if (recvlen < 0) {
		eprintf(DEBUG_ERROR, "recvfrom udpsocket: %s", strerror(errno));
		return;
	}
	if ((their_addr.sin_addr.s_addr & networkMask.s_addr) != networkAddr.s_addr) {
		eprintf(DEBUG_UDP, "got packet from %s not matching %s/%s",
				   inet_ntoa(their_addr.sin_addr),
				   inet_ntoa(networkAddr),
				   inet_ntoa(networkMask) );
		return;
	}
	eprintf(DEBUG_UDP,  "got packet from %s",inet_ntoa(their_addr.sin_addr));
	eprintf(DEBUG_UDP,  "packet contains \"%s\"",buf);
	handle_udp_message(buf, recvlen);
}

static __attribute__((constructor)) void udp_init()
{
	inet_aton(NETWORKADDR, &networkAddr);
	inet_aton(NETWORKMASK, &networkMask);
	broadcastAddr.s_addr = networkAddr.s_addr | (~networkMask.s_addr);
	networkAddr.s_addr = networkAddr.s_addr & networkMask.s_addr;

	eprintf(DEBUG_ERROR,  "Listen to broadcasts for dhcp notifications");
	int udpsocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (udpsocket < 0) {
		eprintf(DEBUG_ERROR, "udp socket: %s", strerror(errno));
		exit(254);
	}

	int broadcastEnable=1;
	int ret=setsockopt(udpsocket, SOL_SOCKET, SO_BROADCAST, &broadcastEnable, sizeof(broadcastEnable));
	if (ret < 0) {
		eprintf(DEBUG_ERROR, "cannot open udp socket: setting SO_BROADCAST failed: %s", strerror(errno));
		close(udpsocket);
		exit(254);
	}

	struct sockaddr_in my_addr;
	memset(&my_addr, 0, sizeof(my_addr));
	my_addr.sin_family = AF_INET;
	my_addr.sin_addr.s_addr = INADDR_ANY;
	my_addr.sin_port = htons(NETWORKPORT);

	if (bind(udpsocket, (struct sockaddr *)&my_addr, sizeof(struct sockaddr)) < 0) {
		eprintf(DEBUG_ERROR, "bind udp: %s", strerror(errno));
		exit(254);
	}

	cb_add_handle(udpsocket, NULL, udp_receive);
	add_updated_lease_hook(sendLease);
}

#endif
