#include "config.h"
#include "debug.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define CHAINNAME "dhcpsnooping"
#define EBTABLES "ebtables"

void ebtables_add(const struct in_addr* yip, const uint8_t* mac, const char* ifname) {
	assert(yip); assert(mac); assert(ifname);
	char cmd[65535];
	snprintf(cmd, sizeof(cmd), EBTABLES " -A " CHAINNAME " -s %s --proto ipv4 --ip-source %s --logical-in %s -j ACCEPT",
	         ether_ntoa((struct ether_addr *)mac), inet_ntoa(*yip), ifname);
	eprintf(DEBUG_GENERAL, "run \"%s\"", cmd);
	if (system(cmd)) {
		eprintf(DEBUG_GENERAL, "failed\n");
	} else {
		eprintf(DEBUG_GENERAL, " ok\n");
	}
	snprintf(cmd, sizeof(cmd), EBTABLES " -A " CHAINNAME " -s %s --proto arp --arp-ip-src %s --logical-in %s -j ACCEPT",
	         ether_ntoa((struct ether_addr *)mac), inet_ntoa(*yip), ifname);
	eprintf(DEBUG_GENERAL, "run \"%s\"", cmd);
	if (system(cmd)) {
		eprintf(DEBUG_GENERAL, "failed\n");
	} else {
		eprintf(DEBUG_GENERAL, " ok\n");
	}
}

void ebtables_del(const struct in_addr* yip, const uint8_t* mac, const char* ifname) {
	char cmd[65535];
	snprintf(cmd, sizeof(cmd), EBTABLES " -D " CHAINNAME " -s %s --proto ipv4 --ip-source %s --logical-in %s -j ACCEPT",
	         ether_ntoa((struct ether_addr *)mac), inet_ntoa(*yip), ifname);
	eprintf(DEBUG_GENERAL, "run \"%s\"", cmd);
	if (system(cmd)) {
		eprintf(DEBUG_GENERAL, " failed\n");
	} else {
		eprintf(DEBUG_GENERAL, " ok\n");
	}
	snprintf(cmd, sizeof(cmd), EBTABLES " -D " CHAINNAME " -s %s --proto arp --arp-ip-src %s --logical-in %s -j ACCEPT",
	         ether_ntoa((struct ether_addr *)mac), inet_ntoa(*yip), ifname);
	eprintf(DEBUG_GENERAL, "run \"%s\"", cmd);
	if (system(cmd)) {
		eprintf(DEBUG_GENERAL, " failed\n");
	} else {
		eprintf(DEBUG_GENERAL, " ok\n");
	}
}
