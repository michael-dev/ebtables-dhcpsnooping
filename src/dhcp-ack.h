#include <net/if.h>
#include <netinet/ether.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

struct cache_ack_entry 
{
	char bridge[IF_NAMESIZE];
	uint8_t mac[ETH_ALEN];
	struct in_addr ip;
	uint32_t expiresAt;
	struct cache_ack_entry* next;
};

typedef void (*ack_update_cb)(struct cache_ack_entry* entry, void* ctx);

struct cache_ack_entry* get_ack_entry(const struct in_addr* yip, const uint8_t* mac, const char* ifname);
struct cache_ack_entry* add_ack_entry(const struct in_addr* yip, const uint8_t* mac, const char* ifname, const uint32_t expiresAt);
void add_ack_entry_if_not_found(const struct in_addr* yip, const uint8_t* mac, const char* ifname, const uint32_t expiresAt);
void add_ack_update_cb(ack_update_cb cb, void* ctx);
void ack_update(ack_update_cb cb, void* ctx);

