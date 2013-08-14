#include <net/if.h>
#include <netinet/ether.h>
#include <stdint.h>
struct cache_req_entry 
{
	char bridge[IF_NAMESIZE];
	uint8_t mac[ETH_ALEN];
	uint32_t expiresAt;
	struct cache_req_entry* next;
};

struct cache_req_entry* get_req_entry(const uint8_t* mac, const char* ifname);
struct cache_req_entry* add_req_entry(const uint8_t* mac, const char* ifname, const uint32_t expiresAt);

