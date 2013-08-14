#ifdef __USE_ROAMING__

#include <net/if.h>
#include <netinet/ether.h>
#include <stdint.h>

struct cache_fdb_entry 
{
	char bridge[IF_NAMESIZE];
	uint8_t mac[ETH_ALEN];
	uint8_t enabled;
	unsigned int portidx;
	struct cache_fdb_entry* next;
};

typedef void (*update_fdb_cb)(struct cache_fdb_entry* entry, void* ctx);

struct cache_fdb_entry* get_fdb_entry(const uint8_t* mac, const char* bridge, const unsigned int portidx);
struct cache_fdb_entry* add_fdb_entry(const uint8_t* mac, const char* ifname, uint8_t enabled, unsigned int portidx);
void update_fdb(update_fdb_cb, void* ctx);
#endif
