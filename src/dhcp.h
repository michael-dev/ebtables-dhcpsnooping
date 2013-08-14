#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

typedef void* (*is_local_cb)(const uint8_t* mac, const char* ifname);
typedef int (*update_lease_cb)(const char* ifname, const uint8_t* mac, const struct in_addr* ip, uint32_t* expiresAt);
typedef void (*updated_lease_cb)(const uint8_t* mac, const struct in_addr* yip, const char* ifname, const uint32_t expiresAt);
typedef void (*lease_cb)(const struct in_addr* yip, const uint8_t* mac, const char* ifname, const uint32_t expiresAt);
typedef void (*lease_lookup_by_mac_cb)(const char* ifname, const uint8_t* mac, lease_cb cb);

void add_is_local_hook(is_local_cb cb);
int is_local (const uint8_t* mac, const char* ifname);
void add_update_lease_hook(update_lease_cb cb);
int update_lease(const char* ifname, const uint8_t* mac, const struct in_addr* ip, uint32_t* expiresAt);
void add_updated_lease_hook(updated_lease_cb cb);
void updated_lease(const uint8_t* mac, const struct in_addr* yip, const char* ifname, const uint32_t expiresAt);
void add_lease_lookup_by_mac(lease_lookup_by_mac_cb cb);
void lease_lookup_by_mac(const char* ifname, const uint8_t* mac, lease_cb cb);

