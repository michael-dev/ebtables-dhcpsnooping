#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
void ebtables_add(const struct in_addr* yip, const uint8_t* mac, const char* ifname);
void ebtables_del(const struct in_addr* yip, const uint8_t* mac, const char* ifname);
