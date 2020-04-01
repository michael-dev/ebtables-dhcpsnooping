#ifndef ETHER_NTOA
#define ETHER_NTOA

char *ether_ntoa_zz(struct ether_addr *addr, char *buf);
char *ether_ntoa_z(struct ether_addr *addr);

#endif
