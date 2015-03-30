#include <netinet/ether.h>
#include "ether_ntoa.h"
#include <stdio.h>

char *ether_ntoa_zz(struct ether_addr *addr, char *buf)
{
    sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
            addr->ether_addr_octet[0], addr->ether_addr_octet[1],
            addr->ether_addr_octet[2], addr->ether_addr_octet[3],
            addr->ether_addr_octet[4], addr->ether_addr_octet[5]);
    return buf;
}

char *ether_ntoa_z(struct ether_addr *addr)
{
    static char buf[18];    /* 12 digits + 5 colons + null terminator */
    return ether_ntoa_zz(addr, buf);
}

