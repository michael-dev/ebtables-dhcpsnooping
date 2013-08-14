#define DEBUG_ERROR   1
#define DEBUG_GENERAL 2
#define DEBUG_UDP     4
#define DEBUG_NFLOG   8
#define DEBUG_NEIGH  16
#define DEBUG_DHCP   32
#define DEBUG_ALL   255

void edprint(int level, char* msg);
#define eprintf(level, ...) { char syslogbuf[4096]; snprintf(syslogbuf, sizeof(syslogbuf), __VA_ARGS__); edprint(level, syslogbuf); };

