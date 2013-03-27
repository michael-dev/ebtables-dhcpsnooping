ebtables-dhcpsnooping
=====================

Linux generic dhcp snooping daemon using nflog and ebtablesThis daemon parses
dhcp ack messages and inserts ebtables ACCEPT rules for packets matching
source IPv4 address + source MAC into the dhcpsnooping chain. These rules get
removed once the lease times out. In order to filter for broadcast acks, dhcp
requests are used to filter those acks so that only local stations get
inserted. The packages are fed into the daemon using netfilter log (nflog),
the default group id is 1.

To use this daemon, you'll need to have
  - NETFILTER\_LOG support in the kernel
  - an ebtables rule copying all dhcp request from local stations (i.e. on
    wlan+) to the daemon using the nflog matcher.
  - an ebtables rule copying all dhcp acks from the *authoritative* dhcp
    servers (i.e. from ! wlan+) to the daemon using the nflog matcher.
  - an ebtables rule filtering all IPv4 and ARP incoming traffic by
    forwaring it to the dhcpsnooping chain, which drops packets by default.

To actually provide protection you neet to ensure that no faked dhcp acks
are copied into the daemon and that all illegal traffic actually gets dropped.
You should also ensure that the mac address cannot be spoofed to prevent faked
dhcp acks and deny of service attacks.

SIGALARM triggers clearing expires entries.
SIGUSR1 triggers dumping cache tables.

