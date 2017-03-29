ebtables-dhcpsnooping
=====================

This daemon ensures that users connected to your linux wifi access point or to
your linux managed switch only use the ip address they have been assigned by
your local dhcp server.

To achieve this, it manages linux ebtables rules that accept packets that match
ip address, mac address and interface with an active dhcp lease. It will also
listen to dhcp requests and replies using ebtables, so you can filter which
dhcp servers should be listened too. The latter is called nflog.

When running on wifi access points, stations roaming between them will not
renew their lease after each single roam. Instead, the target access point
will have to learn the active lease from the originating access point. This
currently is achieved by storing the leases in a central mysql/mariadb database
and udp broadcast notifications. Detecting new (roaming) stations is based on
linux bridge code and thus does not depend on wifi interfaces.

Commercial switches usually name similar features ARPprotect or DHCPsnooping.

Description
===========

Linux generic dhcp snooping daemon using nflog and ebtables.

This daemon parses dhcp ack messages and inserts ebtables ACCEPT rules for
packets matching source IPv4 address + source MAC into the dhcpsnooping chain.
These rules get removed once the lease times out. In order to filter for
broadcast acks, dhcp requests are used to filter those acks so that only local
stations get inserted. The packets are fed into the daemon using netfilter log
(nflog), the default group id is 1.

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

SIGALARM is used internally for clearing expires entries.
SIGUSR1 triggers dumping cache tables.

ARP rewrite support
-------------------

Additionally, ebtables rules are generated to rewrite multicast arp requests to
unicast arp requests if the destination mac is known by dhcpsnoopingd for a
local authenticated station.

This can be used to reduce multicast traffic and drop multicast arp requests
not rewritten.

Use case
========

On AccessPoints running Linux and bridging or routing local clients that want to prevent users from using IP addresses not assigned using DHCP to them.

On Switches running Linux and aiming at providing arp-protection to the clients by preventing clients from using IP addresses not assigned using DHCP to them.

Example ebtables rules (IPv4 only) for APs
-------------------------------------------

```
GWMAC=00:00:00:00:00:01
DHCPMAC=00:00:00:00:00:02
BRIDGE=br+
WLAN=wlan+

ebtables -t nat -F PREROUTING
# ARP rewrite
ebtables -t nat -N dhcpsnooping -P RETURN || true
ebtables -t nat -F dhcpsnooping
ebtables -t nat -A PREROUTING --logical-in $BRIDGE --proto arp \
         --arp-op Request -d multicast -j dhcpsnooping

ebtables -F FORWARD
# protect DHCP MAC and GW MAC - they not in WLAN
ebtables -A FORWARD -i $WLAN --logical-in $BRIDGE -s $GWMAC -j DROP
ebtables -A FORWARD -i $WLAN --logical-in $BRIDGE -s $DHCPMAC -j DROP

# filter multicast ARP not rewritten before going out to WLAN
ebtables -A FORWARD -o $WLAN --logical-in $BRIDGE --proto arp -d multicast -j DROP

# IP source address filter
ebtables -N dhcpsnooping -P DROP
ebtables -A FORWARD -i $WLAN --logical-in $BRIDGE --proto ipv4 -j dhcpsnooping
ebtables -A FORWARD -i $WLAN --logical-in $BRIDGE --proto arp -j dhcpsnooping

ebtables -A dhcpsnooping --proto ipv4 --proto ipv4 --ip-src-address 0.0.0.0 -j RETURN
ebtables -A dhcpsnooping --proto arp --proto arp --arp-src-address 0.0.0.0 -j RETURN

# send DHCPv4 packets to dhcpsnoopingd and drop invalid DHCP packets
ebtables -A FORWARD -i $WLAN --logical-in $BRIDGE \
         --proto ipv4 --ip-protocol UDP --ip-source-port 68 --ip-destination-port 67 --nflog-group 1 -j ACCEPT
ebtables -A FORWARD -s $DHCPMAC --logical-in $BRIDGE \
         --proto ipv4 --ip-protocol UDP --ip-source-port 67 --ip-destination-port 68 --nflog-group 1 -j ACCEPT
ebtables -A FORWARD --logical-in $BRIDGE \
         --proto ipv4 --ip-protocol UDP --ip-source-port 67 --ip-destination-port 68 -j DROP
```

Roaming support
===============

When used on multiple APs that share the ESSID, it looks to the daemon like an
STA attaches locally and used an IP address without doing DHCP. To account for
this, two means have been implemented:
- store leases in a central MySQL/MariaDB or PostgreSQL (Cluster) Database
- track locally connected STAs
- notify other instances about changes

Central Database
----------------

The central DB is required to recover the lease when the AP, where the STA has
received its lease, goes down but the other APs need to learn the leases of
the now roaming STAs.

Tracking locally connected STAs
--------------------------------

In order to know for which STAs ebtables rules shall be installed, the daemon
tracks the locally connected STAs. For more generic use, this is done using the
kernel bridge code. Currently, this needs some simple kernel patching, as
mostly STAs will just switch between the bridge ports "wlan+" and "uplink+".
See patch/ for details.

Update 2014-09-25: c65c7a306 introduced a sufficent change for this into
                   upstream kernel. It is in 3.17-rc6 and 3.16.3 but not
		   3.14.19 at least.

Notification to other instances
-------------------------------

When roaming around, STAs can get marked as connected to multiple APs
simultaneously - depending on the bridge mac cache. To ensure that dhcp
lease changes (i.e. new IPs or renewed/released leases) get applied on
all APs, the daemon sends UDP broadcast packets on the management backbone.
Whenever the STA mac contained in the packet belongs to a locally connected
STA, the ebtables rules get updated.

Configuring Roaming and DB access
---------------------------------

It is strongly recommended to combine DB and Roaming settings. Currently,
using either alone has limited use.

Debugging
=========

See the source code for --debug... commandline flags.

Installation
============

See autoinstall.sh for the steps.

Dependencies
------------

- MySQL client headers (if needed)
- libpq (PgSQL client) headers (if needed)
- Kernel headers
- libnl-3

TODO
----

- Currently there is no IPv6 support, that is support for RouterAdvertisments and DHCPv6
