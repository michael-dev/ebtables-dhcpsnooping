Travis CI:
[![Build Status](https://secure.travis-ci.org/michael-dev/ebtables-dhcpsnooping.png?branch=master)](http://travis-ci.org/michael-dev/ebtables-dhcpsnooping)

Coverity Scan:
[![Coverity Scan Build Status](https://scan.coverity.com/projects/19006/badge.svg)](https://scan.coverity.com/projects/19006)

[![Total alerts](https://img.shields.io/lgtm/alerts/g/michael-dev/ebtables-dhcpsnooping.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/michael-dev/ebtables-dhcpsnooping/alerts/)

[![Language grade: C/C++](https://img.shields.io/lgtm/grade/cpp/g/michael-dev/ebtables-dhcpsnooping.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/michael-dev/ebtables-dhcpsnooping/context:cpp)

ebtables-dhcpsnooping
=====================

This daemon ensures that users connected to your linux wifi access point or to
your linux managed switch only use the ip address they have been assigned by
your local DHCP server.

To achieve this, it manages linux ebtables rules that accept packets that match
ip address, mac address and interface with an active DHCP lease. It will also
listen to DHCP requests and replies using ebtables, so you can filter which
DHCP servers should be listened too. The latter is called nflog.

When running on wifi access points, stations roaming between them will not
renew their lease after each single roam. Instead, the target access point
will have to learn the active lease from the originating access point. This
currently is achieved by storing the leases in a central database and
through udp broadcast notifications. Detecting new (roaming) stations is based
on linux bridge code and thus does not depend on wifi interfaces.

Commercial switches usually name similar features ARPprotect or DHCPsnooping.

Description
===========

Linux generic DHCP snooping daemon using nflog and ebtables.

This daemon parses DHCP ack messages and inserts ebtables ACCEPT rules for
packets matching source IPv4 address + source MAC into the dhcpsnooping chain.
These rules get removed once the lease times out. In order to filter for
broadcast acks, DHCP requests are used to filter those acks so that only local
stations get inserted. The packets are fed into the daemon using netfilter log
(nflog), the default group id is 1.

To use this daemon, you'll need to have
  - NETFILTER\_LOG support in the kernel
  - an ebtables rule copying all DHCP request from local stations (i.e. on
    wlan+) to the daemon using the nflog matcher.
  - an ebtables rule copying all DHCP acks from the *authoritative* DHCP
    servers (i.e. from ! wlan+) to the daemon using the nflog matcher.
  - an ebtables rule filtering all IPv4 and ARP incoming traffic by
    forwarding it to the dhcpsnooping chain, which drops packets by default.

To actually provide protection you need to ensure that no faked DHCP acks
are copied into the daemon and that all illegal traffic actually gets dropped.
You should also ensure that the MAC address cannot be spoofed to prevent faked
DHCP acks and denial of service attacks.

SIGALARM is used internally for clearing expired entries.
SIGUSR1 triggers dumping cache tables.

ARP rewrite support
-------------------

Additionally, ebtables rules are generated to rewrite multicast ARP requests to
unicast ARP requests if the destination MAC is known by dhcpsnoopingd for a
locally authenticated station.

This can be used to reduce multicast traffic and drop multicast ARP requests
which were not rewritten.

VLAN support
------------

Linux kernel bridge comes with VLAN support, that is, you can finally configure
tagged and untagged VLANs per bridge port.
As DHCP is per-VLAN, dhcpsnoopingd can track DHCP and FDB state per VLAN.

This currently requires kernel and libnl patches:
  * patch/kernel:
    * kernel-997-make-nflog-add-vlan-information.patch
  * patch/libnl:
    * 01-header.patch
    * 02-nflog-vlan.patch

This needs to be enabled using --enable-vlan with configure.

Use case
========

On access points running Linux and bridging or routing local clients that want to prevent users from using IP addresses not assigned to them by DHCP.

On switches running Linux and aiming at providing arp-protection to the clients by preventing clients from using IP addresses not assigned to them by DHCP.

Example ebtables rules (IPv4 only) for APs
-------------------------------------------

ebtables can be disabled by using --disable-ebtables.

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

ebtables -A dhcpsnooping --proto ipv4 --ip-src 0.0.0.0 -j RETURN
ebtables -A dhcpsnooping --proto arp --arp-ip-src 0.0.0.0 -j RETURN

# send DHCPv4 packets to dhcpsnoopingd and drop invalid DHCP packets
ebtables -A FORWARD -i $WLAN --logical-in $BRIDGE \
         --proto ipv4 --ip-protocol udp --ip-source-port 68 --ip-destination-port 67 --nflog-group 1 -j ACCEPT
ebtables -A FORWARD -s $DHCPMAC --logical-in $BRIDGE \
         --proto ipv4 --ip-protocol udp --ip-source-port 67 --ip-destination-port 68 --nflog-group 1 -j ACCEPT
ebtables -A FORWARD --logical-in $BRIDGE \
         --proto ipv4 --ip-protocol udp --ip-source-port 67 --ip-destination-port 68 -j DROP
```

Example nftables rules (IPv4 only) with VLAN for APs
-----------------------------------------------------

nftables can be disabled by using --disable-nftables.

See patch/nftables for the required patches to nft or use --nftables-legacy argument. Then instead of sets or maps with vlan_id type, use dhcpsnooping chain also for nat prerouting arp dnat.

```
GWMAC=00:00:00:00:00:01
DHCPMAC=00:00:00:00:00:02
BRIDGE=br*
WLAN=wlan*

nft flush ruleset bridge

nft add table bridge filter\;
nft add set bridge filter leases {type ifname . ether_addr . vlan_id . ipv4_addr  \; }
nft add set bridge filter gw {type ether_addr \; elements = { "$GWMAC" } \; }
nft add set bridge filter dhcpserver {type ether_addr \; elements = { "$DHCPMAC" } \; }
nft add chain bridge filter FORWARD { type filter hook forward priority filter\; policy accept\; }
nft add chain bridge filter dhcpsnooping

nft add table bridge nat\;
nft add map bridge nat leases {type ifname . vlan_id . ipv4_addr : ether_addr \; }
nft add chain bridge nat PREROUTING { type filter hook prerouting priority dstnat\; policy accept\; }

-- multicast ARP rewrite to unicast
nft add rule bridge nat PREROUTING meta ibrname "$BRIDGE" ether daddr & 01:00:00:00:00:00 == 01:00:00:00:00:00 vlan type arp arp operation request dnat meta ibrname . vlan id . arp daddr ip map \@leases

-- protect DHCP MAC and GW MAC - they not in WLAN
nft add rule bridge filter FORWARD iifname "$WLAN" meta ibrname "$BRIDGE" ether saddr \@gw drop
nft add rule bridge filter FORWARD iifname "$WLAN" meta ibrname "$BRIDGE" ether saddr \@dhcpserver drop

-- filter multicast ARP not rewritten before going out to WLAN
nft add rule bridge filter FORWARD oifname \@wlanif meta ibrname "brvlan" ether daddr "&" 01:00:00:00:00:00 == 01:00:00:00:00:00 vlan type arp drop

-- IP source address filter
nft add rule bridge filter FORWARD iifname "$WLAN" meta ibrname "$BRIDGE" vlan type ip jump dhcpsnooping
nft add rule bridge filter FORWARD iifname "$WLAN" meta ibrname "$BRIDGE" vlan type ip6 jump dhcpsnooping
nft add rule bridge filter FORWARD iifname "$WLAN" meta ibrname "$BRIDGE" vlan type arp jump dhcpsnooping

nft add rule bridge filter dhcpsnooping ether type vlan ip saddr 0.0.0.0 return
nft add rule bridge filter dhcpsnooping ether type vlan arp saddr ip 0.0.0.0 return

nft add rule bridge filter dhcpsnooping ether type vlan meta ibrname . vlan id . ether saddr . ip saddr \@leases return
nft add rule bridge filter dhcpsnooping counter drop

-- = send DHCPv4 packets to dhcpsnoopingd =
nft add rule bridge filter FORWARD iifname "$WLAN" meta ibrname "$BRIDGE" vlan type ip udp sport 68 udp dport 67 log group 1 accept
nft add rule bridge filter FORWARD meta ibrname "$BRIDGE" ether saddr \@dhcpserver vlan type ip udp sport 67 udp dport 68 log group 1 accept
nft add rule bridge filter FORWARD meta ibrname "$BRIDGE" vlan type ip udp sport 67 udp dport 68 counter drop
```


Roaming support
===============

When used on multiple APs that share the same ESSID, it looks to the daemon
like an STA attaches locally and used an IP address without doing DHCP. To
account for this, three mechanisms have been implemented:
- store leases in a central MySQL/MariaDB or PostgreSQL (Cluster) Database
- track locally connected STAs
- notify other APs about changes

Central Database
----------------

The central DB is required to recover the lease when the AP, where the STA has
received its lease, goes down but the other APs need to learn the leases of
the now roaming STAs.

Tracking locally connected STAs
--------------------------------

In order to know the STAs for which to install ebtables rules, the daemon
tracks the locally connected STAs.  To cover both wired and wifi use cases,
this is done using the kernel bridge/netlink code.  For kernels older than
3.17-rc6, this requires some simple kernel patching, as mostly STAs will
just switch between the bridge ports "wlan+" and "uplink+".  See patch/ for
details.
Patch: patch/kernel/kernel-997-make-bridge-notify-switched-port-real.diff

Notification to other instances
-------------------------------

When roaming around, STAs can get marked as connected to multiple APs
simultaneously - depending on the bridge MAC cache. To ensure that DHCP
lease changes (i.e. new IPs or renewed/released leases) get applied on
all APs, the daemon sends UDP broadcast packets on the control plane.
Whenever the STA MAC contained in the packet belongs to a locally connected
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

- Currently there is no IPv6 support, that is support for RA, ND, and DHCPv6
