Travis CI:
[![Build Status](https://secure.travis-ci.org/michael-dev/ebtables-dhcpsnooping.png?branch=master)](http://travis-ci.org/michael-dev/ebtables-dhcpsnooping)

Coverity Scan:
[![Coverity Scan Build Status](https://scan.coverity.com/projects/19006/badge.svg)](https://scan.coverity.com/projects/19006)

ebtables-dhcpsnooping
=====================

This daemon ensures that users connected to your linux wifi access point or to
your linux managed switch only use the ip address they have been assigned by
your local DHCP server.

To achieve this, it manages linux ebtables rules that accept packets that match
ip address, mac address and interface with an active DHCP lease. It will also
listen to DHCP requests and replies using ebtables, so you can filter which
DHCP servers should be listened to. The latter is called nflog.

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

See patch/nftables for the required patches to nft or use --nftables-legacy argument. Then instead of sets or maps with vlan\_id type, use dhcpsnooping chain also for nat prerouting arp dnat.

It is also important to note that 
  * packets in the bridge FORWARD chain look untagged if the outgoing port has their vid marked untagged
  * packets in the bridge PREROUTING chain look untagged if they are received untagged and will only be marked with pvid later.
Therefore we need to handle untagged packets using meta ibrpvid.

```
GWMAC=00:00:00:00:00:01
DHCPMAC=00:00:00:00:00:02
BRIDGE=br*
WLAN=wlan*

nft flush ruleset bridge


nft add table bridge nat\;
nft add map bridge nat leases-m {typeof meta ibrname . vlan id . arp daddr ip : ether daddr \; }
nft add set bridge nat leases-s {typeof meta ibrname . vlan id . ip saddr  \; }
nft add set bridge nat gw {type ether\_addr \; elements = { "$GWMAC" } \; }
nft add set bridge nat dhcpserver {type ether\_addr \; elements = { "$DHCPMAC" } \; }
nft add chain bridge nat PREROUTING { type filter hook prerouting priority dstnat\; policy accept\; }
nft add chain bridge nat POSTROUTING { type filter hook postrouting priority srcnat\; policy accept\; }
nft add chain bridge nat dhcpsnooping

-- multicast ARP rewrite to unicast
nft add rule bridge nat PREROUTING meta ibrname "$BRIDGE" ether daddr & 01:00:00:00:00:00 == 01:00:00:00:00:00 vlan type arp arp operation request dnat meta ibrname . vlan id . arp daddr ip map \@leases-m
nft add rule bridge nat PREROUTING meta ibrname "$BRIDGE" ether daddr & 01:00:00:00:00:00 == 01:00:00:00:00:00 ether type arp arp operation request dnat meta ibrname . meta ibrpvid . arp daddr ip map \@leases-m

-- filter multicast ARP not rewritten before going out to WLAN
nft add rule bridge nat POSTROUTING oifname \@wlanif meta ibrname "brvlan" ether daddr "&" 01:00:00:00:00:00 == 01:00:00:00:00:00 vlan type arp drop

-- protect DHCP MAC and GW MAC - they not in WLAN
nft add rule bridge nat PREROUTING iifname "$WLAN" meta ibrname "$BRIDGE" ether saddr \@gw drop
nft add rule bridge nat PREROUTING iifname "$WLAN" meta ibrname "$BRIDGE" ether saddr \@dhcpserver drop

-- IP source address filter
nft add rule bridge nat PREROUTING iifname "$WLAN" meta ibrname "$BRIDGE" vlan type ip jump dhcpsnooping
nft add rule bridge nat PREROUTING iifname "$WLAN" meta ibrname "$BRIDGE" vlan type ip6 jump dhcpsnooping
nft add rule bridge nat PREROUTING iifname "$WLAN" meta ibrname "$BRIDGE" vlan type arp jump dhcpsnooping

nft add rule bridge nat dhcpsnooping ether type vlan ip saddr 0.0.0.0 return
nft add rule bridge nat dhcpsnooping ether type != vlan ip saddr 0.0.0.0 return
nft add rule bridge nat dhcpsnooping ether type vlan arp saddr ip 0.0.0.0 return
nft add rule bridge nat dhcpsnooping ether type != vlan arp saddr ip 0.0.0.0 return

nft add rule bridge nat dhcpsnooping ether type vlan meta ibrname . vlan id . ether saddr . ip saddr \@leases-s return
nft add rule bridge nat dhcpsnooping ether type != vlan meta ibrname . meta ibrpvid . ether saddr . ip saddr \@leases-s return
nft add rule bridge nat dhcpsnooping counter drop

-- = send DHCPv4 packets to dhcpsnoopingd =
nft add rule bridge nat PREROUTING iifname "$WLAN" meta ibrname "$BRIDGE" vlan type ip udp sport 68 udp dport 67 log group 1 accept
nft add rule bridge nat PREROUTING iifname "$WLAN" meta ibrname "$BRIDGE" ether type ip udp sport 68 udp dport 67 log group 1 accept
nft add rule bridge nat PREROUTING meta ibrname "$BRIDGE" ether saddr \@dhcpserver vlan type ip udp sport 67 udp dport 68 log group 1 accept
nft add rule bridge nat PREROUTING meta ibrname "$BRIDGE" ether saddr \@dhcpserver ether type ip udp sport 67 udp dport 68 log group 1 accept
nft add rule bridge nat PREROUTING meta ibrname "$BRIDGE" vlan type ip udp sport 67 udp dport 68 counter drop
nft add rule bridge nat PREROUTING meta ibrname "$BRIDGE" ether type ip udp sport 67 udp dport 68 counter drop
```


Roaming support
===============

When used on multiple APs that share the same ESSID, it looks to the daemon
like an STA attaches locally and uses an IP address without doing DHCP. To
account for this, three mechanisms have been implemented:
- store leases in a central MySQL/MariaDB or PostgreSQL (Cluster) Database
- track locally connected STAs
- notify other APs about changes

Central Database
----------------

The central DB is required to recover the lease when the AP, where the STA has
received its lease, goes down but the other APs need to learn the leases of
the now roaming STAs.

Hostname and credentials get configured using a configuration file.

a) MySQL
  For MySQL backend, use client and dhcpsnooping group of
  /etc/mysql/fembot.cnf (configurable).
  See https://dev.mysql.com/doc/refman/5.7/en/option-files.html for details.

b) PostgreSQL >= 9.5
  For PgSQL backend, use dhcpsnooping section in /etc/pgsql/fembot.cfg
  (configurable).
  See https://www.postgresql.org/docs/9.6/static/libpq-pgservice.html for
  details.

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

Commandline
===========

Debugging-Options
-----------------

- --debug
- --debug-all
- --debug-bridge
- --debug-dhcp
- --debug-neigh
- --debug-nflog
- --debug-udp
- --verbose
- --bridge-dump-netlink

Configuration
-------------

Database
--------
- --mysql-config-file <file>: Database configuration
- --pgsql-config-file <file>: Database configuration
- --pgsql-config-name <name>: Database configuration

Roaming
-------
- --roamifprefix: Which network interfaces are considered for clients (e.g. wlan\*)
- --broadcast-addr
- --broadcast-port

Netfilter
---------

- --disable-ebtables
- --dry-ebtables

- --disable-nftables
- --dry-nftables
- --nftables-legacy : one rule per STA or use map/set
- --nft-cmd : path to nft command
- --nft-tbl1 : table for set or chain1
- --nft-chain1 : chain to filter allowed mac/ip/vlan/bridge tuples (iff legacy)
- --nft-setname : set of allowed mac/ip/vlan/bridge tuples (unless legacy)
- --nft-tbl2 : table for map or chain2
- --nft-chain2 : chain to convert broadcast arp to unicast (iff legacy)
- --nft-mapname : map to convert broadcast arp to unicast (unless legacy)

- --nflog-group <id>: which netfilter log group is used to send dhcp packets to dhcpsnoopingd?

- --bridge <brname>: interface name of bridge

Compiletime-Options
===================

Features
--------

- --enable-roaming: enable roaming support
- --enable-vlan: enable vlan support (detect 802.1q header and ask bridge port for pvid if untagged)

Debugging
---------

- --with-rev: enable rev output
- --enable-debug: enable debug output

Netfilter interface
-------------------

- --enable-ebtables: enable ebtables support
- --enable-nftables: enable nftables support
- --nflog-group <groupid>: default nflog group

MySQL
-----

- --enable-mysql: enable MySQL support
- --mysql-include-path <path>
- --mysql-lib-path <path>

PostgreSQL
----------

- --enable-pgsql: enable PostgreSQL support
- --pgsql-include-path <path>
- --pgsql-lib <path>
- --pgsql-lib-path <path>

