ebtables-dhcpsnooping
=====================

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

Roaming support
===============

When used on multiple APs that share the ESSID, it looks to the daemon like an
STA attaches locally and used an IP address without doing DHCP. To account for
this, two means have been implemented:
- store leases in a central MySQL/MariaDB (Cluster) Database
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
- Kernel headers
- libnl-3

