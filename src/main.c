/*
 * This program reads dhcp ack packets from nflog using libnl and creates a
 * temporary table of all authenticated MAC/IP pairs + their lifetime.
 * When a new entry is added, an ebtables accept rule is added,
 * when the entry expires, it is removed.
 * DHCP requests are used to filter dhcp broadcast acks for unseen dhcp requests,
 * i.e. non-local stations.
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License as
 *	published by the Free Software Foundation version 3 of the License.
 *
 *  gcc -I /usr/include/libnl3/ dhcpsnoopingd.c -l nl-3 -l nl-genl-3 -l nl-nf-3 -l nl-route-3 -o dhcpsnoopingd
 *
 * Roaming:
 * When using on APs, the STAs can roam around - so the DHCP request/reply pair
 * is seen on a different AP that the STA is then connected to.
 * A list of current STAs is derived from NEWNEIGH/DELNEIGH messages from
 * kernel bridge and dhcp replys that change the lease that are broadcastet
 * in the local network. See the defines below to change the network addresses.
 * Note: The roaming support only updates leases for STAs that are currently
 * marked as local by kernel bridge - i.e. they appear on a bridge port named 
 * as given below.
 * BUG: Kernel 3.8.3 does not report changes in bridge port - i.e. if an STA
 *      moves from backbone to local port.
 *      (Sent upstream)
 * Patch: https://patchwork.kernel.org/patch/2444531/
 * Upstream has (does not work):
 *  https://github.com/torvalds/linux/commit/b0a397fb352e65e3b6501dca9662617a18862ef1 in v3.10-rc1
 *  (was: http://git.kernel.org/cgit/linux/kernel/git/next/linux-next.git/commit/net/bridge/br_fdb.c?id=b0a397fb352e65e3b6501dca9662617a18862ef1)
 *
 * EBTABLES FLOW: PREROUTING FILTER -> br_forward -> fdb_update [sends NEWNEIGH] -> FORWARD_FILTER -> ...
 *  --> so put your filter in ebtables FORWARDING chain
 *
 * MySQL aka MariaDB:
 * This makes all leases to be stored in a central MySQL db and ist most useful
 * to enhance roaming. When roaming occurs after a DHCP lease has been obtained,
 * database access can be used to fetch and install the current lease.
 * Expired leases are pruned from DB.
 * Restrictions:
 *  * The bridge-names need to be the same on all APs.
 *
 * Copyright (c) 2012 Michael Braun <michael-dev@fami-braun.de>
 * forked from nf-log.c (libnl):
 *   Copyright (c) 2003-2008 Thomas Graf <tgraf@suug.ch>
 *   Copyright (c) 2007 Philip Craig <philipc@snapgear.com>
 *   Copyright (c) 2007 Secure Computing Corporation
 */

#include "config.h"
#include "cmdline.h"
#include "event.h"
#include "debug.h"
#include <syslog.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
	#ifdef REV
	fprintf(stderr, "dhcpsnoopingd version svn-%s\n", REV);
	#else
	fprintf(stderr, "dhcpsnoopingd version $Id: main.c 950 2013-08-12 18:14:08Z mbr $\n");
	#endif

	parse_cmdline(argc, argv);
	event_runloop();
}
