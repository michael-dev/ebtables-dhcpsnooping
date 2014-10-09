/**
 *  This file is part of ebtables-dhcpsnoopingd.
 *
 *  Ebtables-dhcpsnoopingd is free software: you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Ebtables-dhcpsnoopingd is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with ebtables-dhcpsnoopingd.
 *  If not, see <http://www.gnu.org/licenses/>.
 *
 *  (C) 2013, Michael Braun <michael-dev@fami-braun.de>
 */

#include "config.h"
#ifdef __USE_MYSQL__
#include "debug.h"
#include "dhcp.h"
#include "dhcp-ack.h"
#include "cmdline.h"

#include <signal.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <mysql/mysql.h>
#include <mysql/mysqld_error.h>
#include <mysql/errmsg.h>
#include <sys/stat.h>
#include <netinet/ether.h>

#define MYCNF "/etc/mysql/fembot.cnf"
#define MYSQLDB "dhcpsnooping"
#define MYSQLLEASETABLE "leases"
#define MYSQLGROUP "dhcpsnooping"

MYSQL mysql;
static char* mysql_config_file = MYCNF;

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))

int mysql_connected() 
{
	static int connected = 0;

	if (connected != 0)
		return connected;

	struct stat buf;
	if (stat(mysql_config_file, &buf) != 0) {
		eprintf(DEBUG_ERROR, "stat config file: %s (%d)", strerror(errno), errno);
		eprintf(DEBUG_GENERAL, "missing %s config file", mysql_config_file);
		return connected;
	}
	if (!S_ISREG(buf.st_mode)) {
		eprintf(DEBUG_GENERAL, "missing %s config file", mysql_config_file);
		return connected;
	}

	unsigned int timeout = 2;
	my_bool reconnect = 1;
	mysql_options(&mysql, MYSQL_OPT_CONNECT_TIMEOUT, &timeout);
	mysql_options(&mysql, MYSQL_OPT_RECONNECT, &reconnect);
	mysql_options(&mysql, MYSQL_READ_DEFAULT_FILE, mysql_config_file);
	mysql_options(&mysql, MYSQL_READ_DEFAULT_GROUP, MYSQLGROUP);
	if (mysql_real_connect(&mysql, NULL, NULL, NULL, MYSQLDB, 0, NULL, CLIENT_REMEMBER_OPTIONS) == NULL) {
		eprintf(DEBUG_ERROR,  "connection failed: %s", mysql_error(&mysql));
		return connected;
	}
		
	if (mysql_errno(&mysql)) {
		eprintf(DEBUG_ERROR,  "mysql error: %s", mysql_error(&mysql));
		return connected;
	}

	connected = 1;

	return connected;
}

int mysql_query_errprint(const char* sql) 
{
	int ret, err, retrycnt = 0;
	const time_t start = time(NULL);

retry:
	if (!mysql_connected()) {
		eprintf(DEBUG_ERROR,  "mysql not connected, not running %s", sql);
		return -1;
	}

	ret = mysql_query(&mysql, sql);
	err = mysql_errno(&mysql);
	if (err)
		eprintf(DEBUG_GENERAL | DEBUG_VERBOSE,  "mysql error: %smysql query %s\n\n", mysql_error(&mysql), sql);
	if (
	   ((err == CR_SERVER_GONE_ERROR ) ||
	    (err == CR_SERVER_LOST) ||
	    (err == CR_SERVER_LOST_EXTENDED) ||
	    (err == ER_LOCK_DEADLOCK) ||
	    (err == ER_XA_RBTIMEOUT) ||
	    (err == ER_XA_RBDEADLOCK) ||
	    (err == ER_LOCK_WAIT_TIMEOUT)
	   ) && (
	     (retrycnt < 1000) ||
	     (time(NULL) < start + 10 /*10s*/)
	   )
	   ) {
		eprintf(DEBUG_GENERAL,  "mysql repeat query");
		retrycnt++;
		goto retry;
	} else if(err) {
		eprintf(DEBUG_ERROR, "mysql error (no retry) %s - mysql query %s", mysql_error(&mysql), sql);
	}
	return ret;
}

void mysql_update_lease(const uint8_t* mac, const struct in_addr* yip, const char* ifname, const uint32_t expiresAt, const enum t_lease_update_src reason)
{
	/* only write DHCP ACK packet changes back */
	if (reason != UPDATED_LEASE_FROM_DHCP)
		return;

	/* the mysql commands are both run always, as the initial entry might have been created on another device. */
	/* though, we restrict ACKs to be received on APs that saw the request - no roaming between REQ/ACK */
	/* add to mysql */
	if (!mysql_connected())
		return;
	
	eprintf(DEBUG_VERBOSE, "sql: update lease: MAC: %s IP: %s VLAN: %s expiresAt: %d", ether_ntoa((struct ether_addr *)mac), inet_ntoa(*yip), ifname, expiresAt);

	const uint32_t now =time(NULL);
	char sql_esc_bridge[1024];
	mysql_real_escape_string(&mysql, sql_esc_bridge, ifname, MIN(strlen(ifname), sizeof(sql_esc_bridge) / 2 - 1));
	char sql[2048];
	if (expiresAt > now) {
		snprintf(sql, sizeof(sql), "INSERT INTO " MYSQLLEASETABLE " (bridge, mac, ip, validUntil) VALUES('%s', '%s', '%s', %d + UNIX_TIMESTAMP()) ON DUPLICATE KEY UPDATE validUntil = %d + UNIX_TIMESTAMP();", sql_esc_bridge, ether_ntoa((struct ether_addr *)mac), inet_ntoa(*yip), expiresAt - now, expiresAt - now);
	} else {
		snprintf(sql, sizeof(sql), "UPDATE " MYSQLLEASETABLE " SET validUntil = 0 WHERE bridge = '%s' AND mac = '%s';", sql_esc_bridge, ether_ntoa((struct ether_addr *)mac));
	}
	eprintf(DEBUG_GENERAL, "write sql: %s", sql);
	mysql_query_errprint(sql);
}

int mysql_update_lease_from_sql(const char* ifname, const uint8_t* mac, const struct in_addr* ip, uint32_t* expiresAt)
{
	MYSQL_RES *result;
	MYSQL_ROW row;
	char sql[1024];
	char sql_esc_bridge[1024];

	if (!mysql_connected())
		return -1;
	
	mysql_real_escape_string(&mysql, sql_esc_bridge, ifname, MIN(strlen(ifname), sizeof(sql_esc_bridge) / 2 - 1));
	snprintf(sql, sizeof(sql), "SELECT MAX(validUntil) - UNIX_TIMESTAMP() FROM " MYSQLLEASETABLE " WHERE validUntil > UNIX_TIMESTAMP() AND bridge = '%s' AND mac = '%s' AND ip = '%s';", sql_esc_bridge, ether_ntoa((struct ether_addr *)mac), inet_ntoa(*ip));
	if (mysql_query_errprint(sql) != 0)
		return -1;
	/* mysql query sucessfull */
	result = mysql_store_result(&mysql);
	if (!result) /* Da ist ein Fehler aufgetreten */
		return -1;
	/* MAX(validUntil) - UNIX_TIMESTAMP() == NULL wenn keine records gefunden werden -> row[0] == NULL */
	row = mysql_fetch_row(result);
	if (row && row[0]) {
		*expiresAt = atoi(row[0]) + time(NULL);
	} else {
		*expiresAt = 0;
	}
	mysql_free_result(result);

	return 0;
}

void mysql_iterate_lease_for_ifname_and_mac(const char* ifname, const uint8_t* mac, lease_cb cb)
{
	if (!mysql_connected())
		return;

	eprintf(DEBUG_NEIGH, "query mysql\n");
	/* query sql for lease and add local rules*/
	char sql[1024];
	char sql_esc_bridge[1024];
	const uint32_t now = time(NULL);
	MYSQL_RES *result;
	MYSQL_ROW row;
	
	mysql_real_escape_string(&mysql, sql_esc_bridge, ifname, MIN(strlen(ifname), sizeof(sql_esc_bridge) / 2 - 1));
	snprintf(sql, sizeof(sql), "SELECT ip, MAX(validUntil) - UNIX_TIMESTAMP() FROM %s WHERE validUntil > UNIX_TIMESTAMP() AND bridge = '%s' AND mac = '%s' GROUP BY ip;", MYSQLLEASETABLE, sql_esc_bridge, ether_ntoa((struct ether_addr *)mac));
	eprintf(DEBUG_NEIGH, "query: %s", sql);
	if (mysql_query_errprint(sql) != 0) {
		goto out2;
	}
	/* mysql query sucessfull */
	result = mysql_store_result(&mysql);
	if (!result) {
		eprintf(DEBUG_NEIGH, "query mysql: cannot fetch result");
		goto out2;
	}
	while ((row = mysql_fetch_row(result)) != NULL) {
		eprintf(DEBUG_NEIGH, "query mysql: got row ip = %s, expiresAt = %s", row[0] ? row[0] : "NULL", row[1] ? row[1] : "NULL");
		if (!row[0] || !row[1])
			continue;
		struct in_addr yip;
		if (!inet_aton(row[0], &yip)) {
			eprintf(DEBUG_NEIGH, "cannot parse ip");
			continue;
		}
		uint32_t expiresAt = atoi(row[1]) + now;
		cb (mac, &yip, ifname, expiresAt, UPDATED_LEASE_FROM_EXTERNAL);
	}
	mysql_free_result(result);
out2:
	eprintf(DEBUG_NEIGH, "mysql completed");
}

void set_mysql_config_file(int c) 
{
	mysql_config_file = optarg;
}

static __attribute__((constructor)) void dhcp_mysql_init()
{
	static struct option long_option = {"mysql-config-file", required_argument, 0, 3};
	add_option_cb(long_option, set_mysql_config_file);

	eprintf(DEBUG_ERROR,  "MySQL client version: %s", mysql_get_client_info());
	if (!mysql_init(&mysql)) {
		eprintf(DEBUG_ERROR,  "mysql error: %s", mysql_error(&mysql));
		exit(254);
	}

	add_update_lease_hook(mysql_update_lease_from_sql);
	add_updated_lease_hook(mysql_update_lease);
	add_lease_lookup_by_mac(mysql_iterate_lease_for_ifname_and_mac);
}
#endif
