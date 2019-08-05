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
#ifdef __USE_PGSQL__
#include "debug.h"
#include "dhcp.h"
#include "cmdline.h"
#include "timer.h"

#include <signal.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libpq-fe.h>
#include <sys/stat.h>
#include <netinet/ether.h>
#include "ether_ntoa.h"

#ifndef PGSQLLEASETABLE
#define PGSQLLEASETABLE "leases"
#endif
#ifndef PGSQLSERVICE
#define PGSQLSERVICE "/etc/pgsql/fembot.cnf"
#endif
#ifndef PGSQLSERVICENAME
#define PGSQLSERVICENAME "dhcpsnooping"
#endif

PGconn *pgsql = NULL;
static char* pgsql_config_file = PGSQLSERVICE;
static char* pgsql_config_name = PGSQLSERVICENAME;

static void pgsql_disconnect(void)
{
	if (!pgsql)
		return;
	PQfinish(pgsql);
	pgsql = NULL;
}

static void
pgsqlNoticeProcessor(void *arg, const char *message)
{
	eprintf(DEBUG_ERROR, "%s", message);
}

int pgsql_connected()
{
	static int connected = 0;
	PGresult *res;

	if (connected != 0) {
		if (PQstatus(pgsql) != CONNECTION_OK) {
			PQreset(pgsql);
			res = PQexec(pgsql, "SET timezone TO 'utc';");
			PQclear(res);
		}
		return connected;
	}

	struct stat buf;
	if (stat(pgsql_config_file, &buf) != 0) {
		eprintf(DEBUG_ERROR, "stat config file: %s (%d)", strerror(errno), errno);
		eprintf(DEBUG_GENERAL, "missing %s config file", pgsql_config_file);
		return connected;
	}
	if (!S_ISREG(buf.st_mode)) {
		eprintf(DEBUG_GENERAL, "missing %s config file", pgsql_config_file);
		return connected;
	}
	setenv("PGSERVICEFILE", pgsql_config_file, 0);

	char dsnbuf[1024];
	snprintf(dsnbuf, sizeof(dsnbuf), "service = %s", pgsql_config_name);
	pgsql = PQconnectdb(dsnbuf);
	if (PQstatus(pgsql) != CONNECTION_OK) {
		eprintf(DEBUG_ERROR,  "pgsql error: %s", PQerrorMessage(pgsql));
		return connected;
	}
	PQsetNoticeProcessor(pgsql, pgsqlNoticeProcessor, NULL);

	res = PQexec(pgsql, "SET timezone TO 'utc';");
	PQclear(res);

	connected = 1;

	return connected;
}

PGresult * pgsql_query_errprint_query(const char* sql)
{
	PGresult *res;
	ExecStatusType err;
	int retrycnt = 0;
	const time_t start = reltime();

retry:
	if (!pgsql_connected()) {
		eprintf(DEBUG_ERROR,  "pgsql not connected, not running %s", sql);
		return NULL;
	}

	res = PQexec(pgsql, sql);
	err = PQresultStatus(res);
	if (err == PGRES_BAD_RESPONSE || err == PGRES_FATAL_ERROR) {
		eprintf(DEBUG_GENERAL | DEBUG_VERBOSE,  "pgsql error: %spgsql query %s\n\n", PQerrorMessage(pgsql), sql);
	} else if (err == PGRES_NONFATAL_ERROR)
		eprintf(DEBUG_GENERAL | DEBUG_VERBOSE,  "pgsql warning: %spgsql query %s\n\n", PQerrorMessage(pgsql), sql);

	if ((err == PGRES_BAD_RESPONSE) || (err == PGRES_FATAL_ERROR)) {
		PQclear(res); res = NULL;
		if ((PQstatus(pgsql) != CONNECTION_OK) &&
		    ((retrycnt < 1000) || (reltime() < start + 10 /*10s*/))) {
			eprintf(DEBUG_GENERAL,  "pgsql repeat query");
			retrycnt++;
			goto retry;
		} else {
			eprintf(DEBUG_ERROR, "pgsql error (no retry) %s - pgsql query %s", PQerrorMessage(pgsql), sql);
		}
	}

	return res;
}

int pgsql_query_errprint(const char* sql) {
	PGresult * res = pgsql_query_errprint_query(sql);
	if (res == NULL)
		return -1;
	return 0;
}

void pgsql_remove_old_leases_from_db(void *ctx)
{
	char sql[1024];

	if (!pgsql_connected())
		return;

	/* update pgsql */
	snprintf(sql, sizeof(sql), "DELETE FROM " PGSQLLEASETABLE " WHERE validUntil <= CURRENT_TIMESTAMP");
	pgsql_query_errprint(sql);
}

void pgsql_update_lease(const uint8_t* mac, const struct in_addr* yip, const char* ifname, const uint16_t vlanid, const uint32_t expiresAt, const enum t_lease_update_src reason)
{
	/* only write DHCP ACK packet changes back */
	if (reason != UPDATED_LEASE_FROM_DHCP)
		return;

	/* the pgsql commands are both run always, as the initial entry might have been created on another device. */
	/* though, we restrict ACKs to be received on APs that saw the request - no roaming between REQ/ACK */
	/* add to pgsql */
	if (!pgsql_connected())
		return;

	const uint32_t now = reltime();
	eprintf(DEBUG_VERBOSE, "sql: update lease: MAC: %s IP: %s VLAN: %s expiresIn: %d", ether_ntoa_z((struct ether_addr *)mac), inet_ntoa(*yip), ifname, expiresAt - now);

	char vlan[255];
	if (vlanid)
		snprintf(vlan, sizeof(vlan), "%s%d", ifname, vlanid);
	else
		snprintf(vlan, sizeof(vlan), "%s", ifname);
	char *sql_esc_bridge = PQescapeLiteral(pgsql, vlan, strlen(vlan));
	if (!sql_esc_bridge) return;

	char sql[2048];
	if (expiresAt > now) {
		snprintf(sql, sizeof(sql), "INSERT INTO " PGSQLLEASETABLE " (bridge, mac, ip, validUntil) VALUES(%s, '%s', '%s', CURRENT_TIMESTAMP + interval '%d seconds') ON CONFLICT (bridge, mac, ip) DO UPDATE SET validUntil = CURRENT_TIMESTAMP + interval '%d seconds';", sql_esc_bridge, ether_ntoa_z((struct ether_addr *)mac), inet_ntoa(*yip), expiresAt - now, expiresAt - now);
	} else {
		snprintf(sql, sizeof(sql), "UPDATE " PGSQLLEASETABLE " SET validUntil = CURRENT_TIMESTAMP WHERE bridge = %s AND mac = '%s';", sql_esc_bridge, ether_ntoa_z((struct ether_addr *)mac));
	}
	PQfreemem(sql_esc_bridge); sql_esc_bridge = NULL;
	eprintf(DEBUG_GENERAL, "write sql: %s", sql);
	pgsql_query_errprint(sql);
}

int pgsql_update_lease_from_sql(const char* ifname, const uint16_t vlanid, const uint8_t* mac, const struct in_addr* ip, uint32_t* expiresAt)
{
	PGresult * res;
	char sql[1024];
	char vlan[255];
	char *sql_esc_bridge;

	if (!pgsql_connected())
		return -1;

	if (vlanid)
		snprintf(vlan, sizeof(vlan), "%s%d", ifname, vlanid);
	else
		snprintf(vlan, sizeof(vlan), "%s", ifname);
	sql_esc_bridge = PQescapeLiteral(pgsql, vlan, strlen(vlan));
	snprintf(sql, sizeof(sql), "SELECT ceil(extract('epoch' from (validUntil - CURRENT_TIMESTAMP)))::varchar as expiresin FROM " PGSQLLEASETABLE " WHERE validUntil > CURRENT_TIMESTAMP AND bridge = %s AND mac = '%s' AND ip = '%s';", sql_esc_bridge, ether_ntoa_z((struct ether_addr *)mac), inet_ntoa(*ip));
	PQfreemem(sql_esc_bridge); sql_esc_bridge = NULL;

	res = pgsql_query_errprint_query(sql);
	if (res == NULL)
		return -1;

	/* pgsql query sucessfull */
	int col = -1;
	if (PQntuples(res) > 0) {
		col = PQfnumber(res, "expiresin");
		if (col == -1)
			eprintf(DEBUG_ERROR, "sql: update lease from sql did not find column expiresin");
	}
	if (col != -1) {
		char *val = PQgetvalue(res, 0, col);
		const int now = reltime();
		int expiresIn = atoi(val);
		eprintf(DEBUG_VERBOSE, "sql: update lease from sql: MAC: %s IP: %s VLAN: %s expiresIn (old): %d expiresIn (new): %d raw: %s", ether_ntoa_z((struct ether_addr *)mac), inet_ntoa(*ip), ifname, *expiresAt - now, expiresIn, val);
		*expiresAt = expiresIn + now;
	} else {
		*expiresAt = 0;
	}
	PQclear(res); res = NULL;

	return 0;
}

void pgsql_iterate_lease_for_ifname_and_mac(const char* ifname, const uint16_t vlanid, const uint8_t* mac, lease_cb cb)
{
	/* query sql for lease and add local rules*/
	PGresult * res;
	char sql[1024];
	char vlan[255];
	char *sql_esc_bridge;
	const uint32_t now = reltime();

	if (!pgsql_connected())
		return;
	eprintf(DEBUG_NEIGH, "query pgsql\n");

	if (vlanid)
		snprintf(vlan, sizeof(vlan), "%s%d", ifname, vlanid);
	else
		snprintf(vlan, sizeof(vlan), "%s", ifname);
	sql_esc_bridge = PQescapeLiteral(pgsql, vlan, strlen(vlan));
	snprintf(sql, sizeof(sql), "SELECT ip::varchar as ip, ceil(extract('epoch' from MAX(validUntil) - CURRENT_TIMESTAMP))::varchar as expiresin FROM " PGSQLLEASETABLE " WHERE validUntil > CURRENT_TIMESTAMP AND bridge = %s AND mac = '%s' GROUP BY ip;", sql_esc_bridge, ether_ntoa_z((struct ether_addr *)mac));
	PQfreemem(sql_esc_bridge); sql_esc_bridge = NULL;

	eprintf(DEBUG_NEIGH, "query: %s", sql);
	res = pgsql_query_errprint_query(sql);
	if (res == NULL)
		goto out;

	/* pgsql query sucessfull */
	int colIp = PQfnumber(res, "ip");
	int colExpiresIn = PQfnumber(res, "expiresin");
	for (int row = 0; row < PQntuples(res); row++) {
		char *ip = PQgetvalue(res, row, colIp);
		char *expiresIn = PQgetvalue(res, row, colExpiresIn);

		eprintf(DEBUG_NEIGH, "query pgsql: got row ip = %s, expiresAt = %s", ip ? ip : "NULL", expiresIn ? expiresIn : "NULL");
		if (!ip || !expiresIn)
			continue;
		struct in_addr yip;
		if (!inet_aton(ip, &yip)) {
			eprintf(DEBUG_NEIGH, "cannot parse ip");
			continue;
		}
		uint32_t expiresAt = atoi(expiresIn) + now;
		cb (mac, &yip, ifname, vlanid, expiresAt, UPDATED_LEASE_FROM_EXTERNAL);
	}
	PQclear(res); res = NULL;
out:
	eprintf(DEBUG_NEIGH, "pgsql completed");
}

void set_pgsql_config_file(int c)
{
	pgsql_config_file = optarg;
}

void set_pgsql_config_name(int c)
{
	pgsql_config_name = optarg;
}

static __attribute__((constructor)) void dhcp_pgsql_init()
{
	{
		static struct option long_option = {"pgsql-config-file", required_argument, 0, 3};
		add_option_cb(long_option, set_pgsql_config_file);
	}

	{
		static struct option long_option = {"pgsql-config-name", required_argument, 0, 3};
		add_option_cb(long_option, set_pgsql_config_name);
	}

	{
		int version = PQlibVersion();
		int v1 = version / 10000;
		int v2 = (version / 100) % 100;
		int v3 = version % 100;
		eprintf(DEBUG_ERROR,  "PgSQL client version: %d.%d.%d", v1, v2, v3);
	}

	add_update_lease_hook(pgsql_update_lease_from_sql);
	add_updated_lease_hook(pgsql_update_lease,2);
	add_lease_lookup_by_mac(pgsql_iterate_lease_for_ifname_and_mac);
	cb_add_timer(PRUNE_INTERVAL, 1, NULL, pgsql_remove_old_leases_from_db);
	atexit(pgsql_disconnect);
}
#endif
