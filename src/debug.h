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
#ifndef ETABLES_DHCPSNOOPING_CMDLINE
#define ETABLES_DHCPSNOOPING_CMDLINE

#define DEBUG_ERROR     1
#define DEBUG_GENERAL   2
#define DEBUG_UDP       4
#define DEBUG_NFLOG     8
#define DEBUG_NEIGH    16
#define DEBUG_DHCP     32
#define DEBUG_VERBOSE  64
#define DEBUG_ALL     255

void edprint(const int level, const char* msg, const char* file, const int line, const char* fnc);
#define eprintf(level, ...) { char syslogbuf[8192]; snprintf(syslogbuf, sizeof(syslogbuf), __VA_ARGS__); edprint(level, syslogbuf, __FILE__, __LINE__, __PRETTY_FUNCTION__); };
int isdebug(const int level);

#endif
