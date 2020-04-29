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
 *  (C) 2020, Michael Braun <michael-dev@fami-braun.de>
 */
#ifndef EBTABLES_DHCPSNOOPING_BRIDGE_VLAN
#define EBTABLES_DHCPSNOOPING_BRIDGE_VLAN

#ifdef __USE_VLAN__

int port_pvid(int ifidx, const char* ifname);

#endif /* __USE_VLAN */

#endif /* EBTABLES_DHCPSNOOPING */
