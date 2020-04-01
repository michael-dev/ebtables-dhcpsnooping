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

#ifndef EBTABLES_DHCPSNOOPING_TIMER
#define EBTABLES_DHCPSNOOPING_TIMER

#include <stdint.h>

#define PRUNE_INTERVAL 300

typedef void (*timer_cb) (void* ctx);

void cb_add_timer(int timeout, int repeat, void* ctx, timer_cb cb);
void cb_del_timer(void* ctx, timer_cb cb);
uint32_t reltime();

#endif
