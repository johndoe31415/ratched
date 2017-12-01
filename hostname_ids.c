/**
 *	ratched - TLS connection router that performs a man-in-the-middle attack
 *	Copyright (C) 2017-2017 Johannes Bauer
 *
 *	This file is part of ratched.
 *
 *	ratched is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; this program is ONLY licensed under
 *	version 3 of the License, later versions are explicitly excluded.
 *
 *	ratched is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with ratched; if not, write to the Free Software
 *	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *	Johannes Bauer <JohannesBauer@gmx.de>
**/

#include <stdint.h>
#include <string.h>
#include <errno.h>
#include "logging.h"
#include "hostname_ids.h"
#include "map.h"

static struct map_t *ip_to_hostnames;
/* ip_to_hostnames = {
 * 		0x11223344: {
 * 			"foobar":	1,
 * 			"barfoo":	2,
 * 			"mookoo":	3,
 * 		},
 * 		0x22334455: {
 * 			"moo.com":	1,
 * 			"bar.de":	2,
 * 		},
 * }
 */

unsigned int resolve_hostname_id(uint32_t ipv4_nbo, const char *hostname) {
	if (!hostname) {
		return 0;
	}

	struct map_t *map = map_get(ip_to_hostnames, &ipv4_nbo, sizeof(uint32_t));
	if (!map) {
		/* No entry for that IP address so far */
		map = map_new();
		if (!map) {
			logmsg(LLVL_FATAL, "Unable to create inner map for hostname entry for \"%s\", returning 0.", hostname);
			return 0;
		}
		if (!map_set_ptr(ip_to_hostnames, &ipv4_nbo, sizeof(uint32_t), map)) {
			logmsg(LLVL_FATAL, "Unable to register inner map for hostname entry for \"%s\", returning 0.", hostname);
			map_free(map);
			return 0;
		}
	}

	int hostname_id = strmap_get_int(map, hostname);
	if (hostname_id == -1) {
		hostname_id = map->element_count + 1;
		strmap_set_int(map, hostname, hostname_id);
	}

	return hostname_id;
}

void init_hostname_ids(void) {
	ip_to_hostnames = map_new();
}

static void free_inner_map(void *inner_map) {
	map_free((struct map_t*)inner_map);
}

void deinit_hostname_ids(void) {
	map_foreach_ptrvalue(ip_to_hostnames, free_inner_map);
	map_free(ip_to_hostnames);
}
