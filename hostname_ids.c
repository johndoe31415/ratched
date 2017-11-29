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

struct hostname_id_entry_t {
	uint32_t ipv4_nbo;
	unsigned int hostname_count;
	char **hostnames;
};

static unsigned int hostname_entry_count;
static struct hostname_id_entry_t *hostname_entries;

static struct hostname_id_entry_t* add_entry_for_ip(uint32_t ipv4_nbo) {
	struct hostname_id_entry_t *new_hostname_entries = realloc(hostname_entries, sizeof(struct hostname_id_entry_t) * (hostname_entry_count + 1));
	if (!new_hostname_entries) {
		logmsg(LLVL_FATAL, "Failed to realloc(3) hostname_entries: %s", strerror(errno));
		return NULL;
	}
	hostname_entries = new_hostname_entries;
	struct hostname_id_entry_t *result = &hostname_entries[hostname_entry_count];
	memset(result, 0, sizeof(struct hostname_id_entry_t));
	result->ipv4_nbo = ipv4_nbo;
	hostname_entry_count++;
	return result;
}

static struct hostname_id_entry_t* find_entry_for_ip(uint32_t ipv4_nbo) {
	for (int i = 0; i < hostname_entry_count; i++) {
		if (hostname_entries[i].ipv4_nbo == ipv4_nbo) {
			return &hostname_entries[i];
		}
	}
	return add_entry_for_ip(ipv4_nbo);
}

static unsigned int find_hostname_index(const struct hostname_id_entry_t *entry, const char *hostname) {
	for (unsigned int i = 0; i < entry->hostname_count; i++) {
		if (!strcmp(hostname, entry->hostnames[i])) {
			return i + 1;
		}
	}
	return 0;
}

static unsigned int add_hostname_to_entry(struct hostname_id_entry_t *entry, const char *hostname) {
	char *dup_hostname = strdup(hostname);
	if (!dup_hostname) {
		logmsg(LLVL_FATAL, "Failed to strdup(3) hostname: %s", strerror(errno));
		return 0;
	}

	char **new_hostnames = realloc(entry->hostnames, sizeof(char*) * (entry->hostname_count + 1));
	if (!new_hostnames) {
		logmsg(LLVL_FATAL, "Failed to realloc(3) hostnames: %s", strerror(errno));
		return 0;
	}
	entry->hostnames = new_hostnames;

	entry->hostnames[entry->hostname_count] = dup_hostname;
	entry->hostname_count++;
	return entry->hostname_count;
}

unsigned int resolve_hostname_id(uint32_t ipv4_nbo, const char *hostname) {
	if (!hostname) {
		return 0;
	}
	struct hostname_id_entry_t *entry = find_entry_for_ip(ipv4_nbo);
	if (!entry) {
		logmsg(LLVL_FATAL, "Unable to retrieve hostname entry for \"%s\", returning 0.", hostname);
		return 0;
	}

	unsigned int hostname_index = find_hostname_index(entry, hostname);
	if (hostname_index > 0) {
		return hostname_index;
	}

	/* Not present in entry, add. */
	hostname_index = add_hostname_to_entry(entry, hostname);
	if (!hostname_index) {
		logmsg(LLVL_FATAL, "Failed to add hostname entry \"%s\" to entry %p, returning 0.", hostname, entry);
	}
	return hostname_index;
}

void init_hostname_ids(void) {
}

void deinit_hostname_ids(void) {
	for (int i = 0; i < hostname_entry_count; i++) {
		for (int j = 0; j < hostname_entries[i].hostname_count; j++) {
			free(hostname_entries[i].hostnames[j]);
		}
		free(hostname_entries[i].hostnames);
	}
	free(hostname_entries);
}
