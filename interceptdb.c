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

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include "interceptdb.h"
#include "pgmopts.h"

static struct intercept_entry_t default_entry;
static struct intercept_entry_t *entries;
static unsigned int entry_count;

struct intercept_entry_t* interceptdb_find_entry(const char *hostname, uint32_t ipv4_nbo) {
	if (!hostname) {
		return &default_entry;
	}
	for (int i = 0; i < entry_count; i++) {
		if (!strcasecmp(hostname, entries[i].hostname)) {
			return &entries[i];
		}
	}
	return &default_entry;
}

static bool initialize_intercept_entry_from_pgm_config(struct intercept_entry_t *new_entry, const struct intercept_config_t *pgm_config) {
	memset(new_entry, 0, sizeof(struct intercept_entry_t));
	new_entry->do_intercept = pgm_config->do_intercept;
	if (pgm_config->hostname) {
		new_entry->hostname = strdup(pgm_config->hostname);
	} else {
		new_entry->hostname = strdup("NONE");
	}
	if (!new_entry->hostname) {
		return false;
	}

	struct tls_endpoint_cert_source_t certsrc = {
		.cert_filename = pgm_config->client_cert_filename,
		.key_filename = pgm_config->client_key_filename,
		.chain_filename = pgm_config->client_chain_filename,
	};
	if (!init_tls_endpoint_config(&new_entry->client, pgm_config->hostname, &certsrc)) {
		return false;
	}
	return true;
}

static bool append_intercept_entry_from_pgm_config(const struct intercept_config_t *pgm_config) {
	struct intercept_entry_t *new_entries = realloc(entries, sizeof(struct intercept_entry_t) * (entry_count + 1));
	if (!new_entries) {
		logmsg(LLVL_FATAL, "Failed to realloc(3) entries: %s", strerror(errno));
		return false;
	}
	entries = new_entries;

	struct intercept_entry_t *new_entry = &entries[entry_count++];
	initialize_intercept_entry_from_pgm_config(new_entry, pgm_config);

	/* The *server* needs to issue the RequestCertificate message */
	new_entry->server.request_cert_from_peer = pgm_config->request_client_cert;

	return true;
}

bool init_interceptdb(void) {
	initialize_intercept_entry_from_pgm_config(&default_entry, &pgm_options->default_client);

	for (int i = 0; i < pgm_options->intercept.count; i++) {
		struct intercept_config_t *pgm_config = &pgm_options->intercept.config[i];
		if (!append_intercept_entry_from_pgm_config(pgm_config)) {
			return false;
		}
	}
	return true;
}

void deinit_interceptdb(void) {
}
