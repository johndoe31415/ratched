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
#include "intercept_config.h"
#include "certforgery.h"

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

static bool initialize_default_intercept_entry(struct intercept_entry_t *new_entry) {
	new_entry->interception_mode = OPPORTUNISTIC_TLS_INTERCEPTION;
	return true;
}

static bool init_tls_intercept_entry(struct tls_endpoint_config_t *config, const struct intercept_side_config_t *side_config, const char *description) {
	struct tls_endpoint_cert_source_t certsrc = {
		.cert_filename = side_config->cert_filename,
		.key_filename = side_config->key_filename,
		.chain_filename = side_config->chain_filename,
		.certificate_authority = {
			.cert_filename = side_config->ca_cert_filename,
			.key_filename = side_config->ca_key_filename,
		},
	};
	if (!init_tls_endpoint_config(config, description, &certsrc)) {
		return false;
	}
	if (config->certificate_authority.cert && config->certificate_authority.key) {
		/* Use CA server and key as OCSP responder */
		config->ocsp_responder.cert = config->certificate_authority.cert;
		config->ocsp_responder.key = config->certificate_authority.key;
		X509_up_ref(config->ocsp_responder.cert);
		EVP_PKEY_up_ref(config->ocsp_responder.key);
	}
	config->request_cert_from_peer = side_config->request_client_cert;
	config->ciphersuites = side_config->ciphersuites;
	config->supported_groups = side_config->supported_groups;
	return true;
}

static bool initialize_intercept_entry_from_pgm_config(struct intercept_entry_t *new_entry, const struct intercept_config_t *pgm_config) {
	memset(new_entry, 0, sizeof(struct intercept_entry_t));
	if (!pgm_config) {
		initialize_default_intercept_entry(new_entry);
	} else {
		new_entry->interception_mode = pgm_config->interception_mode;
		new_entry->hostname = pgm_config->hostname;
		new_entry->ipv4_nbo = pgm_config->ipv4_nbo;

		char text[128];
		snprintf(text, sizeof(text), "%s client", pgm_config->hostname);
		if (!init_tls_intercept_entry(&new_entry->client_template, &pgm_config->client, text)) {
			return false;
		}
		snprintf(text, sizeof(text), "%s server", pgm_config->hostname);
		if (!init_tls_intercept_entry(&new_entry->server_template, &pgm_config->server, text)) {
			return false;
		}
	}

	/* Defaults that apply even when options are specified -- for example, if
	 * only client cert is specified, the internal server cert should still be
	 * used instead of throwing an error that it hasn't been specified. */
	if (!new_entry->server_template.key) {
		new_entry->server_template.key = get_tls_server_key();
	}
	if (!new_entry->server_template.certificate_authority.key && !new_entry->server_template.certificate_authority.cert) {
		new_entry->server_template.certificate_authority.cert = get_forged_root_certificate();
		new_entry->server_template.certificate_authority.key = get_forged_root_key();
	}
	if (!new_entry->server_template.ocsp_responder.key && !new_entry->server_template.ocsp_responder.cert) {
		new_entry->server_template.ocsp_responder.cert = get_forged_root_certificate();
		new_entry->server_template.ocsp_responder.key = get_forged_root_key();
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
	return initialize_intercept_entry_from_pgm_config(new_entry, pgm_config);
}

bool init_interceptdb(void) {
	if (!initialize_intercept_entry_from_pgm_config(&default_entry, pgm_options->default_config)) {
		return false;
	}

	for (int i = 0; i < pgm_options->intercept.count; i++) {
		struct intercept_config_t *pgm_config = pgm_options->intercept.config[i];
		if (!append_intercept_entry_from_pgm_config(pgm_config)) {
			return false;
		}
	}
	return true;
}

static void free_entry(struct intercept_entry_t *entry) {
	free_tls_endpoint_config(&entry->client_template);
	free_tls_endpoint_config(&entry->server_template);
}

void deinit_interceptdb(void) {
	free_entry(&default_entry);
	for (int i = 0; i < entry_count; i++) {
		free_entry(&entries[i]);
	}
	free(entries);
}

