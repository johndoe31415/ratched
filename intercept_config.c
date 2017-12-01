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
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "intercept_config.h"
#include "logging.h"
#include "keyvaluelist.h"
#include "parse.h"

const char *interception_mode_to_str(enum interception_mode_t value) {
	switch (value) {
		case OPPORTUNISTIC_TLS_INTERCEPTION: return "OPPORTUNISTIC_TLS_INTERCEPTION";
		case MANDATORY_TLS_INTERCEPTION: return "MANDATORY_TLS_INTERCEPTION";
		case TRAFFIC_FORWARDING: return "TRAFFIC_FORWARDING";
		case REJECT_CONNECTION: return "REJECT_CONNECTION";
	}
	return "?";
}

static bool side_plausibility_check(const char *hostname, const char *sidename, const struct intercept_side_config_t *side) {
	if ((side->cert_filename == NULL) ^ (side->key_filename == NULL)) {
		logmsg(LLVL_ERROR, "%s: When specifying a %s certificate, you also need to specify a corresponding private key.", hostname, sidename);
		return false;
	}
	if ((side->cert_filename == NULL) && (side->chain_filename)) {
		logmsg(LLVL_WARN, "%s: Specifying a %s certificate chain file without specifying a %s certificate does not make sense.", hostname, sidename, sidename);
		return false;
	}
	return true;
}

struct intercept_config_t* intercept_config_new(const char *connection_params, bool contains_hostname) {
	struct intercept_config_t *config = calloc(1, sizeof(struct intercept_config_t));
	if (!config) {
		logmsg(LLVL_FATAL, "Cannot calloc(3) intercept_config_t: %s", strerror(errno));
		return NULL;
	}

	const struct lookup_entry_t intercept_options[] = {
		{ "o",				OPPORTUNISTIC_TLS_INTERCEPTION },
		{ "oti",			OPPORTUNISTIC_TLS_INTERCEPTION },
		{ "opportunistic",	OPPORTUNISTIC_TLS_INTERCEPTION },
		{ "m",				MANDATORY_TLS_INTERCEPTION },
		{ "mti",			MANDATORY_TLS_INTERCEPTION },
		{ "mandatory",		MANDATORY_TLS_INTERCEPTION },
		{ "fwd",			TRAFFIC_FORWARDING },
		{ "forward",		TRAFFIC_FORWARDING },
		{ "reject",			REJECT_CONNECTION },
		{ "no",				REJECT_CONNECTION },
		{ "none",			REJECT_CONNECTION },
		{ 0 }
	};
	struct keyvaluelist_def_t definition[] = {
		{ .key = "intercept", .parser = keyvalue_lookup, .target = &config->interception_mode, .argument = (void*)&intercept_options },
		{ .key = "s_reqclientcert", .parser = keyvalue_bool, .target = &config->server.request_client_cert },
		{ .key = "s_certfile", .parser = keyvalue_string, .target = &config->server.cert_filename },
		{ .key = "s_keyfile", .parser = keyvalue_string, .target = &config->server.key_filename },
		{ .key = "s_chainfile", .parser = keyvalue_string, .target = &config->server.chain_filename },
		{ .key = "s_cacert", .parser = keyvalue_string, .target = &config->server.ca_cert_filename },
		{ .key = "s_cakey", .parser = keyvalue_string, .target = &config->server.ca_key_filename },
		{ .key = "s_ciphers", .parser = keyvalue_string, .target = &config->server.ciphersuites },
		{ .key = "s_groups", .parser = keyvalue_string, .target = &config->server.supported_groups },
		{ .key = "s_sigalgs", .parser = keyvalue_string, .target = &config->server.signature_algorithms },
		{ .key = "c_certfile", .parser = keyvalue_string, .target = &config->client.cert_filename },
		{ .key = "c_keyfile", .parser = keyvalue_string, .target = &config->client.key_filename },
		{ .key = "c_chainfile", .parser = keyvalue_string, .target = &config->client.chain_filename },
		{ .key = "c_ciphers", .parser = keyvalue_string, .target = &config->client.ciphersuites },
		{ .key = "c_groups", .parser = keyvalue_string, .target = &config->client.supported_groups },
		{ .key = "c_sigalgs", .parser = keyvalue_string, .target = &config->client.signature_algorithms },
		{ 0 }
	};

	if (parse_keyvalue_list(connection_params, contains_hostname ? 1 : 0, definition, &config->hostname) == -1) {
		intercept_config_free(config);
		return NULL;
	}

	if (contains_hostname) {
		/* Try to also parse as an IP entry */
		parse_ipv4(config->hostname, &config->ipv4_nbo);
	}

	if (!side_plausibility_check(contains_hostname ? config->hostname : "default config", "server", &config->server)) {
		intercept_config_free(config);
		return NULL;
	}
	if (!side_plausibility_check(contains_hostname ? config->hostname : "default config", "client", &config->client)) {
		intercept_config_free(config);
		return NULL;
	}
	if (config->client.cert_filename) {
		/* Having a CertificateRequest is implied when using a client
		 * certificate */
		if (!config->server.request_client_cert) {
			logmsg(LLVL_DEBUG, "%s: Provided a client certificate -> CertificateRequest message on server side is implied.", contains_hostname ? config->hostname : "default config");
		}
		config->server.request_client_cert = true;
	}

	return config;
}

static void intercept_side_config_free(struct intercept_side_config_t *side) {
	free(side->cert_filename);
	free(side->key_filename);
	free(side->chain_filename);
	free(side->ca_cert_filename);
	free(side->ca_key_filename);
	free(side->ciphersuites);
	free(side->supported_groups);
	memset(side, 0, sizeof(struct intercept_side_config_t));
}

void intercept_config_free(struct intercept_config_t *config) {
	if (!config) {
		return;
	}
	free(config->hostname);
	intercept_side_config_free(&config->server);
	intercept_side_config_free(&config->client);
	free(config);
}
