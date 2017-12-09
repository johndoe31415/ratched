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

#ifndef __INTERCEPT_CONFIG_H__
#define __INTERCEPT_CONFIG_H__

#include <stdint.h>
#include <stdbool.h>

enum interception_mode_t {
	INTERCEPTION_MODE_UNDEFINED = 0,
	OPPORTUNISTIC_TLS_INTERCEPTION,
	MANDATORY_TLS_INTERCEPTION,
	TRAFFIC_FORWARDING,
	REJECT_CONNECTION,
};

enum tls_version_t {
	TLS_VERSION_UNDEFINED = 0,
	TLS_VERSION_SSL2 = (1 << 0),
	TLS_VERSION_SSL3 = (1 << 1),
	TLS_VERSION_TLS10 = (1 << 2),
	TLS_VERSION_TLS11 = (1 << 3),
	TLS_VERSION_TLS12 = (1 << 4),
	TLS_VERSION_TLS13 = (1 << 5),
};

struct intercept_side_config_t {
	// Makes only sense for 'server', but easier this way.
	bool request_client_cert;
	uint32_t tls_versions;

	char *cert_filename;
	char *key_filename;
	char *chain_filename;

	char *ca_cert_filename;
	char *ca_key_filename;

	char *ciphersuites;
	char *supported_groups;
	char *signature_algorithms;
};

struct intercept_config_t {
	char *hostname;
	uint32_t ipv4_nbo;
	enum interception_mode_t interception_mode;
	struct intercept_side_config_t server;
	struct intercept_side_config_t client;
};


/*************** AUTO GENERATED SECTION FOLLOWS ***************/
const char *interception_mode_to_str(enum interception_mode_t value);
struct intercept_config_t* intercept_config_new(const char *connection_params, bool contains_hostname);
void intercept_config_free(struct intercept_config_t *config);
/***************  AUTO GENERATED SECTION ENDS   ***************/

#endif
