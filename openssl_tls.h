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

#ifndef __OPENSSL_TLS_H__
#define __OPENSSL_TLS_H__

#include <stdint.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include "openssl_certs.h"

struct tls_connection_t {
	SSL *ssl;
	X509 *peer_certificate;
};

struct tls_connection_request_t {
	int peer_fd;
	bool is_server;
	const uint8_t *initial_peer_data;
	unsigned int initial_peer_data_length;
	struct tls_endpoint_config_t *config;
	const char *server_name_indication;
};

/*************** AUTO GENERATED SECTION FOLLOWS ***************/
struct tls_connection_t openssl_tls_connect(const struct tls_connection_request_t *request);
/***************  AUTO GENERATED SECTION ENDS   ***************/

#endif
