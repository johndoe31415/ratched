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

#ifndef __CERTFORGERY_H__
#define __CERTFORGERY_H__

#include <stdint.h>
#include <stdbool.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

struct certforgery_data_t {
	X509 *root_ca_cert;
	EVP_PKEY *root_ca_key;
	EVP_PKEY *tls_server_key;
};

struct certificate_runtime_parameters_t {
	X509 *client_certificate;
	EVP_PKEY *client_key;
	STACK_OF(X509) *client_chain;
};

/*************** AUTO GENERATED SECTION FOLLOWS ***************/
bool certforgery_init(void);
X509 *get_forged_root_certificate(void);
EVP_PKEY *get_tls_server_key(void);
EVP_PKEY *get_tls_client_key(void);
X509 *forge_certificate_for_server(const char *hostname, uint32_t ipv4_nbo);
void certforgery_deinit(void);
/***************  AUTO GENERATED SECTION ENDS   ***************/

#endif
