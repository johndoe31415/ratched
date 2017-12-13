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

#ifndef __OPENSSL_CERTS_H__
#define __OPENSSL_CERTS_H__

#include <stdbool.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

enum cryptosystem_t {
	CRYPTOSYSTEM_RSA,
	CRYPTOSYSTEM_ECC_FP,
	CRYPTOSYSTEM_ECC_F2M,
};

struct keyspec_t {
	const char *description;
	enum cryptosystem_t cryptosystem;
	union {
		struct {
			unsigned int bitlength;
		} rsa;
		struct {
			const char *curve_name;
		} ecc_fp;
		struct {
			const char *curve_name;
		} ecc_f2m;
	};
};

struct tls_endpoint_config_t {
	bool request_cert_from_peer;
	bool ocsp_status;
	bool include_root_ca_cert;
	uint32_t tls_versions;
	const char *ciphersuites;
	const char *supported_groups;
	const char *signature_algorithms;
	X509 *cert;
	EVP_PKEY *key;
	STACK_OF(X509) *chain;
	struct {
		X509 *cert;
		EVP_PKEY *key;
	} certificate_authority;
	struct {
		X509 *cert;
		EVP_PKEY *key;
	} ocsp_responder;
};

struct tls_endpoint_cert_source_t {
	const char *cert_filename;
	const char *key_filename;
	const char *chain_filename;
	struct {
		const char *cert_filename;
		const char *key_filename;
	} certificate_authority;
};

struct certificatespec_t {
	const char *description;
	EVP_PKEY *subject_pubkey;
	EVP_PKEY *issuer_privkey;
	X509 *issuer_certificate;
	const char *common_name;
	bool mark_certificate;
	const char *subject_alternative_dns_hostname;
	const char *crl_uri;
	const char *ocsp_responder_uri;
	uint32_t subject_alternative_ipv4_address;
	bool full_authority_keyid;
	bool is_ca_certificate;
	int validity_predate_seconds;
	uint64_t validity_seconds;
};

/*************** AUTO GENERATED SECTION FOLLOWS ***************/
EVP_PKEY* openssl_create_key(const struct keyspec_t *keyspec);
EVP_PKEY *openssl_load_key(const char *filename, const char *description, bool silent);
X509 *openssl_load_cert(const char *filename, const char *description, bool silent);
STACK_OF(X509) *openssl_load_cert_chain(const char *filename, const char *description, bool silent);
bool openssl_store_key(const char *filename, const char *description, bool silent, EVP_PKEY *key);
bool openssl_store_cert(const char *filename, const char *description, bool silent, X509 *cert);
EVP_PKEY* openssl_load_stored_key(const struct keyspec_t *keyspec, const char *filename);
bool add_extension_rawstr(X509 *cert, bool critical, int nid, const char *text);
X509* openssl_create_certificate(const struct certificatespec_t *spec);
X509* openssl_load_stored_certificate(const struct certificatespec_t *certspec, const char *filename, bool recreate_when_expired, bool recreate_when_key_mismatch);
X509 *forge_client_certificate(X509 *original_client_cert, EVP_PKEY *new_subject_pubkey, X509 *new_issuer_cert, EVP_PKEY *new_issuer_privkey, bool recalculate_key_identifiers, bool mark_certificate);
void dump_tls_endpoint_config(char *text, int text_maxlen, const struct tls_endpoint_config_t *config);
bool init_tls_endpoint_config(struct tls_endpoint_config_t *config, const char *description, const struct tls_endpoint_cert_source_t *certsrc);
bool get_certificate_hash(uint8_t hash_value[static 32], X509 *cert);
bool get_public_key_hash(uint8_t hash_value[static 32], EVP_PKEY *pubkey);
bool get_certificate_public_key_hash(uint8_t hash_value[static 32], X509 *cert);
void free_tls_endpoint_config(struct tls_endpoint_config_t *config);
/***************  AUTO GENERATED SECTION ENDS   ***************/

#endif
