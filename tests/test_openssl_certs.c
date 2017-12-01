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

#include "testbed.h"
#include <openssl.h>
#include <openssl_certs.h>

static void test_cert_generation(void) {
	openssl_init();

	struct keyspec_t keyspec = {
		.description = "test",
		.cryptosystem = CRYPTOSYSTEM_ECC_FP,
		.ecc_fp = {
			.curve_name = "secp256r1",
		},
	};

	EVP_PKEY *key = openssl_load_stored_key(&keyspec, "local.key");
	test_assert(key);

	struct certificatespec_t certspec = {
		.description = "test",
		.subject_pubkey = key,
		.issuer_privkey = key,
		.common_name = "Pretty self-signed cert",
		.is_ca_certificate = true,
		.validity_seconds = 10,
	};
	X509 *crt = openssl_load_stored_certificate(&certspec, "local.crt", true, true);
	test_assert(crt);

	X509_free(crt);
	EVP_PKEY_free(key);

	openssl_deinit();
}

static void test_cert_forgery(void) {
	openssl_init();
	X509 *crt = openssl_load_cert("local.crt", "local.crt", false);
	test_assert(crt);

	struct keyspec_t keyspec = {
		.description = "forged key",
		.cryptosystem = CRYPTOSYSTEM_ECC_FP,
		.ecc_fp = {
			.curve_name = "secp256r1",
		},
	};
	EVP_PKEY *key = openssl_create_key(&keyspec);
	test_assert(key);
//	X509_print_fp(stderr, crt);

	X509 *forgery = forge_client_certificate(crt, key, NULL, key, true, true);
	test_assert(forgery);
//	X509_print_fp(stderr, forgery);
	X509_free(forgery);

	X509_free(crt);
	EVP_PKEY_free(key);
	openssl_deinit();
}

static void test_cert_id(void) {
	openssl_init();
	X509 *cert = openssl_load_cert("local.crt", "local.crt", false);
	test_assert(cert);
	uint8_t hashval[32] = { 0 };
	const uint8_t expected_hashval[32] = {
		0x6e, 0x2a, 0xed, 0x85, 0x3c, 0xe5, 0x97, 0x54, 0x64, 0x61, 0xd0, 0x51, 0xa5, 0x9f, 0xb7, 0xbb,
		0x49, 0xe6, 0xca, 0x46, 0x82, 0x6f, 0x8c, 0xa2, 0x8d, 0xdf, 0xf1, 0x0d, 0x50, 0xbd, 0x1e, 0xa4
	};
	test_assert(get_certificate_hash(hashval, cert));
	test_assert(memcmp(hashval, expected_hashval, 32) == 0);
	X509_free(cert);
	openssl_deinit();
}

static void test_cert_pubkey_id(void) {
	openssl_init();
	X509 *cert = openssl_load_cert("local.crt", "local.crt", false);
	test_assert(cert);
	uint8_t hashval[32] = { 0 };
	const uint8_t expected_hashval[32] = {
		0x80, 0x51, 0x45, 0x0f, 0xfc, 0xa2, 0x87, 0x1d, 0x51, 0x31, 0xc8, 0x08, 0xdb, 0xff, 0x33, 0x83,
		0xeb, 0x54, 0x9a, 0x44, 0xa2, 0x06, 0x5c, 0xca, 0x8e, 0x40, 0x60, 0x49, 0x64, 0x3c, 0x98, 0x48
	};
	test_assert(get_certificate_public_key_hash(hashval, cert));
	test_assert(memcmp(hashval, expected_hashval, 32) == 0);
	X509_free(cert);
	openssl_deinit();
}

static void test_key_pubkey_id(void) {
	openssl_init();
	EVP_PKEY *key = openssl_load_key("local.key", "local.key", false);
	test_assert(key);
	uint8_t hashval[32] = { 0 };
	const uint8_t expected_hashval[32] = {
		0x80, 0x51, 0x45, 0x0f, 0xfc, 0xa2, 0x87, 0x1d, 0x51, 0x31, 0xc8, 0x08, 0xdb, 0xff, 0x33, 0x83,
		0xeb, 0x54, 0x9a, 0x44, 0xa2, 0x06, 0x5c, 0xca, 0x8e, 0x40, 0x60, 0x49, 0x64, 0x3c, 0x98, 0x48
	};
	test_assert(get_public_key_hash(hashval, key));
	test_assert(memcmp(hashval, expected_hashval, 32) == 0);
	EVP_PKEY_free(key);
	openssl_deinit();
}

int main(int argc, char **argv) {
	test_start(argc, argv);
	test_cert_generation();
	test_cert_forgery();
	test_cert_id();
	test_cert_pubkey_id();
	test_key_pubkey_id();
	test_finished();
	return 0;
}

