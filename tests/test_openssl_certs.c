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

int main(int argc, char **argv) {
	test_start(argc, argv);
	test_cert_generation();
	test_cert_forgery();
	test_finished();
	return 0;
}

