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

#include <stdio.h>
#include "testbed.h"
#include <openssl.h>
#include <openssl_certs.h>
#include <ocsp_response.h>

static void test_ocsp(void) {
	subtest_start();
	openssl_init();

	X509 *cert = openssl_load_cert("local.crt", "root", false);
	EVP_PKEY *key = openssl_load_key("local.key", "root", false);
	test_assert(cert);
	test_assert(key);

	OCSP_RESPONSE *response = create_ocsp_response(cert, cert, key);
	test_assert(response);

	if (response) {
		BIO *bio = BIO_new_fp(stderr, BIO_NOCLOSE);
		OCSP_RESPONSE_print(bio, response, 0);
		fprintf(stderr, "\n");
		BIO_free(bio);
	}

	EVP_PKEY_free(key);
	X509_free(cert);

	OCSP_RESPONSE_free(response);
	openssl_deinit();
	subtest_finished();
}

int main(int argc, char **argv) {
	test_start(argc, argv);
	test_ocsp();
	test_finished();
	return 0;
}

