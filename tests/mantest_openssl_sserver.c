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
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl.h>
#include <openssl_tls.h>
#include <ipfwd.h>

static void test_sserver(void) {
	subtest_start();
	openssl_init();

	struct tls_endpoint_config_t config;
	struct tls_endpoint_cert_source_t certsrc = {
		.cert_filename = "local.crt",
		.key_filename = "local.key",
	};
	test_assert(init_tls_endpoint_config(&config, "local config", &certsrc));

	const int port = 7777;
	fprintf(stderr, "Listening on port %d...\n", port);
	int sd = tcp_accept(htons(port));

	fprintf(stderr, "Someone connected, reading preliminary data...\n");

	uint8_t client_data[1024];
	ssize_t client_data_len = read(sd, client_data, sizeof(client_data));
	fprintf(stderr, "Read %zd bytes of initial client data. Setting up TLS connection...\n", client_data_len);

	struct tls_connection_request_t request = {
		.peer_fd = sd,
		.is_server = true,
		.initial_peer_data = client_data,
		.initial_peer_data_length = client_data_len,
		.config = &config,
	};
	struct tls_connection_t conn = openssl_tls_connect(&request);
	if (conn.ssl) {
		SSL_write(conn.ssl, "foobar\n", 7);
		SSL_free(conn.ssl);
	}
	close(sd);

	//EVP_PKEY_free(server_key);
	//X509_free(server_cert);

	openssl_deinit();
	subtest_finished();
}

int main(int argc, char **argv) {
	test_start(argc, argv);
	test_sserver();
	test_finished();
	return 0;
}

