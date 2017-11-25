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
#include <ipfwd.h>
#include <openssl.h>
#include <openssl_tls.h>

static void test_tcpip(void) {
	subtest_start();
	openssl_init();

	int sd = tcp_connect(htonl(0x7f000001), htons(9991));
	struct tls_connection_request_t request = {
		.peer_fd = sd,
		.is_server = false,
	};
	struct tls_connection_t connection = openssl_tls_connect(&request);
	if (connection.ssl) {
		SSL_write(connection.ssl, "foobar\n", 7);
		SSL_free(connection.ssl);
	}
	close(sd);
	openssl_deinit();
	subtest_finished();
}

int main(int argc, char **argv) {
	test_start(argc, argv);
	test_tcpip();
	test_finished();
	return 0;
}

