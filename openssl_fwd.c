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

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>
#include "openssl_fwd.h"
#include "logging.h"

struct tls_forwarding_data_t {
	SSL *read_ssl;
	SSL *write_ssl;
	struct connection_t *connection;
	bool direction;
};

static void* tls_forwarding_thread_fnc(void *vctx) {
	struct tls_forwarding_data_t *ctx = (struct tls_forwarding_data_t*)vctx;
	while (true) {
		uint8_t data[4096];
		ssize_t length_read = SSL_read(ctx->read_ssl, data, sizeof(data));
		if (length_read == 0) {
			/* Peer closed connection */
			break;
		}
		if (length_read <= 0) {
			logmsg(LLVL_ERROR, "%zd bytes read when TLS forwarding %p -> %p.", length_read, ctx->read_ssl, ctx->write_ssl);
			break;
		}
		append_tcp_ip_data(ctx->connection, ctx->direction, data, length_read);
		ssize_t length_written = SSL_write(ctx->write_ssl, data, length_read);
		if (length_written != length_read) {
			logmsg(LLVL_ERROR, "%zd bytes written when TLS forwarding %p -> %p, %zd bytes expected.", length_written, ctx->read_ssl, ctx->write_ssl, length_read);
			break;
		}
	}
	SSL_shutdown(ctx->read_ssl);
	SSL_shutdown(ctx->write_ssl);
	return NULL;
}

void tls_forward_data(SSL *ssl1, SSL *ssl2, struct connection_t *conn) {
	struct tls_forwarding_data_t dir1 = {
		.read_ssl = ssl1,
		.write_ssl = ssl2,
		.connection = conn,
		.direction = true,
	};
	struct tls_forwarding_data_t dir2 = {
		.read_ssl = ssl2,
		.write_ssl = ssl1,
		.connection = conn,
		.direction = false,
	};
	pthread_t dir1_thread, dir2_thread;
	if (pthread_create(&dir1_thread, NULL, tls_forwarding_thread_fnc, &dir1)) {
		logmsg(LLVL_ERROR, "Failed to create forwarding thread 1: %s", strerror(errno));
		return;
	}
	if (pthread_create(&dir2_thread, NULL, tls_forwarding_thread_fnc, &dir2)) {
		logmsg(LLVL_ERROR, "Failed to create forwarding thread 2: %s", strerror(errno));
		return;
	}

	/* Wait for both threads to finish */
	pthread_join(dir1_thread, NULL);
	pthread_join(dir2_thread, NULL);

	logmsg(LLVL_INFO, "Closed TLS forwarding %p <-> %p", ssl1, ssl2);
}

