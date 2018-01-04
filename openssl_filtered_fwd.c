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

#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>

#include "openssl_filtered_fwd.h"
#include "logging.h"
#include "atomic.h"
#include "openssl.h"

static void* forwarding_thread_fnc(void *vctx) {
	struct forwarding_thread_data_t *ctx = (struct forwarding_thread_data_t*)vctx;
	BIO *read_bio, *write_bio;
	struct connection_side_stats_t *stats;
	bool tcpip_direction;
	if (ctx->direction == READ_1_WRITE_2) {
		read_bio = ctx->fwd_data->side1;
		write_bio = ctx->fwd_data->side2;
		stats = &ctx->fwd_data->stats->dir1;
		tcpip_direction = true;
	} else {
		read_bio = ctx->fwd_data->side2;
		write_bio = ctx->fwd_data->side1;
		stats = &ctx->fwd_data->stats->dir2;
		tcpip_direction = false;
	}
	while (true) {
		uint8_t data[4096];

		ssize_t length_read = BIO_read(read_bio, data, sizeof(data));
		if (length_read == 0) {
			/* Peer closed connection */
			break;
		}
		if (length_read <= 0) {
			logmsg(LLVL_ERROR, "%zd bytes read when forwarding %p -> %p.", length_read, read_bio, write_bio);
			break;
		}
		stats->bytes_read += length_read;

		if (ctx->fwd_data->conn) {
			append_tcp_ip_data(ctx->fwd_data->conn, tcpip_direction, data, length_read);
		}
		ssize_t length_written = BIO_write(write_bio, data, length_read);
		if (length_written != length_read) {
			logmsg(LLVL_ERROR, "%zd bytes written when TLS forwarding %p -> %p, %zd bytes expected.", length_written, read_bio, write_bio, length_read);
			break;
		}
		stats->bytes_written += length_written;
	}
	ctx->fwd_data->connection_shutdown_callback(ctx);
	logmsg(LLVL_TRACE, "Thread %p -> %p (dir %d) finished.", read_bio, write_bio, ctx->direction);
	return NULL;
}

static void filtered_BIO_forward_data(struct forwarding_data_t *fwd_data, struct connection_stats_t *stats, struct connection_t *conn) {
	memset(stats, 0, sizeof(struct connection_stats_t));
	fwd_data->stats = stats;
	fwd_data->conn = conn;
	struct forwarding_thread_data_t dir1 = {
		.direction = READ_1_WRITE_2,
		.fwd_data = fwd_data,
	};
	struct forwarding_thread_data_t dir2 = {
		.direction = READ_2_WRITE_1,
		.fwd_data = fwd_data,
	};
	atomic_init(&fwd_data->shutdown);

	pthread_t dir1_thread, dir2_thread;
	if (pthread_create(&dir1_thread, NULL, forwarding_thread_fnc, &dir1)) {
		logmsg(LLVL_ERROR, "Failed to create forwarding thread 1: %s", strerror(errno));
		return;
	}
	if (pthread_create(&dir2_thread, NULL, forwarding_thread_fnc, &dir2)) {
		logmsg(LLVL_ERROR, "Failed to create forwarding thread 2: %s", strerror(errno));
		return;
	}

	/* Wait for both threads to finish */
	pthread_join(dir1_thread, NULL);
	pthread_join(dir2_thread, NULL);

	logmsg(LLVL_INFO, "Closed TLS forwarding %p <-> %p (forwarded %u bytes written to server, %u bytes written to client)", fwd_data->side1, fwd_data->side2, stats->dir1.bytes_written, stats->dir2.bytes_written);
}

static void fd_shutdown_callback(struct forwarding_thread_data_t *fwddata) {
	if (atomic_test_and_set(&fwddata->fwd_data->shutdown)) {
		shutdown(fwddata->fwd_data->raw_connection_info.fd.side1, SHUT_RDWR);
		shutdown(fwddata->fwd_data->raw_connection_info.fd.side2, SHUT_RDWR);
	}
}

void filtered_fd_forward_data(int fd1, int fd2, struct connection_stats_t *stats, struct connection_t *conn) {
	struct forwarding_data_t fwd_data = {
		.connection_shutdown_callback = fd_shutdown_callback,
		.raw_connection_info = {
			.fd = {
				.side1 = fd1,
				.side2 = fd2,
			},
		},
	};
	fwd_data.side1 = BIO_new_fd(fd1, BIO_NOCLOSE);
	if (!fwd_data.side1) {
		logmsgext(LLVL_ERROR, FLAG_OPENSSL_ERROR, "Failed to create BIO from fd1 %d.", fd1);
		return;
	}

	fwd_data.side2 = BIO_new_fd(fd2, BIO_NOCLOSE);
	if (!fwd_data.side2) {
		BIO_free_all(fwd_data.side1);
		logmsgext(LLVL_ERROR, FLAG_OPENSSL_ERROR, "Failed to create BIO from fd2 %d.", fd2);
		return;
	}

	filtered_BIO_forward_data(&fwd_data, stats, conn);

	BIO_free_all(fwd_data.side2);
	BIO_free_all(fwd_data.side1);
}

static void ssl_shutdown_callback(struct forwarding_thread_data_t *fwddata) {
	if (atomic_test_and_set(&fwddata->fwd_data->shutdown)) {
		SSL_shutdown(fwddata->fwd_data->raw_connection_info.tls.side1);
		SSL_shutdown(fwddata->fwd_data->raw_connection_info.tls.side2);
	}
}

void filtered_tls_forward_data(SSL *ssl1, SSL *ssl2, struct connection_stats_t *stats, struct connection_t *conn) {
	struct forwarding_data_t fwd_data = {
		.connection_shutdown_callback = ssl_shutdown_callback,
		.raw_connection_info = {
			.tls = {
				.side1 = ssl1,
				.side2 = ssl2,
			},
		},
	};
	fwd_data.side1 = BIO_new(BIO_f_ssl());
	if (!fwd_data.side1) {
		logmsgext(LLVL_ERROR, FLAG_OPENSSL_ERROR, "Failed to create BIO from SSL object 1 at %p.", ssl1);
		return;
	}
	BIO_set_ssl(fwd_data.side1, ssl1, BIO_NOCLOSE);

	fwd_data.side2 = BIO_new(BIO_f_ssl());
	if (!fwd_data.side2) {
		BIO_free_all(fwd_data.side1);
		logmsgext(LLVL_ERROR, FLAG_OPENSSL_ERROR, "Failed to create BIO from SSL object 2 at %p.", ssl2);
		return;
	}
	BIO_set_ssl(fwd_data.side2, ssl2, BIO_NOCLOSE);

	filtered_BIO_forward_data(&fwd_data, stats, conn);

	BIO_free_all(fwd_data.side2);
	BIO_free_all(fwd_data.side1);
}
