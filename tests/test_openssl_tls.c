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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <openssl.h>
#include <openssl_tls.h>
#include <intercept_config.h>
#include <atomic.h>
#include <thread.h>

struct test_ctx_t {
	int sds[2];
	struct atomic_t client_state, server_state;
	struct tls_connection_t client_conn, server_conn;
	struct atomic_t teardown;
	const uint8_t *initial_data;
	int initial_data_length;
};

static void tls_client_thread(void *arg) {
	struct test_ctx_t *ctx = (struct test_ctx_t*)arg;

	struct tls_connection_request_t request = {
		.peer_fd = ctx->sds[0],
		.is_server = false,
	};
	ctx->client_conn = openssl_tls_connect(&request);
	atomic_inc(&ctx->client_state);

	atomic_wait_until_value(&ctx->teardown, 1);
	SSL_shutdown(ctx->server_conn.ssl);
	SSL_free(ctx->client_conn.ssl);
	close(ctx->sds[0]);
	atomic_inc(&ctx->teardown);
}

static void tls_server_thread(void *arg) {
	struct test_ctx_t *ctx = (struct test_ctx_t*)arg;

	struct tls_endpoint_config_t config = {
		.tls_versions = TLS_VERSION_TLS12,
	};
	struct tls_endpoint_cert_source_t certsrc = {
		.cert_filename = "local.crt",
		.key_filename = "local.key",
	};
	test_assert(init_tls_endpoint_config(&config, "local config", &certsrc));

	struct tls_connection_request_t request = {
		.peer_fd = ctx->sds[1],
		.is_server = true,
		.initial_peer_data = ctx->initial_data,
		.initial_peer_data_length = ctx->initial_data_length,
		.config = &config,
	};

	ctx->server_conn = openssl_tls_connect(&request);
	atomic_inc(&ctx->server_state);

	atomic_wait_until_value(&ctx->teardown, 2);
	SSL_shutdown(ctx->server_conn.ssl);
	SSL_free(ctx->server_conn.ssl);
	X509_free(config.cert);
	EVP_PKEY_free(config.key);
	close(ctx->sds[1]);
	atomic_inc(&ctx->teardown);
}

static void urandom(uint8_t *data, int length) {
	int fd = open("/dev/urandom", O_RDONLY);
	test_assert(fd != -1);
	test_assert_int_eq(read(fd, data, length), length);
	close(fd);
}

static void ssl_check_connection(SSL *ssl_write, SSL *ssl_read) {
	uint8_t data[32];
	urandom(data, sizeof(data));
	test_assert_int_eq(SSL_write(ssl_write, data, sizeof(data)), sizeof(data));

	uint8_t read_data[sizeof(data)];
	test_assert_int_eq(SSL_read(ssl_read, read_data, sizeof(read_data)), sizeof(read_data));

	test_assert(memcmp(data, read_data, sizeof(data)) == 0);
}

static void check_communication(struct test_ctx_t *ctx) {
	atomic_wait_until_value(&ctx->server_state, 1);
	atomic_wait_until_value(&ctx->client_state, 1);

	ssl_check_connection(ctx->server_conn.ssl, ctx->client_conn.ssl);
	ssl_check_connection(ctx->client_conn.ssl, ctx->server_conn.ssl);
	ssl_check_connection(ctx->client_conn.ssl, ctx->server_conn.ssl);
	ssl_check_connection(ctx->server_conn.ssl, ctx->client_conn.ssl);
	ssl_check_connection(ctx->server_conn.ssl, ctx->client_conn.ssl);

	atomic_inc(&ctx->teardown);
	atomic_wait_until_value(&ctx->teardown, 3);
}

static void test_tls_direct(void) {
	subtest_start();

	struct test_ctx_t test_ctx = { 0 };
	atomic_init(&test_ctx.client_state);
	atomic_init(&test_ctx.server_state);
	atomic_init(&test_ctx.teardown);
	test_assert(socketpair(AF_LOCAL, SOCK_STREAM, 0, test_ctx.sds) == 0);

	/* Fire up client first */
	start_detached_thread(tls_client_thread, &test_ctx);

	/* Then the server */
	start_detached_thread(tls_server_thread, &test_ctx);

	check_communication(&test_ctx);
	subtest_finished();
}

static void test_tls_initial_data(void) {
	subtest_start();

	struct test_ctx_t test_ctx;
	atomic_init(&test_ctx.client_state);
	atomic_init(&test_ctx.server_state);
	atomic_init(&test_ctx.teardown);
	test_assert(socketpair(AF_LOCAL, SOCK_STREAM, 0, test_ctx.sds) == 0);

	/* Fire up client first */
	start_detached_thread(tls_client_thread, &test_ctx);

	/* Read out data from client. */
	uint8_t initial_data[1024];
	ssize_t length_read = read(test_ctx.sds[1], initial_data, sizeof(initial_data));
	test_assert(length_read > 0);

	test_ctx.initial_data = initial_data;
	test_ctx.initial_data_length = length_read;

	/* Then the server */
	start_detached_thread(tls_server_thread, &test_ctx);

	check_communication(&test_ctx);
	subtest_finished();
}

int main(int argc, char **argv) {
	test_start(argc, argv);
	test_tls_direct();
	test_tls_initial_data();
	test_finished();
	return 0;
}
