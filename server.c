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

#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/select.h>
#include <sys/time.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <linux/netfilter_ipv4.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "openssl_clienthello.h"
#include "openssl_tls.h"
#include "openssl_certs.h"
#include "openssl_fwd.h"
#include "server.h"
#include "pgmopts.h"
#include "logging.h"
#include "ipfwd.h"
#include "thread.h"
#include "atomic.h"
#include "certforgery.h"
#include "tools.h"
#include "interceptdb.h"
#include "errstack.h"
#include "openssl.h"
#include "hostname_ids.h"

static struct atomic_t active_client_connections;
static bool quit;
static int listening_sd;

struct client_thread_data_t {
	int accepted_sd;
	uint32_t source_ip_nbo;
	uint16_t source_port_nbo;
	uint32_t destination_ip_nbo;
	uint16_t destination_port_nbo;
	struct multithread_dumper_t *mtdump;
};

#define MAX_PRELIMINARY_DATA_LEN		4096

struct preliminary_data_t {
	uint8_t data[MAX_PRELIMINARY_DATA_LEN];
	ssize_t data_length;
	bool seen_clienthello;
	struct chello_t parsed_data;
};

static void retrieve_and_parse_preliminary_data(struct errstack_t *es, int read_sd, struct preliminary_data_t *preliminary_data) {
	/* Init structure somewhat (not the buffer though, that'd be pointless) */
	preliminary_data->data_length = 0;
	memset(&preliminary_data->parsed_data, 0, sizeof(struct chello_t));

	/* Connection to target suceeded. First read some bytes that the client
	 * (presumably) has sent so far. */
	bool data_available = select_read(read_sd, pgm_options->network.initial_read_timeout);
	if (data_available) {
		preliminary_data->data_length = read(read_sd, preliminary_data->data, MAX_PRELIMINARY_DATA_LEN);
		logmsg(LLVL_DEBUG, "Initial client connection returned %zd bytes.", preliminary_data->data_length);
	} else {
		logmsg(LLVL_DEBUG, "Initial client connection timed out after %.1f sec.", pgm_options->network.initial_read_timeout);
	}

	/* Now try to parse these bytes as a ClientHello message, if possible */
	if (preliminary_data->data_length > 0) {
		preliminary_data->seen_clienthello = parse_client_hello(&preliminary_data->parsed_data, preliminary_data->data, preliminary_data->data_length);
		if (preliminary_data->seen_clienthello) {
			errstack_push_client_hello(es, &preliminary_data->parsed_data);
			logmsg(LLVL_DEBUG, "Successfully parsed ClientHello message from preliminary data. SNI %s", preliminary_data->parsed_data.server_name_indication ? preliminary_data->parsed_data.server_name_indication : "not present");
		} else {
			logmsg(LLVL_WARN, "The %zd initial bytes couldn't be parsed as a ClientHello.", preliminary_data->data_length);
		}
	}
}

static void start_plain_forwarding(const struct preliminary_data_t *preliminary_data, int accepted_fd, int connected_fd) {
	/* First write the preliminary data to its peer, then forward the rest of the data */
	logmsg(LLVL_INFO, "Direct and unmodified forwarding of traffic, not intercepting.");
	if (preliminary_data->data_length > 0) {
		ssize_t bytes_written = write(connected_fd, preliminary_data->data, preliminary_data->data_length);
		if (bytes_written != preliminary_data->data_length) {
			logmsg(LLVL_WARN, "Preliminary data read was %zd bytes, but only %zd bytes written.", preliminary_data->data_length, bytes_written);
		}
	}
	plain_forward_data(accepted_fd, connected_fd);
}

static void log_tls_endpoint_config(enum loglvl_t loglvl, const char *description, const struct tls_endpoint_config_t *config) {
	if (loglevel_at_least(loglvl)) {
		char buf[128];
		dump_tls_endpoint_config(buf, sizeof(buf), config);
		logmsg(loglvl, "%s: %s", description, buf);
	}
}

static void start_tls_forwarding(struct intercept_entry_t *decision, const struct client_thread_data_t *ctx, const struct preliminary_data_t *preliminary_data, int accepted_fd, int connected_fd) {
	struct errstack_t es = ERRSTACK_INIT;

	/* Now perform TLS handshake with the accepted peer first */
	struct tls_endpoint_config_t server_config = decision->server_template;
	log_tls_endpoint_config(LLVL_TRACE, "Server TLS endpoint configuration template", &server_config);

	if (!server_config.key) {
		logmsg(LLVL_ERROR, "TLS forwarding not possible, configuration is missing the server private key.");
		errstack_pop_all(&es);
		return;
	}

	if (!server_config.cert) {
		/* No static configuration for that host, dynamically generate
		 * server certificate */
		if (!server_config.certificate_authority.cert) {
			logmsg(LLVL_ERROR, "TLS forwarding not possible. Tried to generate server certificate, but CA certificate is missing.");
			errstack_pop_all(&es);
			return;
		}
		if (!server_config.certificate_authority.key) {
			logmsg(LLVL_ERROR, "TLS forwarding not possible. Tried to generate server certificate, but CA private key is missing.");
			errstack_pop_all(&es);
			return;
		}
		server_config.cert = forge_certificate_for_server(preliminary_data->parsed_data.server_name_indication, ctx->destination_ip_nbo);
		errstack_push_X509(&es, server_config.cert);
	}

	log_tls_endpoint_config(LLVL_TRACE, "Server TLS endpoint final configuration", &server_config);

	struct tls_connection_request_t server_request = {
		.is_server = true,
		.peer_fd = accepted_fd,
		.config = &server_config,
		.initial_peer_data = preliminary_data->data,
		.initial_peer_data_length = preliminary_data->data_length,
	};
	struct tls_connection_t accepted_ssl = openssl_tls_connect(&server_request);
	errstack_push_SSL(&es, accepted_ssl.ssl);

	/* Did the accepted peer send a client certificate? */
	struct tls_endpoint_config_t client_config = decision->client_template;
	log_tls_endpoint_config(LLVL_TRACE, "Client TLS endpoint configuration template", &client_config);

	if (accepted_ssl.ssl && accepted_ssl.peer_certificate)  {
		if (!client_config.cert) {
			/* Client certificates are used, but no static client
			 * certificate configuration found. Dynamically generate
			 * client certificate. */
			client_config.key = get_tls_client_key();
			client_config.cert = forge_client_certificate(accepted_ssl.peer_certificate, client_config.key, NULL, client_config.key, pgm_options->forged_certs.recalculate_key_identifiers, pgm_options->forged_certs.mark_forged_certificates);
			log_cert(LLVL_DEBUG, client_config.cert, "Dynamically created client certificate");
		} else {
			X509_up_ref(client_config.cert);
		}
		errstack_push_X509(&es, client_config.cert);
	}
	log_tls_endpoint_config(LLVL_TRACE, "Client TLS endpoint final configuration", &client_config);

	/* And do a TLS handshake with the connected peer as well */
	struct tls_connection_request_t client_request = {
		.is_server = false,
		.peer_fd = connected_fd,
		.config = &client_config,
		.server_name_indication = preliminary_data->parsed_data.server_name_indication,
	};
	struct tls_connection_t connected_ssl = openssl_tls_connect(&client_request);
	errstack_push_SSL(&es, connected_ssl.ssl);

	/* Then forward the TLS channels */
	if (connected_ssl.ssl && accepted_ssl.ssl) {
		/* Create a connection to dump data into */
		struct connection_t conn = {
			.acceptor = {
				.ip_nbo = ctx->destination_ip_nbo,
				.port_nbo = ctx->destination_port_nbo,
				.hostname = preliminary_data->parsed_data.server_name_indication,
				.hostname_id = resolve_hostname_id(ctx->destination_ip_nbo, preliminary_data->parsed_data.server_name_indication),
			},
			.connector = {
				.ip_nbo = ctx->source_ip_nbo,
				.port_nbo = ctx->source_port_nbo,
			},
		};
		char comment[256];
		snprintf(comment, sizeof(comment), "%zd bytes ClientHello, Server Name Indication %s, " PRI_IPv4 ":%u", preliminary_data->data_length, preliminary_data->parsed_data.server_name_indication ? preliminary_data->parsed_data.server_name_indication : "not present", FMT_IPv4(conn.acceptor.ip_nbo), ntohs(conn.acceptor.port_nbo));
		create_tcp_ip_connection(ctx->mtdump, &conn, comment, pgm_options->pcapng.use_ipv6_encapsulation);
		tls_forward_data(accepted_ssl.ssl, connected_ssl.ssl, &conn);
		teardown_tcp_ip_connection(&conn, false);
		flush_tcp_ip_connection(&conn);
	} else {
		logmsg(LLVL_ERROR, "One TLS connection couldn't be established (connected %p, accepted %p). Cannot forward.", connected_ssl.ssl, accepted_ssl.ssl);
	}
	errstack_pop_all(&es);
}

static void client_thread_fnc(void *vctx) {
	struct client_thread_data_t *ctx = (struct client_thread_data_t*)vctx;
	struct errstack_t es = ERRSTACK_INIT;
	errstack_push_atomic_dec(&es, &active_client_connections);
	errstack_push_malloc(&es, ctx);
	errstack_push_fd(&es, ctx->accepted_sd);

	/* Create client connection first */
	int connected_sd = errstack_push_fd(&es, tcp_connect(ctx->destination_ip_nbo, ctx->destination_port_nbo));
	if (connected_sd == -1) {
		/* Connection to client failed. */
		logmsg(LLVL_ERROR, "Outgoing connection to " PRI_IPv4_PORT " failed, closing accepted connection: %s", FMT_IPv4_PORT_TUPLE(ctx->destination_ip_nbo, ctx->destination_port_nbo), strerror(errno));
		errstack_pop_all(&es);
		return;
	}

	struct preliminary_data_t preliminary_data;
	retrieve_and_parse_preliminary_data(&es, ctx->accepted_sd, &preliminary_data);

	/* Given all the facts, determine if and how we should intercept the
	 * connection. Look up the entry in the interception DB */
	struct intercept_entry_t *decision = interceptdb_find_entry(preliminary_data.parsed_data.server_name_indication, ctx->destination_ip_nbo);
	logmsg(LLVL_DEBUG, "Connection to " PRI_IPv4_PORT " in interception mode %s.", FMT_IPv4_PORT_TUPLE(ctx->destination_ip_nbo, ctx->destination_port_nbo), interception_mode_to_str(decision->interception_mode));

	if (decision->interception_mode == REJECT_CONNECTION) {
		/* Do nothing, just close connection. */
	} else if ((decision->interception_mode == TRAFFIC_FORWARDING) || ((decision->interception_mode == OPPORTUNISTIC_TLS_INTERCEPTION) && !preliminary_data.seen_clienthello))  {
		/* We either wanted to forward this connection from the get-go or we
		 * tried opportunstic interception but couldn't parse a ClientHello
		 * from the client data (or received no data). Engage unmodified
		 * forwarding of traffic. */
		start_plain_forwarding(&preliminary_data, ctx->accepted_sd, connected_sd);
	} else if ((decision->interception_mode == OPPORTUNISTIC_TLS_INTERCEPTION) || (decision->interception_mode == MANDATORY_TLS_INTERCEPTION)) {
		/* Do TLS interception */
		start_tls_forwarding(decision, ctx, &preliminary_data, ctx->accepted_sd, connected_sd);
	} else {
		logmsg(LLVL_FATAL, "Programming error: got interception mode 0x%x", decision->interception_mode);
	}
	errstack_pop_all(&es);
}

static void start_client_thread(struct multithread_dumper_t *mtdump, int accepted_sd, const struct sockaddr_in *source, const struct sockaddr_in *destination) {
	struct client_thread_data_t *threaddata = calloc(sizeof(*threaddata), 1);
	threaddata->accepted_sd = accepted_sd;
	threaddata->source_ip_nbo = source->sin_addr.s_addr;
	threaddata->source_port_nbo = source->sin_port;
	threaddata->destination_ip_nbo = destination->sin_addr.s_addr;
	threaddata->destination_port_nbo = destination->sin_port;
	threaddata->mtdump = mtdump;
	atomic_inc(&active_client_connections);
	if (!start_detached_thread(client_thread_fnc, threaddata)) {
		logmsg(LLVL_ERROR, "Error starting client thread for accepted FD %d: %s", accepted_sd, strerror(errno));
	}
}

void stop_forwarding(bool force) {
	/* Do not call 'logmsg' here, it might deadlock from signal handler because
	 * it tries to acquire a mutex */
	fprintf(stderr, "Received SIGINT: %s stopping forwarding (currently %d active client connections).\n", force ? "forcefully" : "gracefully", active_client_connections.value);
	quit = true;
	shutdown(listening_sd, SHUT_RDWR);
	if (force) {
		exit(EXIT_SUCCESS);
	}
}

bool start_forwarding(struct multithread_dumper_t *mtdump) {
	atomic_init(&active_client_connections);

    listening_sd = socket(AF_INET, SOCK_STREAM, 0);
	if (listening_sd == -1) {
		logmsg(LLVL_ERROR, "Creating socket(2) failed: %s", strerror(errno));
		return false;
	}

	{
		int enable = 1;
		if (setsockopt(listening_sd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0) {
		    logmsg(LLVL_ERROR, "setsockopt(SO_REUSEADDR) failed: %s", strerror(errno));
			close(listening_sd);
			return false;
		}
	}

	struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = pgm_options->network.server_socket.ipv4_nbo;
    serv_addr.sin_port = pgm_options->network.server_socket.port_nbo;

	if (bind(listening_sd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1) {
		logmsg(LLVL_ERROR, "Binding socket on " PRI_IPv4_PORT " failed: %s", FMT_IPv4_PORT(serv_addr), strerror(errno));
		close(listening_sd);
		return false;
	}

    if (listen(listening_sd, pgm_options->network.server_socket.listen) == -1) {
		logmsg(LLVL_ERROR, "Listening to %d concurrent requests on bound socket failed: %s", pgm_options->network.server_socket.listen, strerror(errno));
		close(listening_sd);
		return false;
	}

	logmsg(LLVL_INFO, "Listening for incoming connections on " PRI_IPv4_PORT, FMT_IPv4_PORT(serv_addr));

	while (!quit) {
		struct sockaddr_in client_addr;
		socklen_t socklen = sizeof(client_addr);
		int connsd = accept(listening_sd, (struct sockaddr*)&client_addr, &socklen);
		if (connsd == -1) {
			if (quit) {
				break;
			} else {
				logmsg(LLVL_ERROR, "accept(2) failed: %s", strerror(errno));
				continue;
			}
		}
		logmsg(LLVL_INFO, "New incoming connection from " PRI_IPv4_PORT, FMT_IPv4_PORT(client_addr));

		struct sockaddr_in original_addr;
		socklen = sizeof(client_addr);
		if (getsockopt(connsd, SOL_IP, SO_ORIGINAL_DST, (struct sockaddr *)&original_addr, &socklen) == -1) {
			logmsg(LLVL_ERROR, "Error determining original address for socket %d from " PRI_IPv4_PORT " and no local forwarding specified: %s", connsd, FMT_IPv4_PORT(client_addr), strerror(errno));
			close(connsd);
		} else {
			bool start_client = true;
			logmsg(LLVL_DEBUG, "Original connection with FD %d from " PRI_IPv4_PORT " tried to reach " PRI_IPv4_PORT ".", connsd, FMT_IPv4_PORT(client_addr), FMT_IPv4_PORT(original_addr));
			if (ntohl(original_addr.sin_addr.s_addr) == IPv4ADDR(127, 0, 0, 1)) {
				if (pgm_options->network.local_forwarding.ipv4_nbo != 0) {
					original_addr.sin_addr.s_addr = pgm_options->network.local_forwarding.ipv4_nbo;
					original_addr.sin_port = pgm_options->network.local_forwarding.port_nbo;
					logmsg(LLVL_DEBUG, "Local connection detected, rerouting destination to " PRI_IPv4_PORT, FMT_IPv4_PORT(original_addr));
				} else {
					logmsg(LLVL_WARN, "Local connection detected, but no forwarding requested. Dropping connection.");
					close(connsd);
					start_client = false;
				}
			}
			if (start_client) {
				start_client_thread(mtdump, connsd, &client_addr, &original_addr);
			}
		}

		if (pgm_options->operation.singleshot) {
			logmsg(LLVL_INFO, "Shutting down (single shot requested).");
			break;
		}
	}

	/* Close parent FD */
	close(listening_sd);

	/* Wait for all further communication to cease */
	logmsg(LLVL_DEBUG, "Waiting for remaining %d connection(s) to close.", active_client_connections.value);
	atomic_wait_until_value(&active_client_connections, 0);

	return true;
}
