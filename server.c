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

#if 0
static void determine_interception(char *hostname, uint32_t ipv4_nbo, struct interception_decision_t *decision) {
	memset(decision, 0, sizeof(struct interception_decision_t));
	if (hostname[0] == 0) {
		/* Empty string */
		hostname = NULL;
	}

	strtolower(hostname);
	const struct intercept_entry_t* intercept_entry = pgmopts_get_intercept_entry(hostname);

	if (!intercept_entry) {
		/* Default client */
		logmsg(LLVL_DEBUG, "Connection to %s (" PRI_IPv4 ") considered a default client.", hostname ? hostname : "[no SNI]", FMT_IPv4(ipv4_nbo));
		decision->do_intercept = pgm_options->default_client.do_intercept;
		if (decision->do_intercept) {
			decision->client_certificate.request = pgm_options->default_client.client_certificate.request;
		}
	} else {
		logmsg(LLVL_DEBUG, "Connection to %s (" PRI_IPv4 ") has a interception entry in the database.", hostname ? hostname : "[no SNI]", FMT_IPv4(ipv4_nbo));
		decision->do_intercept = intercept_entry->do_intercept;
		if (decision->do_intercept) {
			decision->client_certificate.request = intercept_entry->client_certificate.request;
			/* TODO: Read client cert! */
		}
	 }

	if (decision->do_intercept) {
	}
}
#endif

static bool select_read(int fd, double timeout_secs) {
	fd_set read_fds;
	FD_ZERO(&read_fds);
	FD_SET(fd, &read_fds);

	int usecs = (int)(timeout_secs * 1e6);
	struct timeval timeout = {
		.tv_sec = usecs / 1000000,
		.tv_usec = usecs % 1000000,
	};
	int result = select(fd + 1, &read_fds, NULL, NULL, &timeout);
	if (result == -1) {
		logmsg(LLVL_ERROR, "select(2) of FD %d failed: %s", fd, strerror(errno));
	}
	return result == 1;
}

static void client_thread_fnc(void *vctx) {
	struct client_thread_data_t *ctx = (struct client_thread_data_t*)vctx;

	/* Create client connection first */
	int connected_sd = tcp_connect(ctx->destination_ip_nbo, ctx->destination_port_nbo);

	if (connected_sd == -1) {
		/* Connection to client failed. */
		logmsg(LLVL_ERROR, "Outgoing connection to " PRI_IPv4_PORT " failed, closing accepted connection: %s", FMT_IPv4_PORT_TUPLE(ctx->destination_ip_nbo, ctx->destination_port_nbo), strerror(errno));
	} else {
		/* Connection to target suceeded. First read some bytes that the client
		 * (presumably) has sent so far. */
		uint8_t preliminary_data[4096];
		bool data_available = select_read(ctx->accepted_sd, pgm_options->initial_read_timeout);
		ssize_t bytes_read = 0;
		if (data_available) {
			bytes_read = read(ctx->accepted_sd, preliminary_data, sizeof(preliminary_data));
			logmsg(LLVL_DEBUG, "Initial client connection returned %zd bytes.", bytes_read);
		} else {
			logmsg(LLVL_DEBUG, "Initial client connection timed out after %.1f sec.", pgm_options->initial_read_timeout);
		}

		/* Now try to parse these bytes as a ClientHello message, if possible */
		struct chello_t client_hello = { 0 };
		if (bytes_read > 0) {
			if (parse_client_hello(preliminary_data, bytes_read, &client_hello)) {
				logmsg(LLVL_DEBUG, "Successfully parsed ClientHello message. SNI %s", client_hello.servername[0] ? client_hello.servername : "not present");
			} else {
				logmsg(LLVL_WARN, "The %zd initial bytes couldn't be parsed as a ClientHello, treating connection as a default client.", bytes_read);
			}
		}

		/* Given all the facts, determine if and how we should intercept the
		 * connection. Look up the entry in the interception DB */
		const char *server_name_indication = client_hello.servername;
		if (!*server_name_indication) {
			server_name_indication = NULL;
		}
		struct intercept_entry_t *decision = interceptdb_find_entry(client_hello.servername, ctx->destination_ip_nbo);
		if (!decision->do_intercept) {
			if (pgm_options->reject_unknown_traffic) {
				logmsg(LLVL_WARN, "Rejecting unknown traffic instead of forwarding unmodified.");
				close(ctx->accepted_sd);
				close(connected_sd);
			} else {
				/* First write the preliminary data to its peer, then forward the rest of the data */
				logmsg(LLVL_INFO, "Direct and unmodified forwarding of traffic, not intercepting.");
				if (bytes_read > 0) {
					ssize_t bytes_written = write(connected_sd, preliminary_data, bytes_read);
					if (bytes_written != bytes_read) {
						logmsg(LLVL_WARN, "Preliminary data read was %zd bytes, but only %zd bytes written.", bytes_read, bytes_written);
					}
				}
				plain_forward_data(ctx->accepted_sd, connected_sd);
			}
		} else {
			/* Now perform TLS handshake with the accepted peer first */
			struct tls_endpoint_config_t server_config = decision->server;
			if (!server_config.cert) {
				/* No static configuration for that host, dynamically generate
				 * server certificate */
				server_config.key = get_tls_server_key();
				server_config.cert = forge_certificate_for_server(server_name_indication, ctx->destination_ip_nbo);
			}
			struct tls_connection_request_t server_request = {
				.is_server = true,
				.peer_fd = ctx->accepted_sd,
				.config = &server_config,
				.initial_peer_data = preliminary_data,
				.initial_peer_data_length = bytes_read,
			};
			struct tls_connection_t accepted_ssl = openssl_tls_connect(&server_request);

			/* Did the accepted peer send a client certificate? */
			struct tls_endpoint_config_t client_config = decision->client;
			if (accepted_ssl.ssl && accepted_ssl.peer_certificate)  {
				if (!client_config.cert) {
					/* Client certificates are used, but no static client
					 * certificate configuration found. Dynamically generate
					 * client certificate. */
					client_config.key = get_tls_client_key();
					client_config.cert = forge_client_certificate(accepted_ssl.peer_certificate, client_config.key, NULL, client_config.key, pgm_options->default_recalculate_key_identifiers, pgm_options->mark_forged_certificates);
					log_cert(LLVL_DEBUG, client_config.cert, "Dynamically created client certificate");
				} else {
					X509_up_ref(client_config.cert);
				}
			}

			/* And do a TLS handshake with the connected peer as well */
			struct tls_connection_request_t client_request = {
				.is_server = false,
				.peer_fd = connected_sd,
				.config = &client_config,
				.server_name_indication = server_name_indication,
			};
			struct tls_connection_t connected_ssl = openssl_tls_connect(&client_request);

			/* Then forward the TLS channels */
			if (connected_ssl.ssl && accepted_ssl.ssl) {
				/* Create a connection to dump data into */
				struct connection_t conn = {
					.acceptor = {
						.ip_nbo = ctx->destination_ip_nbo,
						.port_nbo = ctx->destination_port_nbo,
						.hostname = server_name_indication,
					},
					.connector = {
						.ip_nbo = ctx->source_ip_nbo,
						.port_nbo = ctx->source_port_nbo,
					},
				};
				char comment[256];
				snprintf(comment, sizeof(comment), "%zd bytes ClientHello, Server Name Indication %s, " PRI_IPv4 ":%u", bytes_read, server_name_indication ? server_name_indication : "not present", FMT_IPv4(conn.acceptor.ip_nbo), ntohs(conn.acceptor.port_nbo));
				create_tcp_ip_connection(ctx->mtdump, &conn, comment);
				tls_forward_data(accepted_ssl.ssl, connected_ssl.ssl, &conn);
				teardown_tcp_ip_connection(&conn, false);
			} else {
				logmsg(LLVL_ERROR, "One TLS connection couldn't be established (connected %p, accepted %p). Cannot forward.", connected_ssl.ssl, accepted_ssl.ssl);
			}

			SSL_free(connected_ssl.ssl);
			SSL_free(accepted_ssl.ssl);
			X509_free(client_config.cert);
		}
	}
	close(ctx->accepted_sd);
	close(connected_sd);
	free(ctx);
	atomic_dec(&active_client_connections);
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
    serv_addr.sin_addr.s_addr = pgm_options->server_socket.ipv4_nbo;
    serv_addr.sin_port = pgm_options->server_socket.port_nbo;

	if (bind(listening_sd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1) {
		logmsg(LLVL_ERROR, "Binding socket on " PRI_IPv4_PORT " failed: %s", FMT_IPv4_PORT(serv_addr), strerror(errno));
		close(listening_sd);
		return false;
	}

    if (listen(listening_sd, pgm_options->server_socket.listen) == -1) {
		logmsg(LLVL_ERROR, "Listening to %d concurrent requests on bound socket failed: %s", pgm_options->server_socket.listen, strerror(errno));
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
				if (pgm_options->local_forwarding.ipv4_nbo != 0) {
					original_addr.sin_addr.s_addr = pgm_options->local_forwarding.ipv4_nbo;
					original_addr.sin_port = pgm_options->local_forwarding.port_nbo;
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

		if (pgm_options->singleshot) {
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
