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
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <openssl/ssl.h>
#include <openssl/tls1.h>
#include "logging.h"
#include "openssl.h"
#include "openssl_clienthello.h"

struct lookup_table_element_t {
	int value;
	const char *symbol;
};
#define ELEMENT(value)		{ (value), #value }

struct callback_ctx_t {
	bool debug;
	bool seen_client_hello;
	struct chello_t *parse_result;
};

static struct lookup_table_element_t known_extensions[] = {
	ELEMENT(TLSEXT_TYPE_server_name),
	ELEMENT(TLSEXT_TYPE_max_fragment_length),
	ELEMENT(TLSEXT_TYPE_client_certificate_url),
	ELEMENT(TLSEXT_TYPE_trusted_ca_keys),
	ELEMENT(TLSEXT_TYPE_truncated_hmac),
	ELEMENT(TLSEXT_TYPE_status_request),
	ELEMENT(TLSEXT_TYPE_user_mapping),
	ELEMENT(TLSEXT_TYPE_client_authz),
	ELEMENT(TLSEXT_TYPE_server_authz),
	ELEMENT(TLSEXT_TYPE_cert_type),
#ifdef TLSEXT_TYPE_supported_groups
	ELEMENT(TLSEXT_TYPE_supported_groups),
#endif
	ELEMENT(TLSEXT_TYPE_ec_point_formats),
#ifdef TLSEXT_TYPE_srp
	ELEMENT(TLSEXT_TYPE_srp),
#endif
	ELEMENT(TLSEXT_TYPE_signature_algorithms),
	ELEMENT(TLSEXT_TYPE_use_srtp),
	//ELEMENT(TLSEXT_TYPE_heartbeat),
	ELEMENT(TLSEXT_TYPE_application_layer_protocol_negotiation),
	ELEMENT(TLSEXT_TYPE_signed_certificate_timestamp),
	ELEMENT(TLSEXT_TYPE_padding),
	ELEMENT(TLSEXT_TYPE_encrypt_then_mac),
	ELEMENT(TLSEXT_TYPE_extended_master_secret),
	ELEMENT(TLSEXT_TYPE_session_ticket),
#ifdef TLSEXT_TYPE_key_share
	ELEMENT(TLSEXT_TYPE_key_share),
#endif
#ifdef TLSEXT_TYPE_psk
	ELEMENT(TLSEXT_TYPE_psk),
#endif
#ifdef TLSEXT_TYPE_early_data
	ELEMENT(TLSEXT_TYPE_early_data),
#endif
#ifdef TLSEXT_TYPE_supported_versions
	ELEMENT(TLSEXT_TYPE_supported_versions),
#endif
#ifdef TLSEXT_TYPE_cookie
	ELEMENT(TLSEXT_TYPE_cookie),
#endif
#ifdef TLSEXT_TYPE_psk_kex_modes
	ELEMENT(TLSEXT_TYPE_psk_kex_modes),
#endif
#ifdef TLSEXT_TYPE_certificate_authorities
	ELEMENT(TLSEXT_TYPE_certificate_authorities),
#endif
	ELEMENT(TLSEXT_TYPE_renegotiate),
#ifndef OPENSSL_NO_NEXTPROTONEG
	ELEMENT(TLSEXT_TYPE_next_proto_neg),
#endif
	{ 0 }
};

static struct lookup_table_element_t known_content_types[] = {
	ELEMENT(SSL3_RT_HANDSHAKE),
	ELEMENT(SSL3_RT_CHANGE_CIPHER_SPEC),
	ELEMENT(SSL3_RT_ALERT),
	ELEMENT(SSL3_RT_APPLICATION_DATA),
	{ 0 }
};

static const char *lookup(const struct lookup_table_element_t *table, int value) {
	while (table->symbol) {
		if (table->value == value) {
			return table->symbol;
		}
		table++;
	}
	return NULL;
}

static void msg_cb(int from_server, int version, int content_type, const void *vdata, size_t len, SSL *ssl, void *arg) {
	struct callback_ctx_t *ctx = (struct callback_ctx_t*)arg;
	const uint8_t *data = (const uint8_t*)vdata;

	if (ctx->debug) {
		const char *ctypename = lookup(known_content_types, content_type);
		log_memory(LLVL_TRACE, data, len, "TLS message from %s, version 0x%x, content type %d (%s) length %zu bytes: ", from_server ? "server" : "client", version, content_type, ctypename ? ctypename : "unknown", len);
	}

	if ((content_type != SSL3_RT_HANDSHAKE) || from_server) {
		/* We only care about handshake messages from the client */
		return;
	}

	uint8_t message = data[0];
	if (message == SSL3_MT_CLIENT_HELLO) {
		ctx->seen_client_hello = true;
	}
}

static void msg_tlsext(SSL *ssl, int from_server, int type, const unsigned char *data, int len, void *arg) {
	struct callback_ctx_t *ctx = (struct callback_ctx_t*)arg;

	if (ctx->debug) {
		const char *extname = lookup(known_extensions, type);
		log_memory(LLVL_TRACE, data, len, "TLS extension from %s, type 0x%x (%s) length %d bytes:", from_server ? "server" : "client", type, extname ? extname : "unknown", len);
	}

	if (from_server) {
		/* We only care about extensions from the client */
		return;
	}

	if ((type == TLSEXT_TYPE_server_name) && (len > 5)) {
		if ((data[0] == TLSEXT_NAMETYPE_host_name) && (2 + data[1] <= len)) {
			/* Server Name Indication in ClientHello specifying the host name */
			int hostname_len = data[1] - 3;
			logmsg(LLVL_TRACE, "Seen ClientHello TLS extension Server Name Indication (length of hostname %d bytes).", hostname_len);
			ctx->parse_result->server_name_indication = malloc(hostname_len + 1);
			if (!ctx->parse_result->server_name_indication) {
				logmsg(LLVL_FATAL, "Failed to allocate %d bytes for server_name_indication: %s", hostname_len + 1, strerror(errno));
			} else {
				memcpy(ctx->parse_result->server_name_indication, data + 5, hostname_len);
				ctx->parse_result->server_name_indication[hostname_len] = 0;
			}
		}
	} else if (type == TLSEXT_TYPE_status_request) {
		ctx->parse_result->present_extensions.status_request = true;
	} else if (type == TLSEXT_TYPE_encrypt_then_mac) {
		ctx->parse_result->present_extensions.encrypt_then_mac = true;
	} else if (type == TLSEXT_TYPE_extended_master_secret) {
		ctx->parse_result->present_extensions.extended_master_secret = true;
	} else if (type == TLSEXT_TYPE_session_ticket) {
		ctx->parse_result->present_extensions.session_ticket = true;
	}
}

bool parse_client_hello(struct chello_t *result, const uint8_t *data, int length) {
	memset(result, 0, sizeof(struct chello_t));

	SSL_CTX *sslctx = SSL_CTX_new(SSLv23_server_method());
	if (!sslctx) {
		logmsg(LLVL_ERROR, "Unable to create SSL_CTX structure when trying to parse ClientHello.");
		return false;
	}

	SSL *ssl = SSL_new(sslctx);
	if (!ssl) {
		SSL_CTX_free(sslctx);
		logmsg(LLVL_ERROR, "Unable to create SSL structure when trying to parse ClientHello.");
		return false;
	}

	BIO *s_to_c = BIO_new(BIO_s_mem());
	BIO *c_to_s = BIO_new(BIO_s_mem());
	BIO *s_bio = BIO_new(BIO_f_ssl());
	if (!s_to_c || !c_to_s || !s_bio) {
		SSL_free(ssl);
		SSL_CTX_free(sslctx);
		BIO_free_all(s_bio);
		BIO_free_all(c_to_s);
		BIO_free_all(s_to_c);
		logmsg(LLVL_ERROR, "Unable to create BIO structures when trying to parse ClientHello.");
		return false;
	}

	/* Set BIOs of TLS connection */
	SSL_set_accept_state(ssl);
	SSL_set_bio(ssl, c_to_s, s_to_c);
	BIO_set_ssl(s_bio, ssl, BIO_NOCLOSE);

	/* Setup the argument callback structure */
	struct callback_ctx_t cb_ctx = {
		.debug = loglevel_at_least(LLVL_TRACE),
		.parse_result = result,
	};

	/* Register callbacks */
	SSL_set_msg_callback(ssl, msg_cb);
	SSL_set_msg_callback_arg(ssl, &cb_ctx);
	SSL_set_tlsext_debug_callback(ssl, msg_tlsext);
	SSL_set_tlsext_debug_arg(ssl, &cb_ctx);

	/* Put client data into c_to_s BIO */
	BIO_write(c_to_s, data, length);

	/* Do a pseudo-read so that the handshake messages are parsed */
	uint8_t temp_buf[32];
	BIO_read(s_bio, temp_buf, sizeof(temp_buf));

	BIO_free_all(s_bio);
	SSL_free(ssl);
	SSL_CTX_free(sslctx);

	return cb_ctx.seen_client_hello;
}

void free_client_hello(struct chello_t *chello) {
	free(chello->server_name_indication);
	chello->server_name_indication = NULL;
}

static void errstack_free_client_hello(struct errstack_element_t *element) {
	free_client_hello((struct chello_t*)element->ptrvalue);
}

void errstack_push_client_hello(struct errstack_t *errstack, struct chello_t *element) {
	errstack_push_generic_nonnull_ptr(errstack, errstack_free_client_hello, element);
}

static unsigned int lookup_count(const struct lookup_table_element_t *table) {
	unsigned int count = 0;
	while (table->symbol) {
		count++;
		table++;
	}
	return count;
}

static void lookup_dump_wrap(const struct lookup_table_element_t *table, const char *indent) {
	bool first = true;
	int linelen = 0;
	while (table->symbol) {
		if (!first) {
			fprintf(stderr, ", ");
			linelen += 2;
		} else {
			fprintf(stderr, "%s", indent);
			linelen += strlen(indent);
			first = false;
		}
		if (linelen > 80) {
			fprintf(stderr, "\n%s", indent);
			linelen = strlen(indent);
		}
		linelen += fprintf(stderr, "%s", table->symbol);
		table++;
	}
	fprintf(stderr, "\n");
}

void client_hello_dump_options(void) {
	fprintf(stderr, "   %u client hello TLS extensions supported:\n", lookup_count(known_extensions));
	lookup_dump_wrap(known_extensions, "      ");
	fprintf(stderr, "   %u TLS content types supported:\n", lookup_count(known_content_types));
	lookup_dump_wrap(known_content_types, "      ");
#ifdef SSL_OP_NO_TLSv1_3
	const bool have_tls13 = true;
#else
	const bool have_tls13 = false;
#endif
	fprintf(stderr, "   TLSv1.3 support: %s\n", have_tls13 ? "Yes" : "No");
	fprintf(stderr, "   Compiled with: " OPENSSL_VERSION_TEXT "\n");
}
