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

#include <stdbool.h>
#include <string.h>
#include <openssl/ssl.h>
#include "logging.h"
#include "openssl.h"
#include "openssl_tls.h"
#include "ocsp_response.h"
#include "intercept_config.h"

static long biocb(struct bio_st *bio, int oper, const char *argp, int len, long argi, long argl) {
//	fprintf(stderr, "BIO %p: oper 0x%x argp %p len %d i/l %ld %ld\n", bio, oper, argp, len, argi, argl);
	if (oper == BIO_CB_READ) {
		/* Before read, determine: can we serve the requested data? */
		if (BIO_pending(bio)) {
			/* Still have data in memory bio to serve directly */
			return argl;
		} else {
			/* Not enough data anymore, read from subsequent BIO and push into
			 * this one */
			BIO *subsequent = (BIO*)BIO_get_callback_arg(bio);
			uint8_t data[len];
			long subsequent_data_length = BIO_read(subsequent, data, len);
			if (subsequent_data_length > 0) {
				BIO_write(bio, data, subsequent_data_length);
			}
		}
	} else if (oper == BIO_CB_FREE) {
		/* Also close subsequent BIO */
		BIO *subsequent = (BIO*)BIO_get_callback_arg(bio);
		BIO_free_all(subsequent);
	}
	return argl;
}

static int cert_verify_callback(X509_STORE_CTX *x509_store_ctx, void *arg) {
	struct tls_connection_t *result = (struct tls_connection_t*)arg;
	STACK_OF(X509) *sk = X509_STORE_CTX_get0_untrusted(x509_store_ctx);
	result->peer_certificate = X509_STORE_CTX_get0_cert(x509_store_ctx);
	logmsg(LLVL_DEBUG, "Client certificate callback: %d certificates sent by client.", sk_X509_num(sk));

	for (int i = 0; i < sk_X509_num(sk); i++) {
		char text[128];
		snprintf(text, sizeof(text), "Client certificate %d of %d", i + 1, sk_X509_num(sk));
		X509 *cert = sk_X509_value(sk, i);
		log_cert(LLVL_TRACE, cert, text);
	}

	return 1;
}

static int ocsp_status_request_callback(SSL *ssl, void *arg) {
	struct tls_endpoint_config_t *config = (struct tls_endpoint_config_t*)arg;
	if (config->ocsp_responder.cert && config->ocsp_responder.key) {
		OCSP_RESPONSE *response = create_ocsp_response(config->cert, config->ocsp_responder.cert, config->ocsp_responder.key);
		if (response) {
			uint8_t *serialized_ticket;
			int serialized_ticket_length;
			if (serialize_ocsp_response(response, &serialized_ticket, &serialized_ticket_length)) {
				/* Ticket is cleaned up by SSL_free */
				SSL_set_tlsext_status_ocsp_resp(ssl, serialized_ticket, serialized_ticket_length);
			} else {
				logmsg(LLVL_ERROR, "Failed to serialize OCSP ticket, not adding to SSL connection.");
			}
			OCSP_RESPONSE_free(response);
		} else {
			logmsg(LLVL_DEBUG, "Received status request by client, but could not fake OCSP response.");
		}
	} else {
		logmsg(LLVL_DEBUG, "Received status request by client, but no OCSP CA registered in connection.");
	}
	return 0;
}

static void openssl_map_options(uint32_t tls_versions, long *clear_opts, long *set_opts) {
	*((tls_versions & TLS_VERSION_SSL2) ? clear_opts : set_opts) |= SSL_OP_NO_SSLv2;
	*((tls_versions & TLS_VERSION_SSL3) ? clear_opts : set_opts) |= SSL_OP_NO_SSLv3;
	*((tls_versions & TLS_VERSION_TLS10) ? clear_opts : set_opts) |= SSL_OP_NO_TLSv1;
	*((tls_versions & TLS_VERSION_TLS11) ? clear_opts : set_opts) |= SSL_OP_NO_TLSv1_1;
	*((tls_versions & TLS_VERSION_TLS12) ? clear_opts : set_opts) |= SSL_OP_NO_TLSv1_2;
	*((tls_versions & TLS_VERSION_TLS13) ? clear_opts : set_opts) |= SSL_OP_NO_TLSv1_3;
}

struct tls_connection_t openssl_tls_connect(const struct tls_connection_request_t *request) {
	struct tls_connection_t result;
	memset(&result, 0, sizeof(result));

	const SSL_METHOD *method = SSLv23_method();
	if (!method) {
		logmsgext(LLVL_ERROR, FLAG_OPENSSL_ERROR, "openssl_tls %s: Cannot get SSLv23_method()", request->is_server ? "server" : "client");
		return result;
	}


	SSL_CTX *sslctx = SSL_CTX_new(method);
	if (!sslctx) {
		logmsgext(LLVL_ERROR, FLAG_OPENSSL_ERROR, "openssl_tls %s: SSL_CTX_new() failed.", request->is_server ? "server" : "client");
		return result;
	}

	if (request->config) {
		long clear_options = 0;
		long set_options = 0;
		openssl_map_options(request->config->tls_versions, &clear_options, &set_options);
		SSL_CTX_set_options(sslctx, set_options);
		long result_options = SSL_CTX_clear_options(sslctx, clear_options);
		logmsg(LLVL_TRACE, "OpenSSL versions 0x%x, setting flags 0x%lx, clearing flags 0x%lx. Final value 0x%lx", request->config->tls_versions, set_options, clear_options, result_options);
	}

	/* Set verification callback for client certificates */
	if (request->config && request->config->request_cert_from_peer) {
		SSL_CTX_set_verify(sslctx, SSL_VERIFY_PEER, NULL);
		SSL_CTX_set_cert_verify_callback(sslctx, cert_verify_callback, &result);
	}
	if (!SSL_CTX_set_ecdh_auto(sslctx, 1)) {
		logmsgext(LLVL_ERROR, FLAG_OPENSSL_ERROR, "openssl_tls %s: SSL_CTX_set_ecdh_auto() failed.", request->is_server ? "server" : "client");
		SSL_CTX_free(sslctx);
		return result;
	}

	if (request->config && request->config->cert) {
		if (SSL_CTX_use_certificate(sslctx, request->config->cert) != 1) {
			logmsgext(LLVL_ERROR, FLAG_OPENSSL_ERROR, "openssl_tls %s: SSL_CTX_use_certificate() failed.", request->is_server ? "server" : "client");
			SSL_CTX_free(sslctx);
			return result;
		}
	}
	if (request->config && request->config->key) {
		if (SSL_CTX_use_PrivateKey(sslctx, request->config->key) != 1) {
			logmsgext(LLVL_ERROR, FLAG_OPENSSL_ERROR, "openssl_tls %s: SSL_CTX_use_PrivateKey() failed.", request->is_server ? "server" : "client");
			SSL_CTX_free(sslctx);
			return result;
		}
	}
	if (request->config && request->config->chain) {
		if (!SSL_CTX_set0_chain(sslctx, request->config->chain)) {
			logmsgext(LLVL_ERROR, FLAG_OPENSSL_ERROR, "openssl_tls %s: SSL_CTX_set0_chain() failed.", request->is_server ? "server" : "client");
			SSL_CTX_free(sslctx);
			return result;
		}
	}

	if (request->config && request->config->ciphersuites) {
		if (!SSL_CTX_set_cipher_list(sslctx, request->config->ciphersuites)) {
			logmsgext(LLVL_ERROR, FLAG_OPENSSL_ERROR, "openssl_tls %s: SSL_CTX_set_cipher_list(%s) failed.", request->is_server ? "server" : "client", request->config->ciphersuites);
			SSL_CTX_free(sslctx);
			return result;
		}
	}

	if (request->config && request->config->supported_groups) {
		if (!SSL_CTX_set1_curves_list(sslctx, request->config->supported_groups)) {
			logmsgext(LLVL_ERROR, FLAG_OPENSSL_ERROR, "openssl_tls %s: SSL_CTX_set1_curves_list(%s) failed.", request->is_server ? "server" : "client", request->config->supported_groups);
			SSL_CTX_free(sslctx);
			return result;
		}
	}

	if (request->config && request->config->signature_algorithms) {
		if (!SSL_CTX_set1_sigalgs_list(sslctx, request->config->signature_algorithms)) {
			logmsgext(LLVL_ERROR, FLAG_OPENSSL_ERROR, "openssl_tls %s: SSL_CTX_set1_sigalgs_list(%s) failed.", request->is_server ? "server" : "client", request->config->signature_algorithms);
			SSL_CTX_free(sslctx);
			return result;
		}
	}

	/* If a server, set a status request callback as well */
	if (request->is_server) {
		if (!SSL_CTX_set_tlsext_status_cb(sslctx, ocsp_status_request_callback)) {
			logmsgext(LLVL_ERROR, FLAG_OPENSSL_ERROR, "openssl_tls %s: SSL_CTX_set_tlsext_status_cb() failed.", request->is_server ? "server" : "client");
			SSL_CTX_free(sslctx);
			return result;
		}
		if (!SSL_CTX_set_tlsext_status_arg(sslctx, request->config)) {
			logmsgext(LLVL_ERROR, FLAG_OPENSSL_ERROR, "openssl_tls %s: SSL_CTX_set_tlsext_status_arg() failed.", request->is_server ? "server" : "client");
			SSL_CTX_free(sslctx);
			return result;
		}
	}

	result.ssl = SSL_new(sslctx);
	if (!result.ssl) {
		logmsgext(LLVL_ERROR, FLAG_OPENSSL_ERROR, "openssl_tls %s: SSL_new() failed.", request->is_server ? "server" : "client");
		SSL_CTX_free(sslctx);
		return result;
	}
	if (request->server_name_indication) {
		if (!SSL_set_tlsext_host_name(result.ssl, request->server_name_indication)) {
			logmsgext(LLVL_ERROR, FLAG_OPENSSL_ERROR, "openssl_tls %s: SSL_set_tlsext_host_name() failed to set hostname to %s", request->is_server ? "server" : "client", request->server_name_indication);
			SSL_CTX_free(sslctx);
			return result;
		}
	}

	if (request->initial_peer_data_length) {
		/* Forwarding of preliminary data requested, do some buffer dance */
		BIO *preliminary_data_bio = BIO_new(BIO_s_mem());
		int bytes_written = BIO_write(preliminary_data_bio, request->initial_peer_data, request->initial_peer_data_length);
		if (bytes_written != request->initial_peer_data_length) {
			logmsgext(LLVL_WARN, FLAG_OPENSSL_ERROR, "openssl_tls %s: BIO_write() wrote %d bytes of initial data when %d would have been expected.", request->is_server ? "server" : "client", bytes_written, request->initial_peer_data_length);
		}

		BIO *subsequent_data_bio = BIO_new_fd(request->peer_fd, 0);
		BIO_set_callback(preliminary_data_bio, biocb);
		BIO_set_callback_arg(preliminary_data_bio, (char*)subsequent_data_bio);

		BIO *write_bio = BIO_new_fd(request->peer_fd, 0);
		SSL_set_bio(result.ssl, preliminary_data_bio, write_bio);
	} else {
		/* Plain and simple: Directly connect the file descriptor to the SSL
		 * channel */
		SSL_set_fd(result.ssl, request->peer_fd);
	}
	SSL_CTX_free(sslctx);

	if (request->is_server) {
		if (SSL_accept(result.ssl) != 1) {
			logmsgext(LLVL_ERROR, FLAG_OPENSSL_ERROR, "openssl_tls %s: Cannot establish a TLS connection acting as server at FD %d", request->is_server ? "server" : "client", request->peer_fd);
			SSL_free(result.ssl);
			result.ssl = NULL;
			return result;
		}
	} else {
		if (SSL_connect(result.ssl) != 1) {
			logmsgext(LLVL_ERROR, FLAG_OPENSSL_ERROR, "openssl_tls %s: Cannot establish a TLS connection to %s acting as client at FD %d", request->is_server ? "server" : "client", request->server_name_indication, request->peer_fd);
			SSL_free(result.ssl);
			result.ssl = NULL;
			return result;
		}
	}
	return result;
}
