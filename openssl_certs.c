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
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/x509v3.h>

#include "ipfwd.h"
#include "logging.h"
#include "openssl.h"
#include "openssl_certs.h"
#include "errstack.h"
#include "tools.h"

EVP_PKEY* openssl_create_key(const struct keyspec_t *keyspec) {
	struct errstack_t es = ERRSTACK_INIT;
	EVP_PKEY *pkey = errstack_push_EVP_PKEY(&es, EVP_PKEY_new());
	if (!pkey) {
		logmsgext(LLVL_ERROR, FLAG_OPENSSL_ERROR, "Allocating EVP_PKEY structure for %s failed.", keyspec->description);
		return errstack_pop_all(&es);
	}
	if (keyspec->cryptosystem == CRYPTOSYSTEM_RSA) {
		RSA *rsa = errstack_push_RSA(&es, RSA_new());
		if (!rsa) {
			logmsgext(LLVL_ERROR, FLAG_OPENSSL_ERROR, "Allocating RSA structure for %s failed.", keyspec->description);
			return errstack_pop_all(&es);
		}

		BIGNUM *e = errstack_push_BIGNUM(&es, BN_new());
		if (!e) {
			logmsgext(LLVL_ERROR, FLAG_OPENSSL_ERROR, "Allocation of 'e' during RSA key generation of %s failed.", keyspec->description);
			return errstack_pop_all(&es);
		}
		BN_set_word(e, 0x10001);
		if (!RSA_generate_key_ex(rsa, keyspec->rsa.bitlength, e, NULL)) {
			logmsgext(LLVL_ERROR, FLAG_OPENSSL_ERROR, "RSA key generation for %s failed.", keyspec->description);
			return errstack_pop_all(&es);
		}

		EVP_PKEY_set1_RSA(pkey, rsa);
	} else if (keyspec->cryptosystem == CRYPTOSYSTEM_ECC_FP) {
		int nid = 0;
		if (!strcmp(keyspec->ecc_fp.curve_name, "secp192r1")) {
            nid = NID_X9_62_prime192v1;
		} else if (!strcmp(keyspec->ecc_fp.curve_name, "secp256r1")) {
            nid = NID_X9_62_prime256v1;
		} else {
			nid = OBJ_sn2nid(keyspec->ecc_fp.curve_name);
			if (!nid) {
				 nid = EC_curve_nist2nid(keyspec->ecc_fp.curve_name);
			}
		}

		if (!nid) {
			logmsgext(LLVL_ERROR, FLAG_OPENSSL_ERROR, "ECC key creation of %s failed: no such curve '%s'", keyspec->description, keyspec->ecc_fp.curve_name);
			return errstack_pop_all(&es);
		}

		EC_KEY *eckey = errstack_push_EC_KEY(&es, EC_KEY_new_by_curve_name(nid));
		if (!eckey) {
			logmsgext(LLVL_ERROR, FLAG_OPENSSL_ERROR, "ECC key creation of %s failed.", keyspec->description);
			return errstack_pop_all(&es);
		}
		EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);

		if (!EC_KEY_generate_key(eckey)) {
			logmsgext(LLVL_ERROR, FLAG_OPENSSL_ERROR, "ECC key generation of %s failed.", keyspec->description);
			return errstack_pop_all(&es);
		}

		EVP_PKEY_set1_EC_KEY(pkey, eckey);
	} else {
		logmsg(LLVL_ERROR, "Unknown cryptosystem requested for key generation of %s: 0x%x", keyspec->description, keyspec->cryptosystem);
		return errstack_pop_all(&es);
	}

	errstack_pop_until(&es, 1);
	return pkey;
}

static void* load_private_key_callback(FILE *f) {
	return PEM_read_PrivateKey(f, NULL, NULL, NULL);
}

static void* load_x509_cert_callback(FILE *f) {
	return PEM_read_X509(f, NULL, NULL, NULL);
}

static void* load_x509_cert_chain_callback(FILE *f) {
	STACK_OF(X509) *stack = sk_X509_new_null();
	while (true) {
		X509 *cert = PEM_read_X509(f, NULL, NULL, NULL);
		if (!cert) {
			break;
		}
		sk_X509_push(stack, cert);
	}
	if (sk_X509_num(stack) == 0) {
		logmsg(LLVL_WARN, "No X.509 certificates found in certificate chain file.");
		sk_X509_free(stack);
		return NULL;
	}
	return stack;
}

static void* openssl_load_arbitrary(const char *typestr, const char *filename, const char *description, bool silent, void* (*load_cb)(FILE *f)) {
	FILE *f = fopen(filename, "r");
	if (!f) {
		if (!silent) {
			logmsg(LLVL_WARN, "Unable to open %s %s from %s: %s", description, typestr, filename, strerror(errno));
		}
		return NULL;
	}
	void *result = load_cb(f);
	if (!result) {
		if (!silent) {
			logmsgext(LLVL_WARN, FLAG_OPENSSL_ERROR, "Could open %s, but could not parse %s for %s inside.", filename, typestr, description);
			fclose(f);
			return NULL;
		}
	}
	fclose(f);
	return result;
}

EVP_PKEY *openssl_load_key(const char *filename, const char *description, bool silent) {
	return (EVP_PKEY*)openssl_load_arbitrary("private key", filename, description, silent, load_private_key_callback);
}

X509 *openssl_load_cert(const char *filename, const char *description, bool silent) {
	return (X509*)openssl_load_arbitrary("X.509 certificate", filename, description, silent, load_x509_cert_callback);
}

STACK_OF(X509) *openssl_load_cert_chain(const char *filename, const char *description, bool silent) {
	return (STACK_OF(X509)*)openssl_load_arbitrary("X.509 certificate chain", filename, description, silent, load_x509_cert_chain_callback);
}

static bool store_private_key_callback(FILE *f, void *arg) {
	return PEM_write_PrivateKey(f, (EVP_PKEY*)arg, NULL, NULL, 0, NULL, NULL);
}

static bool store_cert_callback(FILE *f, void *arg) {
	return PEM_write_X509(f, (X509*)arg);
}

static bool openssl_store_arbitrary(const char *typestr, const char *filename, const char *description, bool silent, bool (*store_cb)(FILE *f, void *arg), void *arg) {
	FILE *f = fopen(filename, "w");
	if (!f) {
		if (!silent) {
			logmsg(LLVL_WARN, "Unable to open %s for writing of %s %s: %s", filename, description, typestr, strerror(errno));
		}
		return false;
	}

	if (!store_cb(f, arg)) {
		if (!silent) {
			logmsgext(LLVL_WARN, FLAG_OPENSSL_ERROR, "Unable to write %s %s into %s.", description, typestr, filename);
			fclose(f);
			return false;
		}
	}
	fclose(f);
	return true;
}

bool openssl_store_key(const char *filename, const char *description, bool silent, EVP_PKEY *key) {
	return openssl_store_arbitrary("private key", filename, description, silent, store_private_key_callback, key);
}

bool openssl_store_cert(const char *filename, const char *description, bool silent, X509 *cert) {
	return openssl_store_arbitrary("X.509 certificate", filename, description, silent, store_cert_callback, cert);
}

EVP_PKEY* openssl_load_stored_key(const struct keyspec_t *keyspec, const char *filename) {
	EVP_PKEY *privkey = openssl_load_key(filename, keyspec->description, false);
	if (privkey) {
		return privkey;
	}

	/* Key either not present or couldn't be parsed. Create a new one. */
	logmsg(LLVL_INFO, "Creating new %s private key.", keyspec->description);
	privkey = openssl_create_key(keyspec);
	if (privkey) {
		/* Persist this key */
		openssl_store_key(filename, keyspec->description, false, privkey);
	}
	return privkey;
}

static void add_name_field(X509_NAME *name, const char *key, const char *value) {
	X509_NAME_add_entry_by_txt(name, key, MBSTRING_ASC, (const unsigned char*)value, -1, -1, 0);
}

static bool add_extension_raw(X509 *cert, bool critical, int nid, const uint8_t *data, const unsigned int data_length) {
	ASN1_OCTET_STRING *octet_string = ASN1_OCTET_STRING_new();
	if (!octet_string) {
		logmsgext(LLVL_ERROR, FLAG_OPENSSL_ERROR, "Creation of octet string failed.");
		return false;
	}
	ASN1_OCTET_STRING_set(octet_string, data, data_length);

	X509_EXTENSION *extension = X509_EXTENSION_create_by_NID(NULL, nid, critical ? 1 : 0, octet_string);
	if (!extension) {
		logmsgext(LLVL_ERROR, FLAG_OPENSSL_ERROR, "Creation of raw X.509 extension with NID 0x%x failed.", nid);
		ASN1_OCTET_STRING_free(octet_string);
		return false;
	}

	/* Add extension to the end */
	X509_add_ext(cert, extension, -1);

	/* Free data */
	X509_EXTENSION_free(extension);
	ASN1_OCTET_STRING_free(octet_string);
	return true;
}

bool add_extension_rawstr(X509 *cert, bool critical, int nid, const char *text) {
	return add_extension_raw(cert, critical, nid, (const uint8_t*)text, strlen(text));
}

static bool add_extension_conf(X509 *cert, X509 *issuer_cert, int nid, const char *text) {
	X509V3_CTX ctx;
	X509V3_set_ctx_nodb(&ctx);
	X509V3_set_ctx(&ctx, issuer_cert, cert, NULL, NULL, 0);

	X509_EXTENSION *extension = X509V3_EXT_nconf_nid(NULL, &ctx, nid, (char*)text);
	if (!extension) {
		logmsgext(LLVL_ERROR, FLAG_OPENSSL_ERROR, "Creation of X.509 extension with NID 0x%x from config failed.", nid);
		return false;
	}

	X509_add_ext(cert, extension, -1);
	X509_EXTENSION_free(extension);
	return true;
}

X509* openssl_create_certificate(const struct certificatespec_t *spec) {
	if (!spec->subject_pubkey) {
		logmsg(LLVL_ERROR, "Cannot create certificate without a given public key.");
		return NULL;
	}

	/* Create a X.509 v3 certificate */
	X509 *cert = X509_new();
	X509_set_version(cert, 2);

	/* Randomize serial number */
	BIGNUM *serial = BN_new();
	if (!serial) {
		logmsgext(LLVL_ERROR, FLAG_OPENSSL_ERROR, "Error creating serial number BIGNUM.");
		X509_free(cert);
	}
	BN_rand(serial, 128, -1, 0);
	BN_to_ASN1_INTEGER(serial, X509_get_serialNumber(cert));
	BN_free(serial);

	/* Set lifetime */
	X509_gmtime_adj(X509_get_notBefore(cert), -spec->validity_predate_seconds);
	X509_gmtime_adj(X509_get_notAfter(cert), spec->validity_seconds);

	/* Set public key */
	X509_set_pubkey(cert, spec->subject_pubkey);

	/* Set subject */
	X509_NAME *subject = X509_get_subject_name(cert);
	if (spec->common_name) {
		add_name_field(subject, "CN", spec->common_name);
	}
	if (spec->mark_certificate) {
		add_name_field(subject, "OU", "ratched");
	}

	/* If self-signed, set issuer name to subject name */
	if (!spec->issuer_certificate) {
		X509_set_issuer_name(cert, subject);
	} else {
		X509_set_issuer_name(cert, X509_get_subject_name(spec->issuer_certificate));
	}

	bool success = true;
	X509 *issuer_cert = spec->issuer_certificate ? spec->issuer_certificate : cert;
	if (spec->is_ca_certificate) {
		success = success && add_extension_conf(cert, issuer_cert, NID_basic_constraints, "critical,CA:TRUE");
	} else {
		success = success && add_extension_conf(cert, issuer_cert, NID_basic_constraints, "critical,CA:FALSE");
	}
	success = success && add_extension_conf(cert, issuer_cert, NID_subject_key_identifier, "hash");
	success = success && add_extension_conf(cert, issuer_cert, NID_authority_key_identifier, spec->full_authority_keyid ? "keyid,issuer:always" : "keyid");
	success = success && add_extension_conf(cert, issuer_cert, NID_key_usage, "digitalSignature,keyEncipherment,keyAgreement");
	if (spec->subject_alternative_dns_hostname && spec->subject_alternative_ipv4_address) {
		/* IPv4 and hostname specified */
		char configline[256];
		snprintf(configline, sizeof(configline), "DNS:%s,IP:" PRI_IPv4, spec->subject_alternative_dns_hostname, FMT_IPv4(spec->subject_alternative_ipv4_address));
		success = success && add_extension_conf(cert, issuer_cert, NID_subject_alt_name, configline);
	} else if (spec->subject_alternative_dns_hostname) {
		/* Only hostname specified */
		char configline[256];
		snprintf(configline, sizeof(configline), "DNS:%s", spec->subject_alternative_dns_hostname);
		success = success && add_extension_conf(cert, issuer_cert, NID_subject_alt_name, configline);
	} else if (spec->subject_alternative_ipv4_address) {
		/* Only IPv4 specified */
		char configline[256];
		snprintf(configline, sizeof(configline), "IP:" PRI_IPv4, FMT_IPv4(spec->subject_alternative_ipv4_address));
		success = success && add_extension_conf(cert, issuer_cert, NID_subject_alt_name, configline);
	}
	if (spec->crl_uri) {
		char configline[256];
		snprintf(configline, sizeof(configline), "URI:%s", spec->crl_uri);
		success = success && add_extension_conf(cert, issuer_cert, NID_crl_distribution_points, configline);
	}
	if (spec->ocsp_responder_uri) {
		char configline[256];
		snprintf(configline, sizeof(configline), "OCSP;URI:%s", spec->ocsp_responder_uri);
		success = success && add_extension_conf(cert, issuer_cert, NID_info_access, configline);
	}

	if (!success) {
		logmsg(LLVL_ERROR, "Adding of at least one X.509 extension failed.");
		X509_free(cert);
		return NULL;
	}

	if (!X509_sign(cert, spec->issuer_privkey, EVP_sha256())) {
		logmsgext(LLVL_ERROR, FLAG_OPENSSL_ERROR, "Signing of certificate \"%s\" failed.", spec->description);
		X509_free(cert);
		return NULL;
	}
	return cert;
}

static bool is_certificate_expired(X509 *cert) {
	return X509_cmp_current_time(X509_get_notAfter(cert)) <= 0;
}

X509* openssl_load_stored_certificate(const struct certificatespec_t *certspec, const char *filename, bool recreate_when_expired, bool recreate_when_key_mismatch) {
	X509 *cert = openssl_load_cert(filename, certspec->description, false);
	if (cert) {
		return cert;
	}

	/* Validate certificate lifetime */
	if (cert && recreate_when_expired) {
		if (recreate_when_expired) {
			if (is_certificate_expired(cert)) {
				logmsg(LLVL_WARN, "%s certificate has expired, recreating.", certspec->description);
				X509_free(cert);
				cert = NULL;
			}
		}
	}

	/* Validate certificate key */
	if (cert && recreate_when_key_mismatch) {
		EVP_PKEY *cert_pubkey = X509_get_pubkey(cert);
		if (!EVP_PKEY_cmp(cert_pubkey, certspec->subject_pubkey)) {
			logmsg(LLVL_WARN, "%s certificate public key does not match private key, recreating.", certspec->description);
			X509_free(cert);
			cert = NULL;
		}
		EVP_PKEY_free(cert_pubkey);
	}

	if (!cert) {
		logmsg(LLVL_INFO, "Creating new %s certificate.", certspec->description);
		/* Recreate certificate */
		cert = openssl_create_certificate(certspec);
		if (cert) {
			/* Persist newly created certificate */
			openssl_store_cert(filename, certspec->description, false, cert);
		} else {
			logmsg(LLVL_ERROR, "%s certificate generation failed.", certspec->description);
		}
	}

	return cert;
}

static void remove_x509_extension(X509 *certificate, int nid) {
	int index = X509_get_ext_by_NID(certificate, NID_subject_key_identifier, -1);
	if (index != -1) {
		X509_EXTENSION *extension = X509_get_ext(certificate, index);
		if (extension) {
			X509_delete_ext(certificate, index);
			X509_EXTENSION_free(extension);
		}
	}
}

static void remove_keyid_extensions(X509 *certificate) {
	remove_x509_extension(certificate, NID_subject_key_identifier);
	remove_x509_extension(certificate, NID_authority_key_identifier);
}

X509 *forge_client_certificate(X509 *original_client_cert, EVP_PKEY *new_subject_pubkey, X509 *new_issuer_cert, EVP_PKEY *new_issuer_privkey, bool recalculate_key_identifiers, bool mark_certificate) {
	X509 *forgery = X509_dup(original_client_cert);
	X509_set_pubkey(forgery, new_subject_pubkey);
	if (recalculate_key_identifiers) {
		remove_keyid_extensions(forgery);
		add_extension_conf(forgery, new_issuer_cert ? new_issuer_cert : forgery, NID_subject_key_identifier, "hash");
		add_extension_conf(forgery, new_issuer_cert ? new_issuer_cert : forgery, NID_authority_key_identifier, "keyid");
	}
	if (mark_certificate) {
		X509_NAME *subject = X509_get_subject_name(forgery);
		add_name_field(subject, "OU", "ratched");
	}
	X509_sign(forgery, new_issuer_privkey, EVP_sha256());
	return forgery;
}

void dump_tls_endpoint_config(char *text, int text_maxlen, const struct tls_endpoint_config_t *config) {
	if (text_maxlen == 0) {
		return;
	}
	char *buf = text;
	buf = spnprintf(buf, &text_maxlen, "[%1s%1s", config->cert ? "C" : "", config->key ? "K" : "");
	if (config->chain && sk_X509_num(config->chain)) {
		buf = spnprintf(buf, &text_maxlen, "~%d", sk_X509_num(config->chain));
	}
	buf = spnprintf(buf, &text_maxlen, "], CA [%1s%1s], ", config->certificate_authority.cert ? "C" : "", config->certificate_authority.key ? "K" : "");
	buf = spnprintf(buf, &text_maxlen, "Req=%d CS=%d SG=%d", config->request_cert_from_peer ? 1 : 0, config->ciphersuites ? 1 : 0, config->supported_groups ? 1 : 0);
}

bool init_tls_endpoint_config(struct tls_endpoint_config_t *config, const char *description, const struct tls_endpoint_cert_source_t *certsrc) {
	if (certsrc->cert_filename) {
		config->cert = openssl_load_cert(certsrc->cert_filename, description, false);
		if (!config->cert) {
			return false;
		}
	}
	if (certsrc->key_filename) {
		config->key = openssl_load_key(certsrc->key_filename, description, false);
		if (!config->key) {
			return false;
		}
	}
	if (certsrc->chain_filename) {
		config->chain = openssl_load_cert_chain(certsrc->chain_filename, description, false);
		if (!config->chain) {
			return false;
		}
	}
	return true;
}

void free_tls_endpoint_config(struct tls_endpoint_config_t *config) {
	X509_free(config->cert);
	EVP_PKEY_free(config->key);
	sk_X509_pop_free(config->chain, X509_free);
	X509_free(config->certificate_authority.cert);
	EVP_PKEY_free(config->certificate_authority.key);
	X509_free(config->ocsp_responder.cert);
	EVP_PKEY_free(config->ocsp_responder.key);
	config->cert = NULL;
	config->key = NULL;
	config->chain = NULL;
}
