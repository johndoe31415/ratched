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

#include <openssl/ocsp.h>
#include "ocsp_response.h"
#include "logging.h"
#include "errstack.h"

OCSP_RESPONSE *create_ocsp_response(X509 *subject_crt, X509 *issuer_crt, EVP_PKEY *issuer_key) {
	struct errstack_t es = { 0 };
	OCSP_BASICRESP *basic_resp = errstack_add_OCSP_BASICRESP(&es, OCSP_BASICRESP_new());
	if (!basic_resp) {
		logmsgext(LLVL_ERROR, FLAG_OPENSSL_ERROR, "Unable to create OCSP basic response.");
		return errstack_free(&es);
	}

	time_t now = time(NULL);
	ASN1_TIME *thisupd = errstack_add_ASN1_TIME(&es, ASN1_TIME_adj(NULL, now, 0, -(3600 * 3)));
	if (!thisupd) {
		logmsgext(LLVL_ERROR, FLAG_OPENSSL_ERROR, "Unable to create OCSP thisupd timestamp.");
		return errstack_free(&es);
	}

	ASN1_TIME *nextupd = errstack_add_ASN1_TIME(&es, ASN1_TIME_adj(NULL, now, 14, 0));
	if (!thisupd) {
		logmsgext(LLVL_ERROR, FLAG_OPENSSL_ERROR, "Unable to create OCSP nextupd timestamp.");
		return errstack_free(&es);
	}

	const EVP_MD *keyid_hash = EVP_sha1();
	if (!keyid_hash) {
		logmsgext(LLVL_ERROR, FLAG_OPENSSL_ERROR, "Unable to get SHA-1 for hashing of key IDs.");
		return errstack_free(&es);
	}

	OCSP_CERTID *cid = errstack_add_OCSP_CERTID(&es, OCSP_cert_to_id(keyid_hash, subject_crt, issuer_crt));
	if (!cid) {
		logmsgext(LLVL_ERROR, FLAG_OPENSSL_ERROR, "Unable to get OCSP certificate ID.");
		return errstack_free(&es);
	}

	OCSP_basic_add1_status(basic_resp, cid, V_OCSP_CERTSTATUS_GOOD, OCSP_RESPONSE_STATUS_SUCCESSFUL, NULL, thisupd, nextupd);
	errstack_free_except(&es, 1);

	const EVP_MD *signing_hash = EVP_sha256();
	long flags = OCSP_NOCERTS | OCSP_RESPID_KEY;
	if (!OCSP_basic_sign(basic_resp, issuer_crt, issuer_key, signing_hash, NULL, flags)) {
		logmsgext(LLVL_ERROR, FLAG_OPENSSL_ERROR, "Signing of OCSP request failed.");
		return errstack_free(&es);
	}

	OCSP_RESPONSE *response = OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, basic_resp);
	if (!response) {
		logmsgext(LLVL_ERROR, FLAG_OPENSSL_ERROR, "Unable to create OCSP response.");
		return errstack_free(&es);
	}
	OCSP_BASICRESP_free(basic_resp);

	return response;
}

bool serialize_ocsp_response(OCSP_RESPONSE *ocsp_response, uint8_t **data, int *length) {
	*data = NULL;
	*length = 0;

	BIO* ocsp_bio = BIO_new(BIO_s_mem());
	if (!ocsp_bio) {
		logmsgext(LLVL_ERROR, FLAG_OPENSSL_ERROR, "Failed to create OCSP serialization BIO.");
		return false;
	}

	i2d_OCSP_RESPONSE_bio(ocsp_bio, ocsp_response);
	int pending_length = BIO_pending(ocsp_bio);
	if (pending_length <= 0) {
		logmsgext(LLVL_ERROR, FLAG_OPENSSL_ERROR, "OCSP serialization failed, returned %d bytes length.", pending_length);
		BIO_free(ocsp_bio);
		return false;
	}

	uint8_t *response_data = OPENSSL_malloc(pending_length);
	if (!response_data) {
		logmsgext(LLVL_ERROR, FLAG_OPENSSL_ERROR, "Allocation of %d bytes for OCSP response failed.", pending_length);
		BIO_free(ocsp_bio);
		return false;
	}

	int response_len = BIO_read(ocsp_bio, response_data, pending_length);
	if (response_len != pending_length) {
		logmsgext(LLVL_ERROR, FLAG_OPENSSL_ERROR, "Expected %d bytes in OCSP response, but only read %d from BIO.", pending_length, response_len);
		OPENSSL_free(response_data);
		BIO_free(ocsp_bio);
		return false;
	}

	BIO_free(ocsp_bio);

	log_memory(LLVL_TRACE, response_data, response_len, "Serialized positive OCSP response (%d bytes).", response_len);
	*data = response_data;
	*length = response_len;
	return true;
}
