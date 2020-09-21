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

#include <openssl/ssl.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

#include "openssl.h"
#include "errstack.h"

void openssl_init(void) {
}

void openssl_deinit(void) {
}

static void errstack_free_X509(struct errstack_element_t *element) {
	X509_free((X509*)element->ptrvalue);
}

X509* errstack_push_X509(struct errstack_t *errstack, X509 *element) {
	return (X509*)errstack_push_generic_nonnull_ptr(errstack, errstack_free_X509, element);
}

static void errstack_free_EVP_PKEY(struct errstack_element_t *element) {
	EVP_PKEY_free((EVP_PKEY*)element->ptrvalue);
}

EVP_PKEY* errstack_push_EVP_PKEY(struct errstack_t *errstack, EVP_PKEY *element) {
	return (EVP_PKEY*)errstack_push_generic_nonnull_ptr(errstack, errstack_free_EVP_PKEY, element);
}
static void errstack_free_sk_X509(struct errstack_element_t *element) {
	sk_X509_pop_free((STACK_OF(X509)*)element->ptrvalue, X509_free);
}

STACK_OF(X509)* errstack_push_sk_X509(struct errstack_t *errstack, STACK_OF(X509) *element) {
	return (STACK_OF(X509)*)errstack_push_generic_nonnull_ptr(errstack, errstack_free_sk_X509, element);
}

static void errstack_free_OCSP_BASICRESP(struct errstack_element_t *element) {
	OCSP_BASICRESP_free((OCSP_BASICRESP*)element->ptrvalue);
}

OCSP_BASICRESP* errstack_push_OCSP_BASICRESP(struct errstack_t *errstack, OCSP_BASICRESP *element) {
	return (OCSP_BASICRESP*)errstack_push_generic_nonnull_ptr(errstack, errstack_free_OCSP_BASICRESP, element);
}

static void errstack_free_OCSP_CERTID(struct errstack_element_t *element) {
	OCSP_CERTID_free((OCSP_CERTID*)element->ptrvalue);
}

OCSP_CERTID* errstack_push_OCSP_CERTID(struct errstack_t *errstack, OCSP_CERTID *element) {
	return (OCSP_CERTID*)errstack_push_generic_nonnull_ptr(errstack, errstack_free_OCSP_CERTID, element);
}

static void errstack_free_ASN1_TIME(struct errstack_element_t *element) {
	ASN1_TIME_free((ASN1_TIME*)element->ptrvalue);
}

ASN1_TIME* errstack_push_ASN1_TIME(struct errstack_t *errstack, ASN1_TIME *element) {
	return (ASN1_TIME*)errstack_push_generic_nonnull_ptr(errstack, errstack_free_ASN1_TIME, element);
}

static void errstack_free_BIGNUM(struct errstack_element_t *element) {
	BN_free((BIGNUM*)element->ptrvalue);
}

BIGNUM* errstack_push_BIGNUM(struct errstack_t *errstack, BIGNUM *element) {
	return (BIGNUM*)errstack_push_generic_nonnull_ptr(errstack, errstack_free_BIGNUM, element);
}

static void errstack_free_RSA(struct errstack_element_t *element) {
	RSA_free((RSA*)element->ptrvalue);
}

RSA* errstack_push_RSA(struct errstack_t *errstack, RSA *element) {
	return (RSA*)errstack_push_generic_nonnull_ptr(errstack, errstack_free_RSA, element);
}

static void errstack_free_EC_KEY(struct errstack_element_t *element) {
	EC_KEY_free((EC_KEY*)element->ptrvalue);
}

EC_KEY* errstack_push_EC_KEY(struct errstack_t *errstack, EC_KEY *element) {
	return (EC_KEY*)errstack_push_generic_nonnull_ptr(errstack, errstack_free_EC_KEY, element);
}

static void errstack_free_SSL(struct errstack_element_t *element) {
	SSL_free((SSL*)element->ptrvalue);
}

SSL* errstack_push_SSL(struct errstack_t *errstack, SSL *element) {
	return (SSL*)errstack_push_generic_nonnull_ptr(errstack, errstack_free_SSL, element);
}
