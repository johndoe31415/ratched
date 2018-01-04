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

#ifndef __OPENSSL_H__
#define __OPENSSL_H__

#include "errstack.h"
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/ocsp.h>
#include <openssl/ssl.h>
#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER < 0x010100000
#error "Ratched requires at least OpenSSL v1.1 to work."
#endif

/*************** AUTO GENERATED SECTION FOLLOWS ***************/
void openssl_init(void);
void openssl_deinit(void);
X509* errstack_push_X509(struct errstack_t *errstack, X509 *element);
EVP_PKEY* errstack_push_EVP_PKEY(struct errstack_t *errstack, EVP_PKEY *element);
STACK_OF(X509)* errstack_push_sk_X509(struct errstack_t *errstack, STACK_OF(X509) *element);
OCSP_BASICRESP* errstack_push_OCSP_BASICRESP(struct errstack_t *errstack, OCSP_BASICRESP *element);
OCSP_CERTID* errstack_push_OCSP_CERTID(struct errstack_t *errstack, OCSP_CERTID *element);
ASN1_TIME* errstack_push_ASN1_TIME(struct errstack_t *errstack, ASN1_TIME *element);
BIGNUM* errstack_push_BIGNUM(struct errstack_t *errstack, BIGNUM *element);
RSA* errstack_push_RSA(struct errstack_t *errstack, RSA *element);
EC_KEY* errstack_push_EC_KEY(struct errstack_t *errstack, EC_KEY *element);
SSL* errstack_push_SSL(struct errstack_t *errstack, SSL *element);
/***************  AUTO GENERATED SECTION ENDS   ***************/

#endif
