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

#ifndef __ERRSTACK_H__
#define __ERRSTACK_H__

#include "atomic.h"
#include "openssl_clienthello.h"
#include <openssl/x509.h>
#include <openssl/ocsp.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

#define MAX_ERRSTACK_DEPTH	16

enum errstack_type_t {
	ERRSTACK_X509,
	ERRSTACK_EVP_PKEY,
	ERRSTACK_STACK_OF_X509,
	ERRSTACK_OCSP_BASICRESP,
	ERRSTACK_OCSP_CERTID,
	ERRSTACK_ASN1_TIME,
	ERRSTACK_BIGNUM,
	ERRSTACK_RSA,
	ERRSTACK_EC_KEY,
	ERRSTACK_FD,
	ERRSTACK_MALLOC,
	ERRSTACK_ATOMIC_DEC,
	ERRSTACK_CLIENT_HELLO,
};

struct errstack_element_t {
	enum errstack_type_t elementtype;
	union {
		void *ptrvalue;
		int intvalue;
	};
};

struct errstack_t {
	int count;
	struct errstack_element_t element[MAX_ERRSTACK_DEPTH];
};

/*************** AUTO GENERATED SECTION FOLLOWS ***************/
X509* errstack_add_X509(struct errstack_t *errstack, X509 *element);
EVP_PKEY* errstack_add_EVP_PKEY(struct errstack_t *errstack, EVP_PKEY *element);
STACK_OF(X509)* errstack_add_sk_X509(struct errstack_t *errstack, STACK_OF(X509) *element);
OCSP_BASICRESP* errstack_add_OCSP_BASICRESP(struct errstack_t *errstack, OCSP_BASICRESP *element);
OCSP_CERTID* errstack_add_OCSP_CERTID(struct errstack_t *errstack, OCSP_CERTID *element);
ASN1_TIME* errstack_add_ASN1_TIME(struct errstack_t *errstack, ASN1_TIME *element);
BIGNUM* errstack_add_BIGNUM(struct errstack_t *errstack, BIGNUM *element);
RSA* errstack_add_RSA(struct errstack_t *errstack, RSA *element);
EC_KEY* errstack_add_EC_KEY(struct errstack_t *errstack, EC_KEY *element);
void* errstack_add_malloc(struct errstack_t *errstack, void *element);
int errstack_add_fd(struct errstack_t *errstack, int fd);
void errstack_add_atomic_dec(struct errstack_t *errstack, struct atomic_t *element);
void errstack_add_clienthello(struct errstack_t *errstack, struct chello_t *element);
void errstack_reset(struct errstack_t *errstack);
void errstack_pop(struct errstack_t *errstack, int popcnt);
void *errstack_free_except(struct errstack_t *errstack, int keep_on_stack_cnt);
void *errstack_free(struct errstack_t *errstack);
/***************  AUTO GENERATED SECTION ENDS   ***************/

#endif
