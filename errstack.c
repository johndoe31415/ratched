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

#include <unistd.h>
#include <openssl/x509.h>
#include <openssl/ocsp.h>

#include "atomic.h"
#include "errstack.h"
#include "logging.h"

static void* errstack_add_generic_ptr(struct errstack_t *errstack, enum errstack_type_t elementtype, void *element) {
	if (!element) {
		return NULL;
	}

	if (errstack->count >= MAX_ERRSTACK_DEPTH) {
		logmsg(LLVL_FATAL, "Error stack capacity exceeded (%d elements). Might leak memory.", errstack->count);
		return element;
	}
	errstack->element[errstack->count].ptrvalue = element;
	errstack->element[errstack->count].elementtype = elementtype;
	errstack->count++;
	return element;
}

static int errstack_add_int(struct errstack_t *errstack, enum errstack_type_t elementtype, int element) {
	if (errstack->count >= MAX_ERRSTACK_DEPTH) {
		logmsg(LLVL_FATAL, "Error stack capacity exceeded (%d elements). Might leak memory.", errstack->count);
		return element;
	}
	errstack->element[errstack->count].intvalue = element;
	errstack->element[errstack->count].elementtype = elementtype;
	errstack->count++;
	return element;
}

X509* errstack_add_X509(struct errstack_t *errstack, X509 *element) {
	return (X509*)errstack_add_generic_ptr(errstack, ERRSTACK_X509, element);
}

EVP_PKEY* errstack_add_EVP_PKEY(struct errstack_t *errstack, EVP_PKEY *element) {
	return (EVP_PKEY*)errstack_add_generic_ptr(errstack, ERRSTACK_EVP_PKEY, element);
}

STACK_OF(X509)* errstack_add_sk_X509(struct errstack_t *errstack, STACK_OF(X509) *element) {
	return (STACK_OF(X509)*)errstack_add_generic_ptr(errstack, ERRSTACK_STACK_OF_X509, element);
}

OCSP_BASICRESP* errstack_add_OCSP_BASICRESP(struct errstack_t *errstack, OCSP_BASICRESP *element) {
	return (OCSP_BASICRESP*)errstack_add_generic_ptr(errstack, ERRSTACK_OCSP_BASICRESP, element);
}

OCSP_CERTID* errstack_add_OCSP_CERTID(struct errstack_t *errstack, OCSP_CERTID *element) {
	return (OCSP_CERTID*)errstack_add_generic_ptr(errstack, ERRSTACK_OCSP_CERTID, element);
}

ASN1_TIME* errstack_add_ASN1_TIME(struct errstack_t *errstack, ASN1_TIME *element) {
	return (ASN1_TIME*)errstack_add_generic_ptr(errstack, ERRSTACK_ASN1_TIME, element);
}

BIGNUM* errstack_add_BIGNUM(struct errstack_t *errstack, BIGNUM *element) {
	return (BIGNUM*)errstack_add_generic_ptr(errstack, ERRSTACK_BIGNUM, element);
}

RSA* errstack_add_RSA(struct errstack_t *errstack, RSA *element) {
	return (RSA*)errstack_add_generic_ptr(errstack, ERRSTACK_RSA, element);
}

EC_KEY* errstack_add_EC_KEY(struct errstack_t *errstack, EC_KEY *element) {
	return (EC_KEY*)errstack_add_generic_ptr(errstack, ERRSTACK_EC_KEY, element);
}

void* errstack_add_malloc(struct errstack_t *errstack, void *element) {
	return errstack_add_generic_ptr(errstack, ERRSTACK_MALLOC, element);
}

int errstack_add_fd(struct errstack_t *errstack, int fd) {
	if (fd >= 0) {
		return errstack_add_int(errstack, ERRSTACK_FD, fd);
	} else {
		return fd;
	}
}

void errstack_add_atomic_dec(struct errstack_t *errstack, struct atomic_t *element) {
	errstack_add_generic_ptr(errstack, ERRSTACK_ATOMIC_DEC, element);
}

void errstack_add_clienthello(struct errstack_t *errstack, struct chello_t *element) {
	errstack_add_generic_ptr(errstack, ERRSTACK_CLIENT_HELLO, element);
}

void errstack_reset(struct errstack_t *errstack) {
	errstack->count = 0;
}

void errstack_pop(struct errstack_t *errstack, int popcnt) {
	if (errstack->count > popcnt) {
		errstack->count -= popcnt;
	} else {
		errstack->count = 0;
	}
}

static void errstack_free_element(const struct errstack_element_t *element) {
	switch (element->elementtype) {
		case ERRSTACK_X509:
			X509_free((X509*)element->ptrvalue);
			break;

		case ERRSTACK_EVP_PKEY:
			EVP_PKEY_free((EVP_PKEY*)element->ptrvalue);
			break;

		case ERRSTACK_STACK_OF_X509:
			sk_X509_pop_free((STACK_OF(X509)*)element->ptrvalue, X509_free);
			break;

		case ERRSTACK_OCSP_BASICRESP:
			OCSP_BASICRESP_free((OCSP_BASICRESP*)element->ptrvalue);
			break;

		case ERRSTACK_OCSP_CERTID:
			OCSP_CERTID_free((OCSP_CERTID*)element->ptrvalue);
			break;

		case ERRSTACK_ASN1_TIME:
			ASN1_TIME_free((ASN1_TIME*)element->ptrvalue);
			break;

		case ERRSTACK_BIGNUM:
			BN_free((BIGNUM*)element->ptrvalue);
			break;

		case ERRSTACK_RSA:
			RSA_free((RSA*)element->ptrvalue);
			break;

		case ERRSTACK_EC_KEY:
			EC_KEY_free((EC_KEY*)element->ptrvalue);
			break;

		case ERRSTACK_MALLOC:
			free(element->ptrvalue);
			break;

		case ERRSTACK_FD:
			close(element->intvalue);
			break;

		case ERRSTACK_ATOMIC_DEC:
			atomic_dec((struct atomic_t*)element->ptrvalue);
			break;

		case ERRSTACK_CLIENT_HELLO:
			free_client_hello((struct chello_t*)element->ptrvalue);
			break;
	}
}

void *errstack_free_except(struct errstack_t *errstack, int keep_on_stack_cnt) {
	for (int i = errstack->count - 1; i >= keep_on_stack_cnt; i--) {
		errstack_free_element(&errstack->element[i]);
	}
	errstack->count = 0;
	return NULL;
}

void *errstack_free(struct errstack_t *errstack) {
	return errstack_free_except(errstack, 0);
}
