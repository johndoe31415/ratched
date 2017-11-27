#include <openssl/x509.h>
#include <openssl/ocsp.h>

#include "errstack.h"
#include "logging.h"

static void* errstack_add_generic(struct errstack_t *errstack, enum errstack_ptrtype_t ptrtype, void *element) {
	if (!element) {
		return NULL;
	}

	if (errstack->count >= MAX_ERRSTACK_DEPTH) {
		logmsg(LLVL_FATAL, "Error stack capacity exceeded (%d elements). Might leak memory.", errstack->count);
		return element;
	}
	errstack->element[errstack->count].ptr = element;
	errstack->element[errstack->count].ptrtype = ptrtype;
	errstack->count++;
	return element;
}

X509* errstack_add_X509(struct errstack_t *errstack, X509 *element) {
	return (X509*)errstack_add_generic(errstack, ERRSTACK_X509, element);
}

EVP_PKEY* errstack_add_EVP_PKEY(struct errstack_t *errstack, EVP_PKEY *element) {
	return (EVP_PKEY*)errstack_add_generic(errstack, ERRSTACK_EVP_PKEY, element);
}

STACK_OF(X509)* errstack_add_sk_X509(struct errstack_t *errstack, STACK_OF(X509) *element) {
	return (STACK_OF(X509)*)errstack_add_generic(errstack, ERRSTACK_STACK_OF_X509, element);
}

OCSP_BASICRESP* errstack_add_OCSP_BASICRESP(struct errstack_t *errstack, OCSP_BASICRESP *element) {
	return (OCSP_BASICRESP*)errstack_add_generic(errstack, ERRSTACK_OCSP_BASICRESP, element);
}

OCSP_CERTID* errstack_add_OCSP_CERTID(struct errstack_t *errstack, OCSP_CERTID *element) {
	return (OCSP_CERTID*)errstack_add_generic(errstack, ERRSTACK_OCSP_CERTID, element);
}

ASN1_TIME* errstack_add_ASN1_TIME(struct errstack_t *errstack, ASN1_TIME *element) {
	return (ASN1_TIME*)errstack_add_generic(errstack, ERRSTACK_ASN1_TIME, element);
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
	switch (element->ptrtype) {
		case ERRSTACK_X509:
			X509_free((X509*)element->ptr);
			break;

		case ERRSTACK_EVP_PKEY:
			EVP_PKEY_free((EVP_PKEY*)element->ptr);
			break;

		case ERRSTACK_STACK_OF_X509:
			sk_X509_pop_free((STACK_OF(X509)*)element->ptr, X509_free);
			break;

		case ERRSTACK_OCSP_BASICRESP:
			OCSP_BASICRESP_free((OCSP_BASICRESP*)element->ptr);
			break;

		case ERRSTACK_OCSP_CERTID:
			OCSP_CERTID_free((OCSP_CERTID*)element->ptr);
			break;

		case ERRSTACK_ASN1_TIME:
			ASN1_TIME_free((ASN1_TIME*)element->ptr);
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
