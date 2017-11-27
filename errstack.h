#ifndef __ERRSTACK_H__
#define __ERRSTACK_H__

#include <openssl/x509.h>
#include <openssl/ocsp.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

#define MAX_ERRSTACK_DEPTH	16

enum errstack_ptrtype_t {
	ERRSTACK_X509,
	ERRSTACK_EVP_PKEY,
	ERRSTACK_STACK_OF_X509,
	ERRSTACK_OCSP_BASICRESP,
	ERRSTACK_OCSP_CERTID,
	ERRSTACK_ASN1_TIME,
	ERRSTACK_BIGNUM,
	ERRSTACK_RSA,
	ERRSTACK_EC_KEY,
};

struct errstack_element_t {
	enum errstack_ptrtype_t ptrtype;
	void *ptr;
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
void errstack_reset(struct errstack_t *errstack);
void errstack_pop(struct errstack_t *errstack, int popcnt);
void *errstack_free_except(struct errstack_t *errstack, int keep_on_stack_cnt);
void *errstack_free(struct errstack_t *errstack);
/***************  AUTO GENERATED SECTION ENDS   ***************/

#endif
