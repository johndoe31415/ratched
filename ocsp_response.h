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

#ifndef __OCSP_RESPONSE_H__
#define __OCSP_RESPONSE_H__

#include <stdbool.h>
#include <openssl/ocsp.h>

/*************** AUTO GENERATED SECTION FOLLOWS ***************/
OCSP_RESPONSE *create_ocsp_response(X509 *subject_crt, X509 *issuer_crt, EVP_PKEY *issuer_key);
bool serialize_ocsp_response(OCSP_RESPONSE *ocsp_response, uint8_t **data, int *length);
/***************  AUTO GENERATED SECTION ENDS   ***************/

#endif
