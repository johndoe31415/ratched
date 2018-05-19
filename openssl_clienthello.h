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

#ifndef __OPENSSL_CLIENTHELLO_H__
#define __OPENSSL_CLIENTHELLO_H__

#include <stdint.h>
#include <stdbool.h>
#include "errstack.h"

struct chello_t {
	char *server_name_indication;
	struct {
		bool status_request;
		bool encrypt_then_mac;
		bool extended_master_secret;
		bool session_ticket;
	} present_extensions;
};

/*************** AUTO GENERATED SECTION FOLLOWS ***************/
bool parse_client_hello(struct chello_t *result, const uint8_t *data, int length);
void free_client_hello(struct chello_t *chello);
void errstack_push_client_hello(struct errstack_t *errstack, struct chello_t *element);
void client_hello_dump_options(void);
/***************  AUTO GENERATED SECTION ENDS   ***************/

#endif
