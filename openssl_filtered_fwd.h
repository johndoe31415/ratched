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

#ifndef __OPENSSL_FILTERED_FWD_H__
#define __OPENSSL_FILTERED_FWD_H__

#include <openssl/ssl.h>
#include "tcpip.h"

struct connection_side_stats_t {
	unsigned int bytes_read;
	unsigned int bytes_written;
};

struct connection_stats_t {
	struct connection_side_stats_t dir1;
	struct connection_side_stats_t dir2;
};

enum fwd_direction_t {
	READ_1_WRITE_2,
	READ_2_WRITE_1,
};

union raw_connection_info_t {
	struct {
		SSL *side1, *side2;
	} tls;
	struct {
		int side1, side2;
	} fd;
};

struct forwarding_data_t {
	BIO *side1, *side2;
	struct connection_stats_t *stats;
	struct connection_t *conn;
	union raw_connection_info_t raw_connection_info;
	void (*connection_shutdown_callback)(struct forwarding_data_t*);
};

struct forwarding_thread_data_t {
	enum fwd_direction_t direction;
	struct forwarding_data_t *fwd_data;
};

/*************** AUTO GENERATED SECTION FOLLOWS ***************/
void filtered_fd_forward_data(int fd1, int fd2, struct connection_stats_t *stats, struct connection_t *conn);
void filtered_tls_forward_data(SSL *ssl1, SSL *ssl2, struct connection_stats_t *stats, struct connection_t *conn);
/***************  AUTO GENERATED SECTION ENDS   ***************/

#endif
