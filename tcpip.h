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

#ifndef __TCPIP_H__
#define __TCPIP_H__

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>

struct multithread_dumper_t {
	pthread_mutex_t mutex;
	FILE *f;
};

struct connection_t {
	bool ipv6_encapsulation;
	struct multithread_dumper_t *mtdump;
	struct {
		uint32_t ip_nbo;
		uint16_t port_nbo;
		uint32_t seqno;
		const char *hostname;
		uint16_t hostname_id;
	} connector;
	struct {
		uint32_t ip_nbo;
		uint16_t port_nbo;
		uint32_t seqno;
		const char *hostname;
		uint16_t hostname_id;
	} acceptor;
};

/*************** AUTO GENERATED SECTION FOLLOWS ***************/
void create_tcp_ip_connection(struct multithread_dumper_t *mtdump, struct connection_t *conn, const char *comment, bool use_ipv6_encapsulation);
void append_tcp_ip_data(struct connection_t *conn, bool direction, const uint8_t *payload, int payload_len);
void append_tcp_ip_string(struct connection_t *conn, bool direction, const char *string);
void teardown_tcp_ip_connection(struct connection_t *conn, bool direction);
void flush_tcp_ip_connection(struct connection_t *conn);
bool open_pcap_write(struct multithread_dumper_t *mtdump, const char *filename, const char *comment);
bool close_pcap(struct multithread_dumper_t *mtdump);
/***************  AUTO GENERATED SECTION ENDS   ***************/

#endif
