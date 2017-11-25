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

#include "testbed.h"
#include <tcpip.h>
#include <arpa/inet.h>

static void test_tcpip(void) {
	subtest_start();
	struct multithread_dumper_t dumper;
	test_assert(open_pcap_write(&dumper, "tcpip.pcapng", NULL));

	struct connection_t conn = {
		.connector = {
			.ip_nbo = 0x11223344,
			.port_nbo = htons(12378),
		},
		.acceptor = {
			.ip_nbo = 0xaabbccdd,
			.port_nbo = htons(80),
		},
	};

	create_tcp_ip_connection(&dumper, &conn, "comment");
	append_tcp_ip_data(&conn, true, (unsigned char*)"foobar", 6);
	append_tcp_ip_data(&conn, true, (unsigned char*)"foobar", 6);
	append_tcp_ip_data(&conn, true, (unsigned char*)"foobar", 6);
	append_tcp_ip_data(&conn, true, (unsigned char*)"foobar", 6);
	append_tcp_ip_data(&conn, true, (unsigned char*)"foobar", 6);
	append_tcp_ip_data(&conn, false, (unsigned char*)"moep!!", 6);
	append_tcp_ip_data(&conn, false, (unsigned char*)"moep!!", 6);
	teardown_tcp_ip_connection(&conn, true);

#if 1
	conn.connector.ip_nbo = 0x99887766;
	create_tcp_ip_connection(&dumper, &conn, "second connection");
	append_tcp_ip_data(&conn, true, (unsigned char*)"foobar", 6);
	append_tcp_ip_data(&conn, true, (unsigned char*)"foobar", 6);
	append_tcp_ip_data(&conn, true, (unsigned char*)"foobar", 6);
	append_tcp_ip_data(&conn, true, (unsigned char*)"foobar", 6);
	append_tcp_ip_data(&conn, true, (unsigned char*)"foobar", 6);
	append_tcp_ip_data(&conn, false, (unsigned char*)"moep!!", 6);
	teardown_tcp_ip_connection(&conn, true);
#endif

	close_pcap(&dumper);
	subtest_finished();
}

int main(int argc, char **argv) {
	test_start(argc, argv);
	test_tcpip();
	test_finished();
	return 0;
}

