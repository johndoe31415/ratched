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
#include <ipfwd.h>
#include <arpa/inet.h>

static void test_tcpip(void) {
	subtest_start();
	struct multithread_dumper_t dumper;
	test_assert(open_pcap_write(&dumper, "tcpip.pcapng", NULL));

	{
		struct connection_t conn = {
			.connector = {
				.ip_nbo = htonl(IPv4ADDR(1, 2, 3, 4)),
				.port_nbo = htons(2000),
			},
			.acceptor = {
				.ip_nbo = htonl(IPv4ADDR(11, 22, 33, 44)),
				.port_nbo = htons(80),
			},
		};
		create_tcp_ip_connection(&dumper, &conn, "IPv4 without hostnames", false);
		append_tcp_ip_string(&conn, true, "foobar\n");
		append_tcp_ip_string(&conn, false, "moep!!\n");
		append_tcp_ip_string(&conn, true, "foobar?\n");
		append_tcp_ip_string(&conn, false, "moep!! troet.\n");
		teardown_tcp_ip_connection(&conn, true);
	}
	{
		struct connection_t conn = {
			.connector = {
				.ip_nbo = htonl(IPv4ADDR(1, 2, 3, 4)),
				.port_nbo = htons(2001),
				.hostname = "ipv4.smally",
			},
			.acceptor = {
				.ip_nbo = htonl(IPv4ADDR(11, 22, 33, 44)),
				.port_nbo = htons(80),
				.hostname = "ipv4.large",
			},
		};
		create_tcp_ip_connection(&dumper, &conn, "IPv4 without hostnames", false);
		append_tcp_ip_string(&conn, true, "foobar\n");
		append_tcp_ip_string(&conn, false, "moep!!\n");
		append_tcp_ip_string(&conn, true, "foobar?\n");
		append_tcp_ip_string(&conn, false, "moep!! troet.\n");
		teardown_tcp_ip_connection(&conn, true);
	}
	{
		struct connection_t conn = {
			.connector = {
				.ip_nbo = htonl(IPv4ADDR(1, 2, 3, 4)),
				.port_nbo = htons(2002),
				.hostname = "kleine.zahlen",
				.hostname_id = 1234,
			},
			.acceptor = {
				.ip_nbo = htonl(IPv4ADDR(11, 22, 33, 44)),
				.port_nbo = htons(80),
				.hostname = "grosse.zahlen",
				.hostname_id = 987,
			},
		};
		create_tcp_ip_connection(&dumper, &conn, "IPv6 with hostname records", true);
		append_tcp_ip_string(&conn, true, "foobar\n");
		append_tcp_ip_string(&conn, false, "moep!!\n");
		teardown_tcp_ip_connection(&conn, true);
	}
	{
		struct connection_t conn = {
			.connector = {
				.ip_nbo = htonl(IPv4ADDR(1, 2, 3, 4)),
				.port_nbo = htons(2003),
				.hostname = "neue.kleine.zahlen",
				.hostname_id = 1235,
			},
			.acceptor = {
				.ip_nbo = htonl(IPv4ADDR(11, 22, 33, 44)),
				.port_nbo = htons(80),
				.hostname = "neue.grosse.zahlen",
				.hostname_id = 988,
			},
		};
		create_tcp_ip_connection(&dumper, &conn, "IPv6 with different hostname records", true);
		append_tcp_ip_string(&conn, true, "foobar\n");
		append_tcp_ip_string(&conn, false, "moep!!\n");
		teardown_tcp_ip_connection(&conn, true);
	}
	{
		struct connection_t conn = {
			.connector = {
				.ip_nbo = htonl(IPv4ADDR(1, 2, 3, 4)),
				.port_nbo = htons(2004),
			},
			.acceptor = {
				.ip_nbo = htonl(IPv4ADDR(11, 22, 33, 44)),
				.port_nbo = htons(80),
			},
		};
		create_tcp_ip_connection(&dumper, &conn, "IPv6 without hostnames", true);
		append_tcp_ip_string(&conn, true, "foobar\n");
		append_tcp_ip_string(&conn, false, "moep!!\n");
		teardown_tcp_ip_connection(&conn, true);
	}
	close_pcap(&dumper);
	subtest_finished();
}

int main(int argc, char **argv) {
	test_start(argc, argv);
	test_tcpip();
	test_finished();
	return 0;
}

