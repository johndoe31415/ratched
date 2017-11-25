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
#include <parse.h>
#include <arpa/inet.h>

static void test_parse_ip(void) {
	subtest_start();

	uint32_t result;
	test_assert(parse_ipv4("12.34.56.78", &result));
	test_assert(ntohl(result) == 0x0c22384e);

	test_assert(parse_ipv4("170.187.204.221", &result));
	test_assert(ntohl(result) == 0xaabbccdd);

	test_assert(parse_ipv4("0.0.0.0", &result));
	test_assert(ntohl(result) == 0);

	test_assert(parse_ipv4("255.255.255.255", &result));
	test_assert(ntohl(result) == 0xffffffff);

	test_fails(parse_ipv4("12.34.56.78:", &result));
	test_fails(parse_ipv4("1.34.56.256", &result));
	test_fails(parse_ipv4("1.34.56.", &result));
	test_fails(parse_ipv4("...", &result));
	test_fails(parse_ipv4("1.2.3.4:9999", &result));
	subtest_finished();
}

static void test_parse_ip_port(void) {
	subtest_start();

	uint32_t result_ip;
	uint16_t result_port;
	test_assert(parse_ipv4_port("12.34.56.78:9948", &result_ip, &result_port));
	subtest_finished();
}

int main(int argc, char **argv) {
	test_start(argc, argv);
	test_parse_ip();
	test_parse_ip_port();
	test_finished();
	return 0;
}

