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
#include <pcapng.h>

#define TEST_FILENAME "test.pcapng"

static void test_pcapng_simple(void) {
	subtest_start();
	FILE *f = fopen(TEST_FILENAME, "w");
	test_assert(f);
	test_assert(pcapng_write_shb(f, NULL));
	test_assert(pcapng_write_idb(f, LINKTYPE_RAW, 65535, "eth0", "My network interface"));
	uint32_t ip = 0x11223344;
	test_assert(pcapng_write_nrb(f, &ip, "www.foobar.com", true));
	test_assert(pcapng_write_epb(f, (const uint8_t*)"foobar packet", 5, "my comment"));
	fclose(f);
	subtest_finished();
}

int main(int argc, char **argv) {
	test_start(argc, argv);
	test_pcapng_simple();
	test_finished();
	return 0;
}

