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

#include <stdio.h>
#include "testbed.h"
#include <hostname_ids.h>

static void test_hostname_ids(void) {
	subtest_start();
	init_hostname_ids();
	test_assert_int_eq(resolve_hostname_id(0x11223344, NULL), 0);
	test_assert_int_eq(resolve_hostname_id(0x22334455, NULL), 0);
	test_assert_int_eq(resolve_hostname_id(0x11223344, "foobar"), 1);
	test_assert_int_eq(resolve_hostname_id(0x11223344, "foobar"), 1);
	test_assert_int_eq(resolve_hostname_id(0x11223344, "barfoo"), 2);
	test_assert_int_eq(resolve_hostname_id(0x11223344, "foobar"), 1);
	test_assert_int_eq(resolve_hostname_id(0x22334455, "moo.com"), 1);
	test_assert_int_eq(resolve_hostname_id(0x22334455, "foo.bar"), 2);
	deinit_hostname_ids();
	subtest_finished();
}

int main(int argc, char **argv) {
	test_start(argc, argv);
	test_hostname_ids();
	test_finished();
	return 0;
}

