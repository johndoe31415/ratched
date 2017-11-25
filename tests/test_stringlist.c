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
#include <stringlist.h>

static void test_stringlist(void) {
	subtest_start();

	struct stringlist_t list;
	parse_stringlist(&list, "foo:bar:koo", ":");
	test_assert_int_eq(list.token_cnt, 3);
	test_assert_str_eq(list.tokens[0], "foo");
	test_assert_str_eq(list.tokens[1], "bar");
	test_assert_str_eq(list.tokens[2], "koo");
	free_stringlist(&list);

	parse_stringlist(&list, "foo:bar:koo", ",");
	test_assert_int_eq(list.token_cnt, 1);
	test_assert_str_eq(list.tokens[0], "foo:bar:koo");
	free_stringlist(&list);

	parse_stringlist(&list, "", ",");
	test_assert_int_eq(list.token_cnt, 0);
	free_stringlist(&list);

	subtest_finished();
}

int main(int argc, char **argv) {
	test_start(argc, argv);
	test_stringlist();
	test_finished();
	return 0;
}

