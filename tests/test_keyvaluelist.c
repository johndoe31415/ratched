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
#include <stdlib.h>
#include "testbed.h"
#include <keyvaluelist.h>

static void test_keyvalue(void) {
	subtest_start();

	{
		long int longint = 0;
		char *foostring = NULL;
		struct keyvaluelist_def_t definition[] = {
			{ .key = "longint", .parser = keyvalue_longint, .target = &longint },
			{ .key = "foostring", .parser = keyvalue_string, .target = &foostring },
			{ 0 },
		};
		test_assert_int_eq(parse_keyvalue_list("foo,longint=12345", 1, definition, NULL), 1);
		test_assert_int_eq(longint, 12345);
		test_assert_str_eq(foostring, NULL);

		test_assert_int_eq(parse_keyvalue_list("foo,longint=12345,longint=9", 1, definition, NULL), -1);
		test_assert_int_eq(parse_keyvalue_list("foo,longynt=12345", 1, definition, NULL), -1);

		longint = 0;
		foostring = NULL;
		test_assert_int_eq(parse_keyvalue_list("foo,foostring=bar,longint=98765", 1, definition, NULL), 2);
		test_assert_int_eq(longint, 98765);
		test_assert_str_eq(foostring, "bar");
		free(foostring);

		longint = 0;
		foostring = NULL;
		test_assert_int_eq(parse_keyvalue_list("foo,foostring=bar,longint=28765", 0, definition, NULL), -1);
		test_assert_int_eq(longint, 0);
		test_assert_int_eq(parse_keyvalue_list("foo,foostring=bar,longint=28765", 2, definition, NULL), 1);
		test_assert_int_eq(longint, 28765);
		test_assert_int_eq(parse_keyvalue_list("", 0, definition, NULL), 0);

		test_assert_int_eq(parse_keyvalue_list("foo,foostring=mookoo", 2, definition, NULL), 0);
		test_assert_str_eq(foostring, NULL);
		test_assert_int_eq(parse_keyvalue_list("foo,foostring=mookoo", 1, definition, NULL), 1);
		test_assert_str_eq(foostring, "mookoo");
		free(foostring);
	}

	subtest_finished();
}

int main(int argc, char **argv) {
	test_start(argc, argv);
	test_keyvalue();
	test_finished();
	return 0;
}

