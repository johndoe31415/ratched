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
#include <tools.h>

static void test_strxcat(void) {
	subtest_start();
	{
		char buf[3];
		memset(buf, 0, sizeof(buf));
		test_assert(strxcat(buf, sizeof(buf), "xy", NULL));
		test_assert_str_eq(buf, "xy");
	}
	{
		char buf[3];
		memset(buf, 0, sizeof(buf));
		test_fails(strxcat(buf, sizeof(buf), "xyz", NULL));
		test_assert_str_eq(buf, "xy");
	}
	{
		char buf[7];
		memset(buf, 0, sizeof(buf));
		test_assert(strxcat(buf, sizeof(buf), "x", "y", "z", "abc", NULL));
		test_assert_str_eq(buf, "xyzabc");
	}
	subtest_finished();
}

static bool path_callback(const char *path, void *arg) {
	fprintf(stderr, "CALLBACK '%s'\n", path);
	return true;
}

static void test_pathtok(void) {
	subtest_start();
	pathtok("/foo/bar/moo/koo", path_callback, NULL);
	pathtok("foo/bar/moo/koo", path_callback, NULL);
	pathtok("foo", path_callback, NULL);
	pathtok("foo/////bar", path_callback, NULL);
	subtest_finished();
}

static void test_spnprintf(void) {
	subtest_start();
	char foo[8];
	char *buf = foo;
	int len = 8;
	buf = spnprintf(buf, &len, "foo");
	test_assert_str_eq(foo, "foo");
	buf = spnprintf(buf, &len, "b");
	test_assert_str_eq(foo, "foob");
	buf = spnprintf(buf, &len, "a");
	test_assert_str_eq(foo, "fooba");
	buf = spnprintf(buf, &len, "r");
	test_assert_str_eq(foo, "foobar");
	buf = spnprintf(buf, &len, "123456");
	test_assert_str_eq(foo, "foobar1");
	buf = spnprintf(buf, &len, "XXXXXXXX");
	test_assert_str_eq(foo, "foobar1");
	subtest_finished();
}

int main(int argc, char **argv) {
	test_start(argc, argv);
	test_strxcat();
	test_pathtok();
	test_spnprintf();
	test_finished();
	return 0;
}

