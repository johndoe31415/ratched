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
#include <map.h>

static void test_map_create_free(void) {
	subtest_start();
	struct map_t *map = map_new();
	map_free(map);
	subtest_finished();
}

static void test_map_insert(void) {
	subtest_start();
	struct map_t *map = map_new();
	strmap_set_str(map, "foobar", "abc");
	strmap_set_str(map, "barfoo", "abc");
	strmap_set_str(map, "foomoo", "abc");
	strmap_set_str(map, "X", "abc");
	strmap_set_str(map, "Johannes", "0123");
	strmap_set_str(map, "foobar", "123");
	strmap_set_str(map, "foobar", "234");
	strmap_set_str(map, "foobar", "345");
	strmap_set_str(map, "foobar", "456");
	map_free(map);
	subtest_finished();
}

static void test_map_insert_retrieve(void) {
	subtest_start();
	struct map_t *map = map_new();
	test_assert_int_eq(map->element_count, 0);
	strmap_set_str(map, "key", "value");
	test_assert_int_eq(map->element_count, 1);
	test_assert_str_eq(strmap_get_str(map, "key"), "value");
	strmap_set_str(map, "key2", "new value");
	test_assert_int_eq(map->element_count, 2);
	test_assert_str_eq(strmap_get_str(map, "key2"), "new value");
	test_assert_str_eq(strmap_get_str(map, "key"), "value");
	strmap_set_str(map, "key2", "other value");
	test_assert_int_eq(map->element_count, 2);
	test_assert_str_eq(strmap_get_str(map, "key2"), "other value");
	test_assert_str_eq(strmap_get_str(map, "key"), "value");
	map_free(map);
	subtest_finished();
}

static void test_map_raw(void) {
	subtest_start();
	struct map_t *map = map_new();
	strmap_set_ptr(map, "foobar", (void*)0x12345);
	strmap_set_ptr(map, "barfoo", (void*)0x23456);
	strmap_set_ptr(map, "foobar", (void*)0x34567);
	map_free(map);
	subtest_finished();
}

static void test_map_int(void) {
	subtest_start();
	struct map_t *map = map_new();
	strmap_set_int(map, "foobar", 0x11111);
	test_assert_int_eq(strmap_get_int(map, "foobar"), 0x11111);
	test_assert_int_eq(strmap_get_int(map, "foobar2"), -1);
	test_assert_int_eq(strmap_get_int(map, "barfoo"), -1);
	strmap_set_int(map, "barfoo", 0x22222);
	test_assert_int_eq(strmap_get_int(map, "foobar"), 0x11111);
	test_assert_int_eq(strmap_get_int(map, "foobar2"), -1);
	test_assert_int_eq(strmap_get_int(map, "barfoo"), 0x22222);
	map_dump(map);
	map_free(map);
	subtest_finished();
}

int main(int argc, char **argv) {
	test_start(argc, argv);
	test_map_create_free();
	test_map_insert();
	test_map_insert_retrieve();
	test_map_raw();
	test_map_int();
	test_finished();
	return 0;
}
