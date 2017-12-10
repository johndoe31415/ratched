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
#include <datafilter.h>
#include <datafilter_hexdump.h>
#include <datafilter_bytewise.h>

struct sink_callback_data_t {
	unsigned int length;
	uint8_t data[4096];
};

static void sink_callback(void *arg, const uint8_t *data, unsigned int length) {
	struct sink_callback_data_t *ctx = (struct sink_callback_data_t*)arg;
	if (length <= 4096) {
		memcpy(ctx->data, data, length);
		ctx->length = length;
	}
}

static void test_filter_sink(void) {
	subtest_start();
	struct sink_callback_data_t cbdata = { 0 };
	struct datafilter_t *sink = datafilter_new_sink(sink_callback, &cbdata);
	datafilter_put(sink, "foobar", 6);
	test_assert_int_eq(cbdata.length, 6);
	test_assert(!memcmp(cbdata.data, "foobar", cbdata.length));
	datafilter_put(sink, "mookoo123", 9);
	test_assert_int_eq(cbdata.length, 9);
	test_assert(!memcmp(cbdata.data, "mookoo123", cbdata.length));
	datafilter_free_chain(sink);
	subtest_finished();
}

static void test_filter_hexdump(void) {
	subtest_start();
	struct sink_callback_data_t cbdata = { 0 };
	struct datafilter_t *filter = datafilter_new_sink(sink_callback, &cbdata);
	filter = datafilter_new(&filterclass_hexdump, NULL, filter);
	datafilter_put(filter, "mookoo123", 9);
	test_assert_int_eq(cbdata.length, 9);
	test_assert(!memcmp(cbdata.data, "mookoo123", cbdata.length));
	datafilter_free_chain(filter);
	subtest_finished();
}

static void test_filter_bytewise_hexdump(void) {
	subtest_start();
	struct sink_callback_data_t cbdata = { 0 };
	struct datafilter_t *filter = datafilter_new_sink(sink_callback, &cbdata);
	filter = datafilter_new(&filterclass_hexdump, NULL, filter);
	filter = datafilter_new(&filterclass_bytewise, NULL, filter);
	datafilter_put(filter, "mookoo123", 9);
	test_assert_int_eq(cbdata.length, 1);
	test_assert(!memcmp(cbdata.data, "3", cbdata.length));
	datafilter_free_chain(filter);
	subtest_finished();
}

int main(int argc, char **argv) {
	test_start(argc, argv);
	test_filter_sink();
	test_filter_hexdump();
	test_filter_bytewise_hexdump();
	test_finished();
	return 0;
}
