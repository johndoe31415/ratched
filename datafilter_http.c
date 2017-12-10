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

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include "datafilter_http.h"

struct filterdata_http_t {
	bool passthrough;
	uint8_t *buffer;
	unsigned int fill;
};

static bool filterfnc_http_new(void *data, void *init_attrs) {
	struct filterdata_http_t *ctx = (struct filterdata_http_t*)data;
	ctx->buffer = malloc(4096);
	if (!ctx->buffer) {
		return false;
	}
	return true;
}

static void filterfnc_http_put(struct datafilter_t *filter, const uint8_t *data, unsigned int length) {
	struct filterdata_http_t *ctx = (struct filterdata_http_t *)filter->data;
	if (ctx->passthrough) {
		datafilter_put(filter->next, data, length);
	}
}

static void filterfnc_http_free(void *data) {
	struct filterdata_http_t *ctx = (struct filterdata_http_t*)data;
	free(ctx->buffer);
}

const struct filterclass_t filterclass_http = {
	.name = "http",
	.datasize = sizeof(struct filterdata_http_t),
	.flt_new = filterfnc_http_new,
	.flt_put = filterfnc_http_put,
	.flt_free = filterfnc_http_free,
};
