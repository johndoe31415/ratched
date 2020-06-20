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
#include <stdint.h>
#include "hexdump.h"

static const struct hexdump_fmt_t default_format = {
	.bytes_per_line = 16,
	.short_break = 4,
	.long_break = 8,
};

static void hexdump_data_left_col(FILE *f, const struct hexdump_fmt_t *fmt, const uint8_t *data, unsigned int length) {
	for (unsigned int i = 0; i < fmt->bytes_per_line; i++) {
		if (i) {
			if ((i % fmt->long_break) == 0) {
				fprintf(f, "  ");
			} else if ((i % fmt->short_break) == 0) {
				fprintf(f, " ");
			}
		}
		if (i < length) {
			fprintf(f, "%02x ", data[i]);
		} else {
			fprintf(f, "   ");
		}
	}
}

static void hexdump_data_right_col(FILE *f, const struct hexdump_fmt_t *fmt, const uint8_t *data, unsigned int length) {
	for (unsigned int i = 0; i < fmt->bytes_per_line; i++) {
		if (i < length) {
			char c = data[i];
			if ((c > 32) && (c < 127)) {
				fprintf(f, "%c", c);
			} else {
				fprintf(f, ".");
			}
		} else {
			fprintf(f, " ");
		}
	}
}

void hexdump_data_fmt(FILE *f, const struct hexdump_fmt_t *fmt, const void *data, unsigned int length) {
	int line_count = (length + fmt->bytes_per_line - 1) / fmt->bytes_per_line;
	for (int lineno = 0; lineno < line_count; lineno++) {
		unsigned int offset = fmt->bytes_per_line * lineno;
		const uint8_t *linedata = (const uint8_t*)data + offset;
		unsigned int bytes_in_line = length - offset;
		if (bytes_in_line > fmt->bytes_per_line) {
			bytes_in_line = fmt->bytes_per_line;
		}
		fprintf(f, "%6x  ", offset);
		hexdump_data_left_col(f, fmt, linedata, bytes_in_line);
		fprintf(f, " | ");
		hexdump_data_right_col(f, fmt, linedata, bytes_in_line);
		fprintf(f, " |\n");
	}
}

void hexdump_data(FILE *f, const void *data, unsigned int length) {
	hexdump_data_fmt(f, &default_format, data, length);
}
