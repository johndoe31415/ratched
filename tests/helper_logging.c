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
#include <stdarg.h>

#include "logging.h"

bool loglevel_at_least(enum loglvl_t lvl) {
	return true;
}

void logmsg_src(enum loglvl_t lvl, const char *src_file, unsigned int src_lineno, const char *msg, ...) {
	va_list ap;
	va_start(ap, msg);
	vfprintf(stderr, msg, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

void logmsgext_src(enum loglvl_t lvl, const char *src_file, unsigned int src_lineno, unsigned int flags, const char *msg, ...) {
	va_list ap;
	va_start(ap, msg);
	vfprintf(stderr, msg, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

void log_cert_src(enum loglvl_t lvl, const char *src_file, unsigned int src_lineno, X509 *crt, const char *msg) {
}

void log_memory_src(enum loglvl_t lvl, const char *src_file, unsigned int src_lineno, const void *data, unsigned int length, const char *msg, ...) {
}
