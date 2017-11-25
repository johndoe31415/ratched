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

#ifndef __LOGGING_H__
#define __LOGGING_H__

#include <stdbool.h>
#include <openssl/x509.h>

enum loglvl_t {
	LLVL_FATAL,
	LLVL_ERROR,
	LLVL_WARN,
	LLVL_INFO,
	LLVL_DEBUG,
	LLVL_TRACE,
	LLVL_LAST,		// Invalid
};

enum logflag_t {
	FLAG_OPENSSL_ERROR = (1 << 0),
	FLAG_OPENSSL_DUMP_X509_CERT_SUBJECT = (1 << 1),
	FLAG_OPENSSL_DUMP_X509_CERT_PEM = (1 << 2),
	FLAG_OPENSSL_DUMP_X509_CERT_TEXT = (1 << 3),
};

/*************** AUTO GENERATED SECTION FOLLOWS ***************/
bool open_logfile(const char *filename);
void  __attribute__ ((format (printf, 2, 3))) logmsg(enum loglvl_t lvl, const char *msg, ...);
void  __attribute__ ((format (printf, 3, 4))) logmsgext(enum loglvl_t lvl, unsigned int flags, const char *msg, ...);
void  __attribute__ ((format (printf, 4, 5))) logmsgarg(enum loglvl_t lvl, unsigned int flags, void *arg, const char *msg, ...);
void log_cert(enum loglvl_t lvl, X509 *crt, const char *msg);
/***************  AUTO GENERATED SECTION ENDS   ***************/

#endif
