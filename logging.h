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
	FLAG_LOG_SAMELINE = (1 << 0),
	FLAG_LOG_AFTERLINE = (1 << 1),
	FLAG_OPENSSL_ERROR = (1 << 2),
	FLAG_OPENSSL_DUMP_X509_CERT_SUBJECT = (1 << 3),
	FLAG_OPENSSL_DUMP_X509_CERT_PEM = (1 << 4),
	FLAG_OPENSSL_DUMP_X509_CERT_TEXT = (1 << 5),
};

#define logmsg(lvl, msg, ...)							logmsg_src((lvl), __FILE__, __LINE__, (msg), ##__VA_ARGS__)
#define logmsgext(lvl, flags, msg, ...)					logmsgext_src((lvl), __FILE__, __LINE__, (flags), (msg), ##__VA_ARGS__)
#define logmsgarg(lvl, flags, arg, msg, ...)			logmsgext_src((lvl), __FILE__, __LINE__, (flags), (arg), (msg), ##__VA_ARGS__)
#define log_cert(lvl, crt, msg)							log_cert_src((lvl), __FILE__, __LINE__, (crt), (msg))
#define log_memory(lvl, data, length, msg, ...)			log_memory_src((lvl), __FILE__, __LINE__, (data), (length), (msg), ##__VA_ARGS__)

/*************** AUTO GENERATED SECTION FOLLOWS ***************/
struct memdump_data_t;
bool open_logfile(const char *filename);
bool loglevel_at_least(enum loglvl_t lvl);
void  __attribute__ ((format (printf, 4, 5))) logmsg_src(enum loglvl_t lvl, const char *src_file, unsigned int src_lineno, const char *msg, ...);
void  __attribute__ ((format (printf, 5, 6))) logmsgext_src(enum loglvl_t lvl, const char *src_file, unsigned int src_lineno, unsigned int flags, const char *msg, ...);
void  __attribute__ ((format (printf, 6, 7))) logmsgarg_src(enum loglvl_t lvl, const char *src_file, unsigned int src_lineno, unsigned int flags, void *arg, const char *msg, ...);
void  __attribute__ ((format (printf, 6, 7))) log_memory_src(enum loglvl_t lvl, const char *src_file, unsigned int src_lineno, const void *data, unsigned int length, const char *msg, ...);
void log_cert_src(enum loglvl_t lvl, const char *src_file, unsigned int src_lineno, X509 *crt, const char *msg);
/***************  AUTO GENERATED SECTION ENDS   ***************/

#endif
