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
#include <stdbool.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "logging.h"
#include "pgmopts.h"

static pthread_mutex_t loglock = PTHREAD_MUTEX_INITIALIZER;
static FILE *logfile;

static const char *loglevels[] = {
	[LLVL_FATAL] = "FATAL",
	[LLVL_ERROR] = "ERROR",
	[LLVL_WARN] = "WARN",
	[LLVL_INFO] = "INFO",
	[LLVL_DEBUG] = "DEBUG",
	[LLVL_TRACE] = "TRACE",
};

static void log_gettime(char buf[static 32]) {
	time_t tt = time(NULL);
	struct tm localtime;
    if (!localtime_r(&tt, &localtime)) {
		strcpy(buf, "!localtime");
		return;
	}
	strftime(buf, 32, "%Y-%m-%d %H:%M:%S", &localtime);
}

static void log_lock(void) {
	pthread_mutex_lock(&loglock);
	if (!logfile) {
		logfile = stderr;
	}
}

static void log_unlock(void) {
	if (pgm_options->log.flush) {
		fflush(logfile);
	}
	pthread_mutex_unlock(&loglock);
}

bool open_logfile(const char *filename) {
	logfile = fopen(filename, "a");
	if (!logfile) {
		logmsg(LLVL_ERROR, "Cannot open '%s' for writing: %s", filename, strerror(errno));
		return false;
	}
	return true;
}

static void print_log_prefix_str(const char *lvlstr) {
	char datetime[32];
	log_gettime(datetime);
	fprintf(logfile, "%s [%s] ", datetime, lvlstr);
}

static void print_log_prefix(enum loglvl_t lvl) {
	const char *loglvl_str = (lvl < LLVL_LAST) ? loglevels[lvl] : "?";
	print_log_prefix_str(loglvl_str);
}

static int error_print_callback(const char *str, size_t len, void *u) {
	fprintf(logfile, "    %s", str);
	return 1;
}

static void ext_log_callback(unsigned int flags, void *arg) {
	if (flags & FLAG_OPENSSL_ERROR) {
		/* Dump out last OpenSSL error */
		ERR_print_errors_cb(error_print_callback, NULL);
	}
	if ((flags & FLAG_OPENSSL_DUMP_X509_CERT_SUBJECT) && arg) {
		X509 *cert = (X509*)arg;
		fprintf(logfile, " - subject: ");
		X509_NAME_print_ex_fp(logfile, X509_get_subject_name(cert), 0, XN_FLAG_ONELINE);
	}
	if ((flags & FLAG_OPENSSL_DUMP_X509_CERT_TEXT) && arg) {
		X509 *cert = (X509*)arg;
		X509_print_fp(logfile, cert);
	}
	if ((flags & FLAG_OPENSSL_DUMP_X509_CERT_PEM) && arg) {
		X509 *cert = (X509*)arg;
		PEM_write_X509(logfile, cert);
	}
}

static void logmsg_cb(enum loglvl_t lvl, void (*log_cb)(unsigned int flags, void *arg), unsigned int cb_flags, void *cb_arg, const char *msg, va_list ap) {
	if (lvl > pgm_options->log.level) {
		return;
	}

	log_lock();
	print_log_prefix(lvl);
	vfprintf(logfile, msg, ap);
	va_end(ap);
	if (log_cb) {
		log_cb(cb_flags & (FLAG_OPENSSL_DUMP_X509_CERT_SUBJECT), cb_arg);
	}
	fprintf(logfile, "\n");
	if (log_cb) {
		log_cb(cb_flags & ~(FLAG_OPENSSL_DUMP_X509_CERT_SUBJECT), cb_arg);
	}
	log_unlock();
}

void  __attribute__ ((format (printf, 2, 3))) logmsg(enum loglvl_t lvl, const char *msg, ...) {
	va_list ap;
	va_start(ap, msg);
	logmsg_cb(lvl, NULL, 0, NULL, msg, ap);
	va_end(ap);
}

void  __attribute__ ((format (printf, 3, 4))) logmsgext(enum loglvl_t lvl, unsigned int flags, const char *msg, ...) {
	va_list ap;
	va_start(ap, msg);
	logmsg_cb(lvl, ext_log_callback, flags, NULL, msg, ap);
	va_end(ap);
}

void  __attribute__ ((format (printf, 4, 5))) logmsgarg(enum loglvl_t lvl, unsigned int flags, void *arg, const char *msg, ...) {
	va_list ap;
	va_start(ap, msg);
	logmsg_cb(lvl, ext_log_callback, flags, arg, msg, ap);
	va_end(ap);
}

void log_cert(enum loglvl_t lvl, X509 *crt, const char *msg) {
	unsigned int flags = FLAG_OPENSSL_DUMP_X509_CERT_SUBJECT | FLAG_OPENSSL_DUMP_X509_CERT_PEM;
	if (pgm_options->log.level >= LLVL_TRACE) {
		flags |= FLAG_OPENSSL_DUMP_X509_CERT_TEXT;
	}
	logmsgarg(lvl, flags, crt, "%s", msg);
}
