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
#include <string.h>
#include <errno.h>
#include "pgmopts.h"
#include "server.h"
#include "openssl.h"
#include "certforgery.h"
#include "shutdown.h"
#include "daemonize.h"
#include "interceptdb.h"
#include "hostname_ids.h"

int main(int argc, char **argv) {
	if (!parse_options(argc, argv)) {
		show_syntax(argv[0]);
		exit(EXIT_FAILURE);
	}

	if (pgm_options->log.logfilename) {
		if (!open_logfile(pgm_options->log.logfilename)) {
			logmsg(LLVL_FATAL, "Could not open logfile for writing.");
			exit(EXIT_FAILURE);
		}
	}

	if (!init_shutdown_handler()) {
		logmsg(LLVL_FATAL, "Could not install shutdown handler.");
		exit(EXIT_FAILURE);
	}

	init_hostname_ids();

	struct multithread_dumper_t mtdump;
	if (!open_pcap_write(&mtdump, pgm_options->pcapng.filename, pgm_options->pcapng.comment)) {
		logmsg(LLVL_FATAL, "Could not open dump file %s for writing: %s", pgm_options->pcapng.filename, strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (pgm_options->operation.daemonize && !daemonize()) {
		logmsg(LLVL_FATAL, "Requested daemonization failed.");
		exit(EXIT_FAILURE);
	}

	openssl_init();
	if (certforgery_init()) {
		if (init_interceptdb()) {
			start_forwarding(&mtdump);
			deinit_interceptdb();
		} else {
			logmsg(LLVL_FATAL, "Cannot continue without properly initialized interception database.");
		}
		certforgery_deinit();
	} else {
		logmsg(LLVL_FATAL, "Cannot continue without proper certificates and keys.");
	}

	openssl_deinit();
	close_pcap(&mtdump);
	deinit_hostname_ids();
	free_pgm_options();

	return 0;
}
