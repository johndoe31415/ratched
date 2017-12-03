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
#include <signal.h>
#include <string.h>
#include <errno.h>
#include "sighandler.h"
#include "logging.h"
#include "server.h"

static bool shutdown_requested;

static void sigint_handler(int signal) {
	stop_forwarding(shutdown_requested);
	shutdown_requested = true;
}

bool init_signal_handlers(void) {
	{
		struct sigaction action = {
			.sa_handler = sigint_handler,
			.sa_flags = SA_RESTART,
		};
		sigemptyset(&action.sa_mask);
		if (sigaction(SIGINT, &action, NULL) != 0) {
			logmsg(LLVL_ERROR, "sigaction failed to install SIGINT handler: %s", strerror(errno));
			return false;
		}
		if (sigaction(SIGHUP, &action, NULL) != 0) {
			logmsg(LLVL_ERROR, "sigaction failed to install SIGHUP handler: %s", strerror(errno));
			return false;
		}
		if (sigaction(SIGTERM, &action, NULL) != 0) {
			logmsg(LLVL_ERROR, "sigaction failed to install SIGTERM handler: %s", strerror(errno));
			return false;
		}
	}

	{
		struct sigaction action = {
			.sa_handler = SIG_IGN,
			.sa_flags = SA_RESTART,
		};
		if (sigaction(SIGPIPE, &action, NULL) != 0) {
			logmsg(LLVL_ERROR, "sigaction failed to install SIGPIPE handler: %s", strerror(errno));
			return false;
		}
	}
	return true;
}
