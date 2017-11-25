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

#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include "daemonize.h"
#include "logging.h"

bool daemonize(void) {
	pid_t pid = fork();
	if (pid == -1) {
		logmsg(LLVL_FATAL, "First fork(3) failed: %s", strerror(errno));
		return false;
	} else if (pid != 0) {
		/* Parent process, exit. */
		exit(EXIT_SUCCESS);
	}

	/* Child process survives */
	pid  = fork();
	if (pid == -1) {
		logmsg(LLVL_FATAL, "Second fork(3) failed: %s", strerror(errno));
		return false;
	} else if (pid != 0) {
		/* Parent process, exit. */
		exit(EXIT_SUCCESS);
	}

	/* Again, child process survives */
	if (chdir("/") == -1) {
		logmsg(LLVL_FATAL, "chdir(3) to root directory failed: %s", strerror(errno));
		return false;
	}

	return true;
}
