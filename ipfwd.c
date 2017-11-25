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
#include <stdbool.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "logging.h"
#include "ipfwd.h"

struct forwarding_data_t {
	int read_fd;
	int write_fd;
};

int tcp_accept(uint16_t port_nbo) {
	int sd = socket(AF_INET, SOCK_STREAM, 0);
	if (sd == -1) {
		return -1;
	}

	{
		int enable = 1;
		if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0) {
		    logmsg(LLVL_ERROR, "setsockopt(SO_REUSEADDR) failed: %s", strerror(errno));
			close(sd);
			return -1;
		}
	}

	struct sockaddr_in serv_addr;
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = port_nbo;

	if (bind(sd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1) {
		logmsg(LLVL_ERROR, "Binding socket on " PRI_IPv4_PORT " failed: %s", FMT_IPv4_PORT(serv_addr), strerror(errno));
		close(sd);
		return -1;
	}

    if (listen(sd, 1) == -1) {
		logmsg(LLVL_ERROR, "Listening on bound socket failed: %s", strerror(errno));
		close(sd);
		return -1;
	}

	int peer_sd = accept(sd, NULL, NULL);
	if (peer_sd == -1) {
		logmsg(LLVL_ERROR, "Accepting on bound socket failed: %s", strerror(errno));
		close(sd);
		return -1;
	}

	close(sd);
	return peer_sd;
}

int tcp_connect(uint32_t ip_nbo, uint16_t port_nbo) {
	int sd = socket(AF_INET, SOCK_STREAM, 0);
	if (sd == -1) {
		return -1;
	}

	struct sockaddr_in peer;
	memset(&peer, 0, sizeof(peer));
	peer.sin_family = AF_INET;
	peer.sin_addr.s_addr = ip_nbo;
	peer.sin_port = port_nbo;

	logmsg(LLVL_DEBUG, "Connecting to " PRI_IPv4 ":%d for SD %d", FMT_IPv4(ip_nbo), ntohs(port_nbo), sd);
	if (connect(sd, (struct sockaddr*)&peer, sizeof(peer)) == -1) {
		int saved_errno = errno;
		close(sd);
		errno = saved_errno;
		return -1;
	}

	return sd;
}

static void* forwarding_thread_fnc(void *vctx) {
	struct forwarding_data_t *ctx = (struct forwarding_data_t*)vctx;
	while (true) {
		uint8_t data[4096];
		ssize_t length_read = read(ctx->read_fd, data, sizeof(data));
		if (length_read == 0) {
			/* Peer closed connection */
			break;
		}
		if (length_read <= 0) {
			logmsg(LLVL_ERROR, "%zd bytes read when forwarding %d -> %d: %s", length_read, ctx->read_fd, ctx->write_fd, strerror(errno));
			break;
		}
		ssize_t length_written = write(ctx->write_fd, data, length_read);
		if (length_written != length_read) {
			logmsg(LLVL_ERROR, "%zd bytes written when forwarding %d -> %d, %zd bytes expected: %s", length_written, ctx->read_fd, ctx->write_fd, length_read, strerror(errno));
			break;
		}
	}
	shutdown(ctx->read_fd, SHUT_RDWR);
	shutdown(ctx->write_fd, SHUT_RDWR);
	return NULL;
}

void plain_forward_data(int fd1, int fd2) {
	struct forwarding_data_t dir1 = {
		.read_fd = fd1,
		.write_fd = fd2,
	};
	struct forwarding_data_t dir2 = {
		.read_fd = fd2,
		.write_fd = fd1,
	};
	pthread_t dir1_thread, dir2_thread;
	if (pthread_create(&dir1_thread, NULL, forwarding_thread_fnc, &dir1)) {
		logmsg(LLVL_ERROR, "Failed to create forwarding thread 1: %s", strerror(errno));
		return;
	}
	if (pthread_create(&dir2_thread, NULL, forwarding_thread_fnc, &dir2)) {
		logmsg(LLVL_ERROR, "Failed to create forwarding thread 2: %s", strerror(errno));
		return;
	}

	/* Wait for both threads to finish */
	pthread_join(dir1_thread, NULL);
	pthread_join(dir2_thread, NULL);

	logmsg(LLVL_INFO, "Closed plain forwarding between FDs %d <-> %d", fd1, fd2);
}
