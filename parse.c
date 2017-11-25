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
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "parse.h"
#include "stringlist.h"
#include "logging.h"

bool safe_strtol(const char **string, long int *result, bool trailing_data_allowed) {
	char *end;
	errno = 0;
	long int value = strtol(*string, &end, 10);
	bool did_conversion = (*string != end);
	bool success = did_conversion && (errno == 0);
	if (!trailing_data_allowed) {
		success = success && (*end == 0);
	}
	if (success) {
		*result = value;
		*string = end;
	}
	return success;
}

static bool next_char_is(const char **string, char c) {
	bool success = (**string == c);
	if (success) {
		*string = *string + 1;
	}
	return success;
}

static bool internal_parse_ipv4(const char **ipv4, uint32_t *ip_nbo, bool trailing_data_allowed) {
	long int ip[4];

	if (
		safe_strtol(ipv4, &ip[0], true)
		&& (next_char_is(ipv4, '.'))
		&& safe_strtol(ipv4, &ip[1], true)
		&& (next_char_is(ipv4, '.'))
		&& safe_strtol(ipv4, &ip[2], true)
		&& (next_char_is(ipv4, '.'))
		&& safe_strtol(ipv4, &ip[3], trailing_data_allowed)
	) {
		if (!trailing_data_allowed && (**ipv4 != 0)) {
			/* No trailing data allowed, but present. */
			return false;
		}

		for (int i = 0; i < 4; i++) {
			if ((ip[i] < 0) || (ip[i] > 255)) {
				return false;
			}
		}
		uint32_t ip_hbo = (ip[0] << 24) | (ip[1] << 16) | (ip[2] << 8) | (ip[3] << 0);
		*ip_nbo = htonl(ip_hbo);
		return true;
	}
	return false;
}

bool parse_ipv4(const char *ipv4, uint32_t *ip_nbo) {
	return internal_parse_ipv4(&ipv4, ip_nbo, false);
}

bool parse_ipv4_port(const char *ipv4_port, uint32_t *ip_nbo, uint16_t *port_nbo) {
	long int port;
	if (
		internal_parse_ipv4(&ipv4_port, ip_nbo, true)
		&& (next_char_is(&ipv4_port, ':'))
		&& safe_strtol(&ipv4_port, &port, false)) {
		if ((port > 0) && (port <= 65535)) {
			*port_nbo = htons(port);
			return true;
		}
	}
	return false;
}

bool parse_hostname_port(const char *hostname_port, uint32_t *ip_nbo, uint16_t *port_nbo) {
	struct stringlist_t list;
	parse_stringlist(&list, hostname_port, ":");
	if (list.token_cnt != 2) {
		logmsg(LLVL_ERROR, "Expected two arguments for hostname:port combination, but got %d: \"%s\"", list.token_cnt, hostname_port);
		free_stringlist(&list);
		return false;
	}

	/* First try to parse hostname as an IPv4 address */
	if (!parse_ipv4(list.tokens[0], ip_nbo)) {
		/* If this doesn't work, try DNS lookup */
		struct addrinfo addrinfo = {
			.ai_family = AF_INET,
			.ai_flags = AI_PASSIVE,
		};
		struct addrinfo *result;
		int returnvalue = getaddrinfo(list.tokens[0], NULL, &addrinfo, &result);
		if (returnvalue) {
			logmsg(LLVL_ERROR, "DNS lookup of %s failed: %s", list.tokens[0], gai_strerror(returnvalue));
			free_stringlist(&list);
			return false;
		}

		*ip_nbo = ((struct sockaddr_in*)result->ai_addr)->sin_addr.s_addr;
		freeaddrinfo(result);
	}

	/* Then parse the port number */
	long int port;
	const char *port_str = list.tokens[1];
	if (!safe_strtol(&port_str, &port, false)) {
		logmsg(LLVL_ERROR, "Could not pase port number \"%s\" as a valid integer.", list.tokens[1]);
		free_stringlist(&list);
		return false;
	}

	if ((port <= 0) || (port >= 65535)) {
		logmsg(LLVL_ERROR, "%ld is not a valid port number.", port);
		free_stringlist(&list);
		return false;
	}
	*port_nbo = htons(port);

	free_stringlist(&list);
	return true;
}
