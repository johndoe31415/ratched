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

#ifndef __IPFWD_H__
#define __IPFWD_H__

#define IPv4ADDR(a, b, c, d)			((((a) & 0xff) << 24) | (((b) & 0xff) << 16) | (((c) & 0xff) << 8) | (((d) & 0xff) << 0))

#define PRI_IPv4						"%d.%d.%d.%d"
#define FMT_IPv4(x)						((x) >> 0) & 0xff, ((x) >> 8) & 0xff, ((x) >> 16) & 0xff, ((x) >> 24) & 0xff

#define PRI_IPv4_PORT					PRI_IPv4 ":%d"
#define FMT_IPv4_PORT_TUPLE(ip, port)	FMT_IPv4(ip), ntohs(port)
#define FMT_IPv4_PORT(saddr_in)			FMT_IPv4_PORT_TUPLE((saddr_in).sin_addr.s_addr, (saddr_in).sin_port)

#include <stdint.h>

/*************** AUTO GENERATED SECTION FOLLOWS ***************/
int tcp_accept(uint16_t port_nbo);
int tcp_connect(uint32_t ip_nbo, uint16_t port_nbo);
/***************  AUTO GENERATED SECTION ENDS   ***************/

#endif
