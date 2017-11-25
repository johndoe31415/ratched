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

#ifndef __PCAPNG_H__
#define __PCAPNG_H__

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#define LINKTYPE_RAW				101

/*************** AUTO GENERATED SECTION FOLLOWS ***************/
bool pcapng_write_shb(FILE *f, const char *comment);
bool pcapng_write_idb(FILE *f, uint16_t linktype, uint32_t snaplen, const char *ifname, const char *ifdesc);
bool pcapng_write_nrb_ipv4(FILE *f, const uint32_t ipv4_nbo, const char *hostname);
bool pcapng_write_epb(FILE *f, const uint8_t *payload, unsigned int payload_length, const char *comment);
FILE *pcapng_open(const char *filename, uint16_t linktype, uint32_t snaplen, const char *comment);
/***************  AUTO GENERATED SECTION ENDS   ***************/

#endif
