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

#ifndef __STRINGLIST_H__
#define __STRINGLIST_H__

#include <stdbool.h>

struct stringlist_t {
	unsigned int token_cnt;
	char **tokens;
	char *dupstr;
};

/*************** AUTO GENERATED SECTION FOLLOWS ***************/
bool parse_stringlist(struct stringlist_t *list, const char *string, const char *delim);
void free_stringlist(struct stringlist_t *list);
void dump_stringlist(const struct stringlist_t *list);
/***************  AUTO GENERATED SECTION ENDS   ***************/

#endif
