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

#ifndef __KEYVALUELIST_H__
#define __KEYVALUELIST_H__

#include <stdbool.h>
#include "stringlist.h"

typedef bool (*keyvalue_parser_fnc)(char *element, void *arg, void *result);

struct lookup_entry_t {
	const char *key;
	int value;
};

struct keyvaluelist_t {
	struct stringlist_t list;
};

struct keyvaluelist_def_t {
	const char *key;
	keyvalue_parser_fnc parser;
	void *target;
	void *argument;
	bool parsed;
};

/*************** AUTO GENERATED SECTION FOLLOWS ***************/
bool keyvalue_string(char *element, void *argument, void *vresult);
bool keyvalue_longint(char *element, void *argument, void *vresult);
bool keyvalue_ipv4_nbo(char *element, void *argument, void *vresult);
bool keyvalue_bool(char *element, void *argument, void *vresult);
bool keyvalue_lookup(char *element, void *argument, void *vresult);
int parse_keyvalues_from_list(struct stringlist_t *list, unsigned int startindex, struct keyvaluelist_def_t *elements);
int parse_keyvalue_list(const char *string, unsigned int startindex, struct keyvaluelist_def_t *elements, char **positional_args);
/***************  AUTO GENERATED SECTION ENDS   ***************/

#endif
