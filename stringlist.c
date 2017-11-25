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
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "stringlist.h"

bool parse_stringlist(struct stringlist_t *list, const char *string, const char *delim) {
	memset(list, 0, sizeof(struct stringlist_t));
	list->dupstr = strdup(string);
	if (!list->dupstr) {
		return false;
	}

	char *strcopy = list->dupstr;
	char *saveptr = NULL;
	char *next;
	while ((next = strtok_r(strcopy, delim, &saveptr)) != NULL) {
		char **new_tokens = realloc(list->tokens, sizeof(char*) * (list->token_cnt + 1));
		if (!new_tokens) {
			free(list->dupstr);
			free(list->tokens);
			return false;
		}
		list->tokens = new_tokens;
		list->tokens[list->token_cnt] = next;
		list->token_cnt++;
		strcopy = NULL;
	}

	return true;
}

void free_stringlist(struct stringlist_t *list) {
	free(list->dupstr);
	free(list->tokens);
}

void dump_stringlist(const struct stringlist_t *list) {
	fprintf(stderr, "%d strings in stringlist:\n", list->token_cnt);
	for (unsigned int i = 0; i < list->token_cnt; i++) {
		fprintf(stderr, "   %3d: '%s'\n", i, list->tokens[i]);
	}
}
