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

#include <stdint.h>
#include <string.h>
#include <errno.h>
#include "stringlist.h"
#include "keyvaluelist.h"
#include "logging.h"
#include "parse.h"

bool keyvalue_string(char *element, void *argument, void *vresult) {
	char **result = (char**)vresult;
	*result = strdup(element);
	if (!*result) {
		logmsg(LLVL_ERROR, "strdup(3) failed: %s", element);
	}
	return true;
}

bool keyvalue_longint(char *element, void *argument, void *vresult) {
	const char *string = element;
	long int *result = (long int*)vresult;
	return safe_strtol(&string, result, false);
}

bool keyvalue_ipv4_nbo(char *element, void *argument, void *vresult) {
	uint32_t *result = (uint32_t*)vresult;
	return parse_ipv4(element, result);
}

bool keyvalue_bool(char *element, void *argument, void *vresult) {
	bool *result = (bool*)vresult;
	if (!strcmp(element, "0") || !strcmp(element, "off") || !strcmp(element, "false") || !strcmp(element, "no")) {
		*result = false;
		return true;
	} else if (!strcmp(element, "1") || !strcmp(element, "on") || !strcmp(element, "true") || !strcmp(element, "yes")) {
		*result = true;
		return true;
	} else {
		logmsg(LLVL_ERROR, "Not a boolean value: %s", element);
	}
	return false;
}

static const struct lookup_entry_t* table_lookup(const struct lookup_entry_t *table, const char *key) {
	while (table->key) {
		if (!strcmp(table->key, key)) {
			return table;
		}
		table++;
	}
	return NULL;
}

bool keyvalue_lookup(char *element, void *argument, void *vresult) {
	const struct lookup_entry_t *table = (const struct lookup_entry_t *)argument;
	int *result = (int*)vresult;
	if (!argument) {
		logmsg(LLVL_FATAL, "Programming error: keyvalue_lookup() requested, but no lookup table specified.");
		return false;
	}
	const struct lookup_entry_t *match = table_lookup(table, element);
	if (match) {
		*result = match->value;
	} else {
		logmsg(LLVL_ERROR, "'%s' is not a valid element for this type.", element);
	}
	return match;
}

bool keyvalue_flags(char *element, void *argument, void *vresult) {
	const struct lookup_entry_t *table = (const struct lookup_entry_t *)argument;
	if (!argument) {
		logmsg(LLVL_FATAL, "Programming error: keyvalue_flags() requested, but no lookup table specified.");
		return false;
	}

	struct stringlist_t list;
	if (!parse_stringlist(&list, element, ":")) {
		logmsg(LLVL_ERROR, "Could not parse list of items: %s", element);
	}

	uint32_t *result = (uint32_t*)vresult;
	*result = 0;
	bool success = true;
	for (unsigned int i = 0; i < list.token_cnt; i++) {
		const struct lookup_entry_t *match = table_lookup(table, list.tokens[i]);
		if (!match) {
			logmsg(LLVL_ERROR, "'%s' is not a valid element for this type.", list.tokens[i]);
			success = false;
			break;
		}
		*result |= match->value;
	}

	free_stringlist(&list);
	return success;
}

static struct keyvaluelist_def_t *find_keyvalue_def(const char *element, struct keyvaluelist_def_t *elements) {
	while (elements->key) {
		if (!strcmp(elements->key, element)) {
			return elements;
		}
		elements++;
	}
	return NULL;
}

static void reset_parsed_list(struct keyvaluelist_def_t *elements) {
	while (elements->key) {
		elements->parsed = false;
		elements++;
	}
}

int parse_keyvalues_from_list(struct stringlist_t *list, unsigned int startindex, struct keyvaluelist_def_t *elements) {
	reset_parsed_list(elements);

	int successfully_parsed_cnt = 0;
	for (unsigned int i = startindex; i < list->token_cnt; i++) {
		/* First, tokenize */
		char *saveptr = NULL;
		char *key = strtok_r(list->tokens[i], "=", &saveptr);
		if (!key) {
			logmsg(LLVL_ERROR, "Did not find any tokens at keyvalue list element number %d.", i + 1);
			return -1;
		}

		struct keyvaluelist_def_t *match = find_keyvalue_def(key, elements);
		if (!match) {
			logmsg(LLVL_ERROR, "Unknown key at element number %d (\"%s\") found.", i + 1, list->tokens[i]);
			return -1;
		}

		/* Restore original string */
		saveptr[-1] = '=';

		/* Check if already parsed this element */
		if (match->parsed) {
			logmsg(LLVL_ERROR, "Key of element \"%s\" appears twice in list.", list->tokens[i]);
			return -1;
		}
		match->parsed = true;

		/* Now we have the key, parse the value */
		char *value = strtok_r(NULL, "=", &saveptr);
		if (!value) {
			logmsg(LLVL_ERROR, "Found a key, but no value as keyvalue list element number %d.", i + 1);
			return -1;
		}

		if (!match->parser(value, match->argument, match->target)) {
			logmsg(LLVL_ERROR, "Could not successfully parse key/value element number %d (\"%s\") as the requested type.", i + 1, list->tokens[i]);
			return -1;
		}
		successfully_parsed_cnt++;
	}
	return successfully_parsed_cnt;
}

int parse_keyvalue_list(const char *string, unsigned int startindex, struct keyvaluelist_def_t *elements, char **positional_args) {
	struct stringlist_t list;
	if (!parse_stringlist(&list, string, ",")) {
		logmsg(LLVL_ERROR, "Could not successfully tokenize key/value list \"%s\".", string);
		return -1;
	}
	int result = parse_keyvalues_from_list(&list, startindex, elements);
	if (positional_args) {
		memset(positional_args, 0, sizeof(char*) * startindex);
		for (int i = 0; i < startindex; i++) {
			positional_args[i] = strdup(list.tokens[i]);
			if (!positional_args[i]) {
				logmsg(LLVL_FATAL, "strdup(3) failed: %s", strerror(errno));
				for (int j = 0; j < i; j++) {
					free(positional_args[j]);
				}
				free_stringlist(&list);
				return -1;
			}
		}
	}
	free_stringlist(&list);
	return result;
}
