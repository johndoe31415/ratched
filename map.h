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

#ifndef __MAP_H__
#define __MAP_H__

#include <stdbool.h>

struct map_element_t {
	unsigned int key_len;
	const void *key;
	bool value_allocated;
	unsigned int value_len;
	union {
		void *ptrvalue;
		int intvalue;
	};
};

struct map_t {
	unsigned int element_count;
	struct map_element_t **elements;
};

/*************** AUTO GENERATED SECTION FOLLOWS ***************/
bool map_set_value(struct map_element_t *element, const void *new_value, unsigned int new_value_len);
struct map_element_t *map_getitem(struct map_t *map, const void *key, unsigned int key_len);
void *map_get(struct map_t *map, const void *key, unsigned int key_len);
int map_getint(struct map_t *map, const void *key, unsigned int key_len);
struct map_element_t* map_set(struct map_t *map, const void *key, unsigned int key_len, const void *value, unsigned int value_len);
int map_get_str_int(struct map_t *map, const char *strkey);
void* map_get_str(struct map_t *map, const char *strkey);
struct map_element_t* map_set_str(struct map_t *map, const char *strkey, const void *value, unsigned int value_len);
void map_set_str_int(struct map_t *map, const char *strkey, int value);
void map_del_key(struct map_t *map, const void *key, unsigned int key_len);
void strmap_set(struct map_t *map, const char *strkey, const char *strvalue);
void strmap_del(struct map_t *map, const char *strkey);
const char* strmap_get(struct map_t *map, const char *strkey);
void map_dump(const struct map_t *map);
void map_foreach(struct map_t *map, void (*callback_fnc)(struct map_element_t *element));
void map_foreach_ptrvalue(struct map_t *map, void (*callback_fnc)(void *value));
void map_free(struct map_t *map);
struct map_t *map_init(void);
/***************  AUTO GENERATED SECTION ENDS   ***************/

#endif
