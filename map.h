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

enum map_element_type_t {
	UNDEFINED,
	ALLOCED_MEMORY,
	VOID_PTR,
	INTEGER,
};

union value_t {
	void *pointer;
	int integer;
};

struct map_element_t {
	unsigned int key_len;
	const void *key;
	enum map_element_type_t value_type;
	unsigned int value_len;
	union value_t value;
};

struct map_t {
	unsigned int element_count;
	struct map_element_t **elements;
};

/*************** AUTO GENERATED SECTION FOLLOWS ***************/
bool map_set_value(struct map_element_t *element, const enum map_element_type_t value_type, const union value_t new_value, const unsigned int new_value_len);
struct map_element_t *map_getitem(struct map_t *map, const void *key, unsigned int key_len);
void *map_get(struct map_t *map, const void *key, unsigned int key_len);
int map_get_int(struct map_t *map, const void *key, unsigned int key_len);
struct map_element_t* map_set(struct map_t *map, const void *key, const unsigned int key_len, enum map_element_type_t value_type, const union value_t value, const unsigned int value_len);
struct map_element_t* map_set_mem(struct map_t *map, const void *key, const unsigned int key_len, const void *value, const unsigned int value_len);
struct map_element_t* map_set_ptr(struct map_t *map, const void *key, const unsigned int key_len, const void *value);
struct map_element_t* map_set_int(struct map_t *map, const void *key, const unsigned int key_len, int value);
void map_del_key(struct map_t *map, const void *key, unsigned int key_len);
struct map_element_t *strmap_set_mem(struct map_t *map, const char *strkey, const void *value, const unsigned int value_len);
struct map_element_t *strmap_set_ptr(struct map_t *map, const char *strkey, void *value);
struct map_element_t *strmap_set_str(struct map_t *map, const char *strkey, const char *strvalue);
struct map_element_t *strmap_set_int(struct map_t *map, const char *strkey, int value);
void* strmap_get(struct map_t *map, const char *strkey);
const char* strmap_get_str(struct map_t *map, const char *strkey);
int strmap_get_int(struct map_t *map, const char *strkey);
void strmap_del(struct map_t *map, const char *strkey);
void map_dump(const struct map_t *map);
void map_foreach(struct map_t *map, void (*callback_fnc)(struct map_element_t *element));
void map_foreach_ptrvalue(struct map_t *map, void (*callback_fnc)(void *value));
void map_free(struct map_t *map);
struct map_t *map_new(void);
/***************  AUTO GENERATED SECTION ENDS   ***************/

#endif
