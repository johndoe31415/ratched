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

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "map.h"
#include "logging.h"

static void map_element_free(struct map_element_t *element);
static void map_element_value_free(struct map_element_t *element);

static int map_element_cmp(const void *vptr1, const void *vptr2) {
	const struct map_element_t **ptr1 = (const struct map_element_t**)vptr1;
	const struct map_element_t **ptr2 = (const struct map_element_t**)vptr2;
	const struct map_element_t *a = *ptr1;
	const struct map_element_t *b = *ptr2;
	if (a->key_len == b->key_len) {
		/* Key lengths are equal, compare memory */
		return memcmp(a->key, b->key, a->key_len);
	} else if (a->key_len < b->key_len) {
		return -1;
	} else {
		return 1;
	}
}

static struct map_element_t* map_insert_at_end(struct map_t *map, const void *key, const unsigned int key_len, const enum map_element_type_t value_type, const union value_t value, const unsigned int value_len) {
	struct map_element_t *new_element = malloc(sizeof(struct map_element_t));
	if (!new_element) {
		logmsg(LLVL_FATAL, "Failed to malloc(3) new map element: %s", strerror(errno));
		return NULL;
	}
	new_element->key_len = key_len;
	new_element->key = malloc(key_len);
	if (!new_element->key) {
		logmsg(LLVL_FATAL, "Failed to malloc(3) new map element's key memory: %s", strerror(errno));
		free(new_element);
		return NULL;
	}
	memcpy((void*)new_element->key, key, key_len);

	new_element->value_type = UNDEFINED;
	if (!map_set_value(new_element, value_type, value, value_len)) {
		free((void*)new_element->key);
		free(new_element);
		return NULL;
	}

	struct map_element_t **new_elements = realloc(map->elements, sizeof(struct map_element_t*) * (map->element_count + 1));
	if (!new_elements) {
		logmsg(LLVL_FATAL, "Failed to realloc(3) map elements: %s", strerror(errno));
		free((void*)new_element->key);
		free(new_element->value.pointer);
		free(new_element);
		return NULL;
	}
	map->elements = new_elements;
	map->elements[map->element_count] = new_element;
	map->element_count++;
	return new_element;
}

static void map_sort_elements(struct map_t *map) {
	qsort(map->elements, map->element_count, sizeof(struct map_element_t*), map_element_cmp);
}

bool map_set_value(struct map_element_t *element, const enum map_element_type_t value_type, const union value_t new_value, const unsigned int new_value_len) {
	map_element_value_free(element);

	if (value_type == ALLOCED_MEMORY) {
		element->value.pointer = malloc(new_value_len);
		if (!element->value.pointer) {
			logmsg(LLVL_FATAL, "Failed to malloc(3) new map element value to size of %u bytes: %s", new_value_len, strerror(errno));
			element->value_len = 0;
			return false;
		}
		if (new_value.pointer) {
			memcpy(element->value.pointer, new_value.pointer, new_value_len);
		}
	} else if (value_type == VOID_PTR) {
		element->value.pointer = new_value.pointer;
	} else if (value_type == INTEGER) {
		element->value.integer = new_value.integer;
	}
	element->value_type = value_type;
	element->value_len = new_value_len;
	return true;
}

static int map_get_index(struct map_t *map, const void *key, unsigned int key_len) {
	if (map->element_count == 0) {
		return -1;
	}
	struct map_element_t search_key = {
		.key = key,
		.key_len = key_len,
	};
	struct map_element_t *search_key_ptr = &search_key;
	struct map_element_t **result = (struct map_element_t**)bsearch(&search_key_ptr, map->elements, map->element_count, sizeof(struct map_element_t*), map_element_cmp);
	if (!result) {
		return -1;
	} else {
		return result - map->elements;
	}
}

struct map_element_t *map_getitem(struct map_t *map, const void *key, unsigned int key_len) {
	int index = map_get_index(map, key, key_len);
	if (index < 0) {
		return NULL;
	} else {
		return map->elements[index];
	}
}

void *map_get(struct map_t *map, const void *key, unsigned int key_len) {
	struct map_element_t *element = map_getitem(map, key, key_len);
	if (element) {
		if ((element->value_type == ALLOCED_MEMORY) || (element->value_type == VOID_PTR)) {
			return element->value.pointer;
		} else {
			logmsg(LLVL_FATAL, "Type mismatch at map_get(): Wanted pointer, but element type is 0x%x.", element->value_type);
		}
	}
	return NULL;
}

int map_get_int(struct map_t *map, const void *key, unsigned int key_len) {
	struct map_element_t *element = map_getitem(map, key, key_len);
	if (element) {
		if (element->value_type == INTEGER) {
			return element->value.integer;
		} else {
			logmsg(LLVL_FATAL, "Type mismatch at map_get_int(): Wanted integer, but element type is 0x%x.", element->value_type);
		}
	}
	return -1;
}

struct map_element_t* map_set(struct map_t *map, const void *key, const unsigned int key_len, enum map_element_type_t value_type, const union value_t value, const unsigned int value_len) {
	struct map_element_t *element = map_getitem(map, key, key_len);
	if (element) {
		map_set_value(element, value_type, value, value_len);
	} else {
		element = map_insert_at_end(map, key, key_len, value_type, value, value_len);
		map_sort_elements(map);
	}
	return element;
}

struct map_element_t* map_set_mem(struct map_t *map, const void *key, const unsigned int key_len, const void *value, const unsigned int value_len) {
	union value_t uvalue = {
		.pointer = (void*)value,
	};
	return map_set(map, key, key_len, ALLOCED_MEMORY, uvalue, value_len);
}

struct map_element_t* map_set_ptr(struct map_t *map, const void *key, const unsigned int key_len, const void *value) {
	union value_t uvalue = {
		.pointer = (void*)value,
	};
	return map_set(map, key, key_len, VOID_PTR, uvalue, 0);
}

struct map_element_t* map_set_int(struct map_t *map, const void *key, const unsigned int key_len, int value) {
	union value_t uvalue = {
		.integer = value,
	};
	return map_set(map, key, key_len, INTEGER, uvalue, 0);
}

void map_del_key(struct map_t *map, const void *key, unsigned int key_len) {
	int index = map_get_index(map, key, key_len);
	if (index == -1) {
		return;
	}

	map_element_free(map->elements[index]);
	memmove(map->elements + index, map->elements  + 1, (map->element_count - index - 1) * sizeof(struct map_element_t*));

	struct map_element_t **new_elements = realloc(map->elements, sizeof(struct map_element_t*) * (map->element_count - 1));
	if (!new_elements) {
		logmsg(LLVL_FATAL, "Failed to realloc(3) map elements to del element %d: %s", index, strerror(errno));
	}

	map->element_count--;
}

struct map_element_t *strmap_set_mem(struct map_t *map, const char *strkey, const void *value, const unsigned int value_len) {
	return map_set_mem(map, strkey, strlen(strkey) + 1, value, value_len);
}

struct map_element_t *strmap_set_ptr(struct map_t *map, const char *strkey, void *value) {
	return map_set_ptr(map, strkey, strlen(strkey) + 1, value);
}

struct map_element_t *strmap_set_str(struct map_t *map, const char *strkey, const char *strvalue) {
	return map_set_mem(map, strkey, strlen(strkey) + 1, (void*)strvalue, strlen(strvalue) + 1);
}

struct map_element_t *strmap_set_int(struct map_t *map, const char *strkey, int value) {
	return map_set_int(map, strkey, strlen(strkey) + 1, value);
}

bool strmap_has(struct map_t *map, const char *strkey) {
	return (map_getitem(map, strkey, strlen(strkey) + 1) != NULL);
}

void* strmap_get(struct map_t *map, const char *strkey) {
	return map_get(map, strkey, strlen(strkey) + 1);
}

const char* strmap_get_str(struct map_t *map, const char *strkey) {
	return (const char*)strmap_get(map, strkey);
}

int strmap_get_int(struct map_t *map, const char *strkey) {
	return map_get_int(map, strkey, strlen(strkey) + 1);
}

void strmap_del(struct map_t *map, const char *strkey) {
	map_del_key(map, strkey, strlen(strkey) + 1);
}

void map_dump(const struct map_t *map) {
	fprintf(stderr, "%d elements in map:\n", map->element_count);
	for (unsigned int i = 0; i < map->element_count; i++) {
		const struct map_element_t *element = map->elements[i];
		fprintf(stderr, "%3d: %d [ ", i, element->key_len);
		for (unsigned int j = 0; j < element->key_len; j++) {
			fprintf(stderr, "%02x ", ((const uint8_t*)element->key)[j]);
		}
		fprintf(stderr, "] = ");
		if (element->value_type == ALLOCED_MEMORY) {
			fprintf(stderr, "%d [ ", element->value_len);
			for (unsigned int j = 0; j < element->value_len; j++) {
				fprintf(stderr, "%02x ", ((const uint8_t*)element->value.pointer)[j]);
			}
			fprintf(stderr, "]");
		} else if (element->value_type == VOID_PTR) {
			fprintf(stderr, "%p", element->value.pointer);
		} else if (element->value_type == INTEGER) {
			fprintf(stderr, "%d", element->value.integer);
		} else if (element->value_type == UNDEFINED) {
			fprintf(stderr, "undefined");
		} else {
			fprintf(stderr, "unknown");
		}
		fprintf(stderr, "\n");
	}
}

static void map_element_value_free(struct map_element_t *element) {
	if (element->value_type == ALLOCED_MEMORY) {
		free(element->value.pointer);
		element->value_type = UNDEFINED;
	}
}

static void map_element_free(struct map_element_t *element) {
	free((void*)element->key);
	map_element_value_free(element);
	free(element);
}

void map_foreach(struct map_t *map, void (*callback_fnc)(struct map_element_t *element)) {
	for (unsigned int i = 0; i < map->element_count; i++) {
		callback_fnc(map->elements[i]);
	}
}

void map_foreach_ptrvalue(struct map_t *map, void (*callback_fnc)(void *value)) {
	for (unsigned int i = 0; i < map->element_count; i++) {
		callback_fnc(map->elements[i]->value.pointer);
	}
}

void map_free(struct map_t *map) {
	map_foreach(map, map_element_free);
	free(map->elements);
	free(map);
}

struct map_t *map_new(void) {
	struct map_t *map = calloc(1, sizeof(struct map_t));
	return map;
}
