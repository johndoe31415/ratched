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

static void map_free_element(struct map_element_t *element);

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

static struct map_element_t* map_insert_at_end(struct map_t *map, const void *key, unsigned int key_len, const void *value, unsigned int value_len) {
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

	new_element->value_allocated = false;
	if (!map_set_value(new_element, value, value_len)) {
		free((void*)new_element->key);
		free(new_element);
		return NULL;
	}

	struct map_element_t **new_elements = realloc(map->elements, sizeof(struct map_element_t*) * (map->element_count + 1));
	if (!new_elements) {
		logmsg(LLVL_FATAL, "Failed to realloc(3) map elements: %s", strerror(errno));
		free((void*)new_element->key);
		free(new_element->ptrvalue);
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

bool map_set_value(struct map_element_t *element, const void *new_value, unsigned int new_value_len) {
	if (element->value_allocated) {
		free(element->ptrvalue);
	}

	if (new_value_len > 0) {
		element->ptrvalue = malloc(new_value_len);
		if (!element->ptrvalue) {
			logmsg(LLVL_FATAL, "Failed to malloc(3) new map element value to size of %u bytes: %s", new_value_len, strerror(errno));
			element->value_len = 0;
			return false;
		}
		element->value_allocated = true;
		if (new_value) {
			memcpy(element->ptrvalue, new_value, new_value_len);
		}
	} else {
		element->value_allocated = false;
		element->ptrvalue = (void*)new_value;
	}
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
		return element->ptrvalue;
	} else {
		return NULL;
	}
}

int map_getint(struct map_t *map, const void *key, unsigned int key_len) {
	struct map_element_t *element = map_getitem(map, key, key_len);
	if (element) {
		return element->intvalue;
	} else {
		return -1;
	}
}

struct map_element_t* map_set(struct map_t *map, const void *key, unsigned int key_len, const void *value, unsigned int value_len) {
	struct map_element_t *element = map_getitem(map, key, key_len);
	if (element) {
		map_set_value(element, value, value_len);
	} else {
		element = map_insert_at_end(map, key, key_len, value, value_len);
		map_sort_elements(map);
	}
	return element;
}

int map_get_str_int(struct map_t *map, const char *strkey) {
	return map_getint(map, strkey, strlen(strkey) + 1);
}

void* map_get_str(struct map_t *map, const char *strkey) {
	return map_get(map, strkey, strlen(strkey) + 1);
}

struct map_element_t* map_set_str(struct map_t *map, const char *strkey, const void *value, unsigned int value_len) {
	return map_set(map, strkey, strlen(strkey) + 1, value, value_len);
}

void map_set_str_int(struct map_t *map, const char *strkey, int value) {
	struct map_element_t *element = map_set(map, strkey, strlen(strkey) + 1, NULL, 0);
	element->intvalue = value;
}

void map_del_key(struct map_t *map, const void *key, unsigned int key_len) {
	int index = map_get_index(map, key, key_len);
	if (index == -1) {
		return;
	}

	map_free_element(map->elements[index]);
	memmove(map->elements + index, map->elements  + 1, (map->element_count - index - 1) * sizeof(struct map_element_t*));

	struct map_element_t **new_elements = realloc(map->elements, sizeof(struct map_element_t*) * (map->element_count - 1));
	if (!new_elements) {
		logmsg(LLVL_FATAL, "Failed to realloc(3) map elements to del element %d: %s", index, strerror(errno));
	}

	map->element_count--;
}

void strmap_set(struct map_t *map, const char *strkey, const char *strvalue) {
	map_set(map, strkey, strlen(strkey) + 1, strvalue, strlen(strvalue) + 1);
}

void strmap_del(struct map_t *map, const char *strkey) {
	map_del_key(map, strkey, strlen(strkey) + 1);
}

const char* strmap_get(struct map_t *map, const char *strkey) {
	return (const char*)map_get(map, strkey, strlen(strkey) + 1);
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
		if (element->ptrvalue) {
			if (element->value_allocated) {
				fprintf(stderr, "%d [ ", element->value_len);
				for (unsigned int j = 0; j < element->value_len; j++) {
					fprintf(stderr, "%02x ", ((const uint8_t*)element->ptrvalue)[j]);
				}
				fprintf(stderr, "]");
			} else {
				fprintf(stderr, "%p", element->ptrvalue);
			}
		} else {
			fprintf(stderr, "NULL");
		}
		fprintf(stderr, "\n");
	}
}

static void map_free_element(struct map_element_t *element) {
	free((void*)element->key);
	if (element->value_allocated) {
		free(element->ptrvalue);
	}
	free(element);
}

void map_foreach(struct map_t *map, void (*callback_fnc)(struct map_element_t *element)) {
	for (unsigned int i = 0; i < map->element_count; i++) {
		callback_fnc(map->elements[i]);
	}
}

void map_foreach_ptrvalue(struct map_t *map, void (*callback_fnc)(void *value)) {
	for (unsigned int i = 0; i < map->element_count; i++) {
		callback_fnc(map->elements[i]->ptrvalue);
	}
}

void map_free(struct map_t *map) {
	map_foreach(map, map_free_element);
	free(map->elements);
	free(map);
}

struct map_t *map_init(void) {
	struct map_t *map = calloc(1, sizeof(struct map_t));
	return map;
}
