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

#ifndef __ERRSTACK_H__
#define __ERRSTACK_H__

#define MAX_ERRSTACK_DEPTH	16

struct errstack_element_t;
typedef void (*errstack_free_callback_t)(struct errstack_element_t *);

struct errstack_element_t {
	errstack_free_callback_t free_callback;
	union {
		void *ptrvalue;
		int intvalue;
	};
};

struct errstack_t {
	int count;
	struct errstack_element_t element[MAX_ERRSTACK_DEPTH];
};

#define ERRSTACK_INIT		{ .count = 0 }

/*************** AUTO GENERATED SECTION FOLLOWS ***************/
void* errstack_push_generic_ptr(struct errstack_t *errstack, errstack_free_callback_t free_callback, void *element);
void* errstack_push_generic_nonnull_ptr(struct errstack_t *errstack, errstack_free_callback_t free_callback, void *element);
int errstack_push_int(struct errstack_t *errstack, errstack_free_callback_t free_callback, int element);
void* errstack_push_malloc(struct errstack_t *errstack, void *element);
int errstack_push_fd(struct errstack_t *errstack, int fd);
void *errstack_pop_until(struct errstack_t *errstack, int keep_on_stack_cnt);
void *errstack_pop_all(struct errstack_t *errstack);
/***************  AUTO GENERATED SECTION ENDS   ***************/

#endif
