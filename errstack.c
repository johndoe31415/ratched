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

#include <unistd.h>

#include "atomic.h"
#include "errstack.h"
#include "logging.h"

static void errstack_post_push(const struct errstack_t *errstack) {
	//fprintf(stderr, "-> %p %d\n", errstack, errstack->count);
}

static void errstack_post_pop(const struct errstack_t *errstack) {
	//fprintf(stderr, "<- %p %d\n", errstack, errstack->count);
}

void* errstack_push_generic_ptr(struct errstack_t *errstack, errstack_free_callback_t free_callback, void *element) {
	if (errstack->count >= MAX_ERRSTACK_DEPTH) {
		logmsg(LLVL_FATAL, "Error stack capacity exceeded (%d elements). Will leak memory.", errstack->count);
		return element;
	}
	errstack->element[errstack->count].free_callback = free_callback;
	errstack->element[errstack->count].ptrvalue = element;
	errstack->count++;
	errstack_post_push(errstack);
	return element;
}

void* errstack_push_generic_nonnull_ptr(struct errstack_t *errstack, errstack_free_callback_t free_callback, void *element) {
	if (!element) {
		return NULL;
	}
	return errstack_push_generic_ptr(errstack, free_callback, element);
}

int errstack_push_int(struct errstack_t *errstack, errstack_free_callback_t free_callback, int element) {
	if (errstack->count >= MAX_ERRSTACK_DEPTH) {
		logmsg(LLVL_FATAL, "Error stack capacity exceeded (%d elements). Will leak memory.", errstack->count);
		return element;
	}
	errstack->element[errstack->count].free_callback = free_callback;
	errstack->element[errstack->count].intvalue = element;
	errstack->count++;
	errstack_post_push(errstack);
	return element;
}

static void errstack_free_malloc(struct errstack_element_t *element) {
	free(element->ptrvalue);
}

void* errstack_push_malloc(struct errstack_t *errstack, void *element) {
	return errstack_push_generic_nonnull_ptr(errstack, errstack_free_malloc, element);
}

static void errstack_free_fd(struct errstack_element_t *element) {
	close(element->intvalue);
}

int errstack_push_fd(struct errstack_t *errstack, int fd) {
	if (fd >= 0) {
		return errstack_push_int(errstack, errstack_free_fd, fd);
	} else {
		return fd;
	}
}

void *errstack_pop_until(struct errstack_t *errstack, int keep_on_stack_cnt) {
	for (int i = errstack->count - 1; i >= keep_on_stack_cnt; i--) {
		errstack->element[i].free_callback(&errstack->element[i]);
		errstack->count--;
		errstack_post_pop(errstack);
	}
	return NULL;
}

void *errstack_pop_all(struct errstack_t *errstack) {
	return errstack_pop_until(errstack, 0);
}
