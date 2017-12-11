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

#ifndef __ATOMIC_H__
#define __ATOMIC_H__

#include <stdbool.h>
#include <pthread.h>
#include "errstack.h"

struct atomic_t {
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	int value;
};

/*************** AUTO GENERATED SECTION FOLLOWS ***************/
void atomic_init(struct atomic_t *atomic);
void atomic_add(struct atomic_t *atomic, int value);
void atomic_set(struct atomic_t *atomic, int value);
bool atomic_test_and_set(struct atomic_t *atomic);
void atomic_inc(struct atomic_t *atomic);
void atomic_dec(struct atomic_t *atomic);
void atomic_wait_until_value(struct atomic_t *atomic, int value);
void errstack_push_atomic_dec(struct errstack_t *errstack, struct atomic_t *element);
/***************  AUTO GENERATED SECTION ENDS   ***************/

#endif
