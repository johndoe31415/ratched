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

#include <string.h>
#include <pthread.h>
#include "atomic.h"

void atomic_init(struct atomic_t *atomic) {
	memset(atomic, 0, sizeof(*atomic));
	pthread_mutex_init(&atomic->mutex, NULL);
	pthread_cond_init(&atomic->cond, NULL);
}

void atomic_add(struct atomic_t *atomic, int value) {
	pthread_mutex_lock(&atomic->mutex);
	atomic->value += value;
	pthread_cond_broadcast(&atomic->cond);
	pthread_mutex_unlock(&atomic->mutex);
}

void atomic_set(struct atomic_t *atomic, int value) {
	pthread_mutex_lock(&atomic->mutex);
	atomic->value = value;
	pthread_cond_broadcast(&atomic->cond);
	pthread_mutex_unlock(&atomic->mutex);
}

void atomic_inc(struct atomic_t *atomic) {
	return atomic_add(atomic, 1);
}

void atomic_dec(struct atomic_t *atomic) {
	return atomic_add(atomic, -1);
}

void atomic_wait_until_value(struct atomic_t *atomic, int value) {
	pthread_mutex_lock(&atomic->mutex);
	while (atomic->value != value) {
		pthread_cond_wait(&atomic->cond, &atomic->mutex);
	}
	pthread_mutex_unlock(&atomic->mutex);
}
