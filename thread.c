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

#include <pthread.h>
#include "thread.h"

bool start_detached_thread(void* (*thread_fnc)(void*), void *argument) {
	pthread_t thread;
	pthread_attr_t thread_attrs;
	pthread_attr_init(&thread_attrs);
	pthread_attr_setdetachstate(&thread_attrs, PTHREAD_CREATE_DETACHED);
	return pthread_create(&thread, &thread_attrs, (void* (*)(void*))thread_fnc, argument) == 0;
}
