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

#ifndef __TOOLS_H__
#define __TOOLS_H__

#include <stdbool.h>

/*************** AUTO GENERATED SECTION FOLLOWS ***************/
bool select_read(int fd, double timeout_secs);
bool pathtok(const char *path, bool (*callback)(const char *path, void *arg), void *arg);
bool makedirs(const char *path);
bool strxcat(char *dest, int bufsize, ...);
char *spnprintf(char *buf, int *size, const char *fmt, ...);
/***************  AUTO GENERATED SECTION ENDS   ***************/

#endif
