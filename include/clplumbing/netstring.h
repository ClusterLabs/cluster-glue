/*
 * Intracluster message object (struct ha_msg)
 *
 * Copyright (C) 1999, 2000 Guochun Shi<gshi@unix.sh>
 * This software licensed under the GNU LGPL.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#ifndef NET_STRING_H
#define NET_STRING_H
#include <stdlib.h>
#include <stdio.h>
#include <ha_msg.h>

extern gboolean cl_msg_quiet_fmterr;

/* Convert a message to netstring data */
char*			msg2netstring(const struct ha_msg*, size_t*);
char *		msg2netstring_noauth(const struct ha_msg *m, size_t * slen);

/* Convert netstring data to a message */
struct ha_msg *		netstring2msg(const char*, size_t, int);

/* Is this netstring authentic? */
int			is_auth_netstring(const char* datap, size_t datalen, 
					  const char* authstring, size_t authlen);

void cl_set_authentication_computation_method(int (*method)(int authmethod
,	const void * data
,	size_t datalen
,	char * authstr
,	size_t authlen));

#endif
