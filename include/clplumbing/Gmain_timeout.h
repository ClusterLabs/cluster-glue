#ifndef _CLPLUMBING_GMAIN_TIMEOUT_H
#define _CLPLUMBING_GMAIN_TIMEOUT_H
#include <glib.h>
/*
 * Copyright (C) 2002 Alan Robertson <alanr@unix.sh>
 * This software licensed under the GNU LGPL.
 *
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
/*
 * These functions must work correctly even if someone resets the 
 * time-of-day clock.  The g_main_timeout_add() function does not have
 * this property, since it relies on gettimeofday().
 *
 * Our functions have the same semantics - except they always work ;-)
 *
 * This is because we use longclock_t for our time values.
 */
guint Gmain_timeout_add(guint interval
,	GSourceFunc	function
,	gpointer	data);

guint Gmain_timeout_add_full(gint priority
,	guint interval
,	GSourceFunc	function
,	gpointer	data
,	GDestroyNotify	notify);

void Gmain_timeout_remove(guint tag);
#endif
