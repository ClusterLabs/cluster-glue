/*
 * Glib mainloop timeout handling code.
 *
 * These functions work correctly even if someone resets the 
 * time-of-day clock.  The g_main_timeout_add() function does not have
 * this property, since it relies on gettimeofday().
 *
 * Our functions have the same semantics - except they always work ;-)
 *
 * This is because we use longclock_t for our time values.
 *
 * Copyright (c) 2002 Alan Robertson <alanr@unix.sh>
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
#include <glib.h>
#include <clplumbing/longclock.h>
#include <clplumbing/Gmain_timeout.h>

static struct GTimeoutSource*
Gmain_TimeoutSource_new(guint interval, GSourceFunc f);

static gboolean Gmain_timeout_prepare(gpointer     source
,	GTimeVal*	current_time, gint* timeout, gpointer udata);
static gboolean Gmain_timeout_check(gpointer     source
,	GTimeVal*current_time, gpointer user_data);
static gboolean Gmain_timeout_dispatch(gpointer source
,	GTimeVal* currtime, gpointer user_data);
static void Gmain_timeout_destroy(gpointer source);

static GSourceFuncs Gmain_timeout_funcs = {
	Gmain_timeout_prepare,
	Gmain_timeout_check,
	Gmain_timeout_dispatch,
	Gmain_timeout_destroy,
};

struct GTimeoutSource {
	longclock_t	nexttime;
	guint		interval;
	GSourceFunc	f;
};

static struct GTimeoutSource*
Gmain_TimeoutSource_new(guint interval, GSourceFunc f)
{
	struct GTimeoutSource*	gh;
	gh = g_new0(struct GTimeoutSource, 1);
	gh->nexttime = add_longclock(time_longclock()
	,	msto_longclock(interval));
	gh->interval = interval;
	gh->f = f;
	return gh;
}

guint
Gmain_timeout_add(guint interval
,	GSourceFunc	function
,	gpointer	data)
{
	return Gmain_timeout_add_full(G_PRIORITY_DEFAULT
	,	interval, function, data, NULL);
}

guint
Gmain_timeout_add_full(gint priority
,	guint interval
,	GSourceFunc	function
,	gpointer	data
,	GDestroyNotify	notify)
{
	struct GTimeoutSource*	h = Gmain_TimeoutSource_new(interval, function);

	return g_source_add(priority, FALSE
	,	&Gmain_timeout_funcs, h, data, notify);
}

/* g_main_loop-style prepare function */
static gboolean
Gmain_timeout_prepare(gpointer src, GTimeVal* t, gint* timeout
,	gpointer user_data)
{
	
	struct GTimeoutSource* source = src;
	longclock_t	lnow = time_longclock();
	longclock_t	remain;

	if (cmp_longclock(lnow, source->nexttime) >= 0) {
		*timeout = 0L;
		return TRUE;
	}
	/* This is safe - we will always have a positive result */
	remain = sub_longclock(source->nexttime, lnow);
	/* This is also safe - we started out in 'ms' */
	*timeout = longclock_to_ms(remain);
	return ((*timeout) == 0);
}

/* g_main_loop-style check function */
static gboolean
Gmain_timeout_check    (gpointer src, GTimeVal*t, gpointer udata)
{
	struct GTimeoutSource* source = src;
	longclock_t	lnow = time_longclock();

	if (cmp_longclock(lnow, source->nexttime) >= 0) {
		return TRUE;
	}
	return FALSE;
}

/* g_main_loop-style dispatch function */
static gboolean
Gmain_timeout_dispatch(gpointer src, GTimeVal*t, gpointer user_data)
{
	struct GTimeoutSource* source = src;

	/* Schedule our next dispatch */
	source->nexttime = add_longclock(time_longclock()
	,	msto_longclock(source->interval));

	/* Then call the user function */
	return source->f(user_data);
}

/* g_main_loop-style source destruction function */
static void
Gmain_timeout_destroy(gpointer source)
{
	g_free(source);
}
