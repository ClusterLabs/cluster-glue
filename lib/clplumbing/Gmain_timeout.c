/* $Id: Gmain_timeout.c,v 1.16 2006/02/02 14:58:23 alan Exp $ */
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
#if 0
#include <glib.h>
#include <clplumbing/longclock.h>
#include <clplumbing/cl_log.h>
#include <clplumbing/Gmain_timeout.h>
#include <string.h>


static gboolean
Gmain_timeout_prepare(GSource* src,  gint* timeout);

static gboolean
Gmain_timeout_check(GSource* src);

static gboolean
Gmain_timeout_dispatch(GSource* src, GSourceFunc func, gpointer user_data);

static GSourceFuncs Gmain_timeout_funcs = {
	prepare: Gmain_timeout_prepare,
	check: Gmain_timeout_check,
	dispatch: Gmain_timeout_dispatch,
};


struct GTimeoutAppend {
	GSource		Source;
	longclock_t	nexttime;
	guint		interval;
	unsigned long	maxdispatchdelayms;
	unsigned long	maxdispatchms;
};

#define        GTIMEOUT(GS)    ((struct GTimeoutAppend*)((void*)(GS)))

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
	
	struct GTimeoutAppend* append;
	
	GSource* source = g_source_new( &Gmain_timeout_funcs, 
					sizeof(struct GTimeoutAppend));
	
	append = GTIMEOUT(source);
	
	append->nexttime = add_longclock(time_longclock()
					 ,msto_longclock(interval));
  	append->interval = interval; 
	append->maxdispatchms = 0;
	append->maxdispatchdelayms = 10000;
	
	g_source_set_priority(source, priority);
	
	g_source_set_can_recurse(source, FALSE);
	
	g_source_set_callback(source, function, data, notify); 
	
	return g_source_attach(source, NULL);

}

void
Gmain_timeout_remove(guint tag)
{
	GSource* source = g_main_context_find_source_by_id(NULL,tag);
	
	g_source_remove(tag);
	
	if (source != NULL){
		g_source_unref(source);
	}
	
	return;
}

/* g_main_loop-style prepare function */
static gboolean
Gmain_timeout_prepare(GSource* src,  gint* timeout)
{
	
	struct GTimeoutAppend* append = GTIMEOUT(src);
	longclock_t	lnow = time_longclock();
	longclock_t	remain;
	
	if (cmp_longclock(lnow, append->nexttime) >= 0) {
		*timeout = 0L;
		return TRUE;
	}
	/* This is safe - we will always have a positive result */
	remain = sub_longclock(append->nexttime, lnow);
	/* This is also safe - we started out in 'ms' */
	*timeout = longclockto_ms(remain);
	return ((*timeout) == 0);
}

/* g_main_loop-style check function */
static gboolean
Gmain_timeout_check    (GSource* src)
{
	struct GTimeoutAppend* append = GTIMEOUT(src);
	longclock_t	lnow = time_longclock();
	
	if (cmp_longclock(lnow, append->nexttime) >= 0) {
		return TRUE;
	}
	return FALSE;
}

/* g_main_loop-style dispatch function */
static gboolean
Gmain_timeout_dispatch(GSource* src, GSourceFunc func, gpointer user_data)
{
	struct GTimeoutAppend* append = GTIMEOUT(src);
	longclock_t	lstart = time_longclock();
	long		ms = longclockto_ms(sub_longclock(lstart, append->nexttime));
	gboolean	ret;

	if (append->maxdispatchdelayms > 0 && ms > append->maxdispatchdelayms) {
		cl_log(LOG_WARNING, "Timeout dispatch function [%lx] called %ld ms late."
		,	(unsigned long)func, ms);
	}
	

	/* Schedule our next dispatch */
	append->nexttime = add_longclock(time_longclock()
					  , msto_longclock(append->interval));

	/* Then call the user function */
	ret = func(user_data);

	/* Time it if requested */
	if (append->maxdispatchms > 0) {
		longclock_t	lend = time_longclock();
		ms = longclockto_ms(sub_longclock(lend, lstart));
		if (ms > append->maxdispatchms) {
			cl_log(LOG_WARNING, "Timeout dispatch function [%lx] took %ld ms."
			,	(unsigned long)func, ms);
		}
	}
	return ret;
}

void
Gmain_timeout_setmaxdispatchtime(GSource* src, long dispatchms)
{
	struct GTimeoutAppend* append = GTIMEOUT(src);
	append->maxdispatchms = dispatchms;
}

void
Gmain_timeout_setmaxdispatchdelay(GSource* src, long delayms)
{
	struct GTimeoutAppend* append = GTIMEOUT(src);
	append->maxdispatchdelayms = delayms;
}
#endif
