#ifndef _CLPLUMBING_GMAIN_TIMEOUT_H
#define _CLPLUMBING_GMAIN_TIMEOUT_H
#include <glib.h>
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
#endif
