/* $Id: realtime.h,v 1.6 2004/02/17 22:11:58 lars Exp $ */
#ifndef _CLPLUMBING_REALTIME_H
#	define _CLPLUMBING_REALTIME_H
#	include <sched.h>

/*
 *
 * make_realtime() will make the current process a soft realtime process
 * and lock it into memory after growing the heap by heapgrowK*1024 bytes
 *
 * If you set spolicy or priority to <= 0, then defaults will be used.
 * Otherwise you need to use a value for spolicy from <sched.h>
 * and use an appropriate priority for the given spolicy.
 *
 * WARNING: badly behaved programs which use the make_realtime() function
 * can easily hang the machine.
 */

void cl_make_realtime
(	int spolicy,	/* SCHED_RR or SCHED_FIFO */
	int priority,	/* typically 1-99 */
	int stackgrowK,	/* Amount to grow stack by */
	int heapgrowK	/* Amount to grow heap by */
);

void cl_make_normaltime(void);

/* Cause calls to make_realtime() to be ignored */
void cl_disable_realtime(void);

/* Cause calls to make_realtime() to be accepted.
 * This is the default behaviour */
void cl_enable_realtime(void);

/* Sleep a really short (the shortest) time */
int cl_shortsleep(void);

/* Print messages if we've done (more) non-realtime mallocs */
void cl_realtime_malloc_check(void);

/* Number of times we "go to the well" for memory after becoming realtime */
int cl_nonrealtime_malloc_count(void);

#endif
