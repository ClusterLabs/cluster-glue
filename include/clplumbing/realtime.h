/*
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
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _CLPLUMBING_REALTIME_H
#	define _CLPLUMBING_REALTIME_H
#	include <sched.h>

#if defined(SCHED_RR) && defined(_POSIX_PRIORITY_SCHEDULING) && !defined(ON_DARWIN)
#       define DEFAULT_REALTIME_POLICY SCHED_RR
#endif

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
(	int spolicy,	/* SCHED_RR or SCHED_FIFO (or SCHED_OTHER) */
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
/* Number of bytes we "got from the well" for memory after becoming realtime */
unsigned long cl_nonrealtime_malloc_size(void);

#endif
