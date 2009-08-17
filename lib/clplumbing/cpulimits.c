/*
 * Functions to put dynamic limits on CPU consumption.
 *
 * Copyright (C) 2003 IBM Corporation
 *
 * Author:	<alanr@unix.sh>
 *
 * This software licensed under the GNU LGPL.
 *
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of version 2.1 of the GNU Lesser General Public
 * License as published by the Free Software Foundation.
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
 **************************************************************************
 *
 * This allows us to better catch runaway realtime processes that
 * might otherwise hang the whole system (if they're POSIX realtime
 * processes).
 *
 * We do this by getting a "lease" on CPU time, and then extending
 * the lease every so often as real time elapses.  Since we only
 * extend the lease by a bounded amount computed on the basis of an
 * upper bound of how much CPU the code is "expected" to consume during
 * the lease interval, this means that if we go into an infinite
 * loop, it is highly probable that this will be detected and our
 * process will be terminated by the operating system with a SIGXCPU.
 *
 * If you want to handle this signal, then fine... Do so...
 *
 * If not, the default is to terminate the process and produce a core
 * dump.  This is a great default for debugging...
 *
 *
 * The process is basically this:
 *  - Set the CPU percentage limit with cl_cpu_limit_setpercent()
 *	according to what you expect the CPU percentage to top out at
 *	measured over an interval at >= 60 seconds
 *  - Call cl_cpu_limit_ms_interval() to figure out how often to update
 *	the CPU limit (it returns milliseconds)
 *  - At least as often as indicated above, call cl_cpu_limit_update()
 *	to update our current CPU limit.
 *
 * These limits are approximate, so be a little conservative.
 * If you've gone into an infinite loop, it'll likely get caught ;-)
 *
 * As of this writing, this code will never set the soft CPU limit less
 * than four seconds, or greater than 60 seconds.
 *
 */
#include <lha_internal.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <clplumbing/longclock.h>
#include <unistd.h>
#include <clplumbing/cpulimits.h>
#include <clplumbing/cl_log.h>

static longclock_t	nexttimetoupdate;

/* How long between checking out CPU usage? */
static int		cpuinterval_ms = 0;

/* How much cpu (in seconds) allowed at each check interval? */
static int		cpusecs;

#define	ROUND(foo)	((int)((foo)+0.5))


/*
 * Update our current CPU limit (via setrlimit) according to our
 * current resource consumption, and our current cpu % limit
 *
 * We only set the soft CPU limit, and do not change the maximum
 * (hard) CPU limit, but we respect it if it's already set.
 *
 * As a result, this code can be used by privileged and non-privileged
 * processes.
 */

static int
update_cpu_interval(void)
{
	struct rusage	ru;
	struct rlimit	rlim;
	unsigned long	timesecs;
	unsigned long	microsec;

	/* Compute how much CPU we've used so far... */

	getrusage(RUSAGE_SELF, &ru);
	timesecs  = ru.ru_utime.tv_sec  + ru.ru_stime.tv_sec;
	microsec  = ru.ru_utime.tv_usec + ru.ru_stime.tv_usec;

	/* Round up to the next higher second */
	if (microsec > 1000000) {
		timesecs += 2;
	}else{
		timesecs += 1;
	}

	/* Compute our next CPU limit */
	timesecs += cpusecs;

	/* Figure out when we next need to update our CPU limit */
	nexttimetoupdate = add_longclock(time_longclock()
	,	msto_longclock(cpuinterval_ms));

	getrlimit(RLIMIT_CPU, &rlim);

	/* Make sure we don't exceed the hard CPU limit (if set) */
	if (rlim.rlim_max != RLIM_INFINITY && timesecs > rlim.rlim_max) {
		timesecs = rlim.rlim_max;
	}
#if 0
	cl_log(LOG_DEBUG
	,	"Setting max CPU limit to %ld seconds", timesecs);
#endif

	/* Update the OS-level soft CPU limit */
	rlim.rlim_cur = timesecs;
	return setrlimit(RLIMIT_CPU, &rlim);
}

#define	MININTERVAL	60 /* seconds */

int
cl_cpu_limit_setpercent(int ipercent)
{
	float	percent;
	int	interval;

	if (ipercent > 99) {
		ipercent = 99;
	}
	if (ipercent < 1) {
		ipercent = 1;
	}
	percent = ipercent;
	percent /= (float)100;

	interval= MININTERVAL;

	/*
	 * Compute how much CPU we will allow to be used
	 * for each check interval.
	 *
	 * Rules:
	 *  - we won't require checking more often than
	 *    every 60 seconds
	 *  - we won't limit ourselves to less than
	 *	4 seconds of CPU per checking interval
	 */
	for (;;) {
		cpusecs = ROUND((float)interval*percent);
		if (cpusecs >= 4) {
			break;
		}
		interval *= 2;
	}

	/*
	 * Now compute how long to go between updates to our CPU limit
	 * from the perspective of the OS (via setrlimit(2)).
	 *
	 * We do the computation this way because the CPU limit
	 * can only be set to the nearest second, but timers can
	 * generally be set more accurately.
	 */
	cpuinterval_ms = (int)(((float)cpusecs / percent)*1000.0);

	cl_log(LOG_DEBUG
	,	"Limiting CPU: %d CPU seconds every %d milliseconds"
	,	cpusecs, cpuinterval_ms);

	return update_cpu_interval();
}

int
cl_cpu_limit_ms_interval(void)
{
	return	cpuinterval_ms;
}

int
cl_cpu_limit_update(void)
{
	longclock_t	now = time_longclock();
	long		msleft;

	if (cpuinterval_ms <= 0) {
		return 0;
	}
	if (cmp_longclock(now, nexttimetoupdate) > 0) {
		return update_cpu_interval();
	}
	msleft = longclockto_ms(sub_longclock(nexttimetoupdate, now));
	if (msleft < 500) {
		return update_cpu_interval();
	}
	return 0;
}
int
cl_cpu_limit_disable(void)
{
	struct rlimit	rlim;
	getrlimit(RLIMIT_CPU, &rlim);
	rlim.rlim_cur = rlim.rlim_max;
	return setrlimit(RLIMIT_CPU, &rlim);
}
