/*
 * Longclock operations
 *
 * Copyright (c) 2002 International Business Machines
 * Author:	Alan Robertson <alanr@unix.sh>
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

#include <config.h>
#include <unistd.h>
#include <sys/times.h>
#include <clplumbing/longclock.h>

static	clock_t		lasttimes = 0L;
static	unsigned long	wrapcount = 0;

static	longclock_t	lc_wrapcount;
static	unsigned 	Hz = 0;
static	longclock_t 	Lc_Hz;
static	double		d_Hz;
static	longclock_t	ms_per_tick;

#define	WRAPSHIFT	32

unsigned
hz_longclock(void)
{
	if (Hz == 0) {
		/* Compute various hz-related constants */

		Hz = sysconf(_SC_CLK_TCK);
		Lc_Hz = Hz;
		d_Hz = (double) Hz;
		ms_per_tick = (longclock_t)(1000UL/Hz);
	}
	return Hz;
}

longclock_t
time_longclock(void)
{
	clock_t	timesval;
	struct tms	dummy;
	
	
	timesval = times(&dummy);

	if (timesval < lasttimes) {
		++wrapcount;
		lc_wrapcount = ((longclock_t)wrapcount) << WRAPSHIFT;
	}
	return (lc_wrapcount | (longclock_t)timesval);
}

longclock_t
msto_longclock(unsigned long ms)
{
	unsigned long	secs =	ms / 1000UL;
	unsigned long	msec = ms % 1000;
	longclock_t	result;

	(void)(Hz == 0 && hz_longclock());

	if (ms == 0) {
		return (longclock_t)0UL;
	}
	result = secs * Lc_Hz + (msec/ms_per_tick);

	if (result == 0) {
		result = 1;
	}
	return result;
}

longclock_t
secsto_longclock(unsigned long Secs)
{
	longclock_t	secs = Secs;

	(void)(Hz == 0 && hz_longclock());

	return secs * Lc_Hz;
}

longclock_t
dsecsto_longclock(double v)
{
	(void)(Hz == 0 && hz_longclock());

	return (longclock_t) ((v * d_Hz)+0.5);
	
}

longclock_t
add_longclock(longclock_t l, longclock_t r)
{
	return l + r;
}

int
cmp_longclock(longclock_t l, longclock_t r)
{
	if (l < r) {
		return -1;
	}
	if (l > r) {
		return 1;
	}
	return 0;
}
