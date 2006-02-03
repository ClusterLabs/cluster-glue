/* $Id: longclock.c,v 1.17 2006/02/03 15:27:30 alan Exp $ */
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

#include <portability.h>
#include <unistd.h>
#include <sys/times.h>
#include <clplumbing/longclock.h>
#include <clplumbing/cl_log.h>

static	unsigned 	Hz = 0;
static	longclock_t 	Lc_Hz;
static	double		d_Hz;


const longclock_t	zero_longclock = 0UL;

#ifndef CLOCK_T_IS_LONG_ENOUGH
#	undef time_longclock
#endif

#ifdef HAVE_LONGCLOCK_ARITHMETIC
#	undef	msto_longclock
#	undef	longclockto_ms
#	undef	secsto_longclock
#	undef	add_longclock
#	undef	sub_longclock
#	undef	cmp_longclock
#endif


unsigned
hz_longclock(void)
{
	if (Hz == 0) {
		/* Compute various hz-related constants */

		Hz = sysconf(_SC_CLK_TCK);
		Lc_Hz = Hz;
		d_Hz = (double) Hz;
	}
	return Hz;
}

static struct tms	longclock_dummy_tms_struct;
#ifdef CLOCK_T_IS_LONG_ENOUGH
longclock_t
time_longclock(void)
{

	/* See note below about deliberately ignoring errors... */
	return (longclock_t)times(&longclock_dummy_tms_struct);
}

#else	/* clock_t is shorter than 64 bits */

#define	BITSPERBYTE	8
#define	WRAPSHIFT	(BITSPERBYTE*sizeof(clock_t))
#define MAXIMUMULONG	((unsigned long)~(0UL))
#define ENDTIMES	((MAXIMUMULONG/100UL)*99UL)
#define NEWERA		(MAXIMUMULONG/100UL)

longclock_t
time_longclock(void)
{
	static	gboolean	calledbefore	= FALSE;
	static	unsigned long	lasttimes	= 0L;
	static	unsigned long	wrapcount	= 0L;
	static	longclock_t	lc_wrapcount	= 0L;
	static	unsigned long	callcount	= 0L;
	unsigned long		timesval;

	++callcount;
	/*
	 * times(2) really returns an unsigned value ...
	 *
	 * We don't check to see if we got back the error value (-1), because
	 * the only possibility for an error would be if the address of 
	 * longclock_dummy_tms_struct was invalid.  Since it's a
	 * compiler-generated address, we assume that errors are impossible.
	 * And, unfortunately, it is quite possible for the correct return
	 * from times(2) to be exactly (clock_t)-1.  Sigh...
	 *
	 */
	timesval = (unsigned long) times(&longclock_dummy_tms_struct);

	if (calledbefore && timesval < lasttimes)  {
		if ((lasttimes - timesval) <= 2UL) {
			/* Some kind of (SMP) kernel weirdness */
			timesval = lasttimes;
		}else{
			++wrapcount;
			lc_wrapcount = ((longclock_t)wrapcount) << WRAPSHIFT;
			if (lasttimes < ENDTIMES || timesval >= NEWERA) {
				/* Clock jumped a long way(!) */
				cl_log(LOG_CRIT
				,	"%s: clock_t from times(2) appears to"
				" have jumped backwards!"
				,	__FUNCTION__);
				cl_log(LOG_CRIT
				,	"%s: old value was %lu"
				", new value is %lu, callcount %lu"
				,	__FUNCTION__, lasttimes, timesval
				,	callcount);
			}
		}
	}
	lasttimes = timesval;
	calledbefore = TRUE;
	return (lc_wrapcount | (longclock_t)timesval);
}
#endif	/* ! CLOCK_T_IS_LONG_ENOUGH */

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
	result = secs * Lc_Hz + (msec * Lc_Hz)/1000;

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

unsigned long
longclockto_ms(longclock_t t)
{
	(void)(Hz == 0 && hz_longclock());

	if (t == 0) {
		return 0UL;
	}
	return (unsigned long) ((t*1000UL)/Lc_Hz);
}
#ifndef CLOCK_T_IS_LONG_ENOUGH
long
longclockto_long(longclock_t t)
{
	return	((long)(t));
}

longclock_t
add_longclock(longclock_t l, longclock_t r)
{
	return l + r;
}

longclock_t
sub_longclock(longclock_t l, longclock_t r)
{
	return l - r;
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
#endif /* CLOCK_T_IS_LONG_ENOUGH */
