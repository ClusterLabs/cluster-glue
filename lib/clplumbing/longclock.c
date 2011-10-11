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

#include <lha_internal.h>
#include <unistd.h>
#include <sys/times.h>
#include <errno.h>
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
		Lc_Hz = (longclock_t)Hz;
		d_Hz = (double) Hz;
	}
	return Hz;
}

#ifdef	TIMES_ALLOWS_NULL_PARAM
#	define	TIMES_PARAM	NULL
#else
	static struct tms	dummy_longclock_tms_struct;
#	define	TIMES_PARAM	&dummy_longclock_tms_struct
#endif

unsigned long
cl_times(void)	/* Make times(2) behave rationally on Linux */
{
	clock_t		ret;
#ifndef DISABLE_TIMES_KLUDGE
	int		save_errno = errno;

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
	errno	= 0;
#endif /* DISABLE_TIMES_KLUDGE */
	ret	= times(TIMES_PARAM);

#ifndef DISABLE_TIMES_KLUDGE
/*
 *	This is to work around a bug in the system call interface
 *	for times(2) found in glibc on Linux (and maybe elsewhere)
 *	It changes the return values from -1 to -4096 all into
 *	-1 and then dumps the -(return value) into errno.
 *
 *	This totally bizarre behavior seems to be widespread in
 *	versions of Linux and glibc.
 *
 *	Many thanks to Wolfgang Dumhs <wolfgang.dumhs (at) gmx.at>
 *	for finding and documenting this bizarre behavior.
 */
	if (errno != 0) {
		ret = (clock_t) (-errno);
	}
	errno = save_errno;
#endif /* DISABLE_TIMES_KLUDGE */

	/* sizeof(long) may be larger than sizeof(clock_t).
	 * Don't jump from 0x7fffffff to 0xffffffff80000000
	 * because of sign extension.
	 * We do expect sizeof(clock_t) <= sizeof(long), however.
	 */
	BUILD_BUG_ON(sizeof(clock_t) > sizeof(unsigned long));
#define CLOCK_T_MAX	(~0UL >> (8*(sizeof(unsigned long) - sizeof(clock_t))))
	return (unsigned long)ret & CLOCK_T_MAX;
}

#ifdef CLOCK_T_IS_LONG_ENOUGH
longclock_t
time_longclock(void)
{
	/* See note below about deliberately ignoring errors... */
	return (longclock_t)cl_times();
}

#else	/* clock_t is shorter than 64 bits */

#define	BITSPERBYTE	8
#define	WRAPSHIFT	(BITSPERBYTE*sizeof(clock_t))
#define	WRAPAMOUNT	(((longclock_t) 1) << WRAPSHIFT)
#define	MINJUMP		((CLOCK_T_MAX/100UL)*99UL)

longclock_t
time_longclock(void)
{
	/* Internal note: This updates the static fields; care should be
	 * taken to not call a function like cl_log (which internally
	 * calls time_longclock() as well) just before this happens,
	 * because then this can recurse infinitely; that is why the
	 * cl_log call is where it is; found by Simon Graham. */
	static	gboolean	calledbefore	= FALSE;
	static	unsigned long	lasttimes	= 0L;
	static	unsigned long	callcount	= 0L;
	static	longclock_t	lc_wrapcount	= 0L;
	unsigned long		timesval;

	++callcount;

	timesval = cl_times();

	if (calledbefore && timesval < lasttimes)  {
		unsigned long jumpbackby = lasttimes - timesval;

		if (jumpbackby < MINJUMP) {
			/* Kernel weirdness */
			cl_log(LOG_CRIT
			,	"%s: clock_t from times(2) appears to"
			" have jumped backwards (in error)!"
			,	__FUNCTION__);
			cl_log(LOG_CRIT
			,	"%s: old value was %lu"
			", new value is %lu, diff is %lu, callcount %lu"
			,	__FUNCTION__
			,	(unsigned long)lasttimes
			,	(unsigned long)timesval
			,	(unsigned long)jumpbackby
			,	callcount);
			/* Assume jump back was the error and ignore it */
			/* (i.e., hope it goes away) */
		}else{
			/* Normal looking wraparound */
			/* update last time BEFORE loging as log call
			   can call this routine recursively leading
			   to double update of wrapcount! */

			lasttimes = timesval;
			lc_wrapcount += WRAPAMOUNT;

			cl_log(LOG_INFO
			,	"%s: clock_t wrapped around (uptime)."
			,	__FUNCTION__);
		}
	}
	else {
		lasttimes = timesval;
		calledbefore = TRUE;
	}
	return (lc_wrapcount | timesval);
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
