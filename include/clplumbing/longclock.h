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

#ifndef _LONGCLOCK_H
#	define _LONGCLOCK_H
/*
 *	A longclock_t object is a lot like a clock_t object, except that it
 *	won't wrap in the lifetime of the earth.  It is guaranteed to be at
 *	least 64 bits.  This means it should go for around 2 billion years.
 *
 *	It is also supposed to be proof against changes in the local time on
 *	the computer.  This is easy if you have a properly-working times(2)
 *	for us to use.
 *
 *	longclock_t's are definitely not comparable between computers, and in
 *	some implementations, not even between processes on the same computer.
 *
 *
 *	The functions provided here are:
 *
 *	longclock_t	time_longclock(void);
 *			Returns current time as a longclock_t.
 *
 *	longclock_t	msto_longclock(unsigned long);
 *			Converts quantity in milliseconds to longclock_t
 *
 *	unsigned long	longclockto_ms(longclock_t);
 *			Converts quantity in longclock_t to milliseconds
 *			NOTE: Can overflow!
 *
 *	longclock_t	secsto_longclock(unsigned long);
 *			Converts quantity in seconds to longclock_t
 *
 *	longclock_t	add_longclock(longclock_t l, longclock_t r);
 *			Adds two longclock_t values
 *
 *	int		cmp_longclock(longclock_t l, longclock_t r);
 *			Returns negative, zero or positive value
 *
 *	longclock_t	sub_longclock(longclock_t l, longclock_t r);
 *			Subtracts two longclock_t values
 *			NOTE: Undefined if l is < r
 *
 *	longclock_t	dsecsto_longclock(double);
 *			Converts quantity in seconds (as a double)
 *			to a longclock_t
 *
 *	unsigned	hz_longclock(void);
 *			Returns frequency of longclock_t clock.
 *
 *	We provide this constant:
 *
 *	extern const longclock_t	zero_longclock;
 */

#ifdef CLOCK_T_IS_LONG_ENOUGH
#	ifndef	HAVE_LONGCLOCK_ARITHMETIC
#		define	HAVE_LONGCLOCK_ARITHMETIC
#	endif

#	include <sys/times.h>
#	define	time_longclock()			\
	((longclock_t)times(&longclock_dummy_tms_struct))

	typedef clock_t longclock_t;
	extern	struct tms	longclock_dummy_tms_struct;

#else /* clock_t isn't at least 64 bits */

	typedef unsigned long long longclock_t;
	longclock_t	time_longclock(void);
#endif

extern const longclock_t	zero_longclock;

unsigned	hz_longclock(void);
longclock_t	dsecsto_longclock(double);

#ifndef HAVE_LONGCLOCK_ARITHMETIC

longclock_t	msto_longclock(unsigned long);

unsigned long	longclockto_ms(longclock_t);	/* Can overflow! */

longclock_t	secsto_longclock(unsigned long);

longclock_t	add_longclock(longclock_t l, longclock_t r);

		/* Undefined if l is < r according to cmp_longclock() */
longclock_t	sub_longclock(longclock_t l, longclock_t r);

int		cmp_longclock(longclock_t l, longclock_t r);


#else /* We HAVE_LONGCLOCK_ARITHMETIC */

#	define	secsto_longclock(l)				\
	((longclock_t)(l)*hz_longclock())

#	define	msto_longclock(l)				\
	(secs_to_longclock(l)/1000)

#	define	longclockto_ms(l)				\
	(unsigned long)(secs_to_longclock(l)/1000)

#	define	add_longclock(l,r)			\
	((longclock_t)(l) + (longclock_t)(r))

#	define	sub_longclock(l,r)			\
	((longclock_t)(l) - (longclock_t)(r))

#	define	cmp_longclock(l,r)			\
	(((longclock_t)(l) < (longclock_t)(r))		\
	?	-1					\
	: (((longclock_t)(l) > (longclock_t)(r))	\
	?	+1 : 0))
#endif


/* N.B: Possibly not the best place for this, but it will do for now */
/* This is consistent with OpenBSD, and is a good choice anyway */
#define TIME_T  unsigned long
#define TIME_F  "%lu"
#define TIME_X  "%lx"

#endif
