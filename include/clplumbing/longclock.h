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
 */

typedef unsigned long long longclock_t;

unsigned	hz_longclock(void);
longclock_t	time_longclock(void);
longclock_t	msto_longclock(unsigned long);
longclock_t	secsto_longclock(unsigned long);
longclock_t	dsecsto_longclock(double);
longclock_t	add_longclock(longclock_t l, longclock_t r);
int		cmp_longclock(longclock_t l, longclock_t r);

#endif
