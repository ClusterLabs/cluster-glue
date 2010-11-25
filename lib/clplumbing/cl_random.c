/*							
 * Copyright (C) 2005 Guochun Shi <gshi@ncsa.uiuc.edu>
 * Copyright (C) 2005 International Business Machines Inc.
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
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */


#include <lha_internal.h>
#include <strings.h>
#include  <clplumbing/cl_misc.h>
#include  <clplumbing/cl_log.h>
#include  <clplumbing/cl_misc.h>
#include  <clplumbing/Gmain_timeout.h>
#include  <clplumbing/cl_random.h>
#include  <clplumbing/longclock.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#ifdef HAVE_TIME_H
#include <time.h>
#endif
#include <sys/time.h>
#include <sys/times.h>

/* Used to provide seed to the random number generator */
unsigned int
cl_randseed(void)
{
	char buf[16];
	FILE* fs;
	struct timeval tv;
	const char * randdevname [] = {"/dev/urandom", "/dev/random"};
	int			idev;
#if 0
	long horrid;
#endif

	/*
	 * Notes, based on reading of man pages of Solaris, FreeBSD and Linux,
	 * and on proof-of-concept tests on Solaris and Linux (32- and 64-bit).
	 *
	 *	Reminder of a subtlety: our intention is not to return a random
	 *	number, but rather to return a random-enough seed for future
	 *	random numbers.  So don't bother trying (e.g.) "rand()" and
	 *	"random()".
	 *
	 * /dev/random and dev/urandom seem to be a related pair.  In the
	 * words of the song: "You can't have one without the other".
	 *
	 * /dev/random is probably the best.  But it can block.  The Solaris
	 * implementation can apparently honour "O_NONBLOCK" and "O_NDELAY".
	 * But can others?  For this reason, I chose not to use it at present.
	 *
	 * /dev/urandom (with the "u") is also good.  This doesn't block.
	 * But some OSes may lack it.  It is tempting to detect its presence
	 * with autoconf and use the result in a "hash-if" here.  BUT... in
	 * at least one OS, its presence can vary depending upon patch levels,
	 * so a binary/package built on an enabled machine might hit trouble
	 * when run on one where it is absent.  (And vice versa: a build on a
	 * disabled machine would be unable to take advantage of it on an
	 * enabled machine.)  Therefore always try for it at run time.
	 *
	 * "gettimeofday()" returns a random-ish number in its millisecond
	 * component.
	 *
	 * -- David Lee, Jan 2006
	 */

	/*
	 * Each block below is logically of the form:
	 *	if good-feature appears present {
	 *		try feature
	 *		if feature worked {
	 *			return its result
	 *		}
	 *	}
	 *	-- fall through to not-quite-so-good feature --
	 */

	/*
	 * Does any of the random device names work?
	 */
	for (idev=0; idev < DIMOF(randdevname); ++idev) {
		fs = fopen(randdevname[idev], "r");
		if (fs == NULL) {
			cl_log(LOG_INFO, "%s: Opening file %s failed"
		       	,	__FUNCTION__, randdevname[idev]);
		}else{
			if (fread(buf, 1, sizeof(buf), fs)!= sizeof(buf)){
				cl_log(LOG_INFO, "%s: reading file %s failed"
		       	,	__FUNCTION__, randdevname[idev]);
				fclose(fs);
			}else{
				fclose(fs);
				return (unsigned int)cl_binary_to_int(buf, sizeof(buf));
			}
		}
	}

	/*
	 * Try "gettimeofday()"; use its microsecond output.
	 * (Might it be prudent to let, say, the seconds further adjust this,
	 * in case the microseconds are too predictable?)
	 */
	if (gettimeofday(&tv, NULL) != 0) {
		cl_log(LOG_INFO, "%s: gettimeofday failed", 
		       __FUNCTION__);
	}else{
		return (unsigned int) tv.tv_usec;
	}
	/*
	 * times(2) returns the number of clock ticks since
	 * boot.  Fairly predictable, but not completely so...
	 */
	return (unsigned int) cl_times();


#if 0
	/*
	 * If all else has failed, return (as a number) the address of
	 * something on the stack.
	 * Poor, but at least it has a chance of some sort of variability.
	 */
	horrid = (long) &tv;
	return (unsigned int) horrid; /* pointer to local variable exposed */
#endif
}

static gboolean        inityet = FALSE;

static void
cl_init_random(void)
{
	if (inityet)
		return;

	inityet=TRUE;
	srand(cl_randseed());
}

int
get_next_random(void)
{
	if (!inityet)
		cl_init_random();

	return	rand();
}
