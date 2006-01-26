/*							
 * Copyright (C) 2005 Guochun Shi <gshi@ncsa.uiuc.edu>
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


#include <strings.h>
#include  <clplumbing/cl_misc.h>
#include  <clplumbing/cl_log.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#ifdef HAVE_TIME_H
#include <time.h>
#endif

#include <sys/time.h>

int
cl_str_to_boolean(const char * s, int * ret)
{
	if(s == NULL) {
		return HA_FAIL;
	}
	
	if (	strcasecmp(s, "true") == 0
	||	strcasecmp(s, "on") == 0
	||	strcasecmp(s, "yes") == 0
	||	strcasecmp(s, "y") == 0
	||	strcasecmp(s, "1") == 0){
		*ret = TRUE;
		return HA_OK;
	}
	if (	strcasecmp(s, "false") == 0
	||	strcasecmp(s, "off") == 0
	||	strcasecmp(s, "no") == 0
	||	strcasecmp(s, "n") == 0
	||	strcasecmp(s, "0") == 0){
		*ret = FALSE;
		return HA_OK;
	}
	return HA_FAIL;
}

int
cl_file_exists(const char* filename)
{
	struct stat st;

	if (filename == NULL){
		cl_log(LOG_ERR, "%s: NULL filename", 
		       __FUNCTION__);
		return FALSE;
	}

	if (lstat(filename, &st) == 0){	
		return  S_ISREG(st.st_mode);
	}
	
	return FALSE;
}

char*
cl_get_env(const char* env_name)
{	
	if (env_name == NULL){
		cl_log(LOG_ERR, "%s: null name",
		       __FUNCTION__);
		return NULL;
	}
	
	return getenv(env_name);
}


int
cl_binary_to_int(const char* data, int len)
{
	const char *p = data;
	const char *pmax = p + len;
	guint h = *p;
	
	if (h){
		for (p += 1; p < pmax; p++){
			h = (h << 5) - h + *p;
		}
	}
	
	return h;
}

/* Used to provide seed to the random number generator */
int
cl_random(void)
{
	char buf[16];
	FILE* fs;
	struct timeval tv;
	long horrid;

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
	 * Does "/dev/urandom" work?
	 */
	fs = fopen("/dev/urandom", "r");
	if (fs == NULL) {
		cl_log(LOG_INFO, "%s: Opening file /dev/urandom failed", 
		       __FUNCTION__);
	}
	else {
		if (fread(buf,1, sizeof(buf), fs)!= sizeof(buf)){
			cl_log(LOG_INFO, "%s: reading file /dev/urandom failed",
			       __FUNCTION__);
		}
		else {
			return cl_binary_to_int(buf, sizeof(buf));
		}	
	}

	/*
	 * Try "gettimeofday()"; use its microsecond output.
	 * (Might it be prudent to let, say, the seconds further adjust this,
	 * in case * the microseconds are too predictable?)
	 */
	if (gettimeofday(&tv, NULL) != 0) {
		cl_log(LOG_INFO, "%s: gettimeofday failed", 
		       __FUNCTION__);
	}
	else {
		return tv.tv_usec;
	}

	/*
	 * If all else has failed, return (as a number) the address of
	 * something on the stack.
	 * Poor, but at least it has a chance of some sort of variability.
	 */
	horrid = (long) &tv;
	return (int) horrid;
}
