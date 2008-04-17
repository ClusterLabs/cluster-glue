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


#include <lha_internal.h>

#include <strings.h>
#include  <clplumbing/cl_misc.h>
#include  <clplumbing/cl_log.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

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

/*
 *      Convert a string into a positive, rounded number of milliseconds.
 *
 *      Returns -1 on error.
 *
 *      Permissible forms:
 *              [0-9]+                  units are seconds
 *              [0-9]*.[0-9]+           units are seconds
 *              [0-9]+ *[Mm][Ss]        units are milliseconds
 *              [0-9]*.[0-9]+ *[Mm][Ss] units are milliseconds
 *              [0-9]+ *[Uu][Ss]        units are microseconds
 *              [0-9]*.[0-9]+ *[Uu][Ss] units are microseconds
 *
 *      Examples:
 *
 *              1               = 1000 milliseconds
 *              1000ms          = 1000 milliseconds
 *              1000000us       = 1000 milliseconds
 *              0.1             = 100 milliseconds
 *              100ms           = 100 milliseconds
 *              100000us        = 100 milliseconds
 *              0.001           = 1 millisecond
 *              1ms             = 1 millisecond
 *              1000us          = 1 millisecond
 *              499us           = 0 milliseconds
 *              501us           = 1 millisecond
 */

#define NUMCHARS	"0123456789."
#define WHITESPACE	" \t\n\r\f"
#define EOS		'\0'

long
cl_get_msec(const char * input)
{
	const char *	cp = input;
	const char *	units;
	long		multiplier = 1000;
	long		divisor = 1;
	long		ret = -1;
	double		dret;

	cp += strspn(cp, WHITESPACE);
	units = cp + strspn(cp, NUMCHARS);
	units += strspn(units, WHITESPACE);

	if (strchr(NUMCHARS, *cp) == NULL) {
		return ret;
	}

	if (strncasecmp(units, "ms", 2) == 0
	||	strncasecmp(units, "cl_get_msec", 4) == 0) {
		multiplier = 1;
		divisor = 1;
	}else if (strncasecmp(units, "us", 2) == 0
	||	strncasecmp(units, "usec", 4) == 0) {
		multiplier = 1;
		divisor = 1000;
	}else if (*units != EOS && *units != '\n'
	&&	*units != '\r') {
		return ret;
	}
	dret = atof(cp);
	dret *= (double)multiplier;
	dret /= (double)divisor;
	dret += 0.5;
	ret = (long)dret;
	return(ret);
}
