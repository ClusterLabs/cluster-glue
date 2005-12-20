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


int
cl_random(void)
{
	char buf[16];
	
	FILE* fs = fopen("/dev/urandom", "r");
	if (fs == NULL){
		cl_log(LOG_ERR, "%s: Opening file failed", 
		       __FUNCTION__);
		return -1;
	}
	
	if (fread(buf,1, sizeof(buf), fs)!= sizeof(buf)){
		cl_log(LOG_ERR, "%s: reading file failed",
		       __FUNCTION__);
		return -1;
	}	
	
	return cl_binary_to_int(buf, sizeof(buf));
}
