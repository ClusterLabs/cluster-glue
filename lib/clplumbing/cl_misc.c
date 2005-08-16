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
int
cl_str_to_boolean(const char * s, int * ret)
{
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
