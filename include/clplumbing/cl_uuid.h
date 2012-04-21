/*
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

#ifndef _CL_UUID_H_
#define _CL_UUID_H_
#include <glib.h>

typedef struct cl_uuid_s{	
	unsigned char	uuid[16];
}cl_uuid_t;

void cl_uuid_copy(cl_uuid_t* dst, cl_uuid_t* src);
void cl_uuid_clear(cl_uuid_t* uu);
int cl_uuid_compare(const cl_uuid_t* uu1, const cl_uuid_t* uu2);
void cl_uuid_generate(cl_uuid_t* out);
int cl_uuid_is_null(cl_uuid_t* uu);
int cl_uuid_parse( char *in, cl_uuid_t* uu);
#define	UU_UNPARSE_SIZEOF	37 /* Including NULL byte */
void cl_uuid_unparse(const cl_uuid_t* uu, char *out);

/* Suitable for ues as a GHashFunc from glib */
guint cl_uuid_g_hash(gconstpointer uuid_ptr);
/* Suitable for ues as a GEqualFunc from glib */
gboolean cl_uuid_g_equal(gconstpointer uuid_ptr_a, gconstpointer uuid_ptr_b);


#endif
