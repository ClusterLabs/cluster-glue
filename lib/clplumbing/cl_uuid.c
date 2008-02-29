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

#include <lha_internal.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
/*
 * uuid: wrapper declarations.
 *
 *	heartbeat originally used "uuid" functionality by calling directly,
 *	and only, onto the "e2fsprogs" implementation.
 *
 *	The run-time usages in the code have since been abstracted, funnelled
 *	through a thin, common interface layer: a Good Thing.
 *
 *	Similarly, the compile-time usages of "include <uuid/uuid.h>" are
 *	replaced, being funnelled through a reference to this header file.
 *
 *	This header file interfaces onto the actual underlying implementation.
 *	In the case of the "e2fsprogs" implementation, it is simply a stepping
 *	stone onto "<uuid/uuid.h>".  As other implementations are accommodated,
 *	so their header requirements can be accommodated here.
 *
 * Copyright (C) 2004 David Lee <t.d.lee@durham.ac.uk>
 */

#if defined (HAVE_UUID_UUID_H)
/*
 * Almost certainly the "e2fsprogs" implementation.
 */
#	include <uuid/uuid.h>

/* elif defined(HAVE...UUID_OTHER_1 e.g. OSSP ...) */

/* elif defined(HAVE...UUID_OTHER_2...) */
#else
#	include <replace_uuid.h>
#endif

#include <clplumbing/cl_uuid.h>
#include <clplumbing/cl_log.h>
#include <assert.h>

void
cl_uuid_copy(cl_uuid_t* dst, cl_uuid_t* src)
{
	if (dst == NULL || src == NULL){
		cl_log(LOG_ERR, "cl_uuid_copy: "
		       "wrong argument %s is NULL",
		       dst == NULL?"dst":"src");
		assert(0);
	}
	
	uuid_copy(dst->uuid, src->uuid);		
}

void 
cl_uuid_clear(cl_uuid_t* uu)
{
	if (uu == NULL){
		cl_log(LOG_ERR, "cl_uuid_clear: "
		       "wrong argument (uu is NULL)");
		assert(0);
	}
	
	uuid_clear(uu->uuid);
	
}

int 
cl_uuid_compare(const cl_uuid_t* uu1, const cl_uuid_t* uu2)
{
	if (uu1 == NULL || uu2 == NULL){
		cl_log(LOG_ERR, "cl_uuid_compare: "
		       " wrong argument (%s is NULL)",
		       uu1 == NULL?"uu1":"uu2");
		assert(0);
	}
	
	return uuid_compare(uu1->uuid, uu2->uuid);

}



void
cl_uuid_generate(cl_uuid_t* out)
{
	if (out == NULL){
		cl_log(LOG_ERR, "cl_uuid_generate: "
		       " wrong argument (out is NULL)");
		assert(0);
	}

	uuid_generate(out->uuid);
	
}

int
cl_uuid_is_null(cl_uuid_t* uu)
{
	if (uu == NULL){
		cl_log(LOG_ERR, "cl_uuid_is_null: "
		       "wrong argument (uu is NULL)");
		assert(0);
	}
	
	return uuid_is_null(uu->uuid);
	
}

int
cl_uuid_parse( char *in, cl_uuid_t* uu)
{
	if (in == NULL || uu == NULL){

		cl_log(LOG_ERR, "cl_uuid_parse: "
		       "wrong argument (%s is NULL)",
		       in == NULL? "in":"uu");
		assert(0);
	}
	
	return uuid_parse(in, uu->uuid);
}


void
cl_uuid_unparse(const cl_uuid_t* uu, char *out){
	
	if (uu == NULL || out == NULL){
		cl_log(LOG_ERR, "cl_uuid_unparse: "
		       "wrong argument (%s is NULL)",
		       uu == NULL? "uu":"out");
		assert(0);
	}
	
	uuid_unparse(uu->uuid, out);
}


guint
cl_uuid_g_hash(gconstpointer uuid_ptr)
{
	guint			ret = 0U;
	guint32			value32;
	int			index;
	const unsigned char *	uuid_char = uuid_ptr;

	/* It is probably not strictly necessary, but I'm trying to get the
	 * same hash result on all platforms.  After all, the uuids are the
	 * same on every platform.
	 */

	for (index = 0; index < sizeof(cl_uuid_t); index += sizeof(value32)) {
		memcpy(&value32, uuid_char+index, sizeof (value32));
		ret += g_ntohl(value32);
	}
	return ret;
}
gboolean
cl_uuid_g_equal(gconstpointer uuid_ptr_a, gconstpointer uuid_ptr_b)
{
	return cl_uuid_compare(uuid_ptr_a, uuid_ptr_b) == 0;
}
