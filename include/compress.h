/*
 * compress.h: Compression functions for Linux-HA
 *
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

#ifndef _COMPRESS_H_
#define _COMPRESS_H_ 

#define HB_COMPRESS_TYPE	compress
#define HB_COMPRESS_TYPE_S	"compress"

/*
 *	List of functions provided by implementations of the heartbeat 
 *	compress interface.
 */
struct hb_compress_fns {
	int (*compress) (char*, size_t*, const char*, size_t);
	int (*decompress) (char*, size_t* , const char*, size_t);
	const char* (*getname) (void);
};

struct ha_msg;

/* set the compression method*/
int		cl_compress_remove_plugin(const char* pluginname);
int		cl_compress_load_plugin(const char* pluginname);
struct hb_compress_fns* cl_get_compress_fns(void);
int		cl_set_compress_fns(const char*);
char*		cl_compressmsg(struct ha_msg*m, size_t* len);
struct ha_msg*	cl_decompressmsg(struct ha_msg* m);
gboolean	is_compressed_msg(struct ha_msg* m);
int		cl_compress_field(struct ha_msg* msg, int index, char* buf, size_t* buflen);
int		cl_decompress_field(struct ha_msg* msg, int index, char* buf, size_t* buflen);

#endif
