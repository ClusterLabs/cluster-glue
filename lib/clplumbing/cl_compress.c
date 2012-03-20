
/*
 * compress.c: Compression functions for Linux-HA
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

/*
 * Compression is designed to handle big messages, right now with 4 nodes
 * cib message can go up to 64 KB or more. I expect much larger messages
 * when the number of node increase. This makes message compression necessary.
 *
 *
 * Compression is handled in field level. One can add a struct field using
 * ha_msg_addstruct() -- the field will not get compressed, or using 
 * ha_msg_addstruct_compress(), and the field will get compressed when
 * the message is converted to wire format, i.e. when msg2wirefmt() is called.
 * The compressed field will stay compressed until it reached the desination.
 * It will finally decompressed when the user start to get the field value.
 * It is designed this way so that the compression/decompression only happens
 * in end users so that heartbeat itself can save cpu cycle and memory.
 * (more info about compression can be found in cl_msg_types.c about FT_COMPRESS
 * FT_UNCOMPRESS types)
 *
 * compression has another legacy mode, which is there so it can be compatible 
 * to old ways of compression. In the old way, no field is compressed individually
 * and the messages is compressed before it is sent out, and it will be decompressed
 * in the receiver side immediately. So in each IPC channel, the message is compressed
 * and decompressed once. This way will cost a lot of cpu time and memory and it is 
 * discouraged.
 *
 * If use_traditional_compression is true, then it is using the legacy mode, otherwise
 * it is using the new compression. For back compatibility, the default is legacy mode.
 *
 * The real compression work is done by compression plugins. There are two plugins right
 * now: zlib and bz2, they are in lib/plugins/compress
 *
 */

#include <lha_internal.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <unistd.h>
#include <assert.h>
#include <glib.h>
#include <compress.h>
#include <ha_msg.h>
#include <clplumbing/netstring.h>
#include <pils/plugin.h>
#include <pils/generic.h>
#include <stonith/stonith.h>
#include <stonith/stonith_plugin.h>

#define COMPRESSED_FIELD "_compressed_payload"
#define COMPRESS_NAME "_compression_algorithm"
#define HACOMPRESSNAME "HA_COMPRESSION"
#define DFLT_COMPRESS_PLUGIN "bz2"

static struct hb_compress_fns* msg_compress_fns = NULL;
static char*  compress_name = NULL;
GHashTable*		CompressFuncs = NULL;

static PILGenericIfMgmtRqst	Reqs[] =
	{
		{"compress", &CompressFuncs, NULL, NULL, NULL},
		{NULL, NULL, NULL, NULL, NULL}
	};

static PILPluginUniv*		CompressPIsys = NULL;

static int
init_pluginsys(void){
	
	if (CompressPIsys) {
		return TRUE;
	}

	CompressPIsys = NewPILPluginUniv(HA_PLUGIN_DIR);
	
	if (CompressPIsys) {
		if (PILLoadPlugin(CompressPIsys, PI_IFMANAGER, "generic", Reqs)
		!=	PIL_OK){
			cl_log(LOG_ERR, "generic plugin load failed\n");
			DelPILPluginUniv(CompressPIsys);
			CompressPIsys = NULL;
		}
	}else{
		cl_log(LOG_ERR, "pi univ creation failed\n");
	}
	return CompressPIsys != NULL;

}

int
cl_compress_remove_plugin(const char* pluginname)
{
	return HA_OK;
}

int
cl_compress_load_plugin(const char* pluginname)
{
	struct hb_compress_fns*	funcs = NULL;

	if (!init_pluginsys()){
		return HA_FAIL;
	}
	
	if ((funcs = g_hash_table_lookup(CompressFuncs, pluginname))
	    == NULL){
		if (PILPluginExists(CompressPIsys, HB_COMPRESS_TYPE_S,
				    pluginname) == PIL_OK){
			PIL_rc rc;
			if ((rc = PILLoadPlugin(CompressPIsys,
						HB_COMPRESS_TYPE_S, 
						pluginname,
						NULL))!= PIL_OK){
				cl_log(LOG_ERR, 
				       "Cannot load compress plugin %s[%s]",
				       pluginname, 
				       PIL_strerror(rc));
				return HA_FAIL;
			}
			funcs = g_hash_table_lookup(CompressFuncs, 
						    pluginname);
		}
		
	}
	if (funcs == NULL){
		cl_log(LOG_ERR, "Compression module(%s) not found", pluginname);
		return HA_FAIL;
	}

	/* set the environment variable so that later programs can
	 * load the appropriate plugin
	 */
	setenv(HACOMPRESSNAME,pluginname,1);
	msg_compress_fns = funcs;
	
	return HA_OK;
}

int
cl_set_compress_fns(const char* pluginname)
{
	/* this function was unnecessary duplication of the
	 * code in cl_compress_load_plugin
	 */
	return cl_compress_load_plugin(pluginname);
}

struct hb_compress_fns*
cl_get_compress_fns(void)
{
	static int try_dflt = 1;

	if (try_dflt && !msg_compress_fns) {
		try_dflt = 0;
		cl_log(LOG_INFO, "%s: user didn't set compression type, "
		       "loading %s plugin",
		       __FUNCTION__, DFLT_COMPRESS_PLUGIN);
		cl_compress_load_plugin(DFLT_COMPRESS_PLUGIN);
	}
	return msg_compress_fns;
}

static struct hb_compress_fns*
get_compress_fns(const char* pluginname)
{
	struct hb_compress_fns*	funcs = NULL;
	
	if (cl_compress_load_plugin(pluginname) != HA_OK){
		cl_log(LOG_ERR, "%s: loading compression module"
		       "(%s) failed",
		       __FUNCTION__, pluginname);
		return NULL;
	}
	
	funcs = g_hash_table_lookup(CompressFuncs, pluginname);      
	return funcs;	
}

void cl_realtime_malloc_check(void);

char* 
cl_compressmsg(struct ha_msg* m, size_t* len)
{
	char*	src;
	char*	dest;
	size_t	destlen;
	int rc;
	char* ret = NULL;
	struct ha_msg* tmpmsg;
	size_t datalen;

	destlen = MAXMSG;

	dest = malloc(destlen);
	if (!dest) {
		cl_log(LOG_ERR, "%s: failed to allocate destination buffer",
		       __FUNCTION__);
		return NULL;
	}

	if (msg_compress_fns == NULL){
		cl_log(LOG_ERR, "%s: msg_compress_fns is NULL!",
		       __FUNCTION__);
		goto out;
	}
	if ( get_netstringlen(m) > MAXUNCOMPRESSED
	     || get_stringlen(m) > MAXUNCOMPRESSED){
		cl_log(LOG_ERR, "%s: msg too big(stringlen=%d,"
		       "netstringlen=%d)", 
		       __FUNCTION__, 
		       get_stringlen(m),
		       get_netstringlen(m));
		goto out;
	}
	
	
	if ((src = msg2wirefmt_noac(m, &datalen)) == NULL){
		cl_log(LOG_ERR,"%s: converting msg"
		       " to wirefmt failed", __FUNCTION__);
		goto out;
	}
	
	rc = msg_compress_fns->compress(dest, &destlen, 
					src, datalen);
	if (rc != HA_OK){
		cl_log(LOG_ERR, "%s: compression failed",
		       __FUNCTION__);
		goto out;
	}
	
	free(src);

	tmpmsg =ha_msg_new(0);
	rc = ha_msg_addbin(tmpmsg, COMPRESSED_FIELD, dest, destlen)/*discouraged function*/;
	
	if (rc != HA_OK){
		cl_log(LOG_ERR, "%s: adding binary to msg failed",
		       __FUNCTION__);
		goto out;
	}

	rc = ha_msg_add(tmpmsg, COMPRESS_NAME, 
			msg_compress_fns->getname());
	
	if (rc != HA_OK){
		cl_log(LOG_ERR, "%s: adding compress name to msg failed",
		       __FUNCTION__);
		goto out;
	}
	

	ret = msg2netstring(tmpmsg, len);
	ha_msg_del(tmpmsg);
	
#if 0
	cl_log(LOG_INFO, "------original stringlen=%d, netstringlen=%d,"
	       "compressed_datalen=%d,current len=%d",
	       get_stringlen(m), get_netstringlen(m),(int)destlen,  (int)*len);
	
#endif

out:
	if (dest) {
		free(dest);
	}
	
	return ret;
}


gboolean 
is_compressed_msg(struct ha_msg* m)
{
	if( cl_get_binary(m, COMPRESSED_FIELD, NULL) /*discouraged function*/
	    != NULL){
		return TRUE;
	}

	return FALSE;
	
}

/* the decompressmsg function is not exactly the reverse
 * operation of compressmsg, it starts when the prorgram
 * detects there is compressed_field in a msg
 */

struct ha_msg*
cl_decompressmsg(struct ha_msg* m)
{
	const char* src;
	size_t srclen;
	char *dest = NULL;
	size_t destlen = MAXUNCOMPRESSED;
	int rc;
	struct ha_msg* ret = NULL;
	const char* decompress_name;
	struct hb_compress_fns* funcs = NULL;

	dest = malloc(destlen);
	
	if (!dest) {
		cl_log(LOG_ERR, "%s: Failed to allocate buffer.", __FUNCTION__);
		return NULL;
	}
	
	if (m == NULL){
		cl_log(LOG_ERR, "%s: NULL message", __FUNCTION__);
		goto out;
	}
	src = cl_get_binary(m, COMPRESSED_FIELD, &srclen)/*discouraged function*/;
	if (src == NULL){
		cl_log(LOG_ERR, "%s: compressed-field is NULL",
		       __FUNCTION__);
		goto out;
	}

	if (srclen > MAXMSG){
		cl_log(LOG_ERR, "%s: field too long(%d)", 
		       __FUNCTION__, (int)srclen);
		goto out;
	}
	
	decompress_name = ha_msg_value(m, COMPRESS_NAME);
	if (decompress_name == NULL){
		cl_log(LOG_ERR, "compress name not found");
		goto out;
	}

	
	funcs = get_compress_fns(decompress_name);
	
	if (funcs == NULL){
		cl_log(LOG_ERR, "%s: compress method(%s) is not"
		       " supported in this machine",		       
		       __FUNCTION__, decompress_name);
		goto out;
	}
	
	rc = funcs->decompress(dest, &destlen, src, srclen);
	
	if (rc != HA_OK){
		cl_log(LOG_ERR, "%s: decompression failed",
		       __FUNCTION__);
		goto out;
	}
	
	ret = wirefmt2msg(dest, destlen, 0);	
	
#if 0
	cl_log(LOG_INFO, "%s: srclen =%d, destlen=%d", 
	       __FUNCTION__, 
	       srclen, destlen);
#endif

out:
	if (dest) {
		free(dest);
	}
	
	return ret;
}


int
cl_decompress_field(struct ha_msg* msg, int index, char* buf, size_t* buflen)
{
	char*		value;
	int		vallen;
	int		rc;
	const char*	decompress_name;
	struct hb_compress_fns* funcs;
	
	if ( msg == NULL|| index >= msg->nfields){
		cl_log(LOG_ERR, "%s: wrong argument",
		       __FUNCTION__);
		return HA_FAIL;
	}
	
	value = msg->values[index];
	vallen = msg->vlens[index];	
	
	decompress_name = ha_msg_value(msg, COMPRESS_NAME);
	if (decompress_name == NULL){
		cl_log(LOG_ERR, "compress name not found");
		return HA_FAIL;
	}
	
	
	funcs = get_compress_fns(decompress_name);
	
	if (funcs == NULL){
		cl_log(LOG_ERR, "%s: compress method(%s) is not"
		       " supported in this machine",		       
		       __FUNCTION__, decompress_name);
		return HA_FAIL;
	}
	
	rc = funcs->decompress(buf, buflen, value, vallen);		
	if (rc != HA_OK){
		cl_log(LOG_ERR, "%s: decompression failed",
		       __FUNCTION__);
		return HA_FAIL;
	}
	
	return HA_OK;
}


int 
cl_compress_field(struct ha_msg* msg, int index, char* buf, size_t* buflen)
{
	char*   src;
	size_t	srclen;
	int	rc;

	if ( msg == NULL|| index >= msg->nfields 
	     || msg->types[index] != FT_UNCOMPRESS){
		cl_log(LOG_ERR, "%s: wrong argument",
		       __FUNCTION__);
		return HA_FAIL;
	}
	
	if (msg_compress_fns == NULL){
		if (compress_name == NULL){
			compress_name = getenv(HACOMPRESSNAME);
		}
		
		if (compress_name == NULL){
			cl_log(LOG_ERR, "%s: no compression module name found",
			       __FUNCTION__);
			return HA_FAIL;			
		}

		if(cl_set_compress_fns(compress_name) != HA_OK){
			cl_log(LOG_ERR, "%s: loading compression module failed",
			       __FUNCTION__);
			return HA_FAIL;
		}
	}
	
	if (msg_compress_fns == NULL){
		cl_log(LOG_ERR, "%s: msg_compress_fns is NULL!",
		       __FUNCTION__);
		return HA_FAIL;
	}
	
	src = msg2wirefmt_noac(msg->values[index], &srclen);
	if (src == NULL){
		 cl_log(LOG_ERR,"%s: converting msg"
			" to wirefmt failed", __FUNCTION__);
		 return HA_FAIL;
	}
	
	rc = msg_compress_fns->compress(buf, buflen, 
					src, srclen);
	if (rc != HA_OK){
		cl_log(LOG_ERR, "%s: compression failed",
		       __FUNCTION__);
		return HA_FAIL;
	}
	
	
	rc = ha_msg_mod(msg, COMPRESS_NAME, 
			msg_compress_fns->getname());
	
	if (rc != HA_OK){
		cl_log(LOG_ERR, "%s: adding compress name to msg failed",
		       __FUNCTION__);
		return HA_FAIL;;
	}
	
	free(src);
	src = NULL;
	
	return HA_OK;
	
}
