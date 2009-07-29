/*
 * Message  Functions  For Local Resource Manager
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

/*
 * By Huang Zhen <zhenh@cn.ibm.com> 2004/2/13
 *
 */
#include <lha_internal.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <clplumbing/cl_log.h>
#include <ha_msg.h>
#include <lrm/lrm_api.h>
#include <lrm/lrm_msg.h>
#define LOG_BASIC_ERROR(apiname)	\
	cl_log(LOG_ERR, "%s(%d): %s failed.", __FUNCTION__, __LINE__, apiname)

const lrm_op_t	lrm_zero_op; /* Default initialized to zeros */

static void
copy_pair(gpointer key, gpointer value, gpointer user_data)
{
	GHashTable* taget_table = (GHashTable*)user_data;
	g_hash_table_insert(taget_table, g_strdup(key), g_strdup(value));
}

GHashTable*
copy_str_table(GHashTable* src_table)
{
	GHashTable* target_table = NULL;

	if ( NULL == src_table) {
		return NULL;
	}
	target_table = g_hash_table_new(g_str_hash, g_str_equal);
	g_hash_table_foreach(src_table, copy_pair, target_table);
	return target_table;
}

static void
merge_pair(gpointer key, gpointer value, gpointer user_data)
{
	GHashTable *merged = (GHashTable*)user_data;

	if (g_hash_table_lookup(merged, key)) {
		return;
	} 

	g_hash_table_insert(merged, g_strdup(key), g_strdup(value));
}

GHashTable*
merge_str_tables(GHashTable* old, GHashTable* new)
{
	GHashTable* merged = NULL;
	if ( NULL == old ) {
		return copy_str_table(new);
	}
	if ( NULL == new ) {
		return copy_str_table(old);
	}
	merged = copy_str_table(new);
	g_hash_table_foreach(old, merge_pair, merged);
	return merged;
}

static gboolean
free_pair(gpointer key, gpointer value, gpointer user_data)
{
	g_free(key);
	g_free(value);
	return TRUE;
}

void
free_str_table(GHashTable* hash_table)
{
	g_hash_table_foreach_remove(hash_table, free_pair, NULL);
	g_hash_table_destroy(hash_table);
}



struct ha_msg*
create_lrm_msg (const char* msg)
{
	struct ha_msg* ret;
	if ((NULL == msg) || (0 == strlen(msg))) {
		return NULL;
	}

	ret = ha_msg_new(1);
	if (HA_OK != ha_msg_add(ret, F_LRM_TYPE, msg)) {
		ha_msg_del(ret);
		LOG_BASIC_ERROR("ha_msg_add");
		return NULL;
	}

	return ret;
}

struct ha_msg*
create_lrm_reg_msg(const char* app_name)
{
	struct ha_msg* ret;
	if ((NULL == app_name) || (0 == strlen(app_name))) {
		return NULL;
	}

	ret = ha_msg_new(5);

	if(HA_OK != ha_msg_add(ret, F_LRM_TYPE, REGISTER)
	|| HA_OK != ha_msg_add(ret, F_LRM_APP, app_name)
	|| HA_OK != ha_msg_add_int(ret, F_LRM_PID, getpid())
	|| HA_OK != ha_msg_add_int(ret, F_LRM_GID, getegid())
	|| HA_OK != ha_msg_add_int(ret, F_LRM_UID, getuid())) {
		ha_msg_del(ret);
		LOG_BASIC_ERROR("ha_msg_add");
		return NULL;
	}
	
	return ret;
}

struct ha_msg*
create_lrm_addrsc_msg(const char* rid, const char* class, const char* type,
			const char* provider, GHashTable* params)
{
	struct ha_msg* msg;
	if (NULL==rid||NULL==class||NULL==type) {
		return NULL;
	}
	
	msg = ha_msg_new(5);
	if(HA_OK != ha_msg_add(msg, F_LRM_TYPE, ADDRSC)
	|| HA_OK != ha_msg_add(msg, F_LRM_RID, rid)
	|| HA_OK != ha_msg_add(msg, F_LRM_RCLASS, class)
	|| HA_OK != ha_msg_add(msg, F_LRM_RTYPE, type)) {
		ha_msg_del(msg);
		LOG_BASIC_ERROR("ha_msg_add");
		return NULL;
	}
		
	if( provider ) {
		if (HA_OK != ha_msg_add(msg, F_LRM_RPROVIDER, provider)) {
			ha_msg_del(msg);
			LOG_BASIC_ERROR("ha_msg_add");
			return NULL;
		}
	}
	
	if ( params ) {
		if (HA_OK != ha_msg_add_str_table(msg,F_LRM_PARAM,params)) {
			ha_msg_del(msg);
			LOG_BASIC_ERROR("ha_msg_add");
			return NULL;
		}
	}
	return msg;
}


struct ha_msg*
create_lrm_rsc_msg(const char* rid, const char* msg)
{
	struct ha_msg* ret;
	if ((NULL == rid) ||(NULL == msg) || (0 == strlen(msg))) {
		return NULL;
	}

	ret = ha_msg_new(2);
	if(HA_OK != ha_msg_add(ret, F_LRM_TYPE, msg)
	|| HA_OK != ha_msg_add(ret, F_LRM_RID, rid)) {
		ha_msg_del(ret);
		LOG_BASIC_ERROR("ha_msg_add");
		return NULL;
	}
	return ret;
}



struct ha_msg*
create_lrm_ret(int ret, int fields)
{
	struct ha_msg* msg = ha_msg_new(fields);
	if(HA_OK != ha_msg_add(msg, F_LRM_TYPE, RETURN)
	|| HA_OK != ha_msg_add_int(msg, F_LRM_RET, ret)) {
		ha_msg_del(msg);
		LOG_BASIC_ERROR("ha_msg_add");
		return NULL;
	}
	return msg;
}

