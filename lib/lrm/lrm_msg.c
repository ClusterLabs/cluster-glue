/* $Id: lrm_msg.c,v 1.18 2004/09/27 08:33:55 zhenh Exp $ */
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
#include <portability.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <clplumbing/cl_log.h>
#include <ha_msg.h>
#include <heartbeat.h>
#include <lrm/lrm_api.h>
#include <lrm/lrm_msg.h>

/* static void pair_to_string(gpointer key, gpointer value, gpointer user_data); */
static gboolean free_pair(gpointer key, gpointer value, gpointer user_data);
static void pair_to_msg(gpointer key, gpointer value, gpointer user_data);
static void copy_pair(gpointer key, gpointer value, gpointer user_data);
static void merge_pair(gpointer key, gpointer value, gpointer user_data);

int
ha_msg_add_int(struct ha_msg * msg, const char * name, int value)
{
	return ha_msg_addbin(msg, name, &value, sizeof(int));
}

int
ha_msg_mod_int(struct ha_msg * msg, const char * name, int value)
{
	return cl_msg_modbin(msg, name, &value, sizeof(int));
}

int
ha_msg_value_int(struct ha_msg * msg, const char * name, int* value)
{
	size_t size;
	const void* data = cl_get_binary(msg, name, &size);
	if (NULL == data || NULL == value || sizeof(int) != size) {
		return HA_FAIL;
	}
	*value = *(const int *)data;
	return HA_OK;
}
#ifdef LRM_MSG_UUID_SUPPORT
int
ha_msg_add_uuid(struct ha_msg * msg, const char * name, const uuid_t id)
{
	char buf[UUID_SLEN];
	uuid_unparse(id, buf);
	return (ha_msg_nadd(msg, name, strlen(name), buf, strlen(buf)));
}

int
ha_msg_value_uuid(struct ha_msg * msg, const char * name, uuid_t id)
{
	const char* value = ha_msg_value(msg, name);
	char buf[UUID_SLEN];

	if (NULL == value) {
		return HA_FAIL;
	}
	strncpy(buf,value,UUID_SLEN);
	if( 0 != uuid_parse(value, id)) {
		return HA_FAIL;
	}

	return HA_OK;
}
#endif

/*
 * ha_msg_value_str_list()/ha_msg_add_str_list():
 * transform a string list suitable for putting into an ha_msg is by a convention
 * of naming the fields into the following format:
 *	listname1=foo
 *	listname2=bar
 *	listname3=stuff
 *	etc.
 */

GList* 
ha_msg_value_str_list(struct ha_msg * msg, const char * name)
{
	
	int i = 1;
	int len = 0;
	const char* value;
	char* element;
	GList* list = NULL;
	
	
	if( NULL==msg||NULL==name||strnlen(name, MAX_NAME_LEN)>=MAX_NAME_LEN ){
		return NULL;
	}	
	len = cl_msg_list_length(msg,name);
	for(i=0; i<len; i++) {
		value = cl_msg_list_nth_data(msg,name,i);
		if (NULL == value) {
			break;
		}
		element = g_strdup(value);
		list = g_list_append(list, element);
	}
	return list;
}

int
ha_msg_add_str_list(struct ha_msg * msg, const char * name, GList* list)
{
	int i = 1;
	if( NULL==msg||NULL==name||strnlen(name, MAX_NAME_LEN)>=MAX_NAME_LEN ){
		return HA_FAIL;
	}
	
	if (NULL != list) {
		GList* element = g_list_first(list);
		while (NULL != element) {
			char* value = (char*)element->data;
			if( HA_OK != cl_msg_list_add_string(msg,name,value)) {
				cl_log(LOG_ERR,
				"cl_msg_list_add_string failed");
				return HA_FAIL;
			}
			element = g_list_next(element);
			i++;
		}
	}
	return HA_OK;
}

static void
pair_to_msg(gpointer key, gpointer value, gpointer user_data)
{
	struct ha_msg* msg = (struct ha_msg*)user_data;
	if( HA_OK != ha_msg_add(msg, key, value)) {
		cl_log(LOG_ERR, "ha_msg_add in pair_to_msg failed");
	}
}

GHashTable*
ha_msg_value_str_table(struct ha_msg * msg, const char * name)
{
	struct ha_msg* hash_msg;
	GHashTable * hash_table = NULL;

	if (NULL == msg || NULL == name) {
		return NULL;
	}

	hash_msg = cl_get_struct(msg, name);
	if (NULL == hash_msg) {
		return NULL;
	}
	hash_table = msg_to_str_table(hash_msg);
	return hash_table;
}

int
ha_msg_add_str_table(struct ha_msg * msg, const char * name,
			GHashTable* hash_table)
{
	struct ha_msg* hash_msg;
	if (NULL == msg || NULL == name || NULL == hash_table) {
		return HA_FAIL;
	}

	hash_msg = str_table_to_msg(hash_table);
	if( HA_OK != ha_msg_addstruct(msg, name, hash_msg)) {
		ha_msg_del(hash_msg);
		cl_log(LOG_ERR, "ha_msg_add in ha_msg_add_str_table failed");
		return HA_FAIL;
	}
	ha_msg_del(hash_msg);
	return HA_OK;
}

GHashTable*
msg_to_str_table(struct ha_msg * msg)
{
	int i;
	GHashTable* hash_table;

	if ( NULL == msg) {
		return NULL;
	}

	hash_table = g_hash_table_new(g_str_hash, g_str_equal);

	for (i = 0; i < msg->nfields; i++) {
		if( FT_STRING != msg->types[i] ) {
			continue;
		}
		g_hash_table_insert(hash_table,
				    strndup(msg->names[i],msg->nlens[i]),
				    strndup(msg->values[i],msg->vlens[i]));
	}
	return hash_table;
}

struct ha_msg*
str_table_to_msg(GHashTable* hash_table)
{
	struct ha_msg* hash_msg;

	if ( NULL == hash_table) {
		return NULL;
	}

	hash_msg = ha_msg_new(5);
	g_hash_table_foreach(hash_table, pair_to_msg, hash_msg);
	return hash_msg;
}


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
	gpointer oldvalue;
	gpointer oldkey;
	GHashTable* ret = (GHashTable*)user_data;

	if (g_hash_table_lookup_extended(ret, key, &oldkey, &oldvalue)){
		g_hash_table_remove(ret, oldkey);
		g_free(oldvalue);
		g_free(oldkey);
	}
	g_hash_table_insert(ret, g_strdup(key), g_strdup(value));
}

GHashTable*
merge_str_tables(GHashTable* old, GHashTable* new)
{
	GHashTable* ret = NULL;
	if ( NULL == old ) {
		return copy_str_table(new);
	}
	if ( NULL == new ) {
		return copy_str_table(old);
	}
	ret = copy_str_table(old);
	g_hash_table_foreach(new, merge_pair, ret);
	return ret;
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
		cl_log(LOG_ERR, "ha_msg_add in create_lrm_msg failed");
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
		cl_log(LOG_ERR, "ha_msg_add in create_lrm_reg_msg failed");
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
		cl_log(LOG_ERR, "ha_msg_add in create_lrm_addrsc_msg failed");
		return NULL;
	}
		
	if( provider ) {
		if (HA_OK != ha_msg_add(msg, F_LRM_RPROVIDER, provider)) {
			ha_msg_del(msg);
			cl_log(LOG_ERR,
			"ha_msg_add in create_lrm_addrsc_msg failed");
			return NULL;
		}
	}
	
	if ( params ) {
		if (HA_OK != ha_msg_add_str_table(msg,F_LRM_PARAM,params)) {
			ha_msg_del(msg);
			cl_log(LOG_ERR,
			"ha_msg_add_str_table in create_lrm_addrsc_msg failed");
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
		cl_log(LOG_ERR, "ha_msg_add in create_lrm_rsc_msg failed");
		return NULL;
	}
	return ret;
}



struct ha_msg*
create_lrm_ret(int rc, int fields)
{
	struct ha_msg* ret = ha_msg_new(fields);
	if(HA_OK != ha_msg_add(ret, F_LRM_TYPE, RETURN)
	|| HA_OK != ha_msg_add_int(ret, F_LRM_RC, rc)) {
		ha_msg_del(ret);
		cl_log(LOG_ERR, "ha_msg_add in create_lrm_ret failed");
		return NULL;
	}
	return ret;
}

/* 
 * $Log: lrm_msg.c,v $
 * Revision 1.18  2004/09/27 08:33:55  zhenh
 * apply the new cl_msg_list_xxx() funcions in lrm
 *
 * Revision 1.17  2004/09/17 03:33:24  zhenh
 * in some platform(maybe 64bits), using int as size_t causes warning.
 *
 * Revision 1.16  2004/09/13 07:10:30  zhenh
 * fix a bug: the msg does not contain the request field so returning NULL is correct. not an error. remove the wrong log
 *
 * Revision 1.15  2004/09/10 10:09:43  sunjd
 * Fix a bug: duplicate keys in GHashtable, is not expected
 *
 * Revision 1.14  2004/09/10 02:07:16  zhenh
 * make names of functions more clear,fix some bug and  make it more robust
 *
 * Revision 1.13  2004/09/03 01:07:08  zhenh
 * add provider for resource
 *
 * Revision 1.12  2004/08/29 04:38:08  msoffen
 * Added log for history to end of file.
 *
 */
