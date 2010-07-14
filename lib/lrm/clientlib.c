/* 
 * Client Library for Local Resource Manager  API.
 *
 * Author:  Huang Zhen <zhenh@cn.ibm.com>
 * Copyright (c) 2004 International Business Machines
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
#include <lha_internal.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include <glib.h>
#include <clplumbing/ipc.h>
#include <ha_msg.h>
#include <lrm/lrm_api.h>

#include <lrm/lrm_msg.h>

/* FIXME: Notice: this define should be replaced when merge to the whole pkg*/
#define	LRM_MAXPIDLEN 	256
#define LRM_ID		"lrm"

#define LOG_FAIL_create_lrm_msg(msg_type)				\
	cl_log(LOG_ERR, "%s(%d): failed to create a %s message with "	\
		"function create_lrm_msg."				\
	,	__FUNCTION__, __LINE__, msg_type)

#define LOG_FAIL_create_lrm_rsc_msg(msg_type)				\
	cl_log(LOG_ERR, "%s(%d): failed to create a %s message with "	\
		"function create_lrm_rsc_msg."				\
	,	__FUNCTION__, __LINE__, msg_type)

#define LOG_FAIL_receive_reply(msg_type)					\
	cl_log(LOG_ERR, "%s(%d): failed to receive a reply message of %s."	\
	,	__FUNCTION__, __LINE__, msg_type)

#define LOG_FAIL_SEND_MSG(msg_type, chan_name)				\
	cl_log(LOG_ERR, "%s(%d): failed to send a %s message to lrmd "	\
		"via %s channel."					\
	,	__FUNCTION__, __LINE__, msg_type, chan_name)

#define LOG_GOT_FAIL_RET(priority, msg_type)				\
	cl_log(priority, "%s(%d): got a return code HA_FAIL from "	\
		"a reply message of %s with function get_ret_from_msg."	\
	,	__FUNCTION__, __LINE__, msg_type)

#define LOG_BASIC_ERROR(apiname)			\
	cl_log(LOG_ERR, "%s(%d): %s failed."		\
	, __FUNCTION__, __LINE__, apiname)

#define LOG_FAIL_GET_MSG_FIELD(priority, field_name, msg)		\
		{cl_log(priority, "%s(%d): failed to get the value "	\
			"of field %s from a ha_msg"			\
		,	__FUNCTION__, __LINE__, field_name);		\
		cl_log(LOG_INFO, "%s: Message follows:", __FUNCTION__);	\
		cl_log_message(LOG_INFO, (msg));			\
		}

/* declare the functions used by the lrm_ops structure*/
static int lrm_signon (ll_lrm_t* lrm, const char * app_name);
static int lrm_signoff (ll_lrm_t*);
static int lrm_delete (ll_lrm_t*);
static int lrm_set_lrm_callback (ll_lrm_t* lrm,
				 lrm_op_done_callback_t op_done_callback_func);
static GList* lrm_get_rsc_class_supported (ll_lrm_t* lrm);
static GList* lrm_get_rsc_type_supported (ll_lrm_t* lrm, const char* class);
static GList* lrm_get_rsc_provider_supported (ll_lrm_t* lrm
				,const char* class, const char* type);
static char* lrm_get_rsc_type_metadata(ll_lrm_t* lrm, const char* class
				,const char* type, const char* provider);
static GHashTable* lrm_get_all_type_metadata(ll_lrm_t*, const char* class);
static GList* lrm_get_all_rscs (ll_lrm_t* lrm);
static lrm_rsc_t* lrm_get_rsc (ll_lrm_t* lrm, const char* rsc_id);
static int lrm_add_rsc (ll_lrm_t*, const char* id, const char* class
			,const char* type, const char* provider
			,GHashTable* parameter);
static int lrm_delete_rsc (ll_lrm_t*, const char* id);
static int lrm_fail_rsc (ll_lrm_t* lrm, const char* rsc_id, const int fail_rc
			,const char* fail_reason);
static int lrm_set_lrmd_param (ll_lrm_t* lrm, const char* name, const char *value);
static char* lrm_get_lrmd_param (ll_lrm_t* lrm, const char* name);
static IPC_Channel* lrm_ipcchan (ll_lrm_t*);
static int lrm_msgready (ll_lrm_t*);
static int lrm_rcvmsg (ll_lrm_t*, int blocking);
static struct lrm_ops lrm_ops_instance =
{
	lrm_signon,
	lrm_signoff,
	lrm_delete,
	lrm_set_lrm_callback,
	lrm_set_lrmd_param,
	lrm_get_lrmd_param,
	lrm_get_rsc_class_supported,
	lrm_get_rsc_type_supported,
	lrm_get_rsc_provider_supported,
	lrm_get_rsc_type_metadata,
	lrm_get_all_type_metadata,
	lrm_get_all_rscs,
	lrm_get_rsc,
	lrm_add_rsc,
	lrm_delete_rsc,
	lrm_fail_rsc,
	lrm_ipcchan,
	lrm_msgready,
	lrm_rcvmsg
};
/* declare the functions used by the lrm_rsc_ops structure*/
static int rsc_perform_op (lrm_rsc_t*, lrm_op_t* op);
static int rsc_cancel_op (lrm_rsc_t*, int call_id);
static int rsc_flush_ops (lrm_rsc_t*);
static GList* rsc_get_cur_state (lrm_rsc_t*, state_flag_t* cur_state);
static lrm_op_t* rsc_get_last_result (lrm_rsc_t*, const char* op_type);
static gint compare_call_id(gconstpointer a, gconstpointer b);

static struct rsc_ops rsc_ops_instance =
{
	rsc_perform_op,
	rsc_cancel_op,
	rsc_flush_ops,
	rsc_get_cur_state,
	rsc_get_last_result
};


/* define the internal data used by the client library*/
static int is_signed_on					= FALSE;
static IPC_Channel* ch_cmd				= NULL;
static IPC_Channel* ch_cbk 				= NULL;
static lrm_op_done_callback_t	op_done_callback 	= NULL;

/* define some utility functions*/
static int get_ret_from_ch(IPC_Channel* ch);
static int get_ret_from_msg(struct ha_msg* msg);
static struct ha_msg* op_to_msg (lrm_op_t* op);
static lrm_op_t* msg_to_op(struct ha_msg* msg);
static void free_op (lrm_op_t* op);

/* define of the api functions*/
ll_lrm_t*
ll_lrm_new (const char * llctype)
{
	ll_lrm_t* lrm;

	/* check the parameter*/
	if (0 != STRNCMP_CONST(llctype, LRM_ID)) {
		cl_log(LOG_ERR, "ll_lrm_new: wrong parameter");
		return NULL;
	}

	/* alloc memory for lrm*/
	if (NULL == (lrm = (ll_lrm_t*) g_new(ll_lrm_t,1))) {
		cl_log(LOG_ERR, "ll_lrm_new: can not allocate memory");
		return NULL;
	}
	/* assign the ops*/
	lrm->lrm_ops = &lrm_ops_instance;

	return lrm;
}

static int
lrm_signon (ll_lrm_t* lrm, const char * app_name)
{

	GHashTable* ch_cmd_attrs;
	GHashTable* ch_cbk_attrs;

	struct ha_msg* msg;

	char path[] = IPC_PATH_ATTR;
	char cmd_path[] = LRM_CMDPATH;
	char callback_path[] = LRM_CALLBACKPATH;

	/* check parameters*/
	if (NULL == lrm || NULL == app_name) {
		cl_log(LOG_ERR, "lrm_signon: wrong parameter");
		return HA_FAIL;
	}

	/* if already signed on, sign off first*/
	if (is_signed_on) {
		cl_log(LOG_WARNING,
			"lrm_signon: the client is alreay signed on, re-sign");
		lrm_signoff(lrm);
	}

	/* create the command ipc channel to lrmd*/
	ch_cmd_attrs = g_hash_table_new(g_str_hash, g_str_equal);
	g_hash_table_insert(ch_cmd_attrs, path, cmd_path);
	ch_cmd = ipc_channel_constructor(IPC_ANYTYPE, ch_cmd_attrs);
	g_hash_table_destroy(ch_cmd_attrs);

	if (NULL == ch_cmd){
		lrm_signoff(lrm);
		cl_log(LOG_WARNING,
			"lrm_signon: can not connect to lrmd for cmd channel");
		return HA_FAIL;
	}

	if (IPC_OK != ch_cmd->ops->initiate_connection(ch_cmd)) {
		lrm_signoff(lrm);
		cl_log(LOG_WARNING,
			"lrm_signon: can not initiate connection");
		return HA_FAIL;
	}

	/* construct the reg msg*/
	if (NULL == (msg = create_lrm_reg_msg(app_name))) {
		lrm_signoff(lrm);
		cl_log(LOG_ERR,"lrm_signon: failed to create a register message");
		return HA_FAIL;
	}

	/* send the msg*/
	if (HA_OK != msg2ipcchan(msg,ch_cmd)) {
		lrm_signoff(lrm);
		ha_msg_del(msg);
		LOG_FAIL_SEND_MSG(REGISTER, "ch_cmd");
		return HA_FAIL;
	}
	/* parse the return msg*/
	if (HA_OK != get_ret_from_ch(ch_cmd)) {
		ha_msg_del(msg);
		lrm_signoff(lrm);
		LOG_FAIL_receive_reply(REGISTER);
		return HA_FAIL;
	}

	/* create the callback ipc channel to lrmd*/
	ch_cbk_attrs = g_hash_table_new(g_str_hash, g_str_equal);
	g_hash_table_insert(ch_cbk_attrs, path, callback_path);
	ch_cbk = ipc_channel_constructor(IPC_ANYTYPE,ch_cbk_attrs);
	g_hash_table_destroy(ch_cbk_attrs);

	if (NULL == ch_cbk) {
		ha_msg_del(msg);
		lrm_signoff(lrm);
		cl_log(LOG_ERR, "lrm_signon: failed to construct a callback "
			"channel to lrmd");
		return HA_FAIL;
	}

	if (IPC_OK != ch_cbk->ops->initiate_connection(ch_cbk)) {
		ha_msg_del(msg);
		lrm_signoff(lrm);
		cl_log(LOG_ERR,
			"lrm_signon: failed to initiate the callback channel.");
		return HA_FAIL;
	}
	/* send the msg*/
	if (HA_OK != msg2ipcchan(msg,ch_cbk)) {
		lrm_signoff(lrm);
		ha_msg_del(msg);
		LOG_FAIL_SEND_MSG(REGISTER, "ch_cbk");
		return HA_FAIL;
	}
	ha_msg_del(msg);
	/* parse the return msg*/
	if (HA_OK != get_ret_from_ch(ch_cbk)) {
		lrm_signoff(lrm);
		LOG_FAIL_receive_reply(REGISTER);
		return HA_FAIL;
	}
	/* ok, we sign on sucessfully now*/
	is_signed_on = TRUE;
	return HA_OK;
}

static int
lrm_signoff (ll_lrm_t* lrm)
{
	/* close channels */
	if (NULL != ch_cmd) {
		if (IPC_ISWCONN(ch_cmd)) {
	 		ch_cmd->ops->destroy(ch_cmd);
	 	}
		ch_cmd = NULL;
	}
	if (NULL != ch_cbk) {
		if (IPC_ISWCONN(ch_cbk)) {
			ch_cbk->ops->destroy(ch_cbk);
		}
		ch_cbk = NULL;
	}
	is_signed_on = FALSE;

	return HA_OK;
}

static int
lrm_delete (ll_lrm_t* lrm)
{
	/* check the parameter */
	if (NULL == lrm) {
		cl_log(LOG_ERR,"lrm_delete: the parameter is a null pointer.");
		return HA_FAIL;
	}
	g_free(lrm);
	
	return HA_OK;
}

static int
lrm_set_lrm_callback (ll_lrm_t* lrm,
			lrm_op_done_callback_t op_done_callback_func)

{
	op_done_callback = op_done_callback_func;

	return HA_OK;
}

static GList*
lrm_get_rsc_class_supported (ll_lrm_t* lrm)
{
	struct ha_msg* msg;
	struct ha_msg* ret;
	GList* class_list = NULL;
	/* check whether the channel to lrmd is available */
	if (NULL == ch_cmd)
	{
		cl_log(LOG_ERR,
			"lrm_get_rsc_class_supported: ch_cmd is a null pointer.");
		return NULL;
	}
	/* create the get ra type message */
	msg = create_lrm_msg(GETRSCCLASSES);
	if ( NULL == msg) {
		LOG_FAIL_create_lrm_msg(GETRSCCLASSES);
		return NULL;
	}

	/* send the msg to lrmd */
	if (HA_OK != msg2ipcchan(msg,ch_cmd)) {
		ha_msg_del(msg);
		LOG_FAIL_SEND_MSG(GETRSCCLASSES, "ch_cmd");
		return NULL;
	}
	ha_msg_del(msg);
	/* get the return message */
	ret = msgfromIPC(ch_cmd, MSG_ALLOWINTR);
	if (NULL == ret) {
		LOG_FAIL_receive_reply(GETRSCCLASSES);
		return NULL;
	}
	/* get the return code of the message */
	if (HA_OK != get_ret_from_msg(ret)) {
		LOG_GOT_FAIL_RET(LOG_WARNING, GETRSCCLASSES);
		ha_msg_del(ret);
		return NULL;
	}
	/* get the ra type list from message */
	class_list = ha_msg_value_str_list(ret,F_LRM_RCLASS);

	ha_msg_del(ret);

	return class_list;
}
static GList*
lrm_get_rsc_type_supported (ll_lrm_t* lrm, const char* rclass)
{
	struct ha_msg* msg;
	struct ha_msg* ret;
	GList* type_list = NULL;
	/* check whether the channel to lrmd is available */
	if (NULL == ch_cmd)
	{
		cl_log(LOG_ERR, "%s(%d): ch_cmd is null."
		,	__FUNCTION__, __LINE__);
		
		return NULL;
	}
	/* create the get ra type message */
	msg = create_lrm_msg(GETRSCTYPES);
	if ( NULL == msg) {
		LOG_FAIL_create_lrm_msg(GETRSCTYPES);
		return NULL;
	}
	if ( HA_OK != ha_msg_add(msg, F_LRM_RCLASS, rclass)) {
		ha_msg_del(msg);
		LOG_BASIC_ERROR("ha_msg_add");
		return NULL;
	}

	/* send the msg to lrmd */
	if (HA_OK != msg2ipcchan(msg,ch_cmd)) {
		ha_msg_del(msg);
		LOG_FAIL_SEND_MSG(GETRSCTYPES, "ch_cmd");
		return NULL;
	}
	ha_msg_del(msg);
	/* get the return message */
	ret = msgfromIPC(ch_cmd, MSG_ALLOWINTR);
	if (NULL == ret) {
		LOG_FAIL_receive_reply(GETRSCTYPES);
		return NULL;
	}
	/* get the return code of the message */
	if (HA_OK != get_ret_from_msg(ret)) {
		LOG_GOT_FAIL_RET(LOG_ERR, GETRSCTYPES);
		ha_msg_del(ret);
		return NULL;
	}
	/* get the ra type list from message */
	type_list = ha_msg_value_str_list(ret,F_LRM_RTYPES);

	ha_msg_del(ret);

	return type_list;
}
static GList*
lrm_get_rsc_provider_supported (ll_lrm_t* lrm, const char* class, const char* type)
{
	struct ha_msg* msg;
	struct ha_msg* ret;
	GList* provider_list = NULL;
	/* check whether the channel to lrmd is available */
	if (NULL == ch_cmd)
	{
		cl_log(LOG_ERR,
			"lrm_get_rsc_provider_supported: ch_mod is null.");
		return NULL;
	}
	/* create the get ra providers message */
	msg = create_lrm_msg(GETPROVIDERS);
	if ( NULL == msg) {
		LOG_FAIL_create_lrm_msg(GETPROVIDERS);
		return NULL;
	}
	if (HA_OK != ha_msg_add(msg, F_LRM_RCLASS, class)
	||  HA_OK != ha_msg_add(msg, F_LRM_RTYPE, type)) {
		ha_msg_del(msg);
		LOG_BASIC_ERROR("ha_msg_add");
		return NULL;
	}

	/* send the msg to lrmd */
	if (HA_OK != msg2ipcchan(msg,ch_cmd)) {
		ha_msg_del(msg);
		LOG_FAIL_SEND_MSG(GETPROVIDERS, "ch_cmd");
		return NULL;
	}
	ha_msg_del(msg);
	/* get the return message */
	ret = msgfromIPC(ch_cmd, MSG_ALLOWINTR);
	if (NULL == ret) {
		LOG_FAIL_receive_reply(GETPROVIDERS);
		return NULL;
	}
	/* get the return code of the message */
	if (HA_OK != get_ret_from_msg(ret)) {
		LOG_GOT_FAIL_RET(LOG_ERR, GETPROVIDERS);
		ha_msg_del(ret);
		return NULL;
	}
	/* get the ra provider list from message */
	provider_list = ha_msg_value_str_list(ret,F_LRM_RPROVIDERS);

	ha_msg_del(ret);

	return provider_list;
}
	
/*
 * lrm_get_all_type_metadatas():
 * The key of the hash table is in the format "type:provider"
 * The value of the hash table is the metadata.
 */
static GHashTable*
lrm_get_all_type_metadata (ll_lrm_t* lrm, const char* rclass)
{
	GHashTable* metas = g_hash_table_new_full(g_str_hash, g_str_equal
						  , g_free, g_free);
	GList* types = lrm_get_rsc_type_supported (lrm, rclass);
	GList* providers = NULL;
	GList* cur_type = NULL;
	GList* cur_provider = NULL;

	cur_type = g_list_first(types);
	while (cur_type != NULL)
	{
	        const char* type;
	        char key[MAXLENGTH];
		type = (const char*) cur_type->data;
		providers = lrm_get_rsc_provider_supported(lrm, rclass, type);
		cur_provider = g_list_first(providers);
		while (cur_provider != NULL) {
		        const char* meta;
		        const char* provider;
			provider = (const char*) cur_provider->data;
			meta = lrm_get_rsc_type_metadata(lrm,rclass,type,provider);
			if (NULL == meta) {
				cur_provider = g_list_next(cur_provider);
				continue;
			}
			snprintf(key,MAXLENGTH, "%s:%s",type,provider);
			key[MAXLENGTH-1]='\0';
			g_hash_table_insert(metas,g_strdup(key),g_strdup(meta));
			cur_provider = g_list_next(cur_provider);
		}
		lrm_free_str_list(providers);
		cur_type=g_list_next(cur_type);
	}
	lrm_free_str_list(types);
	return metas;
}

static char*
lrm_get_rsc_type_metadata (ll_lrm_t* lrm, const char* rclass, const char* rtype,
				const char* provider)
{
	struct ha_msg* msg;
	struct ha_msg* ret;
	const char* tmp = NULL;
	char* metadata = NULL;
	
	/* check whether the channel to lrmd is available */
	if (NULL == ch_cmd)
	{
		cl_log(LOG_ERR,
			"lrm_get_rsc_type_metadata: ch_mod is null.");
		return NULL;
	}
	/* create the get ra type message */
	msg = create_lrm_msg(GETRSCMETA);
	if (NULL == msg ) {
		LOG_FAIL_create_lrm_msg(GETRSCMETA);
		return NULL;
	}
	
	if (HA_OK != ha_msg_add(msg, F_LRM_RCLASS, rclass)
	||  HA_OK != ha_msg_add(msg, F_LRM_RTYPE, rtype)){
		ha_msg_del(msg);
		LOG_BASIC_ERROR("ha_msg_add");
		return NULL;
	}

	if( provider ) {
		if (HA_OK != ha_msg_add(msg, F_LRM_RPROVIDER, provider)) {
			LOG_BASIC_ERROR("ha_msg_add");	
			ha_msg_del(msg);
			return NULL;
		}
	}

	/* send the msg to lrmd */
	if (HA_OK != msg2ipcchan(msg,ch_cmd)) {
		ha_msg_del(msg);
		LOG_FAIL_SEND_MSG(GETRSCMETA, "ch_cmd");
		return NULL;
	}
	ha_msg_del(msg);
	/* get the return message */
	ret = msgfromIPC(ch_cmd, MSG_ALLOWINTR);
	if (NULL == ret) {
		LOG_FAIL_receive_reply(GETRSCMETA);
		return NULL;
	}
	/* get the return code of the message */
	if (HA_OK != get_ret_from_msg(ret)) {
		LOG_GOT_FAIL_RET(LOG_ERR, GETRSCMETA);
		ha_msg_del(ret);
		return NULL;
	}

	/* get the metadata from message */
	tmp = cl_get_string(ret, F_LRM_METADATA);
	if (NULL!=tmp) {
		metadata = g_strdup(tmp);
	}
	ha_msg_del(ret);

	return metadata;
}

static GList*
lrm_get_all_rscs (ll_lrm_t* lrm)
{
	struct ha_msg* msg = NULL;
	struct ha_msg* ret = NULL;
	GList* rid_list = NULL;

	/* check whether the channel to lrmd is available */
	if (NULL == ch_cmd) {
		cl_log(LOG_ERR, "lrm_get_all_rscs: ch_mod is null.");
		return NULL;
	}
	/* create the msg of get all resource */
	msg = create_lrm_msg(GETALLRCSES);
	if ( NULL == msg) {
		LOG_FAIL_create_lrm_msg(GETALLRCSES);
		return NULL;
	}
	/* send the msg to lrmd */
	if (HA_OK != msg2ipcchan(msg,ch_cmd)) {
		ha_msg_del(msg);
		LOG_FAIL_SEND_MSG(GETALLRCSES, "ch_cmd");
		return NULL;
	}
	ha_msg_del(msg);
	/* get the return msg */
	ret = msgfromIPC(ch_cmd, MSG_ALLOWINTR);
	if (NULL == ret) {
		LOG_FAIL_receive_reply(GETALLRCSES);
		return NULL;
	}
	/* get the return code of msg */
	if (HA_OK != get_ret_from_msg(ret)) {
		LOG_GOT_FAIL_RET(LOG_ERR, GETALLRCSES);
		ha_msg_del(ret);
		return NULL;
	}
	/* get the rsc_id list from msg */
	rid_list = ha_msg_value_str_list(ret,F_LRM_RID);

	ha_msg_del(ret);
	/* return the id list */
	return rid_list;

}

static lrm_rsc_t*
lrm_get_rsc (ll_lrm_t* lrm, const char* rsc_id)
{
	struct ha_msg* msg = NULL;
	struct ha_msg* ret = NULL;
	lrm_rsc_t* rsc     = NULL;

	/* check whether the rsc_id is available */
	if (strlen(rsc_id) >= RID_LEN)	{
		cl_log(LOG_ERR, "lrm_get_rsc: rsc_id is too long.");
		return NULL;
	}

	/* check whether the channel to lrmd is available */
	if (NULL == ch_cmd)	{
		cl_log(LOG_ERR, "lrm_get_rsc: ch_mod is null.");
		return NULL;
	}
	/* create the msg of get resource */
	msg = create_lrm_rsc_msg(rsc_id, GETRSC);
	if ( NULL == msg) {
		LOG_FAIL_create_lrm_rsc_msg(GETRSC);
		return NULL;
	}
	/* send the msg to lrmd */
	if (HA_OK != msg2ipcchan(msg,ch_cmd)) {
		ha_msg_del(msg);
		LOG_FAIL_SEND_MSG(GETRSC, "ch_cmd");
		return NULL;
	}
	ha_msg_del(msg);
	/* get the return msg from lrmd */
	ret = msgfromIPC(ch_cmd, MSG_ALLOWINTR);
	if (NULL == ret) {
		LOG_FAIL_receive_reply(GETRSC);
		return NULL;
	}
	/* get the return code of return message */
	if (HA_OK != get_ret_from_msg(ret)) {
		ha_msg_del(ret);
		return NULL;
	}
	/* create a new resource structure */
	rsc = g_new(lrm_rsc_t, 1);

	/* fill the field of resource with the data from msg */
	rsc->id = g_strdup(ha_msg_value(ret, F_LRM_RID));
	rsc->type = g_strdup(ha_msg_value(ret, F_LRM_RTYPE));
	rsc->class = g_strdup(ha_msg_value(ret, F_LRM_RCLASS));
	rsc->provider = g_strdup(ha_msg_value(ret, F_LRM_RPROVIDER));
	rsc->params = ha_msg_value_str_table(ret,F_LRM_PARAM);

	rsc->ops = &rsc_ops_instance;
	ha_msg_del(ret);
	/* return the new resource */
	return rsc;
}

static int
lrm_fail_rsc (ll_lrm_t* lrm, const char* rsc_id, const int fail_rc
,		 const char* fail_reason)
{
	struct ha_msg* msg;

	/* check whether the rsc_id is available */
	if (NULL == rsc_id || RID_LEN <= strlen(rsc_id))	{
		cl_log(LOG_ERR, "%s: wrong parameter rsc_id.", __FUNCTION__);
		return HA_FAIL;
	}

	/* check whether the channel to lrmd is available */
	if (NULL == ch_cmd)	{
		cl_log(LOG_ERR, "%s: ch_mod is null.", __FUNCTION__);
		return HA_FAIL;
	}

	/* create the message */
	msg = create_lrm_rsc_msg(rsc_id,FAILRSC);
	if (NULL == msg) {
		LOG_FAIL_create_lrm_rsc_msg(FAILRSC);
		return HA_FAIL;
	}
	if ((fail_reason && HA_OK != ha_msg_add(msg,F_LRM_FAIL_REASON,fail_reason))
		|| HA_OK != ha_msg_add_int(msg, F_LRM_ASYNCMON_RC, fail_rc)
	) {
		ha_msg_del(msg);
		LOG_BASIC_ERROR("ha_msg_add");
		return HA_FAIL;
	}
	/* send to lrmd */
	if (HA_OK != msg2ipcchan(msg,ch_cmd)) {
		ha_msg_del(msg);
		LOG_FAIL_SEND_MSG(FAILRSC, "ch_cmd");
		return HA_FAIL;
	}
	ha_msg_del(msg);
	/* check the result */
	if (HA_OK != get_ret_from_ch(ch_cmd)) {
		LOG_GOT_FAIL_RET(LOG_ERR, FAILRSC);
		return HA_FAIL;
	}

	return HA_OK;
}

static int
lrm_set_lrmd_param(ll_lrm_t* lrm, const char* name, const char *value)
{
	struct ha_msg* msg;

	if (!name || !value) {
		cl_log(LOG_ERR, "%s: no parameter name or value", __FUNCTION__);
		return HA_FAIL;
	}

	/* check whether the channel to lrmd is available */
	if (NULL == ch_cmd)	{
		cl_log(LOG_ERR, "%s: ch_mod is null.", __FUNCTION__);
		return HA_FAIL;
	}

	/* create the message */
	msg = create_lrm_msg(SETLRMDPARAM);
	if (NULL == msg) {
		LOG_FAIL_create_lrm_rsc_msg(SETLRMDPARAM);
		return HA_FAIL;
	}
	if (HA_OK != ha_msg_add(msg,F_LRM_LRMD_PARAM_NAME,name)
	|| HA_OK != ha_msg_add(msg,F_LRM_LRMD_PARAM_VAL,value)) {
		ha_msg_del(msg);
		LOG_BASIC_ERROR("ha_msg_add");
		return HA_FAIL;
	}
	/* send to lrmd */
	if (HA_OK != msg2ipcchan(msg,ch_cmd)) {
		ha_msg_del(msg);
		LOG_FAIL_SEND_MSG(FAILRSC, "ch_cmd");
		return HA_FAIL;
	}
	ha_msg_del(msg);
	/* check the result */
	if (HA_OK != get_ret_from_ch(ch_cmd)) {
		LOG_GOT_FAIL_RET(LOG_ERR, FAILRSC);
		return HA_FAIL;
	}

	return HA_OK;
}

static char*
lrm_get_lrmd_param (ll_lrm_t* lrm, const char *name)
{
	struct ha_msg* msg = NULL;
	struct ha_msg* ret = NULL;
	const char* value = NULL;
	char* v2;

	/* check whether the channel to lrmd is available */
	if (NULL == ch_cmd)	{
		cl_log(LOG_ERR, "lrm_get_rsc: ch_mod is null.");
		return NULL;
	}
	/* create the msg of get resource */
	msg = create_lrm_msg(GETLRMDPARAM);
	if ( NULL == msg) {
		LOG_FAIL_create_lrm_msg(GETLRMDPARAM);
		return NULL;
	}
	if (HA_OK != ha_msg_add(msg,F_LRM_LRMD_PARAM_NAME,name)) {
		ha_msg_del(msg);
		LOG_BASIC_ERROR("ha_msg_add");
		return NULL;
	}
	/* send the msg to lrmd */
	if (HA_OK != msg2ipcchan(msg,ch_cmd)) {
		ha_msg_del(msg);
		LOG_FAIL_SEND_MSG(GETLRMDPARAM, "ch_cmd");
		return NULL;
	}
	ha_msg_del(msg);
	/* get the return msg from lrmd */
	ret = msgfromIPC(ch_cmd, MSG_ALLOWINTR);
	if (NULL == ret) {
		LOG_FAIL_receive_reply(GETLRMDPARAM);
		return NULL;
	}
	/* get the return code of return message */
	if (HA_OK != get_ret_from_msg(ret)) {
		ha_msg_del(ret);
		return NULL;
	}
	value = ha_msg_value(ret,F_LRM_LRMD_PARAM_VAL);
	if (!value) {
		LOG_FAIL_GET_MSG_FIELD(LOG_ERR, F_LRM_LRMD_PARAM_VAL, ret);
		ha_msg_del(ret);
		return NULL;
	}
	v2 = g_strdup(value);
	ha_msg_del(ret);
	return v2;
}

static int
lrm_add_rsc (ll_lrm_t* lrm, const char* rsc_id, const char* class
, 	     const char* type, const char* provider, GHashTable* parameter)
{
	struct ha_msg* msg;

	/* check whether the rsc_id is available */
	if (NULL == rsc_id || RID_LEN <= strlen(rsc_id))	{
		cl_log(LOG_ERR, "lrm_add_rsc: wrong parameter rsc_id.");
		return HA_FAIL;
	}

	/* check whether the channel to lrmd is available */
	if (NULL == ch_cmd)	{
		cl_log(LOG_ERR, "lrm_add_rsc: ch_mod is null.");
		return HA_FAIL;
	}

	/* create the message of add resource */
	msg = create_lrm_addrsc_msg(rsc_id, class, type, provider, parameter);
	if ( NULL == msg) {
		cl_log(LOG_ERR, "%s(%d): failed to create a ADDSRC message "
			"with function create_lrm_addrsc_msg"
		,	__FUNCTION__, __LINE__);
		return HA_FAIL;
	}
	/* send to lrmd */
	if (HA_OK != msg2ipcchan(msg,ch_cmd)) {
		ha_msg_del(msg);
		LOG_FAIL_SEND_MSG(ADDRSC, "ch_cmd");
		return HA_FAIL;
	}
	ha_msg_del(msg);
	/* check the result */
	if (HA_OK != get_ret_from_ch(ch_cmd)) {
		LOG_GOT_FAIL_RET(LOG_ERR, ADDRSC);
		return HA_FAIL;
	}

	return HA_OK;
}

static int
lrm_delete_rsc (ll_lrm_t* lrm, const char* rsc_id)
{
	struct ha_msg* msg = NULL;
	int rc;

	/* check whether the rsc_id is available */
	if (NULL == rsc_id || RID_LEN <= strlen(rsc_id))	{
		cl_log(LOG_ERR, "lrm_delete_rsc: wrong parameter rsc_id.");
		return HA_FAIL;
	}

	/* check whether the channel to lrmd is available */
	if (NULL == ch_cmd)	{
		cl_log(LOG_ERR, "lrm_delete_rsc: ch_mod is null.");
		return HA_FAIL;
	}

	/* create the msg of del resource */
	msg = create_lrm_rsc_msg(rsc_id, DELRSC);
	if ( NULL == msg) {
		LOG_FAIL_create_lrm_rsc_msg(DELRSC);
		return HA_FAIL;
	}
	/* send the msg to lrmd */
	if (HA_OK != msg2ipcchan(msg,ch_cmd)) {
		ha_msg_del(msg);
		LOG_FAIL_SEND_MSG(DELRSC, "ch_cmd");
		return HA_FAIL;
	}
	ha_msg_del(msg);
	/* check the response of the msg */
	rc = get_ret_from_ch(ch_cmd);
	if (rc != HA_OK && rc != HA_RSCBUSY) {
		LOG_GOT_FAIL_RET(LOG_ERR, DELRSC);
		return HA_FAIL;
	}

	return rc;
}

static IPC_Channel*
lrm_ipcchan (ll_lrm_t* lrm)
{
	if (NULL == ch_cbk) {
		cl_log(LOG_ERR,
			"lrm_inputfd: callback channel is null.");
		return NULL;
	}

	return ch_cbk;
}

static gboolean
lrm_msgready (ll_lrm_t* lrm)
{
	if (NULL == ch_cbk) {
		cl_log(LOG_ERR,
			"lrm_msgready: callback channel is null.");
		return FALSE;
	}
	return ch_cbk->ops->is_message_pending(ch_cbk);
}

static int
lrm_rcvmsg (ll_lrm_t* lrm, int blocking)
{
	struct ha_msg* msg = NULL;
	lrm_op_t* op = NULL;
	int msg_count = 0;

	/* if it is not blocking mode and no message in the channel, return */
	if ((!lrm_msgready(lrm)) && (!blocking)) {
		cl_log(LOG_DEBUG,
			"lrm_rcvmsg: no message and non-block.");
		return msg_count;
	}
	/* wait until message ready */
	if (!lrm_msgready(lrm)) {
		ch_cbk->ops->waitin(ch_cbk);
	}
	while (lrm_msgready(lrm)) {
		if (ch_cbk->ch_status == IPC_DISCONNECT) {
			return msg_count;
		}
		/* get the message */
		msg = msgfromIPC(ch_cbk, MSG_ALLOWINTR);
		if (msg == NULL) {
			cl_log(LOG_WARNING,
				"%s(%d): receive a null message with msgfromIPC."
			,	__FUNCTION__, __LINE__);
			return msg_count;
		}
		msg_count++;

		op = msg_to_op(msg);
		if (NULL!=op && NULL!=op_done_callback) {
			(*op_done_callback)(op);
		}
		free_op(op);
		ha_msg_del(msg);
	}

	return msg_count;
}

/* following are the functions for rsc_ops */
static int
rsc_perform_op (lrm_rsc_t* rsc, lrm_op_t* op)
{
	int rc = 0;
	struct ha_msg* msg = NULL;
	char* rsc_id;

	/* check whether the channel to lrmd is available */
	if (NULL == ch_cmd
	||  NULL == rsc
	||  NULL == rsc->id
	||  NULL == op
	||  NULL == op->op_type) {
		cl_log(LOG_ERR,
			"rsc_perform_op: wrong parameters.");
		return HA_FAIL;
	}
	/* create the msg of perform op */
	rsc_id = op->rsc_id;
	op->rsc_id = rsc->id;
	msg = op_to_msg(op);
	op->rsc_id = rsc_id;
	if ( NULL == msg) {
		cl_log(LOG_ERR, "rsc_perform_op: failed to create a message "
			"with function op_to_msg");
		return HA_FAIL;
	}
	/* send it to lrmd */
	if (HA_OK != msg2ipcchan(msg,ch_cmd)) {
		ha_msg_del(msg);
		LOG_FAIL_SEND_MSG(PERFORMOP, "ch_cmd");
		return HA_FAIL;
	}
	ha_msg_del(msg);

	/* check return code, the return code is the call_id of the op */
	rc = get_ret_from_ch(ch_cmd);
	return rc;
}

static int
rsc_cancel_op (lrm_rsc_t* rsc, int call_id)
{
	int rc;
	struct ha_msg* msg = NULL;

	/* check whether the channel to lrmd is available */
	if (NULL == ch_cmd)	{
		cl_log(LOG_ERR, "rsc_cancel_op: ch_mod is null.");
		return HA_FAIL;
	}
	/* check parameter */
	if (NULL == rsc) {
		cl_log(LOG_ERR, "rsc_cancel_op: parameter rsc is null.");
		return HA_FAIL;
	}
	/* create the msg of flush ops */
	msg = create_lrm_rsc_msg(rsc->id,CANCELOP);
	if (NULL == msg) {
		LOG_FAIL_create_lrm_rsc_msg(CANCELOP);
		return HA_FAIL;
	}
	if (HA_OK != ha_msg_add_int(msg, F_LRM_CALLID, call_id))	{
		LOG_BASIC_ERROR("ha_msg_add_int");
		ha_msg_del(msg);
		return HA_FAIL;
	}
	
	/* send the msg to lrmd */
	if (HA_OK != msg2ipcchan(msg,ch_cmd)) {
		ha_msg_del(msg);
		LOG_FAIL_SEND_MSG(CANCELOP, "ch_cmd");
		return HA_FAIL;
	}
	ha_msg_del(msg);

	rc = get_ret_from_ch(ch_cmd);

	return rc;
}

static int
rsc_flush_ops (lrm_rsc_t* rsc)
{
	int rc;
	struct ha_msg* msg = NULL;

	/* check whether the channel to lrmd is available */
	if (NULL == ch_cmd)	{
		cl_log(LOG_ERR, "rsc_flush_ops: ch_mod is null.");
		return HA_FAIL;
	}
	/* check parameter */
	if (NULL == rsc) {
		cl_log(LOG_ERR, "rsc_flush_ops: parameter rsc is null.");
		return HA_FAIL;
	}
	/* create the msg of flush ops */
	msg = create_lrm_rsc_msg(rsc->id,FLUSHOPS);
	if ( NULL == msg) {
		LOG_FAIL_create_lrm_rsc_msg(CANCELOP);
		return HA_FAIL;
	}
	/* send the msg to lrmd */
	if (HA_OK != msg2ipcchan(msg,ch_cmd)) {
		ha_msg_del(msg);
		LOG_FAIL_SEND_MSG(FLUSHOPS, "ch_cmd");
		return HA_FAIL;
	}
	ha_msg_del(msg);

	rc = get_ret_from_ch(ch_cmd);

	return rc>0?rc:HA_FAIL;
}
static gint 
compare_call_id(gconstpointer a, gconstpointer b)
{
	const lrm_op_t* opa = (const lrm_op_t*)a;
	const lrm_op_t* opb = (const lrm_op_t*)b;
	return opa->call_id - opb->call_id;
}
static GList*
rsc_get_cur_state (lrm_rsc_t* rsc, state_flag_t* cur_state)
{
	GList* op_list = NULL, * tmplist = NULL;
	struct ha_msg* msg = NULL;
	struct ha_msg* ret = NULL;
	struct ha_msg* op_msg = NULL;
	lrm_op_t* op = NULL;
	int state;
	int op_count, i;

	/* check whether the channel to lrmd is available */
	if (NULL == ch_cmd)	{
		cl_log(LOG_ERR, "rsc_get_cur_state: ch_mod is null.");
		return NULL;
	}
	/* check paramter */
	if (NULL == rsc) {
		cl_log(LOG_ERR, "rsc_get_cur_state: parameter rsc is null.");
		return NULL;
	}
	/* create the msg of get current state of resource */
	msg = create_lrm_rsc_msg(rsc->id,GETRSCSTATE);
	if ( NULL == msg) {
		LOG_FAIL_create_lrm_rsc_msg(GETRSCSTATE);
		return NULL;
	}
	/* send the msg to lrmd */
	if (HA_OK != msg2ipcchan(msg,ch_cmd)) {
		ha_msg_del(msg);
		LOG_FAIL_SEND_MSG(GETRSCSTATE, "ch_cmd");
		return NULL;
	}
	ha_msg_del(msg);

	/* get the return msg */
	ret = msgfromIPC(ch_cmd, MSG_ALLOWINTR);
	if (NULL == ret) {
		LOG_FAIL_receive_reply(GETRSCSTATE);
		return NULL;
	}

	/* get the state of the resource from the message */
	if (HA_OK != ha_msg_value_int(ret, F_LRM_STATE, &state)) {
		LOG_FAIL_GET_MSG_FIELD(LOG_ERR, F_LRM_STATE, ret);
		ha_msg_del(ret);
		return NULL;
	}
	*cur_state = (state_flag_t)state;
	/* the first msg includes the count of pending ops. */
	if (HA_OK != ha_msg_value_int(ret, F_LRM_OPCNT, &op_count)) {
		LOG_FAIL_GET_MSG_FIELD(LOG_WARNING, F_LRM_OPCNT, ret);
		ha_msg_del(ret);
		return NULL;
	}
	ha_msg_del(ret);
	for (i = 0; i < op_count; i++) {
		/* one msg for one op */
		op_msg = msgfromIPC(ch_cmd, MSG_ALLOWINTR);

		if (NULL == op_msg) {
			cl_log(LOG_WARNING, "%s(%d): failed to receive a "
				"(pending operation) message from lrmd."
			,	__FUNCTION__, __LINE__);
			continue;
		}
		op = msg_to_op(op_msg);
		/* add msg to the return list */
		
		if (NULL != op) {
			op_list = g_list_append(op_list, op);
		}
		else {
			cl_log(LOG_WARNING, "%s(%d): failed to make a operation "
				"from a message with function msg_to_op"
			,	__FUNCTION__, __LINE__);
		}
		ha_msg_del(op_msg);
	}
	op_list = g_list_sort(op_list, compare_call_id);

	/* Delete the duplicate op for call_id */
#if 0	
	cl_log(LOG_WARNING, "Before uniquing");
	tmplist = g_list_first(op_list);
	while (tmplist != NULL) {
		cl_log(LOG_WARNING, "call_id=%d", ((lrm_op_t*)(tmplist->data))->call_id);
		tmplist = g_list_next(tmplist);
	}
#endif

	tmplist = g_list_first(op_list);
	while (tmplist != NULL) {
		if (NULL != g_list_previous(tmplist)) {
			if (((lrm_op_t*)(g_list_previous(tmplist)->data))->call_id
			     == ((lrm_op_t*)(tmplist->data))->call_id) {
				op_list = g_list_remove_link (op_list, tmplist);
				free_op((lrm_op_t *)tmplist->data);
				g_list_free_1(tmplist);
				tmplist = g_list_first(op_list);
			}
		}
		tmplist = g_list_next(tmplist);
	}

#if 0
	cl_log(LOG_WARNING, "After uniquing");
	while (tmplist != NULL) {
		cl_log(LOG_WARNING, "call_id=%d", ((lrm_op_t*)(tmplist->data))->call_id);
		tmplist = g_list_next(tmplist);
	}
#endif

	return op_list;
}

static lrm_op_t*
rsc_get_last_result (lrm_rsc_t* rsc, const char* op_type)
{
	struct ha_msg* msg = NULL;
	struct ha_msg* ret = NULL;
	lrm_op_t* op = NULL;
	int opcount = 0;
	/* check whether the channel to lrmd is available */
	if (NULL == ch_cmd)	{
		cl_log(LOG_ERR, "rsc_get_last_result: ch_mod is null.");
		return NULL;
	}
	/* check parameter */
	if (NULL == rsc) {
		cl_log(LOG_ERR, "rsc_get_last_result: parameter rsc is null.");
		return NULL;
	}
	/* create the msg of get last op */
	msg = create_lrm_rsc_msg(rsc->id,GETLASTOP);
	if (NULL == msg) {
		LOG_FAIL_create_lrm_rsc_msg(GETLASTOP);
		return NULL;
	}
	if (HA_OK != ha_msg_add(msg, F_LRM_RID, rsc->id))	{
		LOG_BASIC_ERROR("ha_msg_add");
		ha_msg_del(msg);
		return NULL;
	}
	if (HA_OK != ha_msg_add(msg, F_LRM_OP, op_type))	{
		LOG_BASIC_ERROR("ha_msg_add");
		ha_msg_del(msg);
		return NULL;
	}
	
	/* send the msg to lrmd */
	if (HA_OK != msg2ipcchan(msg,ch_cmd)) {
		ha_msg_del(msg);
		LOG_FAIL_SEND_MSG(GETLASTOP, "ch_cmd");
		return NULL;
	}
	
	/* get the return msg */
	ret = msgfromIPC(ch_cmd, MSG_ALLOWINTR);
	if (NULL == ret) {
		LOG_FAIL_receive_reply(GETLASTOP);
		ha_msg_del(msg);
		return NULL;
	}
	if (HA_OK != ha_msg_value_int(ret,F_LRM_OPCNT, &opcount)) {
		op = NULL;
	} 
	else if ( 1 == opcount ) {
		op = msg_to_op(ret);
	}
	ha_msg_del(msg);
	ha_msg_del(ret);
	return op;
}
/* 
 * following are the implements of the utility functions
 */
lrm_op_t*
lrm_op_new(void)
{
	lrm_op_t* op;

	op = g_new0(lrm_op_t, 1);
	op->op_status = LRM_OP_PENDING;
	return op;
}

static lrm_op_t*
msg_to_op(struct ha_msg* msg)
{
	lrm_op_t* op;
	const char* op_type;
	const char* app_name;
	const char* rsc_id;
	const char* fail_reason;
	const char* output;
	const void* user_data;

	op = lrm_op_new();

	/* op->timeout, op->interval, op->target_rc, op->call_id*/
	if (HA_OK != ha_msg_value_int(msg,F_LRM_TIMEOUT, &op->timeout)
	||  HA_OK != ha_msg_value_int(msg,F_LRM_INTERVAL, &op->interval)
	||  HA_OK != ha_msg_value_int(msg,F_LRM_TARGETRC, &op->target_rc)
	||  HA_OK != ha_msg_value_int(msg,F_LRM_DELAY, &op->start_delay)
	||  HA_OK != ha_msg_value_int(msg,F_LRM_CALLID, &op->call_id)) {
		LOG_BASIC_ERROR("ha_msg_value_int");
		free_op(op);
		return NULL;
	}

	/* op->op_status */
	if (HA_OK !=
		ha_msg_value_int(msg, F_LRM_OPSTATUS, (int*)&op->op_status)) {
		LOG_FAIL_GET_MSG_FIELD(LOG_WARNING, F_LRM_OPSTATUS, msg);
                op->op_status = LRM_OP_PENDING;
	}

	/* if it finished successfully */
	if (LRM_OP_DONE == op->op_status ) {
		/* op->rc */
		if (HA_OK != ha_msg_value_int(msg, F_LRM_RC, &op->rc)) {
			free_op(op);
			LOG_FAIL_GET_MSG_FIELD(LOG_ERR, F_LRM_RC, msg);
			return NULL;
		}
		/* op->output */
		output = cl_get_string(msg, F_LRM_DATA);
		if (NULL != output){
			op->output = g_strdup(output);
		}
		else {
			op->output = NULL;
		}
	} else if(op->op_status == LRM_OP_PENDING) {
		op->rc = EXECRA_STATUS_UNKNOWN;
		
	} else {
		op->rc = EXECRA_EXEC_UNKNOWN_ERROR;
	}


	/* op->app_name */
	app_name = ha_msg_value(msg, F_LRM_APP);
	if (NULL == app_name) {
		LOG_FAIL_GET_MSG_FIELD(LOG_ERR, F_LRM_APP, msg);
		free_op(op);
		return NULL;
	}
	op->app_name = g_strdup(app_name);
	
	
	/* op->op_type */
	op_type = ha_msg_value(msg, F_LRM_OP);
	if (NULL == op_type) {
		LOG_FAIL_GET_MSG_FIELD(LOG_ERR, F_LRM_OP, msg);
		free_op(op);
		return NULL;
	}
	op->op_type = g_strdup(op_type);

	/* op->rsc_id */
	rsc_id = ha_msg_value(msg, F_LRM_RID);
	if (NULL == rsc_id) {
		LOG_FAIL_GET_MSG_FIELD(LOG_ERR, F_LRM_RID, msg);
		free_op(op);
		return NULL;
	}
	op->rsc_id = g_strdup(rsc_id);

	/* op->fail_reason present only on async failures */
	fail_reason = ha_msg_value(msg, F_LRM_FAIL_REASON);
	if (fail_reason) {
		op->fail_reason = g_strdup(fail_reason);
	}

	/* op->user_data */
	user_data = cl_get_string(msg, F_LRM_USERDATA);
	
	if (NULL != user_data) {
		op->user_data = g_strdup(user_data);
	}
	
	/* time_stamps */
	if (ha_msg_value_ul(msg, F_LRM_T_RUN, &op->t_run) != HA_OK
	   || ha_msg_value_ul(msg, F_LRM_T_RCCHANGE, &op->t_rcchange) != HA_OK
	   || ha_msg_value_ul(msg, F_LRM_EXEC_TIME, &op->exec_time) != HA_OK
	   || ha_msg_value_ul(msg, F_LRM_QUEUE_TIME, &op->queue_time) != HA_OK) {
		/* cl_log(LOG_WARNING
		, "%s:%d: failed to get the timing information"
		, __FUNCTION__, __LINE__);
		*/
	}
	
	/* op->params */
	op->params = ha_msg_value_str_table(msg, F_LRM_PARAM);

	ha_msg_value_int(msg, F_LRM_RSCDELETED, &op->rsc_deleted);

	return op;
}

static struct ha_msg*
op_to_msg (lrm_op_t* op)
{
	struct ha_msg* msg = ha_msg_new(15);
	if (!msg) {
		LOG_BASIC_ERROR("ha_msg_new");
		return NULL;
	}
	
	if (HA_OK != ha_msg_add(msg, F_LRM_TYPE, PERFORMOP)
	||  HA_OK != ha_msg_add(msg, F_LRM_RID, op->rsc_id)
	||  HA_OK != ha_msg_add(msg, F_LRM_OP, op->op_type)
	||  HA_OK != ha_msg_add_int(msg, F_LRM_TIMEOUT, op->timeout)
	||  HA_OK != ha_msg_add_int(msg, F_LRM_INTERVAL, op->interval)
	||  HA_OK != ha_msg_add_int(msg, F_LRM_DELAY, op->start_delay)
	||  HA_OK != ha_msg_add_int(msg, F_LRM_COPYPARAMS, op->copyparams)
	||  HA_OK != ha_msg_add_ul(msg, F_LRM_T_RUN,op->t_run)
	||  HA_OK != ha_msg_add_ul(msg, F_LRM_T_RCCHANGE, op->t_rcchange)
	||  HA_OK != ha_msg_add_ul(msg, F_LRM_EXEC_TIME, op->exec_time)
	||  HA_OK != ha_msg_add_ul(msg, F_LRM_QUEUE_TIME, op->queue_time)
	||  HA_OK != ha_msg_add_int(msg, F_LRM_TARGETRC, op->target_rc)
	||  ( op->app_name && (HA_OK != ha_msg_add(msg, F_LRM_APP, op->app_name)))
	||  ( op->user_data && (HA_OK != ha_msg_add(msg,F_LRM_USERDATA,op->user_data)))
	||  ( op->params && (HA_OK != ha_msg_add_str_table(msg,F_LRM_PARAM,op->params)))) {
		LOG_BASIC_ERROR("op_to_msg conversion failed");
		ha_msg_del(msg);
		return NULL;
	}

	return msg;
}

static int
get_ret_from_ch(IPC_Channel* ch)
{
	int ret;
	struct ha_msg* msg;

	msg = msgfromIPC(ch, MSG_ALLOWINTR);

	if (NULL == msg) {
		cl_log(LOG_ERR
		, "%s(%d): failed to receive message with function msgfromIPC"
		, __FUNCTION__, __LINE__);
		return HA_FAIL;
	}
	if (HA_OK != ha_msg_value_int(msg, F_LRM_RET, &ret)) {
		LOG_FAIL_GET_MSG_FIELD(LOG_ERR, F_LRM_RET, msg);
		ha_msg_del(msg);
		return HA_FAIL;
	}
	ha_msg_del(msg);
	return ret;
}

static int
get_ret_from_msg(struct ha_msg* msg)
{
	int ret;

	if (NULL == msg) {
		cl_log(LOG_ERR, "%s(%d): the parameter is a NULL pointer."
		,	__FUNCTION__, __LINE__);
		return HA_FAIL;
	}
	if (HA_OK != ha_msg_value_int(msg, F_LRM_RET, &ret)) {
		LOG_FAIL_GET_MSG_FIELD(LOG_ERR, F_LRM_RET, msg);
		return HA_FAIL;
	}
	return ret;
}
static void
free_op (lrm_op_t* op)
{
	if (NULL == op) {
		return;
	}
	if (NULL != op->op_type) {
		g_free(op->op_type);
	}
	if (NULL != op->output) {
		g_free(op->output);
	}
	if (NULL != op->rsc_id) {
		g_free(op->rsc_id);
	}
	if (NULL != op->app_name) {
		g_free(op->app_name);
	}
	if (NULL != op->user_data) {
		g_free(op->user_data);
	}
	if (NULL != op->params) {
		free_str_table(op->params);
	}
	g_free(op);
}

void lrm_free_op(lrm_op_t* op) {
	free_op(op);
}
void lrm_free_rsc(lrm_rsc_t* rsc) {
	if (NULL == rsc) {
		return;
	}
	if (NULL != rsc->id) {
		g_free(rsc->id);
	}
	if (NULL != rsc->type) {
		g_free(rsc->type);
	}
	if (NULL != rsc->class) {
		g_free(rsc->class);
	}
	if (NULL != rsc->provider) {
		g_free(rsc->provider);
	}
	if (NULL != rsc->params) {
		free_str_table(rsc->params);
	}
	g_free(rsc);
}
void lrm_free_str_list(GList* list) {
	GList* item;
	if (NULL == list) {
		return;
	}
	item = g_list_first(list);
	while (NULL != item) {
		if (NULL != item->data) {
			g_free(item->data);
		}
		list = g_list_delete_link(list, item);
		item = g_list_first(list);
	}
}	
void lrm_free_op_list(GList* list) {
	GList* item;
	if (NULL == list) {
		return;
	}
	item = g_list_first(list);
	while (NULL != item) {
		if (NULL != item->data) {
			free_op((lrm_op_t*)item->data);
		}
		list = g_list_delete_link(list, item);
		item = g_list_first(list);
	}
}	
void lrm_free_str_table(GHashTable* table) {
	if (NULL != table) {
		free_str_table(table);
	}
}

const char *
execra_code2string(uniform_ret_execra_t code)
{
	switch(code) {
		case EXECRA_EXEC_UNKNOWN_ERROR:
			return "unknown exec error";
		case EXECRA_NO_RA:
			return "no RA";
		case EXECRA_OK:
			return "ok";
		case EXECRA_UNKNOWN_ERROR:
			return "unknown error";
		case EXECRA_INVALID_PARAM:
			return "invalid parameter";
		case EXECRA_UNIMPLEMENT_FEATURE:
			return "unimplemented feature";
		case EXECRA_INSUFFICIENT_PRIV:
			return "insufficient privileges";
		case EXECRA_NOT_INSTALLED:
			return "not installed";
		case EXECRA_NOT_CONFIGURED:
			return "not configured";
		case EXECRA_NOT_RUNNING:
			return "not running";
		/* For status command only */
		case EXECRA_RUNNING_MASTER:
			return "master";
		case EXECRA_FAILED_MASTER:
			return "master (failed)";
		case EXECRA_RA_DEAMON_DEAD1:
			return "status: daemon dead";
		case EXECRA_RA_DEAMON_DEAD2:
			return "status: daemon dead";
		case EXECRA_RA_DEAMON_STOPPED:
			return "status: daemon stopped";
		case EXECRA_STATUS_UNKNOWN:
			return "status: unknown";
		default:
		break;
	}

	return "<unknown>";
}
