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
#include <portability.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include <glib.h>
#include <heartbeat.h>
#include <clplumbing/ipc.h>
#include <ha_msg.h>
#include <lrm/lrm_api.h>
#include <lrm/lrm_msg.h>

/* Notice: this define should be replaced when merge to the whole pkg*/
#define	LRM_MAXPIDLEN 	256
#define LRM_ID		"lrm"

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
static int lrm_inputfd (ll_lrm_t*);
static int lrm_msgready (ll_lrm_t*);
static int lrm_rcvmsg (ll_lrm_t*, int blocking);

static struct lrm_ops lrm_ops_instance =
{
	lrm_signon,
	lrm_signoff,
	lrm_delete,
	lrm_set_lrm_callback,
	lrm_get_rsc_class_supported,
	lrm_get_rsc_type_supported,
	lrm_get_rsc_provider_supported,
	lrm_get_rsc_type_metadata,
	lrm_get_all_type_metadata,
	lrm_get_all_rscs,
	lrm_get_rsc,
	lrm_add_rsc,
	lrm_delete_rsc,
	lrm_inputfd,
	lrm_msgready,
	lrm_rcvmsg
};
/* declare the functions used by the lrm_rsc_ops structure*/
static int rsc_perform_op (lrm_rsc_t*, lrm_op_t* op);
static int rsc_stop_op (lrm_rsc_t*, int call_id);
static int rsc_flush_ops (lrm_rsc_t*);
static GList* rsc_get_cur_state (lrm_rsc_t*, state_flag_t* cur_state);

static struct rsc_ops rsc_ops_instance =
{
	rsc_perform_op,
	rsc_stop_op,
	rsc_flush_ops,
	rsc_get_cur_state,
};


/* define the internal data used by the client library*/
typedef struct {
	char*		rsc_id;
	int 		call_id;
	int		interval;
	gpointer	user_data;
}op_save_t;

static int is_signed_on					= FALSE;
static IPC_Channel* ch_cmd				= NULL;
static IPC_Channel* ch_cbk 				= NULL;
static lrm_op_done_callback_t	op_done_callback 	= NULL;
static GList* op_save_list				= NULL;

/* define some utility functions*/
static int get_rc_from_ch(IPC_Channel* ch);
static int get_rc_from_msg(struct ha_msg* msg);
static void client_log (int priority, const char* fmt);
static struct ha_msg* op_to_msg (lrm_op_t* op);
static lrm_op_t* msg_to_op(struct ha_msg* msg);
static op_save_t* lookup_op_save(int call_id);

/* define of the api functions*/
ll_lrm_t*
ll_lrm_new (const char * llctype)
{
	ll_lrm_t* lrm;

	client_log(LOG_INFO, "ll_lrm_new: start.");

	/* check the parameter*/
	if (0 != strncmp(LRM_ID, llctype, strlen(LRM_ID))) {
		client_log(LOG_ERR, "ll_lrm_new: wrong parameter");
		return NULL;
	}

	/* alloc memory for lrm*/
	if (NULL == (lrm = (ll_lrm_t*) g_new(ll_lrm_t,1))) {
		client_log(LOG_ERR, "ll_lrm_new: can not alloc memory");
		return NULL;
	}
	/* assign the ops*/
	lrm->lrm_ops = &lrm_ops_instance;

	client_log(LOG_INFO, "ll_lrm_new: end.");
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

	client_log(LOG_INFO, "lrm_signon: start.");

	/* check parameters*/
	if (NULL == lrm || NULL == app_name) {
		client_log(LOG_ERR, "lrm_signon: wrong parameter");
		return HA_FAIL;
	}

	/* if already signed on, sign off first*/
	if (is_signed_on) {
		client_log(LOG_INFO,
			"lrm_signon: the client is alreay signed on,re-sign");
		lrm_signoff(lrm);
	}

	/* create the command ipc channel to lrmd*/
	ch_cmd_attrs = g_hash_table_new(g_str_hash, g_str_equal);
	g_hash_table_insert(ch_cmd_attrs, path, cmd_path);
	ch_cmd = ipc_channel_constructor(IPC_ANYTYPE, ch_cmd_attrs);
	g_hash_table_destroy(ch_cmd_attrs);

	if (NULL == ch_cmd){
		lrm_signoff(lrm);
		client_log(LOG_ERR,
			"lrm_signon: can not connect to lrmd for cmd channel");
		return HA_FAIL;
	}

	if (IPC_OK != ch_cmd->ops->initiate_connection(ch_cmd)) {
		lrm_signoff(lrm);
		client_log(LOG_ERR,
			"lrm_signon: can not initiate connection");
		return HA_FAIL;
	}

	/* construct the reg msg*/
	if (NULL == (msg = create_lrm_reg_msg(app_name))) {
		lrm_signoff(lrm);
		client_log(LOG_ERR,"lrm_signon: can not create reg msg");
		return HA_FAIL;
	}

	/* send the msg*/
	if (HA_OK != msg2ipcchan(msg,ch_cmd)) {
		lrm_signoff(lrm);
		ha_msg_del(msg);
		client_log(LOG_ERR,"lrm_signon: can not send msg to lrmd");
		return HA_FAIL;
	}
	/* parse the return msg*/
	if (HA_OK != get_rc_from_ch(ch_cmd)) {
		ha_msg_del(msg);
		lrm_signoff(lrm);
		client_log(LOG_ERR,
			"lrm_signon: can not recv result from lrmd");
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
		client_log(LOG_ERR,
			"lrm_signon: can not connect to lrmd for callback");
		return HA_FAIL;
	}

	if (IPC_OK != ch_cbk->ops->initiate_connection(ch_cbk)) {
		ha_msg_del(msg);
		lrm_signoff(lrm);
		client_log(LOG_ERR,
			"lrm_signon: can not initiate connection");
		return HA_FAIL;
	}
	/* send the msg*/
	if (HA_OK != msg2ipcchan(msg,ch_cbk)) {
		lrm_signoff(lrm);
		ha_msg_del(msg);
		client_log(LOG_ERR,"lrm_signon: can not send msg to lrmd");
		return HA_FAIL;
	}
	ha_msg_del(msg);
	/* parse the return msg*/
	if (HA_OK != get_rc_from_ch(ch_cbk)) {
		lrm_signoff(lrm);
		client_log(LOG_ERR,
			"lrm_signon: can not recv result from lrmd");
		return HA_FAIL;
	}
	/* ok, we sign on sucessfully now*/
	is_signed_on = TRUE;
	client_log(LOG_INFO, "lrm_signon: end.");
	return HA_OK;
}

static int
lrm_signoff (ll_lrm_t* lrm)
{
	int ret = HA_OK;
	struct ha_msg* msg = NULL;
	client_log(LOG_INFO,"lrm_signoff: start.");

	/* construct the unreg msg*/
	if ( NULL == ch_cmd ) {
		client_log(LOG_INFO,"lrm_signoff: ch_cmd is NULL");
		ret = HA_FAIL;
	}
	else
	if ( NULL == (msg = create_lrm_msg(UNREGISTER))) {
		client_log(LOG_INFO,"lrm_signoff: can not create unreg msg");
		ret = HA_FAIL;
	}
	else
	/* send the msg*/
	if (HA_OK != msg2ipcchan(msg,ch_cmd)) {
		client_log(LOG_INFO,"lrm_signoff: can not send msg to lrmd");
		ret = HA_FAIL;
	}
	else
	/* parse the return msg*/
	if (HA_OK != get_rc_from_ch(ch_cmd)) {
		client_log(LOG_INFO,
			"lrm_signoff: can not return failed from lrmd");
		ret = HA_FAIL;
	}

	if( NULL != msg ) {
		ha_msg_del(msg);
	}

	/* close channels */
	if (NULL != ch_cmd) {
 		ch_cmd->ops->destroy(ch_cmd);
		ch_cmd = NULL;
	}
	if (NULL != ch_cbk) {
		ch_cbk->ops->destroy(ch_cbk);
		ch_cbk = NULL;
	}
	is_signed_on = FALSE;

	client_log(LOG_INFO, "lrm_signoff: end.");
	return ret;
}

static int
lrm_delete (ll_lrm_t* lrm)
{
	client_log(LOG_INFO,"lrm_delete: start.");
	/* check the parameter */
	if (NULL == lrm) {
		client_log(LOG_ERR,"lrm_delete: lrm is null.");
		return HA_FAIL;
	}

	g_free(lrm);
	client_log(LOG_INFO,"lrm_delete: end.");
	return HA_OK;
}

static int
lrm_set_lrm_callback (ll_lrm_t* lrm,
			lrm_op_done_callback_t op_done_callback_func)

{
	client_log(LOG_INFO, "lrm_set_lrm_callback: start.");

	op_done_callback = op_done_callback_func;

	client_log(LOG_INFO, "lrm_set_lrm_callback: end.");
	return HA_OK;
}

static GList*
lrm_get_rsc_class_supported (ll_lrm_t* lrm)
{
	struct ha_msg* msg;
	struct ha_msg* ret;
	GList* class_list = NULL;
	/* check whether the channel to lrmd is available */
	client_log(LOG_INFO, "lrm_get_rsc_class_supported: start.");
	if (NULL == ch_cmd)
	{
		client_log(LOG_ERR,
			"lrm_get_rsc_class_supported: ch_mod is null.");
		return NULL;
	}
	/* create the get ra type message */
	msg = create_lrm_msg(GETRSCCLASSES);
	if ( NULL == msg) {
		client_log(LOG_ERR,
			"lrm_get_rsc_class_supported: can not create types msg");
		return NULL;
	}

	/* send the msg to lrmd */
	if (HA_OK != msg2ipcchan(msg,ch_cmd)) {
		ha_msg_del(msg);
		client_log(LOG_ERR,
			"lrm_get_rsc_class_supported: can not send msg to lrmd");
		return NULL;
	}
	ha_msg_del(msg);
	/* get the return message */
	ret = msgfromIPC_noauth(ch_cmd);
	if (NULL == ret) {
		client_log(LOG_ERR,
			"lrm_get_rsc_class_supported: can not recieve ret msg");
		return NULL;
	}
	/* get the rc of the message */
	if (HA_OK != get_rc_from_msg(ret)) {
		ha_msg_del(ret);
		client_log(LOG_ERR,
			"lrm_get_rsc_class_supported: rc from msg is fail");
		return NULL;
	}
	/* get the ra type list from message */
	class_list = ha_msg_value_str_list(ret,F_LRM_RCLASS);

	ha_msg_del(ret);
	client_log(LOG_INFO, "lrm_get_rsc_class_supported: end.");

	return class_list;
}
static GList*
lrm_get_rsc_type_supported (ll_lrm_t* lrm, const char* rclass)
{
	struct ha_msg* msg;
	struct ha_msg* ret;
	GList* type_list = NULL;
	/* check whether the channel to lrmd is available */
	client_log(LOG_INFO, "lrm_get_rsc_type_supported: start.");
	if (NULL == ch_cmd)
	{
		client_log(LOG_ERR,
			"lrm_get_rsc_type_supported: ch_mod is null.");
		return NULL;
	}
	/* create the get ra type message */
	msg = create_lrm_msg(GETRSCTYPES);
	if ( NULL == msg) {
		client_log(LOG_ERR,
			"lrm_get_rsc_type_supported: can not create types msg");
		return NULL;
	}
	if ( HA_OK != ha_msg_add(msg, F_LRM_RCLASS, rclass)) {
		ha_msg_del(msg);
		client_log(LOG_ERR,
			"lrm_get_rsc_type_supported: can not add field to msg");
		return NULL;
	}

	/* send the msg to lrmd */
	if (HA_OK != msg2ipcchan(msg,ch_cmd)) {
		ha_msg_del(msg);
		client_log(LOG_ERR,
			"lrm_get_rsc_type_supported: can not send msg to lrmd");
		return NULL;
	}
	ha_msg_del(msg);
	/* get the return message */
	ret = msgfromIPC_noauth(ch_cmd);
	if (NULL == ret) {
		client_log(LOG_ERR,
			"lrm_get_rsc_type_supported: can not recieve ret msg");
		return NULL;
	}
	/* get the rc of the message */
	if (HA_OK != get_rc_from_msg(ret)) {
		ha_msg_del(ret);
		client_log(LOG_ERR,
			"lrm_get_rsc_type_supported: rc from msg is fail");
		return NULL;
	}
	/* get the ra type list from message */
	type_list = ha_msg_value_str_list(ret,F_LRM_RTYPES);

	ha_msg_del(ret);

	client_log(LOG_INFO, "lrm_get_rsc_type_supported: end.");
	return type_list;
}
static GList*
lrm_get_rsc_provider_supported (ll_lrm_t* lrm, const char* class, const char* type)
{
	struct ha_msg* msg;
	struct ha_msg* ret;
	GList* provider_list = NULL;
	/* check whether the channel to lrmd is available */
	client_log(LOG_INFO, "lrm_get_rsc_provider_supported: start.");
	if (NULL == ch_cmd)
	{
		client_log(LOG_ERR,
			"lrm_get_rsc_provider_supported: ch_mod is null.");
		return NULL;
	}
	/* create the get ra providers message */
	msg = create_lrm_msg(GETPROVIDERS);
	if ( NULL == msg) {
		client_log(LOG_ERR,
			"lrm_get_rsc_provider_supported: can not create types msg");
		return NULL;
	}
	if (HA_OK != ha_msg_add(msg, F_LRM_RCLASS, class)
	||  HA_OK != ha_msg_add(msg, F_LRM_RTYPE, type)) {
		ha_msg_del(msg);
		client_log(LOG_ERR,
			"lrm_get_rsc_provider_supported: can not add field to msg");
		return NULL;
	}

	/* send the msg to lrmd */
	if (HA_OK != msg2ipcchan(msg,ch_cmd)) {
		ha_msg_del(msg);
		client_log(LOG_ERR,
			"lrm_get_rsc_provider_supported: can not send msg to lrmd");
		return NULL;
	}
	ha_msg_del(msg);
	/* get the return message */
	ret = msgfromIPC_noauth(ch_cmd);
	if (NULL == ret) {
		client_log(LOG_ERR,
			"lrm_get_rsc_provider_supported: can not recieve ret msg");
		return NULL;
	}
	/* get the rc of the message */
	if (HA_OK != get_rc_from_msg(ret)) {
		ha_msg_del(ret);
		client_log(LOG_ERR,
			"lrm_get_rsc_provider_supported: rc from msg is fail");
		return NULL;
	}
	/* get the ra provider list from message */
	provider_list = ha_msg_value_str_list(ret,F_LRM_RPROVIDERS);

	ha_msg_del(ret);
	client_log(LOG_INFO, "lrm_get_rsc_provider_supported: end.");

	return provider_list;
}
	
/*
 * lrm_get_all_type_metadatas():
 * For OCF RAs, they may have more than one providers so they may have more than
 * one metadata. The hash table is not suitable for this. Fix Me
 */
static GHashTable*
lrm_get_all_type_metadata (ll_lrm_t* lrm, const char* rclass)
{
	GHashTable* metas = g_hash_table_new(g_str_hash, g_str_equal);
	GList* types = lrm_get_rsc_type_supported (lrm, rclass);
	GList* node = NULL;
        const char* meta;

	client_log(LOG_INFO,"lrm_get_all_type_metadatas: start.");
	for (node = g_list_first(types); NULL!=node; node=g_list_next(node)) {
		meta = lrm_get_rsc_type_metadata(lrm,rclass,node->data,NULL);
		if (NULL == meta) {
			continue;
		}
		g_hash_table_insert(metas, node->data,strdup(meta));
	}
	g_list_free(types);
	
	client_log(LOG_INFO,"lrm_get_all_type_metadatas: end.");
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
	size_t len;
	/* check whether the channel to lrmd is available */
	client_log(LOG_INFO, "lrm_get_rsc_type_metadata: start.");
	if (NULL == ch_cmd)
	{
		client_log(LOG_ERR,
			"lrm_get_rsc_type_metadata: ch_mod is null.");
		return NULL;
	}
	/* create the get ra type message */
	msg = create_lrm_msg(GETRSCMETA);
	if (NULL == msg ) {
		client_log(LOG_ERR,
			"lrm_get_rsc_type_metadata: can not create msg");
		return NULL;
	}
	
	if (HA_OK != ha_msg_add(msg, F_LRM_RCLASS, rclass)
	||  HA_OK != ha_msg_add(msg, F_LRM_RTYPE, rtype)){
		ha_msg_del(msg);
		client_log(LOG_ERR,
			"lrm_get_rsc_type_metadata: can not add fields");
		return NULL;
	}

	if( provider ) {
		if (HA_OK != ha_msg_add(msg, F_LRM_RPROVIDER, provider)) {
			client_log(LOG_ERR,
			"lrm_get_rsc_type_metadata: can not add provider");
			ha_msg_del(msg);
			return NULL;
		}
	}

	/* send the msg to lrmd */
	if (HA_OK != msg2ipcchan(msg,ch_cmd)) {
		ha_msg_del(msg);
		client_log(LOG_ERR,
			"lrm_get_rsc_type_supported: can not send msg to lrmd");
		return NULL;
	}
	ha_msg_del(msg);
	/* get the return message */
	ret = msgfromIPC_noauth(ch_cmd);
	if (NULL == ret) {
		client_log(LOG_ERR,
			"lrm_get_rsc_type_supported: can not recieve ret msg");
		return NULL;
	}
	/* get the rc of the message */
	if (HA_OK != get_rc_from_msg(ret)) {
		ha_msg_del(ret);
		client_log(LOG_ERR,
			"lrm_get_rsc_type_supported: rc from msg is fail");
		return NULL;
	}

	/* get the metadata from message */
	tmp = cl_get_binary(ret, F_LRM_METADATA, &len);

	metadata = strndup(tmp, len);
	ha_msg_del(ret);

	client_log(LOG_INFO, "lrm_get_rsc_type_supported: end.");

	return metadata;
}

static GList*
lrm_get_all_rscs (ll_lrm_t* lrm)
{
	struct ha_msg* msg = NULL;
	struct ha_msg* ret = NULL;
	GList* rid_list = NULL;

	client_log(LOG_INFO, "lrm_get_all_rscs: start.");

	/* check whether the channel to lrmd is available */
	if (NULL == ch_cmd) {
		client_log(LOG_ERR, "lrm_get_all_rscs: ch_mod is null.");
		return NULL;
	}
	/* create the msg of get all resource */
	msg = create_lrm_msg(GETALLRCSES);
	if ( NULL == msg) {
		client_log(LOG_ERR,
			"lrm_get_all_rscs: can not create types msg");
		return NULL;
	}
	/* send the msg to lrmd */
	if (HA_OK != msg2ipcchan(msg,ch_cmd)) {
		ha_msg_del(msg);
		client_log(LOG_ERR,
			"lrm_get_all_rscs: can not send msg to lrmd");
		return NULL;
	}
	ha_msg_del(msg);
	/* get the return msg */
	ret = msgfromIPC_noauth(ch_cmd);
	if (NULL == ret) {
		client_log(LOG_ERR,
			"lrm_get_all_rscs: can not recieve ret msg");
		return NULL;
	}
	/* get the rc of msg */
	if (HA_OK != get_rc_from_msg(ret)) {
		ha_msg_del(ret);
		client_log(LOG_ERR,
			"lrm_get_all_rscs: rc from msg is fail");
		return NULL;
	}
	/* get the rsc_id list from msg */
	rid_list = ha_msg_value_str_list(ret,F_LRM_RID);

	ha_msg_del(ret);
	client_log(LOG_INFO, "lrm_get_all_rscs: end.");
	/* return the id list */
	return rid_list;

}

static lrm_rsc_t*
lrm_get_rsc (ll_lrm_t* lrm, const char* rsc_id)
{
	struct ha_msg* msg = NULL;
	struct ha_msg* ret = NULL;
	lrm_rsc_t* rsc     = NULL;

	client_log(LOG_INFO, "lrm_get_rsc: start.");

	/* check whether the rsc_id is available */
	if (RID_LEN <= strlen(rsc_id))	{
		client_log(LOG_ERR, "lrm_get_rsc: rsc_id is too long.");
		return NULL;
	}

	/* check whether the channel to lrmd is available */
	if (NULL == ch_cmd)	{
		client_log(LOG_ERR, "lrm_get_rsc: ch_mod is null.");
		return NULL;
	}
	/* create the msg of get resource */
	msg = create_lrm_rsc_msg(rsc_id, GETRSC);
	if ( NULL == msg) {
		client_log(LOG_ERR, "lrm_get_rsc: can not create types msg");
		return NULL;
	}
	/* send the msg to lrmd */
	if (HA_OK != msg2ipcchan(msg,ch_cmd)) {
		ha_msg_del(msg);
		client_log(LOG_ERR, "lrm_get_rsc: can not send msg to lrmd");
		return NULL;
	}
	ha_msg_del(msg);
	/* get the return msg from lrmd */
	ret = msgfromIPC_noauth(ch_cmd);
	if (NULL == ret) {
		client_log(LOG_ERR, "lrm_get_rsc: can not recieve ret msg");
		return NULL;
	}
	/* get the rc of return message */
	if (HA_OK != get_rc_from_msg(ret)) {
		ha_msg_del(ret);
		client_log(LOG_ERR, "lrm_get_rsc: rc from msg is fail");
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
	client_log(LOG_INFO, "lrm_get_rsc: end.");
	/* return the new resource */
	return rsc;
}

static int
lrm_add_rsc (ll_lrm_t* lrm, const char* rsc_id, const char* class
, 	     const char* type, const char* provider, GHashTable* parameter)
{
	struct ha_msg* msg;
	client_log(LOG_INFO, "lrm_add_rsc: start.");

	/* check whether the rsc_id is available */
	if (NULL == rsc_id || RID_LEN <= strlen(rsc_id))	{
		client_log(LOG_ERR, "lrm_add_rsc: parameter rsc_id wrong.");
		return HA_FAIL;
	}

	/* check whether the channel to lrmd is available */
	if (NULL == ch_cmd)	{
		client_log(LOG_ERR, "lrm_add_rsc: ch_mod is null.");
		return HA_FAIL;
	}

	/* create the message of add resource */
	msg = create_lrm_addrsc_msg(rsc_id, class, type, provider, parameter);
	if ( NULL == msg) {
		client_log(LOG_ERR, "lrm_add_rsc: can not create types msg");
		return HA_FAIL;
	}
	/* send to lrmd */
	if (HA_OK != msg2ipcchan(msg,ch_cmd)) {
		ha_msg_del(msg);
		client_log(LOG_ERR, "lrm_add_rsc: can not send msg to lrmd");
		return HA_FAIL;
	}
	ha_msg_del(msg);
	/* check the result */
	if (HA_OK != get_rc_from_ch(ch_cmd)) {
		client_log(LOG_ERR, "lrm_add_rsc: rc is fail");
		return HA_FAIL;
	}
	client_log(LOG_INFO, "lrm_add_rsc: end.");

	return HA_OK;
}

static int
lrm_delete_rsc (ll_lrm_t* lrm, const char* rsc_id)
{
	struct ha_msg* msg = NULL;

	client_log(LOG_INFO, "lrm_delete_rsc: start.");

	/* check whether the rsc_id is available */
	if (NULL == rsc_id || RID_LEN <= strlen(rsc_id))	{
		client_log(LOG_ERR, "lrm_delete_rsc: parameter rsc_id wrong.");
		return HA_FAIL;
	}


	/* check whether the channel to lrmd is available */
	if (NULL == ch_cmd)	{
		client_log(LOG_ERR, "lrm_delete_rsc: ch_mod is null.");
		return HA_FAIL;
	}

	/* create the msg of del resource */
	msg = create_lrm_rsc_msg(rsc_id, DELRSC);
	if ( NULL == msg) {
		client_log(LOG_ERR,
			"lrm_delete_rsc: can not create types msg");
		return HA_FAIL;
	}
	/* send the msg to lrmd */
	if (HA_OK != msg2ipcchan(msg,ch_cmd)) {
		ha_msg_del(msg);
		client_log(LOG_ERR,
			"lrm_delete_rsc: can not send msg to lrmd");
		return HA_FAIL;
	}
	ha_msg_del(msg);
	/* check the response of the msg */
	if (HA_OK != get_rc_from_ch(ch_cmd)) {
		client_log(LOG_ERR, "lrm_delete_rsc: rc from msg is fail");
		return HA_FAIL;
	}

	client_log(LOG_INFO, "lrm_delete_rsc: end.");

	return HA_OK;
}

static int
lrm_inputfd (ll_lrm_t* lrm)
{
	client_log(LOG_INFO, "lrm_inputfd: start.");

	if (NULL == ch_cbk) {
		client_log(LOG_ERR,
			"lrm_inputfd: callback channel is null.");
		return -1;
	}

	client_log(LOG_INFO, "lrm_inputfd: end.");
	return ch_cbk->ops->get_recv_select_fd(ch_cbk);
}

static gboolean
lrm_msgready (ll_lrm_t* lrm)
{
	client_log(LOG_INFO, "lrm_msgready: start.");
	if (NULL == ch_cbk) {
		client_log(LOG_ERR,
			"lrm_msgready: callback channel is null.");
		return FALSE;
	}
	client_log(LOG_INFO, "lrm_msgready: end.");
	return ch_cbk->ops->is_message_pending(ch_cbk);
}

static int
lrm_rcvmsg (ll_lrm_t* lrm, int blocking)
{
	struct ha_msg* msg = NULL;
	lrm_op_t* op = NULL;
	int msg_count = 0;

	client_log(LOG_INFO, "lrm_rcvmsg: start.");

	/* if it is not blocking mode and no message in the channel, return */
	if ((!lrm_msgready(lrm)) && (!blocking)) {
		client_log(LOG_INFO,
			"lrm_rcvmsg: no message and non-block.");
		return msg_count;
	}
	/* wait until message ready */
	if (!lrm_msgready(lrm)) {
		ch_cbk->ops->waitin(ch_cbk);
	}
	while (lrm_msgready(lrm)) {
		/* get the message */
		msg = msgfromIPC_noauth(ch_cbk);
		if (msg == NULL) {
			client_log(LOG_ERR,
				"lrm_rcvmsg: recieve a null msg.");
			return msg_count;
		}
		msg_count++;

		op = msg_to_op(msg);
		op->rsc = lrm_get_rsc( NULL, op->rsc_id );
		if (NULL!=op && NULL!=op_done_callback) {
			(*op_done_callback)(op);
		}
		ha_msg_del(msg);
	}
	client_log(LOG_INFO, "lrm_rcvmsg: end.");

	return msg_count;
}

/* following are the functions for rsc_ops */
static int
rsc_perform_op (lrm_rsc_t* rsc, lrm_op_t* op)
{
	int rc = 0;
	struct ha_msg* msg = NULL;

	client_log(LOG_INFO, "rsc_perform_op: start.");


	/* check whether the channel to lrmd is available */
	if (NULL == ch_cmd
	||  NULL == rsc
	||  NULL == rsc->id
	||  NULL == op
	||  NULL == op->op_type) {
		client_log(LOG_ERR,
			"rsc_perform_op: parameter wrong.");
		return HA_FAIL;
	}
	/* create the msg of perform op */
	op->rsc_id = rsc->id;
	msg = op_to_msg(op);
	if ( NULL == msg) {
		client_log(LOG_ERR, "rsc_perform_op: can not create msg");
		return HA_FAIL;
	}
	/* send it to lrmd */
	if (HA_OK != msg2ipcchan(msg,ch_cmd)) {
		ha_msg_del(msg);
		client_log(LOG_ERR,
			"rsc_perform_op: can not send msg to lrmd");
		return HA_FAIL;
	}
	ha_msg_del(msg);

	/* check return code, the return code is the call_id of the op */
	rc = get_rc_from_ch(ch_cmd);
	if (rc > 0) {
		op_save_t* op_save = g_new(op_save_t, 1);
		op_save->call_id = rc;
		op_save->user_data = op->user_data;
		op_save->interval = op->interval;
		op_save->rsc_id = g_strdup(rsc->id);
		op_save_list = g_list_append(op_save_list, op_save);
	}
	op->rsc_id = NULL;
	client_log(LOG_INFO, "rsc_perform_op: end.");
	return rc;
}

static int
rsc_stop_op (lrm_rsc_t* rsc, int call_id)
{
	int rc;
	struct ha_msg* msg = NULL;

	client_log(LOG_INFO, "rsc_stop_ops: start.");
	/* check whether the channel to lrmd is available */
	if (NULL == ch_cmd)	{
		client_log(LOG_ERR, "rsc_stop_ops: ch_mod is null.");
		return HA_FAIL;
	}
	/* check parameter */
	if (NULL == rsc) {
		client_log(LOG_ERR, "rsc_stop_ops: rsc is null.");
		return HA_FAIL;
	}
	/* create the msg of flush ops */
	msg = create_lrm_rsc_msg(rsc->id,STOPOP);
	if (NULL == msg) {
		client_log(LOG_ERR, "rsc_stop_ops: can not create msg");
		return HA_FAIL;
	}
	if (HA_OK != ha_msg_add_int(msg, F_LRM_CALLID, call_id))	{
		client_log(LOG_ERR, "rsc_stop_ops: can not add call_id");
		ha_msg_del(msg);
		return HA_FAIL;
	}
	
	/* send the msg to lrmd */
	if (HA_OK != msg2ipcchan(msg,ch_cmd)) {
		ha_msg_del(msg);
		client_log(LOG_ERR,
			"rsc_stop_ops: can not send msg to lrmd");
		return HA_FAIL;
	}
	ha_msg_del(msg);

	rc = get_rc_from_ch(ch_cmd);

	client_log(LOG_INFO, "rsc_stop_ops: end.");

	return rc;
}

static int
rsc_flush_ops (lrm_rsc_t* rsc)
{
	int rc;
	struct ha_msg* msg = NULL;

	client_log(LOG_INFO, "rsc_flush_ops: start.");
	/* check whether the channel to lrmd is available */
	if (NULL == ch_cmd)	{
		client_log(LOG_ERR, "rsc_flush_ops: ch_mod is null.");
		return HA_FAIL;
	}
	/* check parameter */
	if (NULL == rsc) {
		client_log(LOG_ERR, "rsc_flush_ops: rsc is null.");
		return HA_FAIL;
	}
	/* create the msg of flush ops */
	msg = create_lrm_rsc_msg(rsc->id,FLUSHOPS);
	if ( NULL == msg) {
		client_log(LOG_ERR, "rsc_flush_ops: can not create msg");
		return HA_FAIL;
	}
	/* send the msg to lrmd */
	if (HA_OK != msg2ipcchan(msg,ch_cmd)) {
		ha_msg_del(msg);
		client_log(LOG_ERR,
			"rsc_flush_ops: can not send msg to lrmd");
		return HA_FAIL;
	}
	ha_msg_del(msg);

	rc = get_rc_from_ch(ch_cmd);

	client_log(LOG_INFO, "rsc_flush_ops: end.");

	return rc;
}

static GList*
rsc_get_cur_state (lrm_rsc_t* rsc, state_flag_t* cur_state)
{
	GList* pending_op_list = NULL;
	struct ha_msg* msg = NULL;
	struct ha_msg* ret = NULL;
	struct ha_msg* op_msg = NULL;
	lrm_op_t* op       = NULL;
	int state;
	int op_count, i;

	client_log(LOG_INFO, "rsc_get_cur_state: start.");
	/* check whether the channel to lrmd is available */
	if (NULL == ch_cmd)	{
		client_log(LOG_ERR, "rsc_get_cur_state: ch_mod is null.");
		return NULL;
	}
	/* check paramter */
	if (NULL == rsc) {
		client_log(LOG_ERR, "rsc_get_cur_state: rsc is null.");
		return NULL;
	}
	/* create the msg of get current state of resource */
	msg = create_lrm_rsc_msg(rsc->id,GETRSCSTATE);
	if ( NULL == msg) {
		client_log(LOG_ERR, "rsc_get_cur_state: can not create msg");
		return NULL;
	}
	/* send the msg to lrmd */
	if (HA_OK != msg2ipcchan(msg,ch_cmd)) {
		ha_msg_del(msg);
		client_log(LOG_ERR,
			"rsc_get_cur_state: can not send msg to lrmd");
		return NULL;
	}
	ha_msg_del(msg);

	/* get the return msg */
	ret = msgfromIPC_noauth(ch_cmd);
	if (NULL == ret) {
		client_log(LOG_ERR,
			"rsc_get_cur_state: can not recieve ret msg");
		return NULL;
	}

	/* get the state of the resource from the message */
	if (HA_OK != ha_msg_value_int(ret, F_LRM_STATE, &state)) {
		ha_msg_del(ret);
		client_log(LOG_ERR,
			"rsc_get_cur_state: can not get state from msg");
		return NULL;
	}
	*cur_state = (state_flag_t)state;

	if (LRM_RSC_IDLE == *cur_state) {
		/* if the state is idle, the last finsihed op returned. */
		/* the op is stored in the same msg, just get it out */
		op = msg_to_op(ret);
		if (NULL != op) {
			pending_op_list = g_list_append(pending_op_list, op);
		}
		client_log(LOG_INFO, "rsc_get_cur_state: end.");
		ha_msg_del(ret);
		return pending_op_list;
	}
	if (LRM_RSC_BUSY == *cur_state) {
	/* if the state is busy, the whole pending op list would be return */
		/* the first msg includes the count of pending ops. */
		if (HA_OK != ha_msg_value_int(ret, F_LRM_OPCNT, &op_count)) {
			client_log(LOG_ERR,
				"rsc_get_cur_state: can not get op count");
			ha_msg_del(ret);
			return NULL;
		}
		ha_msg_del(ret);
		for (i = 0; i < op_count; i++) {
			/* one msg for one pending op */
			op_msg = msgfromIPC_noauth(ch_cmd);

			if (NULL == op_msg) {
				client_log(LOG_ERR,
				"rsc_get_cur_state: can not recieve ret msg");
				continue;
			}
			op = msg_to_op(op_msg);
			/* add msg to the return list */
			if (NULL != op) {
				pending_op_list =
					g_list_append(pending_op_list, op);
			}
			ha_msg_del(op_msg);
		}
		client_log(LOG_INFO, "rsc_get_cur_state: end.");
		return pending_op_list;
	}
	client_log(LOG_ERR, "rsc_get_cur_state: unkown state from msg");
	return NULL;
}
/* 
 * following are the implements of the utility functions
 */


static lrm_op_t*
msg_to_op(struct ha_msg* msg)
{
	lrm_op_t* op;
	const char* op_type;
	const char* app_name;
	const char* output;
	size_t output_len = 0;

	client_log(LOG_INFO, "msg_to_op: start.");
	op = g_new0(lrm_op_t, 1);



	/* op->timeout, op->interval, op->target_rc, op->call_id*/
	if (HA_OK != ha_msg_value_int(msg,F_LRM_TIMEOUT, &op->timeout)
	||  HA_OK != ha_msg_value_int(msg,F_LRM_INTERVAL, &op->interval)
	||  HA_OK != ha_msg_value_int(msg,F_LRM_TARGETRC, &op->target_rc)
	||  HA_OK != ha_msg_value_int(msg,F_LRM_CALLID, &op->call_id)) {
		client_log(LOG_ERR, "msg_to_op: can not get fields.");
		g_free(op);
		return NULL;
	}

	/* op->op_status */
	if (HA_OK !=
		ha_msg_value_int(msg, F_LRM_OPSTATUS, (int*)&op->op_status)) {
		client_log(LOG_INFO,
			"on_op_done: can not get op status from msg.");
                op->op_status = -1;
	}

	/* if it finished successfully */
	if (LRM_OP_DONE == op->op_status ) {
		/* op->rc */
		if (HA_OK != ha_msg_value_int(msg, F_LRM_RC, &op->rc)) {
			g_free(op);
			client_log(LOG_ERR,
				"on_op_done: can not get op rc from msg.");
			return NULL;
		}
		/* op->output */
		output = cl_get_binary(msg, F_LRM_DATA,&output_len);
		if (NULL != output){
			op->output = output;
		}
		else {
			op->output = NULL;
		}
	}



	/* op->app_name */
	app_name = ha_msg_value(msg, F_LRM_APP);
	if (NULL == app_name) {
		client_log(LOG_ERR, "msg_to_op: can not get app_name.");
		g_free(op);
		return NULL;
	}
	op->app_name = app_name;
	
	
	/* op->op_type */
	op_type = ha_msg_value(msg, F_LRM_OP);
	if (NULL == op_type) {
		client_log(LOG_ERR, "msg_to_op: can not get op_type.");
		g_free(op);
		return NULL;
	}
	op->op_type = op_type;

	/* op->params */
	op->params = ha_msg_value_str_table(msg, F_LRM_PARAM);

	if (0<op->call_id) {
		op_save_t* op_save = lookup_op_save(op->call_id);
		if (NULL!=op_save) {
			op->user_data = op_save->user_data;
			op->rsc_id = g_strdup(op_save->rsc_id);
			if (0==op_save->interval) {
				op_save_list = g_list_remove(op_save_list,
							op_save);
				g_free(op_save->rsc_id);
				g_free(op_save);
			}

		}
	}
	client_log(LOG_INFO, "msg_to_op: end.");

	return op;
}

static struct ha_msg*
op_to_msg (lrm_op_t* op)
{
	struct ha_msg* msg = ha_msg_new(5);
	if (NULL == msg) {
		client_log(LOG_ERR, "op_to_msg: can not create msg.");
		return NULL;
	}
	
	if (HA_OK != ha_msg_add(msg, F_LRM_TYPE, PERFORMOP)
	||  HA_OK != ha_msg_add(msg, F_LRM_RID, op->rsc_id)
	||  HA_OK != ha_msg_add(msg, F_LRM_OP, op->op_type)
	||  HA_OK != ha_msg_add_int(msg, F_LRM_TIMEOUT, op->timeout)
	||  HA_OK != ha_msg_add_int(msg, F_LRM_INTERVAL, op->interval)
	||  HA_OK != ha_msg_add_int(msg, F_LRM_TARGETRC, op->target_rc)) {
		ha_msg_del(msg);
		client_log(LOG_ERR, "op_to_msg: can not add field.");
		return NULL;
	}
	if (NULL != op->params) {
		if (HA_OK != ha_msg_add_str_table(msg,F_LRM_PARAM,op->params)){
			ha_msg_del(msg);
			client_log(LOG_ERR, "op_to_msg: can not add field.");
			return NULL;
		}	
	}


	return msg;
}

static op_save_t*
lookup_op_save(int call_id)
{
	GList* node;
	op_save_t* save;
	client_log(LOG_INFO, "lookup_op: start.");

	for(node=g_list_first(op_save_list); NULL!=node; node=g_list_next(node)) {

		save = (op_save_t*)node->data;
		if (call_id == save->call_id) {
			client_log(LOG_INFO, "lookup_op: end.");
			return save;
		}

	}

	client_log(LOG_INFO, "lookup_op: end.");
	return NULL;
}

static int
get_rc_from_ch(IPC_Channel* ch)
{
	int rc;
	struct ha_msg* msg;
	client_log(LOG_INFO, "get_rc_from_ch: start.");

	msg = msgfromIPC_noauth(ch);

	if (NULL == msg) {
		client_log(LOG_ERR, "get_rc_from_ch: can not recieve msg");
		return HA_FAIL;
	}
	if (HA_OK != ha_msg_value_int(msg, F_LRM_RC, &rc)) {
		ha_msg_del(msg);
		client_log(LOG_ERR, 
			"get_rc_from_ch: can not get rc from msg");
		return HA_FAIL;
	}
	ha_msg_del(msg);
 	client_log(LOG_INFO, "get_rc_from_ch: end.");
	return rc;
}

static int
get_rc_from_msg(struct ha_msg* msg)
{
	int rc;
	client_log(LOG_INFO, "get_rc_from_msg: start.");

	if (NULL == msg) {
		client_log(LOG_ERR, "get_rc_from_msg: msg is null");
		return HA_FAIL;
	}
	if (HA_OK != ha_msg_value_int(msg, F_LRM_RC, &rc)) {
		client_log(LOG_ERR, 
			"get_rc_from_msg: can not get rc from msg");
		return HA_FAIL;
	}
	client_log(LOG_INFO, "get_rc_from_msg: end.");
	return rc;
}

static int debug_level = 0;

void set_debug_level(int level)
{
	client_log(LOG_INFO, "set_debug_level: start.");
	if(0!=level && LOG_INFO!=level && LOG_ERR!=level) {
		client_log(LOG_ERR,  "set_debug_level: wrong parameter");
		return;
	}
	debug_level = level;
	client_log(LOG_INFO, "set_debug_level: end.");
}

static void
client_log (int priority, const char* fmt)
{
	if (0 == debug_level) {
		return;
	}
	if (LOG_ERR == priority) {
		printf("client_log:ERR:%s\n",fmt);
	}
	else if (LOG_INFO == debug_level)
	{
		printf("client_log:INFO:%s\n",fmt);
	}
}
