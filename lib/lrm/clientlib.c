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

/*Notice: this define should be replaced when merge to the whole pkg*/
#define	LRM_MAXPIDLEN 	256
#define LRM_ID		"lrm"

/*declare the functions used by the lrm_ops structure*/
static int lrm_signon (ll_lrm_t* lrm, const char * app_name);
static int lrm_signoff (ll_lrm_t*);
static int lrm_delete (ll_lrm_t*);
static int lrm_set_lrm_callback (ll_lrm_t* lrm,
				 lrm_op_done_callback_t op_done_callback_func,
				 lrm_monitor_callback_t	monitor_callback_func);
static GList* lrm_get_ra_supported (ll_lrm_t* lrm);
static GList* lrm_get_all_rscs (ll_lrm_t* lrm);
static lrm_rsc_t* lrm_get_rsc (ll_lrm_t* lrm, rsc_id_t rsc_id);
static int lrm_add_rsc (ll_lrm_t*, rsc_id_t rsc_id, const char* rsc_type
			,const char* rsc_name, GHashTable* parameter);
static int lrm_delete_rsc (ll_lrm_t*, rsc_id_t rsc_id);
static int lrm_inputfd (ll_lrm_t*);
static int lrm_msgready (ll_lrm_t*);
static int lrm_rcvmsg (ll_lrm_t*, int blocking);

struct sys_config *		config  = NULL;

static struct lrm_ops lrm_ops_instance =
{
	lrm_signon,
	lrm_signoff,
	lrm_delete,
	lrm_set_lrm_callback,
	lrm_get_ra_supported,
	lrm_get_all_rscs,
	lrm_get_rsc,
	lrm_add_rsc,
	lrm_delete_rsc,
	lrm_inputfd,
	lrm_msgready,
	lrm_rcvmsg
};
/*declare the functions used by the lrm_rsc_ops structure*/
static int rsc_perform_op (lrm_rsc_t*, lrm_op_t* op);
static int rsc_flush_ops (lrm_rsc_t*);
static int rsc_set_monitor (lrm_rsc_t*, lrm_mon_t* monitor);
static GList* rsc_get_monitors (lrm_rsc_t*);
static GList* rsc_get_cur_state (lrm_rsc_t*, state_flag_t* cur_state);

static struct rsc_ops rsc_ops_instance =
{
	rsc_perform_op,
	rsc_flush_ops,
	rsc_set_monitor,
	rsc_get_monitors,
	rsc_get_cur_state,
};

/*define the internal data used by the client library*/
static int is_signed_on					= FALSE;
static IPC_Channel* ch_cmd				= NULL;
static IPC_Channel* ch_cbk 				= NULL;
static lrm_op_done_callback_t	op_done_callback 	= NULL;
static lrm_monitor_callback_t	monitor_callback 	= NULL;
static GList*	op_list				 	= NULL;
static GList*	mon_list 				= NULL;

/*define some utility functions*/
static int on_op_done (int call_id, lrm_op_t* op, struct ha_msg* msg);
static int on_monitor (int call_id, lrm_mon_t* mon, struct ha_msg* msg);
static lrm_op_t* msg_to_op(struct ha_msg* msg);
static lrm_mon_t* lookup_mon(int call_id);
static lrm_op_t* lookup_op(int call_id);
static int get_rc_from_ch(IPC_Channel* ch);
static int get_rc_from_msg(struct ha_msg* msg);
static lrm_mon_t* copy_mon(lrm_mon_t* mon_in);
static lrm_op_t* copy_op(lrm_op_t* op_in);
static void free_op (lrm_op_t* op);
static void free_mon (lrm_mon_t* mon);
static void client_log (int priority, int level, const char* fmt);
void ha_msg_print(struct ha_msg * msg);

/*define of the api functions*/
ll_lrm_t*
ll_lrm_new (const char * llctype)
{
	ll_lrm_t* lrm;

	client_log(LOG_INFO, 1, "ll_lrm_new: start.");

	/*check the parameter*/
	if (0 != strncmp(LRM_ID, llctype, strlen(LRM_ID))) {
		client_log(LOG_ERR, -1, "ll_lrm_new: wrong parameter");
		return NULL;
	}

	/*alloc memory for lrm*/
	if (NULL == (lrm = (ll_lrm_t*) g_new(ll_lrm_t,1))) {
		client_log(LOG_ERR, -1, "ll_lrm_new: can not alloc memory");
		return NULL;
	}
	/*assign the ops*/
	lrm->lrm_ops = &lrm_ops_instance;

	client_log(LOG_INFO, -1, "ll_lrm_new: end.");
	return lrm;
}

int
lrm_signon (ll_lrm_t* lrm, const char * app_name)
{

	GHashTable* ch_cmd_attrs;
	GHashTable* ch_cbk_attrs;

	struct ha_msg* msg;

	char path[] = IPC_PATH_ATTR;
	char cmd_path[] = LRM_CMDPATH;
	char callback_path[] = LRM_CALLBACKPATH;

	client_log(LOG_INFO, 1, "lrm_signon: start.");

	/*check parameters*/
	if (NULL == lrm || NULL == app_name) {
		client_log(LOG_ERR, -1, "lrm_signon: wrong parameter");
		return HA_FAIL;
	}

	/*if already signed on, sign off first*/
	if (is_signed_on) {
		client_log(LOG_INFO,0,
			"lrm_signon: the client is alreay signed on,re-sign");
		lrm_signoff(lrm);
	}

	/*create the command ipc channel to lrmd*/
	ch_cmd_attrs = g_hash_table_new(g_str_hash, g_str_equal);
	g_hash_table_insert(ch_cmd_attrs, path, cmd_path);
	if (NULL == 
		(ch_cmd = ipc_channel_constructor(IPC_ANYTYPE, ch_cmd_attrs))){
		lrm_signoff(lrm);
		client_log(LOG_ERR,-1,
			"lrm_signon: can not connect to lrmd for cmd channel");
		return HA_FAIL;
	}

	if (IPC_OK != ch_cmd->ops->initiate_connection(ch_cmd)) {
		lrm_signoff(lrm);
		client_log(LOG_ERR,-1,
			"lrm_signon: can not initiate connection");
		return HA_FAIL;
	}

	/*construct the reg msg*/
	if (NULL == (msg = create_lrm_reg_msg(app_name))) {
		lrm_signoff(lrm);
		client_log(LOG_ERR,-1,"lrm_signon: can not create reg msg");
		return HA_FAIL;
	}

	/*send the msg*/
	if (HA_OK != msg2ipcchan(msg,ch_cmd)) {
		lrm_signoff(lrm);
		ha_msg_del(msg);
		client_log(LOG_ERR,-1,"lrm_signon: can not send msg to lrmd");
		return HA_FAIL;
	}
	/*parse the return msg*/
	if (HA_OK != get_rc_from_ch(ch_cmd)) {
		lrm_signoff(lrm);
		client_log(LOG_ERR,-1,
			"lrm_signon: can not recv result from lrmd");
		return HA_FAIL;
	}

	/*create the callback ipc channel to lrmd*/
	ch_cbk_attrs = g_hash_table_new(g_str_hash, g_str_equal);
	g_hash_table_insert(ch_cbk_attrs, path, callback_path);
	if (NULL ==
		(ch_cbk = ipc_channel_constructor(IPC_ANYTYPE,ch_cbk_attrs))) {
		lrm_signoff(lrm);
		client_log(LOG_ERR,-1,
			"lrm_signon: can not connect to lrmd for callback");
		return HA_FAIL;
	}

	if (IPC_OK != ch_cbk->ops->initiate_connection(ch_cbk)) {
		lrm_signoff(lrm);
		client_log(LOG_ERR,-1, 
			"lrm_signon: can not initiate connection");
		return HA_FAIL;
	}


	/*send the msg*/
	if (HA_OK != msg2ipcchan(msg,ch_cbk)) {
		lrm_signoff(lrm);
		ha_msg_del(msg);
		client_log(LOG_ERR,-1, "lrm_signon: can not send msg to lrmd");
		return HA_FAIL;
	}
	ha_msg_del(msg);

	/*parse the return msg*/
	if (HA_OK != get_rc_from_ch(ch_cbk)) {
		lrm_signoff(lrm);
		client_log(LOG_ERR,-1, 
			"lrm_signon: can not recv result from lrmd");
		return HA_FAIL;
	}

	/*ok, we sign on sucessfully now*/
	is_signed_on = TRUE;

	client_log(LOG_INFO, -1, "lrm_signon: end.");
	return HA_OK;
}

int
lrm_signoff (ll_lrm_t* lrm)
{
	int ret = HA_OK;
	struct ha_msg* msg = NULL;
	client_log(LOG_INFO,1,"lrm_signoff: start.");

	/*construct the unreg msg*/
	if ( NULL == ch_cmd ) {
		client_log(LOG_ERR,0,"lrm_signoff: ch_cmd is NULL");
		ret = HA_FAIL;
	}
	else
	if ( NULL == (msg = create_lrm_msg(UNREGISTER))) {
		client_log(LOG_ERR,0,"lrm_signoff: can not create unreg msg");
		ret = HA_FAIL;
	}
	else
	/*send the msg*/
	if (HA_OK != msg2ipcchan(msg,ch_cmd)) {
		client_log(LOG_ERR,0,"lrm_signoff: can not send msg to lrmd");
		ret = HA_FAIL;
	}
	else
	/*parse the return msg*/
	if (HA_OK != get_rc_from_ch(ch_cmd)) {
		client_log(LOG_ERR,0,
			"lrm_signoff: can not return failed from lrmd");
		ret = HA_FAIL;
	}

	if( NULL != msg ) {
		ha_msg_del(msg);
	}

	/*close channels */
	if (NULL != ch_cmd) {
 		ch_cmd->ops->destroy(ch_cmd);
		ch_cmd = NULL;
	}

	if (NULL != ch_cbk) {
		ch_cbk->ops->destroy(ch_cbk);
		ch_cbk = NULL;
	}

	is_signed_on = FALSE;

	client_log(LOG_INFO, -1, "lrm_signoff: end.");
	return ret;
}

int
lrm_delete (ll_lrm_t* lrm)
{
	client_log(LOG_INFO,1,"lrm_delete: start.");
	//check the parameter
	if (NULL == lrm) {
		client_log(LOG_ERR,-1,"lrm_delete: lrm is null.");
		return HA_FAIL;
	}

	g_free(lrm);
	client_log(LOG_INFO,-1,"lrm_delete: end.");
	return HA_OK;
}

int
lrm_set_lrm_callback (ll_lrm_t* lrm,
			lrm_op_done_callback_t op_done_callback_func,
			lrm_monitor_callback_t monitor_callback_func)

{
	client_log(LOG_INFO, 1, "lrm_set_lrm_callback: start.");

	op_done_callback = op_done_callback_func;
	monitor_callback = monitor_callback_func;

	client_log(LOG_INFO, -1, "lrm_set_lrm_callback: end.");
	return HA_OK;
}

GList*
lrm_get_ra_supported (ll_lrm_t* lrm)
{
	struct ha_msg* msg;
	struct ha_msg* ret;
	GList* type_list = NULL;
	//check whether the channel to lrmd is available
	client_log(LOG_INFO, 1, "lrm_get_ra_supported: start.");
	if (NULL == ch_cmd)
	{
		client_log(LOG_ERR, -1, 
			"lrm_get_ra_supported: ch_mod is null.");
		return NULL;
	}
	//create the get ra type message
	msg = create_lrm_msg(GETRATYPES);
	if ( NULL == msg) {
		client_log(LOG_ERR, -1,
			"lrm_get_ra_supported: can not create types msg");
		return NULL;
	}

	//send the msg to lrmd
	if (HA_OK != msg2ipcchan(msg,ch_cmd)) {
		ha_msg_del(msg);
		client_log(LOG_ERR, -1,
			"lrm_get_ra_supported: can not send msg to lrmd");
		return NULL;
	}
	ha_msg_del(msg);
	//get the return message
	ret = msgfromIPC_noauth(ch_cmd);
	if (NULL == ret) {
		client_log(LOG_ERR, -1, 
			"lrm_get_ra_supported: can not recieve ret msg");
		return NULL;
	}
	//get the rc of the message
	if (HA_FAIL == get_rc_from_msg(ret)) {
		ha_msg_del(ret);
		client_log(LOG_ERR, -1, 
			"lrm_get_ra_supported: rc from msg is fail");
		return NULL;
	}
	//get the ra type list from message
	type_list = ha_msg_value_list(ret,F_LRM_RTYPE);

	ha_msg_del(ret);
	client_log(LOG_INFO, -1, "lrm_get_ra_supported: end.");

	return type_list;

}

GList*
lrm_get_all_rscs (ll_lrm_t* lrm)
{
	struct ha_msg* msg;
	struct ha_msg* ret;
	GList* rid_str_list = NULL;
	GList* rid_list = NULL;
	client_log(LOG_INFO, 1, "lrm_get_all_rscs: start.");

	//check whether the channel to lrmd is available
	if (NULL == ch_cmd)	{
		client_log(LOG_ERR, -1, "lrm_get_all_rscs: ch_mod is null.");
		return NULL;
	}
	//create the msg of get all resource
	msg = create_lrm_msg(GETALLRCSES);
	if ( NULL == msg) {
		client_log(LOG_ERR, -1,
			"lrm_get_all_rscs: can not create types msg");
		return NULL;
	}
	//send the msg to lrmd
	if (HA_OK != msg2ipcchan(msg,ch_cmd)) {
		ha_msg_del(msg);
		client_log(LOG_ERR, -1,
			"lrm_get_all_rscs: can not send msg to lrmd");
		return NULL;
	}
	ha_msg_del(msg);
	//get the return msg
	ret = msgfromIPC_noauth(ch_cmd);
	if (NULL == ret) {
		client_log(LOG_ERR, -1, 
			"lrm_get_all_rscs: can not recieve ret msg");
		return NULL;
	}
	//get the rc of msg
	if (HA_FAIL == get_rc_from_msg(ret)) {
		ha_msg_del(ret);
		client_log(LOG_ERR, -1, 
			"lrm_get_all_rscs: rc from msg is fail");
		return NULL;
	}
	//get the rsc_id(in string)list from msg
	rid_str_list = ha_msg_value_list(ret,F_LRM_RID);

	//convert the string id to uuid format
	if (NULL != rid_str_list) {
		GList* element = g_list_first(rid_str_list);
		while (NULL != element) {
			rsc_id_t* rid = g_new(rsc_id_t, 1);
			uuid_parse(element->data, *rid);
			g_free(element->data);
			rid_list = g_list_append(rid_list, *rid);
			element = g_list_next(element);
		}
	}
	g_list_free(rid_str_list);
	ha_msg_del(ret);
	client_log(LOG_INFO, -1, "lrm_get_all_rscs: end.");
	//return the uuid list
	return rid_list;

}

lrm_rsc_t*
lrm_get_rsc (ll_lrm_t* lrm, rsc_id_t rsc_id)
{
	struct ha_msg* msg;
	struct ha_msg* ret;

	client_log(LOG_INFO, 1, "lrm_get_rsc: start.");

	//check whether the channel to lrmd is available
	if (NULL == ch_cmd)	{
		client_log(LOG_ERR, -1, "lrm_get_rsc: ch_mod is null.");
		return NULL;
	}
	//create the msg of get resource
	msg = create_lrm_rsc_msg(rsc_id, GETRSC);
	if ( NULL == msg) {
		client_log(LOG_ERR, -1,"lrm_get_rsc: can not create types msg");
		return NULL;
	}
	//send the msg to lrmd
	if (HA_OK != msg2ipcchan(msg,ch_cmd)) {
		ha_msg_del(msg);
		client_log(LOG_ERR, -1,"lrm_get_rsc: can not send msg to lrmd");
		return NULL;
	}
	ha_msg_del(msg);
	//get the return msg from lrmd
	ret = msgfromIPC_noauth(ch_cmd);
	if (NULL == ret) {
		client_log(LOG_ERR, -1, "lrm_get_rsc: can not recieve ret msg");
		return NULL;
	}
	//get the rc of return message
	if (HA_FAIL == get_rc_from_msg(ret)) {
		ha_msg_del(ret);
		client_log(LOG_ERR, -1, "lrm_get_rsc: rc from msg is fail");
		return NULL;
	}
	//create a new resource structure
	lrm_rsc_t* rsc = g_new(lrm_rsc_t, 1);

	//fill the field of resource with the data from msg
	ha_msg_value_uuid(msg,F_LRM_RID, rsc->id);
	rsc->name = g_strdup(ha_msg_value(msg, F_LRM_RNAME));
	rsc->ra_type = g_strdup(ha_msg_value(msg, F_LRM_RTYPE));
	rsc->params = NULL;
	char* params = g_strdup(ha_msg_value(msg, F_LRM_PARAM));
	if (NULL != params) {
		rsc->params = string_to_hash_table(params);
	}
	else {
		rsc->params = NULL;
	}
	rsc->ops = &rsc_ops_instance;
	ha_msg_del(ret);
	client_log(LOG_INFO, -1, "lrm_get_rsc: end.");
	//return the new resource
	return rsc;
}

int
lrm_add_rsc (ll_lrm_t* lrm, rsc_id_t rsc_id, const char* rsc_type
, 			 const char* rsc_name, GHashTable* parameter)
{
	struct ha_msg* msg;
	client_log(LOG_INFO, 1, "lrm_add_rsc: start.");
	//check whether the channel to lrmd is available
	if (NULL == ch_cmd)	{
		client_log(LOG_ERR, -1, "lrm_add_rsc: ch_mod is null.");
		return HA_FAIL;
	}

	//create the message of add resource
	msg = create_lrm_addrsc_msg(rsc_id, rsc_name, rsc_type, parameter);
	if ( NULL == msg) {
		client_log(LOG_ERR, -1,"lrm_add_rsc: can not create types msg");
		return HA_FAIL;
	}
	//send to lrmd
	if (HA_OK != msg2ipcchan(msg,ch_cmd)) {
		ha_msg_del(msg);
		client_log(LOG_ERR, -1,"lrm_add_rsc: can not send msg to lrmd");
		return HA_FAIL;
	}
	ha_msg_del(msg);
	//check the result
	if (HA_OK != get_rc_from_ch(ch_cmd)) {
		client_log(LOG_ERR, -1,"lrm_add_rsc: rc is fail");
		return HA_FAIL;
	}
	client_log(LOG_INFO, -1, "lrm_add_rsc: end.");

	return HA_OK;
}

int
lrm_delete_rsc (ll_lrm_t* lrm, rsc_id_t rsc_id)
{
	struct ha_msg* msg;

	client_log(LOG_INFO, 1, "lrm_delete_rsc: start.");

	//check whether the channel to lrmd is available
	if (NULL == ch_cmd)	{
		client_log(LOG_ERR, -1, "lrm_delete_rsc: ch_mod is null.");
		return HA_FAIL;
	}

	//create the msg of del resource
	msg = create_lrm_rsc_msg(rsc_id, DELRSC);
	if ( NULL == msg) {
		client_log(LOG_ERR, -1,
			"lrm_delete_rsc: can not create types msg");
		return HA_FAIL;
	}
	//send the msg to lrmd
	if (HA_OK != msg2ipcchan(msg,ch_cmd)) {
		ha_msg_del(msg);
		client_log(LOG_ERR, -1,
			"lrm_delete_rsc: can not send msg to lrmd");
		return HA_FAIL;
	}
	ha_msg_del(msg);
	//check the response of the msg
	if (HA_FAIL == get_rc_from_ch(ch_cmd)) {
		client_log(LOG_ERR, -1, "lrm_delete_rsc: rc from msg is fail");
		return HA_FAIL;
	}
	//remove all ops belong to this resource
	GList* op_node = g_list_first(op_list);
	while (NULL != op_node) {
		lrm_op_t* op = (lrm_op_t*)op_node->data;
		if (0 == uuid_compare(op->rsc->id, rsc_id)) {
			op_node = g_list_next(op_node);
			op_list = g_list_remove(op_list, op);
			free_op(op);
		}
		else {
			op_node = g_list_next(op_node);
		}
	}
	//remove all monitors belong to this resource
	GList* mon_node = g_list_first(mon_list);
	while (NULL != mon_node) {
		lrm_mon_t* mon = (lrm_mon_t*)mon_node->data;
		if (0 == uuid_compare(mon->rsc->id, rsc_id)) {
			mon_node = g_list_next(mon_node);
			mon_list = g_list_remove(mon_list, mon);
			free_mon(mon);
		}
		else {
			mon_node = g_list_next(mon_node);
		}
	}

	client_log(LOG_INFO, -1, "lrm_delete_rsc: end.");

	return HA_OK;
}

int
lrm_inputfd (ll_lrm_t* lrm)
{
	client_log(LOG_INFO, 1, "lrm_inputfd: start.");

	if (NULL == ch_cbk) {
		client_log(LOG_ERR, -1, 
			"lrm_inputfd: callback channel is null.");
		return -1;
	}

	client_log(LOG_INFO, -1, "lrm_inputfd: end.");
	return ch_cbk->ops->get_recv_select_fd(ch_cbk);
}

gboolean
lrm_msgready (ll_lrm_t* lrm)
{
	client_log(LOG_INFO, 1, "lrm_msgready: start.");
	if (NULL == ch_cbk) {
		client_log(LOG_ERR, -1, 
			"lrm_msgready: callback channel is null.");
		return FALSE;
	}
	client_log(LOG_INFO, -1, "lrm_msgready: end.");
	return ch_cbk->ops->is_message_pending(ch_cbk);
}

int
lrm_rcvmsg (ll_lrm_t* lrm, int blocking)
{
	client_log(LOG_INFO, 1, "lrm_rcvmsg: start.");
	int msg_count = 0;
	struct ha_msg* msg = NULL;
	//if it is not blocking mode and no message in the channel, return
	if ((!lrm_msgready(lrm)) && (!blocking)) {
		client_log(LOG_INFO, -1, 
			"lrm_rcvmsg: no message and non-block.");
		return msg_count;
	}
	//wait until message ready
	if (!lrm_msgready(lrm)) {
		ch_cbk->ops->waitin(ch_cbk);
	}
	while (lrm_msgready(lrm)) {
		//get the message
		msg = msgfromIPC_noauth(ch_cbk);
		if (msg == NULL) {
			client_log(LOG_ERR, -1, 
				"lrm_rcvmsg: recieve a null msg.");
			return msg_count;
		}
		msg_count++;
		//get tthe call_id from message
		int call_id = 0;
		if (HA_FAIL == ha_msg_value_int(msg, F_LRM_CALLID, &call_id)) {
			client_log(LOG_ERR, -1, 
				"lrm_rcvmsg: can not get call id from msg.");
			return msg_count;
		}
		//check whether it is an op done call back.
		lrm_op_t* op = lookup_op(call_id);
		if (NULL != op ) {
			//if it is an op done call back, call on_op_done
			on_op_done (call_id, op, msg);
		}
		else {
			//if it is an monitor notify msg, call on_monitor
			lrm_mon_t* mon = lookup_mon(call_id);
			if (NULL != mon) {
				on_monitor(call_id, mon, msg);
			}
			else {
				client_log(LOG_ERR, 0,
				"lrm_rcvmsg: get a msg with unknown call id.");
			}
		}
		ha_msg_del(msg);
	}
	client_log(LOG_INFO, -1, "lrm_rcvmsg: end.");

	return msg_count;
}

// following are the functions for rsc_ops
int
rsc_perform_op (lrm_rsc_t* rsc, lrm_op_t* op_in)
{
	int rc = 0;
	client_log(LOG_INFO, 1, "rsc_perform_op: start.");


	//check whether the channel to lrmd is available
	if (NULL == ch_cmd)	{
		client_log(LOG_ERR, -1, "rsc_perform_op: ch_mod is null.");
		return HA_FAIL;
	}
	//check the parameters
	if (NULL == rsc) {
		client_log(LOG_ERR, -1, "rsc_perform_op: rsc is null.");
		return HA_FAIL;
	}
	if (NULL == op_in || NULL == op_in->op_type) {
		client_log(LOG_ERR, -1, 
			"rsc_perform_op: op or op_type is null.");
		return HA_FAIL;
	}
	//copy the op
	op_in->rsc = rsc;
	op_in->app_name = NULL;
	op_in->data = NULL;

	lrm_op_t* op = copy_op(op_in);
	//create the msg of perform op
	struct ha_msg* msg = create_rsc_perform_op_msg(rsc->id, op);
	if ( NULL == msg) {
		client_log(LOG_ERR, -1,"rsc_perform_op: can not create msg");
		return HA_FAIL;
	}
	//send it to lrmd
	if (HA_OK != msg2ipcchan(msg,ch_cmd)) {
		ha_msg_del(msg);
		client_log(LOG_ERR, -1,
			"rsc_perform_op: can not send msg to lrmd");
		return HA_FAIL;
	}
	ha_msg_del(msg);
	//check return code, the return code is the call_id of the op
	rc = get_rc_from_ch(ch_cmd);
	//add the op to op_list
	if (rc > 0) {
		op->call_id = rc;
		op_list = g_list_append(op_list, op);
	}else {
		client_log(LOG_ERR, 0,"rsc_perform_op: lrmd return 0");
	}
	client_log(LOG_INFO, -1, "rsc_perform_op: end.");

	return rc;
}
int
rsc_flush_ops (lrm_rsc_t* rsc)
{
	int rc;
	client_log(LOG_INFO, 1, "rsc_flush_ops: start.");
	//check whether the channel to lrmd is available
	if (NULL == ch_cmd)	{
		client_log(LOG_ERR, -1, "rsc_flush_ops: ch_mod is null.");
		return HA_FAIL;
	}
	//check parameter
	if (NULL == rsc) {
		client_log(LOG_ERR, -1, "rsc_flush_ops: rsc is null.");
		return HA_FAIL;
	}
	//create the msg of flush ops
	struct ha_msg* msg = create_lrm_rsc_msg(rsc->id,FLUSHOPS);
	if ( NULL == msg) {
		client_log(LOG_ERR, -1,"rsc_flush_ops: can not create msg");
		return HA_FAIL;
	}
	//send the msg to lrmd
	if (HA_OK != msg2ipcchan(msg,ch_cmd)) {
		ha_msg_del(msg);
		client_log(LOG_ERR, -1,
			"rsc_flush_ops: can not send msg to lrmd");
		return HA_FAIL;
	}
	ha_msg_del(msg);

	rc = get_rc_from_ch(ch_cmd);

	client_log(LOG_INFO, -1, "rsc_flush_ops: end.");

	return rc;
}

int
rsc_set_monitor (lrm_rsc_t* rsc, lrm_mon_t* mon_in)
{
	client_log(LOG_INFO, 1, "rsc_set_monitor: start.");
	//check whether the channel to lrmd is available
	if (NULL == ch_cmd)	{
		client_log(LOG_ERR, -1, "rsc_set_monitor: ch_mod is null.");
		return HA_FAIL;
	}
	//check parameter
	if (NULL == mon_in) {
		client_log(LOG_ERR, -1, "rsc_set_monitor: mon is null.");
		return HA_FAIL;
	}
	if (NULL == rsc) {
		client_log(LOG_ERR, -1, "rsc_set_monitor: rsc is null.");
		return HA_FAIL;
	}
	//copy the mon
	mon_in->rsc = rsc;
	lrm_mon_t* mon = copy_mon(mon_in);
	int rc;
	//create the message for set a monitor
	struct ha_msg* msg = create_rsc_set_monitor_msg(rsc->id, mon);
	if (NULL == msg) {
		client_log(LOG_ERR, -1,"rsc_set_monitor: can not create msg");
		return HA_FAIL;
	}
	//send the message
	if (HA_OK != msg2ipcchan(msg,ch_cmd)) {
		ha_msg_del(msg);
		client_log(LOG_ERR, -1,
			"rsc_set_monitor: can not send msg to lrmd");
		return HA_FAIL;
	}

	ha_msg_del(msg);
	//get the rc of the mesage and add the monitor to mon_list
	rc = get_rc_from_ch(ch_cmd);
	if (rc > 0) {
		mon->call_id = rc;
		mon_list = g_list_append(mon_list, mon);
	}else {
		client_log(LOG_ERR, 0,"rsc_set_monitor: lrmd return 0");
	}

	client_log(LOG_INFO, -1, "rsc_set_monitor: end.");
	return rc;
}

GList*
rsc_get_monitors (lrm_rsc_t* rsc)
{
	client_log(LOG_INFO, 1, "rsc_get_monitors: start.");
	GList* rsc_mon_list = NULL;

	GList* node;
	for(node = g_list_first(mon_list); NULL != node; 
		node = g_list_next(node)){
		lrm_mon_t* mon = (lrm_mon_t*)node->data;
		if (rsc == mon->rsc) {
			rsc_mon_list = g_list_append(rsc_mon_list, 
							copy_mon(mon));
		}
	}

	client_log(LOG_INFO, -1, "rsc_get_monitors: end.");

	return rsc_mon_list;
}
GList*
rsc_get_cur_state (lrm_rsc_t* rsc, state_flag_t* cur_state)
{
	GList* pending_op_list = NULL;
	client_log(LOG_INFO, 1, "rsc_get_cur_state: start.");

	//check whether the channel to lrmd is available
	if (NULL == ch_cmd)	{
		client_log(LOG_ERR, -1, "rsc_get_cur_state: ch_mod is null.");
		return HA_FAIL;
	}
	//check paramter
	if (NULL == rsc) {
		client_log(LOG_ERR, -1, "rsc_get_cur_state: rsc is null.");
		return NULL;
	}
	//create the msg of get current state of resource
	struct ha_msg* msg = create_lrm_rsc_msg(rsc->id,GETRSCSTATE);
	if ( NULL == msg) {
		client_log(LOG_ERR, -1,"rsc_get_cur_state: can not create msg");
		return NULL;
	}
	//send the msg to lrmd
	if (HA_OK != msg2ipcchan(msg,ch_cmd)) {
		ha_msg_del(msg);
		client_log(LOG_ERR, -1,
			"rsc_get_cur_state: can not send msg to lrmd");
		return NULL;
	}
	ha_msg_del(msg);

	//get the return msg
	struct ha_msg* ret = msgfromIPC_noauth(ch_cmd);
	if (NULL == ret) {
		client_log(LOG_ERR, -1, 
			"rsc_get_cur_state: can not recieve ret msg");
		return NULL;
	}
//	ha_msg_print(ret);
	//get the state of the resource from the message
	int state;
	if (HA_FAIL == ha_msg_value_int(ret, F_LRM_STATE, &state)) {
		ha_msg_del(ret);
		client_log(LOG_ERR, -1, 
			"rsc_get_cur_state: can not get state from msg");
		return NULL;
	}
	*cur_state = (state_flag_t)state;

	if (LRM_RSC_IDLE == *cur_state) {
		//if the state is idle, the last finsihed op returned.
		//the op is stored in the same msg, just get it out
		lrm_op_t* op = msg_to_op(ret);
		if (NULL != op) {
			op->rsc = rsc;
			pending_op_list = g_list_append(pending_op_list, op);
		}
		client_log(LOG_INFO, -1, "rsc_get_cur_state: end.");
		ha_msg_del(ret);
		return pending_op_list;
	}
	if (LRM_RSC_BUSY == *cur_state) {
	//if the state is busy, the whole pending op list would be return
		int op_count, i;
		//the first msg includes the count of pending ops.
		if (HA_FAIL == ha_msg_value_int(ret, F_LRM_OPCNT, &op_count)) {
			client_log(LOG_ERR, -1, 
				"rsc_get_cur_state: can not get op count");
			ha_msg_del(ret);
			return NULL;
		}
		for (i = 0; i < op_count; i++) {
			//one msg for one pending op
			struct ha_msg* op_msg = msgfromIPC_noauth(ch_cmd);

			if (NULL == op_msg) {
				client_log(LOG_ERR, 0,
				"rsc_get_cur_state: can not recieve ret msg");
				continue;
			}
			lrm_op_t* op = msg_to_op(op_msg);
			//add msg to the return list
			if (NULL != op) {
				op->rsc = rsc;
				pending_op_list = 
					g_list_append(pending_op_list, op);
			}
			ha_msg_del(op_msg);
		}
		ha_msg_del(ret);
		client_log(LOG_INFO, -1, "rsc_get_cur_state: end.");
		return pending_op_list;
	}
	client_log(LOG_ERR, -1,"rsc_get_cur_state: can not get state from msg");
	return NULL;
}
/*
 * following are the implements of the utility functions
 */
//when an operation is done, a message will send back to client library.
//this function will be call.
int
on_op_done (int call_id, lrm_op_t* op, struct ha_msg* msg)
{
	client_log(LOG_INFO, 1, "on_op_done: start.");
//	ha_msg_print(msg);
	//get the status of the operation's excuation
	if (HA_FAIL == 
		ha_msg_value_int(msg, F_LRM_OPSTATUS, (int*)&op->status)) {
		client_log(LOG_ERR, -1, 
			"on_op_done: can not get op status from msg.");
		return HA_FAIL;
	}
	//if it finished successfully, get the return code of the operation
	if (LRM_OP_DONE == op->status ) {
		if (HA_FAIL == ha_msg_value_int(msg, F_LRM_RC, &op->rc)) {
			client_log(LOG_ERR, -1, 
				"on_op_done: can not get op rc from msg.");
			return HA_FAIL;
		}
	}
	const char* app_name = ha_msg_value(msg, F_LRM_APP);
	if (NULL != app_name) {
		op->app_name = g_strdup(app_name);
	}
	//if it has data (for example, metadata operation), get the data
	int data_len = 0;
	const char* data = cl_get_binary(msg, F_LRM_DATA,&data_len);
	if (NULL != data){
		op->data = strndup(data, data_len);
	}
	else {
		op->data = NULL;
	}
	//call the callback function
	if (NULL != op_done_callback) {
		op->call_id = call_id;
		(*op_done_callback)(copy_op(op));
	}

	//remove the op from the op_list.
	lrm_op_t* to_del_op = lookup_op(call_id);
	if (NULL != to_del_op) {
		op_list = g_list_remove(op_list, to_del_op);
		free_op(op);
	}

	client_log(LOG_INFO, -1, "on_op_done: end.");
	return HA_OK;
}

/*
 *when the condition of a monitor is satisfied, the monitor will send
 *back a msg,this function will be called to process the msg
 */
int
on_monitor ( int call_id, lrm_mon_t* mon, struct ha_msg* msg)
{
	
	client_log(LOG_INFO, 1, "on_monitor: start.");

	//get the status of the monitor
	if (HA_FAIL == 
		ha_msg_value_int(msg, F_LRM_OPSTATUS, (int*)&mon->status)) {
		client_log(LOG_ERR, -1, 
				"on_monitor: can not get op status from msg.");
		return HA_FAIL;
	}
	//if it is ok, get the rc of RA
	if (LRM_OP_DONE == mon->status ) {
		if (HA_FAIL == ha_msg_value_int(msg, F_LRM_RC, &mon->rc)) {
			client_log(LOG_ERR, -1, 
				"on_monitor: can not get op rc from msg.");
			return HA_FAIL;
		}
	}
	//call the callback function
	if (NULL != monitor_callback) {
		mon->call_id = call_id;
		(*monitor_callback)(copy_mon(mon));
	}
	client_log(LOG_INFO, -1, "on_monitor: end.");
	return HA_OK;
}


lrm_op_t*
msg_to_op(struct ha_msg* msg)
{
	client_log(LOG_INFO, 1, "msg_to_op: start.");
	lrm_op_t* op = g_new(lrm_op_t, 1);
	//op->op_type
	const char* op_temp = ha_msg_value(msg, F_LRM_OP);
	if (NULL == op_temp) {
		client_log(LOG_ERR, -1, "msg_to_op: can not get op_type.");
		return NULL;
	}
	op->op_type = g_strdup(op_temp);

	//op->params
	const char* temp_params = ha_msg_value(msg, F_LRM_PARAM);
	if (NULL != temp_params) {
		char* params = g_strdup(temp_params);
		op->params = string_to_hash_table(params);
		g_free(params);
	}
	else {
		op->params = NULL;
	}

	//op->timeout
	if (HA_FAIL == ha_msg_value_int(msg,F_LRM_TIMEOUT, &op->timeout)) {
		client_log(LOG_ERR, -1, "msg_to_op: can not get op_type.");
		return NULL;
	}
	//op->call_id
	if (HA_FAIL == ha_msg_value_int(msg,F_LRM_CALLID, &op->call_id)) {
		client_log(LOG_ERR, -1, "msg_to_op: can not get call_id.");
		return NULL;
	}
	//op->user_data
	lrm_op_t* save_op = lookup_op(op->call_id);
	if (NULL != save_op) {
		op->user_data = save_op->user_data;
	}
	else {
		op->user_data = NULL;
	}
	//op->status
	if (HA_FAIL==ha_msg_value_int(msg,F_LRM_OPSTATUS, (int*)&op->status)) {
		client_log(LOG_INFO, 0, "msg_to_op: can not get status.");
	}
	//op->data
	int data_len = 0;
	const char* data = cl_get_binary(msg, F_LRM_DATA,&data_len);
	if (NULL != data){
		op->data = strndup(data, data_len);
	}
	else {
		op->data = NULL;
	}
	//op->rc
	if (HA_FAIL == ha_msg_value_int(msg,F_LRM_RC, &op->rc)) {
		client_log(LOG_INFO, 0, "msg_to_op: can not get rc.");
	}
	//op->app_name
	op->app_name = g_strdup(ha_msg_value(msg, F_LRM_APP));
	client_log(LOG_INFO, -1, "msg_to_op: end.");

	return op;
}

lrm_op_t*
lookup_op(int call_id)
{
	client_log(LOG_INFO, 1, "lookup_op: start.");

	GList* node;
	for(node=g_list_first(op_list); NULL!=node; node=g_list_next(node)) {

		lrm_op_t* op = (lrm_op_t*)node->data;
		if (call_id == op->call_id) {
			client_log(LOG_INFO, -1, "lookup_op: end.");
			return op;
		}

	}

	client_log(LOG_INFO, -1, "lookup_op: end.");
	return NULL;
}


lrm_mon_t*
lookup_mon(int call_id)
{
	client_log(LOG_INFO, 1, "lookup_mon: start.");

	GList* node;
	for(node=g_list_first(mon_list); NULL!=node; node=g_list_next(node)) {
		lrm_mon_t* mon = (lrm_mon_t*)node->data;
		if (call_id == mon->call_id) {
			client_log(LOG_INFO, -1, "lookup_mon: end.");
			return mon;
		}
	}

	client_log(LOG_INFO, -1, "lookup_mon: end.");
	return NULL;
}



int
get_rc_from_ch(IPC_Channel* ch)
{
	int rc;
	client_log(LOG_INFO, 1, "get_rc_from_ch: start.");

	struct ha_msg* msg = msgfromIPC_noauth(ch);

	if (NULL == msg) {
		client_log(LOG_ERR, -1, "get_rc_from_ch: can not recieve msg");
		return HA_FAIL;
	}
	if (HA_FAIL == ha_msg_value_int(msg, F_LRM_RC, &rc)) {
		client_log(LOG_ERR, -1, 
			"get_rc_from_ch: can not get rc from msg");
		return HA_FAIL;
	}
	ha_msg_del(msg);
 	client_log(LOG_INFO, -1, "get_rc_from_ch: end.");
	return rc;
}

int
get_rc_from_msg(struct ha_msg* msg)
{
	int rc;
	client_log(LOG_INFO, 1, "get_rc_from_msg: start.");

	if (NULL == msg) {
		client_log(LOG_ERR, -1, "get_rc_from_msg: msg is null");
		return HA_FAIL;
	}
	if (HA_FAIL == ha_msg_value_int(msg, F_LRM_RC, &rc)) {
		client_log(LOG_ERR, -1, 
			"get_rc_from_msg: can not get rc from msg");
		return HA_FAIL;
	}
	client_log(LOG_INFO, -1, "get_rc_from_msg: end.");
	return rc;
}
lrm_mon_t*
copy_mon(lrm_mon_t* mon_in)
{
	lrm_mon_t* mon = g_new(lrm_mon_t, 1);
	mon->call_id = mon_in->call_id;
	mon->interval = mon_in->interval;
	mon->mode = mon_in->mode;
	mon->op_type = g_strdup(mon_in->op_type);
	if (NULL != mon_in->params) {
		char* params_str = hash_table_to_string(mon_in->params);
		mon->params = string_to_hash_table(params_str);
		g_free(params_str);
	}
	else {
		mon->params = NULL;
	}
	
	mon->rc = mon_in->rc;
	mon->rsc = mon_in->rsc;
	mon->status = mon_in->status;	
	mon->target = mon_in->target;
	mon->timeout = mon_in->timeout;
	mon->user_data = mon_in->user_data;
	return mon;
	
}
lrm_op_t*
copy_op(lrm_op_t* op_in)
{
	lrm_op_t* op = g_new(lrm_op_t, 1);
	if (NULL != op_in->app_name) {
		op->app_name = g_strdup(op_in->app_name);
	}
	else {
		op->app_name = NULL;
	}
	
	op->call_id = op_in->call_id;
	
	if (NULL != op_in->data) {
		op->data = g_strdup(op_in->data);
	}
	else {
		op->data = NULL;
	}
	
	op->op_type = g_strdup(op_in->op_type);
	if (NULL != op_in->params) {
		char* params_str = hash_table_to_string(op_in->params);
		op->params = string_to_hash_table(params_str);
		g_free(params_str);
	}
	else {
		op->params = NULL;
	}
	op->rc = op_in->rc;
	op->rsc = op_in->rsc;
	op->status = op_in->status;
	op->timeout = op_in->timeout;
	op->user_data = op_in->user_data;
	
	return op;
}
void
free_op (lrm_op_t* op) {
	g_free(op->app_name);
	g_free(op->data);
	if (NULL != op->params) {
		free_hash_table(op->params);
	}
}
void
free_mon (lrm_mon_t* mon) {
	if (NULL != mon->params) {
		free_hash_table(mon->params);
	}
}
#define INDENT 4
void
client_log (int priority, int level, const char* fmt)
{
	if (LOG_ERR != priority) {
		return;
	}
	
	static int indent = INDENT;
	printf("\t\tclient_log:");
	int i;
	if( 1 == level) {
		indent = indent + INDENT;
	}
	for (i = 0; i < indent; i++) {
		printf("%c",' ');
	}
	if (LOG_ERR == priority) {
		printf("%c",'*');
	}
	printf("%s\n",fmt);

	if( -1 == level) {
		indent = indent - INDENT;
	}

}
void
ha_msg_print(struct ha_msg * msg)
{
	int i;
	printf("print msg:%p\n",msg);
	printf("\tnfields:%d\n",msg->nfields);
	for (i = 0; i < msg->nfields; i++){
		printf("\tname:%s\tvalue:%s\n",msg->names[i],
				(char *)msg->values[i]);
	}
	printf("print end\n");

}
