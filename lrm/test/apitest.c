
/*
 * Test program for Local Resource Manager  API.
 *
 * Copyright (C) 2004 Huang Zhen <zhenh@cn.ibm.com>
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
#include <stdio.h>
#include <sys/poll.h>
#include <string.h>
#include <glib.h>
#include <lrm/lrm_api.h>
#include <syslog.h>

void lrm_op_done_callback (lrm_op_t* op);
void lrm_monitor_callback (lrm_mon_t* monitor);
void printf_rsc(lrm_rsc_t* rsc);
void printf_op(lrm_op_t* op);
void printf_mon(lrm_mon_t* mon);
void printf_hash_table(GHashTable* hash_table);
void get_all_rsc(ll_lrm_t* lrm);
void get_cur_state(lrm_rsc_t* rsc);

int main (int argc, char* argv[])
{
	ll_lrm_t* lrm;
	lrm_rsc_t* rsc = NULL;
	lrm_op_t* op = NULL;
	const char* rid = "ip248";
	GList * class, * type, * classes, * types;
	GHashTable* param = NULL;
	state_flag_t state;
	lrm_mon_t setmon;
	lrm_mon_t chgmon;
	GList* ops = NULL;
	GList* mons = NULL;

	set_debug_level(LOG_INFO);

	lrm = ll_lrm_new("lrm");

	if(NULL == lrm)
	{
		printf("lrm==NULL\n");
		return 1;
	}
	puts("sigon...");
	lrm->lrm_ops->signon(lrm,"apitest");
 	puts("get_rsc_class_supported...");
	classes = lrm->lrm_ops->get_rsc_class_supported(lrm);
	for(class = g_list_first(classes); NULL!=class; class = g_list_next(class)) {
		printf("class:%s\n", (char*)class->data);
		types = lrm->lrm_ops->get_rsc_type_supported(lrm, class->data);
		for(type = g_list_first(types); NULL!=type; type = g_list_next(type)) {
			char* meta = lrm->lrm_ops->get_rsc_type_metadata(lrm,(char*)class->data,(char*)type->data);
			printf("\ntype:%s\nmetadata:%s\n", (char*)type->data, meta);
		}
	}

	puts("set_lrm_callback...");
	lrm->lrm_ops->set_lrm_callback(lrm, lrm_op_done_callback,
					lrm_monitor_callback);

	param = g_hash_table_new(g_str_hash,g_str_equal);
	g_hash_table_insert(param, strdup("1"), strdup("3ffe:ffff:0:f101::3"));

	puts("add_rsc...");
	lrm->lrm_ops->add_rsc(lrm, rid, "heartbeat", "IPv6addr", param);

	puts("get_rsc...");
	rsc = lrm->lrm_ops->get_rsc(lrm, rid);
	printf_rsc(rsc);

	puts("perform_op(start)...");
	op = g_new(lrm_op_t, 1);
	op->op_type = "start";
	op->params = param;
	op->timeout = 0;
	op->user_data = strdup("It is a start op!");
	rsc->ops->perform_op(rsc,op);
	printf_op(op);

	puts("perform_op(status)...");
	op = g_new(lrm_op_t, 1);
	op->op_type = "status";
	op->params = param;
	op->timeout = 0;
	op->user_data = strdup("It is a status op!");
	rsc->ops->perform_op(rsc,op);
	printf_op(op);

	puts("perform_op(stop)...");
	op = g_new(lrm_op_t, 1);
	op->op_type = "stop";
	op->params = param;
	op->timeout = 0;
	op->user_data = strdup("It is a stop op!");
	rsc->ops->perform_op(rsc,op);
	printf_op(op);

	puts("perform_op(status)...");
	op = g_new(lrm_op_t, 1);
	op->op_type = "status";
	op->params = param;
	op->timeout = 0;
	op->user_data = strdup("It is a status op!");
	rsc->ops->perform_op(rsc,op);
	printf_op(op);

	puts("get_cur_state...");
	ops = rsc->ops->get_cur_state(rsc,&state);
	printf("resource state:%s\n", state==LRM_RSC_IDLE?"LRM_RSC_IDLE":"LRM_RSC_BUSY");
	printf("resource op list:\n");
	while (NULL!=ops) {
		printf_op((lrm_op_t*)ops->data);
		ops = g_list_next(ops);
	}

	puts("rcvmsg...");
	lrm->lrm_ops->rcvmsg(lrm,TRUE);
	lrm->lrm_ops->rcvmsg(lrm,TRUE);
	lrm->lrm_ops->rcvmsg(lrm,TRUE);
	lrm->lrm_ops->rcvmsg(lrm,TRUE);

	puts("get_cur_state...");
	ops = rsc->ops->get_cur_state(rsc,&state);
	printf("resource state:%s\n", state==LRM_RSC_IDLE?"LRM_RSC_IDLE":"LRM_RSC_BUSY");
	printf("resource op list:\n");
	while (NULL!=ops) {
		printf_op((lrm_op_t*)ops->data);
		ops = g_list_next(ops);
	}

	setmon.mode = LRM_MONITOR_SET;
	setmon.interval = 2;
	setmon.user_data = NULL;
	setmon.target = 0;
	setmon.op_type = "status";
	setmon.params = param;
	setmon.timeout = 0;
	rsc->ops->set_monitor(rsc, &setmon);

	chgmon.mode = LRM_MONITOR_CHANGE;
	chgmon.interval = 2;
	chgmon.user_data = NULL;
	chgmon.target = 0;
	chgmon.op_type = "status";
	chgmon.params = param;
	chgmon.timeout = 0;
	rsc->ops->set_monitor(rsc, &chgmon);
/*
	lrm_mon_t clrmon;
	clrmon.mode = LRM_MONITOR_CLEAR;
	clrmon.interval = 2;
	clrmon.user_data = NULL;
	clrmon.target = 0;
	clrmon.op_type = "status";
	clrmon.params = param;
	clrmon.timeout = 0;
	rsc->ops->set_monitor(rsc, &clrmon);
*/
	puts("get_monitors...");
	mons = rsc->ops->get_monitors(rsc);
	while (NULL!=mons) {
		printf_mon((lrm_mon_t*)mons->data);
		mons = g_list_next(mons);
	}
	
	while(1) {
		lrm->lrm_ops->rcvmsg(lrm,TRUE);
	}	
	puts("signoff...");
	lrm->lrm_ops->signoff(lrm);
	return 0;
}
void lrm_op_done_callback(lrm_op_t* op)
{
	puts("lrm_op_done_callback...");
	printf_op(op);
}
void lrm_monitor_callback(lrm_mon_t* monitor)
{
	static int n = 0;
	printf("*****************rcvmsg:%d*******************\n",n++);
	printf("lrm_monitor_callback is called\n");
	printf_mon(monitor);
}

void printf_rsc(lrm_rsc_t* rsc)
{
	printf("print resource\n");
	if (NULL == rsc) {
		printf("resource is null\n");
		printf("print end\n");
		return;
	}
	printf("\tresource of id:%s\n", rsc->id);
	printf("\ttype:%s\n", rsc->type);
	printf("\tclass:%s\n", rsc->class);
	printf("\tparams:\n");
	printf_hash_table(rsc->params);
	printf("print end\n");
}

void printf_op(lrm_op_t* op)
{
	printf("print op\n");

	if (NULL == op) {
		printf("op is null\n");
		printf("print end\n");
		return;
	}
	if (NULL == op->rsc) {
		printf("\tresource is null\n");
	} else {
		printf("\trsc->id:%s\n", op->rsc->id);
	}

	printf("\top_type:%s\n",op->op_type?op->op_type:"null");
	printf("\tparams:\n");
	printf_hash_table(op->params);
	printf("\ttimeout:%d\n",op->timeout);
	printf("\tuser_data:%s\n",op->user_data?(char*)op->user_data:"null");
	printf("\tstatus:%d\n",op->status);
	printf("\tapp_name:%s\n",op->app_name?op->app_name:"null");
	printf("\tdata:%s\n",op->data?op->data:"null");
	printf("\trc:%d\n",op->rc);
	printf("\tcall_id:%d\n",op->call_id);
	printf("print end\n");
}

void printf_mon(lrm_mon_t* mon)
{

	printf("print mon\n");
	if (NULL == mon) {
		printf("mon is null\n");
		printf("print end\n");
		return;
	}
	if (NULL == mon->rsc) {
		printf("\tresource is null\n");
	} else {
		printf("\trsc->id:%s\n", mon->rsc->id);
	}
	switch(mon->mode)
	{
		case LRM_MONITOR_SET:
			printf("\tmode:%s\n","LRM_MONITOR_SET");
			break;

		case LRM_MONITOR_CHANGE:
			printf("\tmode:%s\n","LRM_MONITOR_CHANGE");
			break;

		case LRM_MONITOR_CLEAR:
			printf("\tmode:%s\n","LRM_MONITOR_CLEAR");
			break;
	}
	printf("\tinterval:%d\n",mon->interval);
	printf("\ttarget:%d\n",mon->target);

	printf("\top_type:%s\n",mon->op_type?mon->op_type:"null");
	printf("\tparams:\n");
	printf_hash_table(mon->params);
	printf("\ttimeout:%d\n",mon->timeout);
	printf("\tuser_data:%s\n",mon->user_data?(char*)mon->user_data:"null");
	printf("\tstatus:%d\n",mon->status);
	printf("\trc:%d\n",mon->rc);
	printf("\tcall_id:%d\n",mon->call_id);
	printf("print end\n");
}

static void
printf_pair(gpointer key, gpointer value, gpointer user_data)
{
	printf("\t\t%s=%s\n",(char*)key,(char*)value);
}
void
printf_hash_table(GHashTable* hash_table)
{
	if (NULL == hash_table) {
		printf("\t\tnull\n");
		return;
	}
	g_hash_table_foreach(hash_table, printf_pair, NULL);
}
void
get_all_rsc(ll_lrm_t* lrm)
{
	GList* element = NULL, * rid_list = NULL;

	puts("get_all_rscs...");
	rid_list = lrm->lrm_ops->get_all_rscs(lrm);
	if (NULL != rid_list) {
		element = g_list_first(rid_list);
		while (NULL != element) {
			printf("\tid:%s\n",(char*)element->data);
			element = g_list_next(element);
		}
	} else {
		puts("\tnone.");
	}
}
void
get_cur_state(lrm_rsc_t* rsc)
{
	state_flag_t state;
	GList* node = NULL, * op_list = NULL;
	lrm_op_t* op = NULL;

	puts("get_cur_state...");
	printf("\tcurrent state:%s\n",state==LRM_RSC_IDLE?"Idel":"Busy");

	op_list = rsc->ops->get_cur_state(rsc, &state);

	for(node = g_list_first(op_list); NULL != node; node = g_list_next(node)) {
		op = (lrm_op_t*)node->data;
		printf_op(op);
	}

}
