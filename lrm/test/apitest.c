
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

#include <unistd.h>
#include <stdio.h>
#include <sys/poll.h>
#include <string.h>
#include <glib.h>
#include <lrm/lrm_api.h>

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
	lrm = ll_lrm_new("lrm");	
	if(NULL == lrm)
	{
		printf("lrm==NULL\n");
		return 1;
	}
	puts("sigon...");
	lrm->lrm_ops->signon(lrm,"apitest");

	puts("set_lrm_callback...");
	lrm->lrm_ops->set_lrm_callback(lrm, lrm_op_done_callback,
					lrm_monitor_callback);
	
	rsc_id_t rid;
	puts("add_rsc...");
	uuid_generate(rid);
	lrm->lrm_ops->add_rsc(lrm, rid, "lsb", "lsb_initscript_sim.sh", NULL);

	puts("get_rsc...");
	lrm_rsc_t*	rsc = lrm->lrm_ops->get_rsc(lrm, rid);
	printf_rsc(rsc);

	
	puts("set_monitor...");
	lrm_mon_t* mon = g_new(lrm_mon_t, 1);
	mon->op_type = "status";
	mon->params = NULL;
	mon->timeout = 0;
	mon->user_data = NULL;
	mon->mode = LRM_MONITOR_SET;
	mon->interval = 2;
	mon->target = 1;
	rsc->ops->set_monitor(rsc,mon);
	printf_mon(mon);
	mon = g_new(lrm_mon_t, 1);

	mon->op_type = "status";
	mon->params = NULL;
	mon->timeout = 0;
	mon->user_data = NULL;
	mon->mode = LRM_MONITOR_CHANGE;
	mon->interval = 2;
	mon->target = 1;
	rsc->ops->set_monitor(rsc,mon);
	printf_mon(mon);

	puts("perform_op...");
	lrm_op_t* op = g_new(lrm_op_t, 1);
	op->op_type = "start";
	op->params = NULL;
	op->timeout = 0;
	op->user_data = strdup("It is a start op!");
	rsc->ops->perform_op(rsc,op);
	printf_op(op);

	sleep(10);
	
	op = g_new(lrm_op_t, 1);
	op->op_type = "stop";
	op->params = NULL;
	op->timeout = 0;
	op->user_data = strdup("It is a stop op!");
	rsc->ops->perform_op(rsc,op);
	printf_op(op);

	sleep(10);
	puts("rcvmsg...");
	while (TRUE) {
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
	char buf[37];
	uuid_unparse(rsc->id, buf);
	printf("\tresource of id:%s\n", buf);
	printf("\tname:%s\n", rsc->name);
	printf("\ttype:%s\n", rsc->ra_type);
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
		char buf[37];
		uuid_unparse(op->rsc->id, buf);
		printf("\trsc->id:%s\n", buf);
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
		char buf[37];
		uuid_unparse(mon->rsc->id, buf);
		printf("\trsc->id:%s\n", buf);
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
	puts("get_all_rscs...");
	GList* rid_list = lrm->lrm_ops->get_all_rscs(lrm);
	if (NULL != rid_list) {
		char buf[37];
		rsc_id_t rid;
		GList* element = g_list_first(rid_list);
		while (NULL != element) {
			uuid_copy(rid,element->data);
			uuid_unparse(rid, buf);
			printf("\tid:%s\n",buf);
			element = g_list_next(element);
		}
	} else {
		puts("\tnone.");
	}
}
void
get_cur_state(lrm_rsc_t* rsc)
{
	puts("get_cur_state...");
	state_flag_t state;
	GList* op_list = rsc->ops->get_cur_state(rsc, &state);
	printf("\tcurrent state:%s\n",state==LRM_RSC_IDLE?"Idel":"Busy");

	GList* node;
	for(node = g_list_first(op_list); NULL != node; node = g_list_next(node)) {
		lrm_op_t* op = (lrm_op_t*)node->data;
		printf_op(op);
	}

}
