
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

#include <lha_internal.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/poll.h>
#include <string.h>
#include <glib.h>
#include <lrm/lrm_api.h>
#include <clplumbing/cl_log.h>
#include <syslog.h>

void lrm_op_done_callback (lrm_op_t* op);
void printf_rsc(lrm_rsc_t* rsc);
void printf_op(lrm_op_t* op);
void printf_hash_table(GHashTable* hash_table);
void get_all_rsc(ll_lrm_t* lrm);
void get_cur_state(lrm_rsc_t* rsc);

int main (int argc, char* argv[])
{
	ll_lrm_t* lrm;
	lrm_rsc_t* rsc = NULL;
	lrm_op_t* op = NULL;
	const char* rid = "ip248";
	GHashTable* param = NULL;
	GList* classes;
	int i;
	
	cl_log_set_entity("apitest");
	cl_log_set_facility(LOG_USER);

	lrm = ll_lrm_new("lrm");

	if(NULL == lrm)
	{
		printf("lrm==NULL\n");
		return 1;
	}
	puts("sigon...");
	lrm->lrm_ops->signon(lrm,"apitest");
	
	classes = lrm->lrm_ops->get_rsc_class_supported(lrm);
	lrm_free_str_list(classes);
	
	param = g_hash_table_new(g_str_hash,g_str_equal);
	g_hash_table_insert(param, strdup("1"), strdup("192.168.192.100"));
	puts("add_rsc...");
	lrm->lrm_ops->add_rsc(lrm, rid, "heartbeat", "IPaddr", "heartbeat", param);
	puts("get_rsc...");
	rsc = lrm->lrm_ops->get_rsc(lrm, rid);
	printf_rsc(rsc);

	puts("perform_op(start)...");
	op = lrm_op_new();
	op->op_type = g_strdup("start");
	op->params = param;
	op->timeout = 0;
	op->user_data = strdup("It is a start op!");
	if ( op->user_data == NULL ) {
		fprintf(stderr, "No enough memory.\n");
		return -1;
	}
	op->user_data_len = strlen(op->user_data)+1;
	op->interval = 0;
	op->target_rc = EVERYTIME;
	rsc->ops->perform_op(rsc,op);
	printf_op(op);
	lrm_free_op(op);
	
	puts("perform_op(status)...");
	param = g_hash_table_new(g_str_hash,g_str_equal);
	g_hash_table_insert(param, strdup("1"), strdup("192.168.192.100"));
	op = lrm_op_new();
	op->op_type = g_strdup("status");
	op->params = param;
	op->timeout = 0;
	op->user_data = strdup("It is a status op!");
	if ( op->user_data == NULL ) {
		fprintf(stderr, "No enough memory.\n");
		return -1;
	}
	op->user_data_len = strlen(op->user_data)+1;
	op->interval = 1000;
	op->target_rc=EVERYTIME;
	rsc->ops->perform_op(rsc,op);
	printf_op(op);
	lrm_free_op(op);

	puts("perform_op(stop)...");
	param = g_hash_table_new(g_str_hash,g_str_equal);
	g_hash_table_insert(param, strdup("1"), strdup("192.168.192.100"));
	op = lrm_op_new();
	op->op_type = g_strdup("stop");
	op->params = param;
	op->timeout = 0;
	op->user_data = strdup("It is a stop op!");
	if ( op->user_data == NULL ) {
		fprintf(stderr, "No enough memory.\n");
		return -1;
	}
	op->user_data_len = strlen(op->user_data)+1;
	op->interval = 0;
	op->target_rc=EVERYTIME;
	rsc->ops->perform_op(rsc,op);
	printf_op(op);
	lrm_free_op(op);
	
	puts("perform_op(status)...");
	param = g_hash_table_new(g_str_hash,g_str_equal);
	g_hash_table_insert(param, strdup("1"), strdup("192.168.192.100"));
	op = lrm_op_new();
	op->op_type = g_strdup("status");
	op->params = param;
	op->timeout = 0;
	op->user_data = strdup("It is a status op!");
	if ( op->user_data == NULL ) {
		fprintf(stderr, "No enough memory.\n");
		return -1;
	}
	op->user_data_len = strlen(op->user_data)+1;
	op->interval = 2000;
	op->target_rc=EVERYTIME;
	rsc->ops->perform_op(rsc,op);
	printf_op(op);
	lrm_free_op(op);

	puts("perform_op(start)...");
	param = g_hash_table_new(g_str_hash,g_str_equal);
	g_hash_table_insert(param, strdup("1"), strdup("192.168.192.100"));
	op = lrm_op_new();
	op->op_type = g_strdup("start");
	op->params = param;
	op->timeout = 0;
	op->user_data = strdup("It is a start op!");
	if ( op->user_data == NULL ) {
		fprintf(stderr, "No enough memory.\n");
		return -1;
	}
	op->user_data_len = strlen(op->user_data)+1;
	op->interval = 0;
	op->target_rc = EVERYTIME;
	rsc->ops->perform_op(rsc,op);
	printf_op(op);
	lrm_free_op(op);
	
	puts("perform_op(status)...");
	param = g_hash_table_new(g_str_hash,g_str_equal);
	g_hash_table_insert(param, strdup("1"), strdup("192.168.192.100"));
	op = lrm_op_new();
	op->op_type = g_strdup("status");
	op->params = param;
	op->timeout = 0;
	op->user_data = strdup("It is a status op!");
	if ( op->user_data == NULL ) {
		fprintf(stderr, "No enough memory.\n");
		return -1;
	}
	op->user_data_len = strlen(op->user_data)+1;
	op->interval = 3000;
	op->target_rc=EVERYTIME;
	rsc->ops->perform_op(rsc,op);
	printf_op(op);
	lrm_free_op(op);

	puts("perform_op(stop)...");
	param = g_hash_table_new(g_str_hash,g_str_equal);
	g_hash_table_insert(param, strdup("1"), strdup("192.168.192.100"));
	op = lrm_op_new();
	op->op_type = g_strdup("stop");
	op->params = param;
	op->timeout = 0;
	op->user_data = strdup("It is a stop op!");
	if ( op->user_data == NULL ) {
		fprintf(stderr, "No enough memory.\n");
		return -1;
	}
	op->user_data_len = strlen(op->user_data)+1;
	op->interval = 0;
	op->target_rc=EVERYTIME;
	rsc->ops->perform_op(rsc,op);
	printf_op(op);
	lrm_free_op(op);
		
	for(i = 0; i < 5; i++) {
		puts("get_cur_state...");
		get_cur_state(rsc);
        	puts("sleep a while...");
		sleep(1);
	}
	
	puts("delete_rsc...");
	lrm->lrm_ops->delete_rsc(lrm, rid);
	lrm_free_rsc(rsc);
	
	puts("signoff...");
	lrm->lrm_ops->signoff(lrm);
	
	return 0;
}
void lrm_op_done_callback(lrm_op_t* op)
{
	puts("lrm_op_done_callback...");
	printf_op(op);
}
void printf_rsc(lrm_rsc_t* rsc)
{
	printf("print resource>>>>>>>>>\n");
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
	printf("print end<<<<<<<<<<<<<<<\n");
}

void printf_op(lrm_op_t* op)
{
	printf("print op>>>>>>>>>>>>>>>>\n");

	if (NULL == op) {
		printf("op is null\n");
		printf("print end\n");
		return;
	}

	printf("\top_type:%s\n",op->op_type?op->op_type:"null");
	printf("\tparams:\n");
	printf_hash_table(op->params);
	printf("\ttimeout:%d\n",op->timeout);
	printf("\tuser_data:%s\n",op->user_data?(char*)op->user_data:"null");
	printf("\top_status:%d\n",op->op_status);
	printf("\tapp_name:%s\n",op->app_name?op->app_name:"null");
	printf("\toutput:%s\n",op->output?op->output:"null");
	printf("\trc:%d\n",op->rc);
	printf("\tcall_id:%d\n",op->call_id); 
	printf("print end<<<<<<<<<<<<<<<<<<\n");
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
	lrm_free_str_list(rid_list);
}
void
get_cur_state(lrm_rsc_t* rsc)
{
	state_flag_t state;
	GList* node = NULL, * op_list = NULL;
	lrm_op_t* op = NULL;
	printf("current state>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");

	op_list = rsc->ops->get_cur_state(rsc, &state);

	printf("\tcurrent state:%s\n",state==LRM_RSC_IDLE?"Idle":"Busy");

       
	for(node = g_list_first(op_list); NULL != node;
                node = g_list_next(node)) {
		op = (lrm_op_t*)node->data;
		printf_op(op);
	}
	lrm_free_op_list(op_list);
	printf("current end<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n");
}
