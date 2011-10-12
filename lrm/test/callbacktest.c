
/*
 * Test program for the callback function of Local Resource Manager  API.
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
#include <syslog.h>
#include <clplumbing/GSource.h>

static void lrm_op_done_callback(lrm_op_t *op);
static void printf_rsc(lrm_rsc_t *rsc);
static void printf_op(lrm_op_t *op);
static void printf_hash_table(GHashTable *hash_table);
static gboolean lrm_dispatch(IPC_Channel *notused, gpointer user_data);
static GMainLoop *mainloop;

int
main(int argc, char *argv[])
{
	ll_lrm_t* lrm;
	lrm_rsc_t* rsc = NULL;
	lrm_op_t* op = NULL;
	const char* rid = "ip248";
	GHashTable* param = NULL;

	lrm = ll_lrm_new("lrm");

	if(NULL == lrm)
	{
		printf("lrm==NULL\n");
		return 1;
	}
	puts("sigon...");
	lrm->lrm_ops->signon(lrm,"apitest");
	lrm->lrm_ops->set_lrm_callback(lrm, lrm_op_done_callback);

	param = g_hash_table_new(g_str_hash,g_str_equal);
	g_hash_table_insert(param, strdup("1"), strdup("3ffe:ffff:0:f101::3"));
	puts("add_rsc...");
	lrm->lrm_ops->add_rsc(lrm, rid, "heartbeat", "IPv6addr", NULL, param);
	puts("get_rsc...");
	rsc = lrm->lrm_ops->get_rsc(lrm, rid);
	printf_rsc(rsc);

	puts("perform_op(start)...");
	op = lrm_op_new();
	op->op_type = g_strdup("start");
	op->params = NULL;
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

	puts("perform_op(status)...");
	op = lrm_op_new();
	op->op_type = g_strdup("status");
	op->params = NULL;
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

	puts("perform_op(stop)...");
	op = lrm_op_new();
	op->op_type = g_strdup("stop");
	op->params = NULL;
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

	G_main_add_IPC_Channel(G_PRIORITY_LOW,
		      lrm->lrm_ops->ipcchan(lrm),
		      FALSE,
		      lrm_dispatch, lrm,
		      NULL);

	mainloop = g_main_new(FALSE);
	g_main_run(mainloop);

	puts("delete_rsc...");
	lrm->lrm_ops->delete_rsc(lrm, rid);

	puts("signoff...");
	lrm->lrm_ops->signoff(lrm);

	return 0;
}

static void
lrm_op_done_callback(lrm_op_t *op)
{
	puts("lrm_op_done_callback...");
	printf_op(op);
}

static gboolean
lrm_dispatch(IPC_Channel *notused, gpointer user_data)
{
	ll_lrm_t *lrm = (ll_lrm_t*)user_data;
	lrm->lrm_ops->rcvmsg(lrm, FALSE);
	return TRUE;
}

static void
printf_rsc(lrm_rsc_t *rsc)
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

static void
printf_op(lrm_op_t *op)
{
	printf("print op\n");

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
	printf("\tuser_data pointer:%p\n",op->user_data);
	printf("\top_status:%d\n",op->op_status);
	printf("\tapp_name:%s\n",op->app_name?op->app_name:"null");
	printf("\toutput:%s\n",op->output?op->output:"null");
	printf("\trc:%d\n",op->rc);
/*	printf("\tcall_id:%d\n",op->call_id); */
	printf("print end\n");
}

static void
printf_pair(gpointer key, gpointer value, gpointer user_data)
{
	printf("\t\t%s=%s\n",(char*)key,(char*)value);
}

static void
printf_hash_table(GHashTable *hash_table)
{
	if (NULL == hash_table) {
		printf("\t\tnull\n");
		return;
	}
	g_hash_table_foreach(hash_table, printf_pair, NULL);
}
