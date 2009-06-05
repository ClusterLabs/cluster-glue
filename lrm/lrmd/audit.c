/*
 * Audit lrmd global data structures
 *
 * Author: Dejan Muhamedagic <dejan@suse.de>
 * Copyright (c) 2007 Novell GmbH
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <lha_internal.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <dirent.h>
#include <pwd.h>
#include <time.h>

#include <glib.h>
#include <pils/plugin.h>
#include <pils/generic.h>
#include <clplumbing/GSource.h>
#include <clplumbing/lsb_exitcodes.h>
#include <clplumbing/cl_signal.h>
#include <clplumbing/proctrack.h>
#include <clplumbing/coredumps.h>
#include <clplumbing/uids.h>
#include <clplumbing/Gmain_timeout.h>
#include <clplumbing/cl_pidfile.h>
#include <ha_msg.h>
#ifdef ENABLE_APPHB
#  include <apphb.h>
#endif

#include <lrm/lrm_api.h>
#include <lrm/lrm_msg.h>
#include <lrm/raexec.h>
#include <lrmd.h>

#ifdef DOLRMAUDITS

extern GHashTable* clients;
extern GHashTable* resources;

#define ptr_bad(level,p,item,text) \
	lrmd_log(level,"LRMAUDIT: 0x%lx unallocated pointer for: %s(%s)", \
		(unsigned long)p,item,text);
#define ptr_null(level,item,text) \
	lrmd_log(level,"LRMAUDIT: pointer null for: %s(%s)", \
		item,text);

/* NB: this macro contains return */
#define ret_on_null(p,item,text) do { \
	if( !p ) { \
		ptr_bad(LOG_INFO,p,item,text); \
		return; \
	} \
} while(0)
#define log_on_null(p,item,text) do { \
	if( !p ) { \
		ptr_null(LOG_INFO,item,text); \
	} \
} while(0)

void
lrmd_audit(const char *function, int line)
{
	lrmd_log(LOG_DEBUG, "LRMAUDIT: in %s:%d",function,line);
#ifdef LRMAUDIT_CLIENTS
	audit_clients();
#endif
#ifdef LRMAUDIT_RESOURCES
	audit_resources();
#endif
}

void
audit_clients()
{
	g_hash_table_foreach(clients, on_client, NULL);
}

void
audit_resources()
{
	g_hash_table_foreach(resources, on_resource, NULL);
}

void
audit_ops(GList* rsc_ops, lrmd_rsc_t* rsc, const char *desc)
{
	GList *oplist;

	for( oplist = g_list_first(rsc_ops);
		oplist; oplist = g_list_next(oplist) )
	{
		on_op(oplist->data, rsc, desc);
	}
}

void
on_client(gpointer key, gpointer value, gpointer user_data)
{
	lrmd_client_t * client = (lrmd_client_t*)value;

	ret_on_null(client,"","client");
	log_on_null(client->app_name,"","app_name");
	log_on_null(client->ch_cmd,client->app_name,"ch_cmd");
	log_on_null(client->ch_cbk,client->app_name,"ch_cbk");
	log_on_null(client->g_src,client->app_name,"g_src");
	log_on_null(client->g_src_cbk,client->app_name,"g_src_cbk");
}

void
on_resource(gpointer key, gpointer value, gpointer user_data)
{
	lrmd_rsc_t* rsc = (lrmd_rsc_t*)value;

	ret_on_null(rsc,"","rsc");
	ret_on_null(rsc->id,"","id");
	log_on_null(rsc->type,rsc->id,"type");
	log_on_null(rsc->class,rsc->id,"class");
	log_on_null(rsc->provider,rsc->id,"provider");
	/*log_on_null(rsc->params,rsc->id,"params");*/
	log_on_null(rsc->last_op_table,rsc->id,"last_op_table");
	log_on_null(rsc->last_op_done,rsc->id,"last_op_done");
	audit_ops(rsc->op_list,rsc,"op_list");
	audit_ops(rsc->repeat_op_list,rsc,"repeat_op_list");
}

void
on_op(lrmd_op_t *op, lrmd_rsc_t* rsc, const char *desc)
{
	ret_on_null(op,rsc->id,desc);
	log_on_null(op->rsc_id,rsc->id,"rsc_id");
	if( strcmp(op->rsc_id,rsc->id) ) {
		lrmd_log(LOG_ERR,"LRMAUDIT: rsc %s, op %s "
			"op->rsc_id does not match rsc->id",
			rsc->id,small_op_info(op));
	}
	log_on_null(op->msg,small_op_info(op),"msg");
	if( op->rapop ) {
		if( op->rapop->lrmd_op != op ) {
			lrmd_log(LOG_ERR,
				"LRMAUDIT: rsc %s, op %s: rapop->lrmd_op does not match op",
				rsc->id,small_op_info(op));
		}
		if( strcmp(op->rapop->rsc_id,op->rsc_id) ) {
			lrmd_log(LOG_ERR,
				"LRMAUDIT: rsc %s, op %s rapop->rsc_id does not match op->rsc_id",
				rsc->id,small_op_info(op));
		}
		on_ra_pipe_op(op->rapop,op,"rapop");
	}
}

void
on_ra_pipe_op(ra_pipe_op_t *rapop, lrmd_op_t *op, const char *desc)
{
	ret_on_null(rapop,small_op_info(op),desc);
	log_on_null(rapop->ra_stdout_gsource,small_op_info(op),"ra_stdout_gsource");
	log_on_null(rapop->ra_stderr_gsource,small_op_info(op),"ra_stderr_gsource");
	log_on_null(rapop->rsc_id,small_op_info(op),"rsc_id");
	log_on_null(rapop->op_type,small_op_info(op),"op_type");
	log_on_null(rapop->rsc_class,small_op_info(op),"rsc_class");
	if( strcmp(op->rsc_id,rapop->rsc_id) ) {
		lrmd_log(LOG_ERR,"LRMAUDIT: %s: rapop->rsc_id "
			"does not match op_rsc->id",
			small_op_info(op));
	}
}

#endif /*DOLRMAUDITS*/
