/*
 * Local Resource Manager Daemon
 *
 * Author: Huang Zhen <zhenhltc@cn.ibm.com>
 * Partly contributed by Andrew Beekhof <andrew@beekhof.net> 
 * Copyright (c) 2004 International Business Machines
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
#include <sched.h>

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
#include <clplumbing/realtime.h>
#include <ha_msg.h>
#ifdef ENABLE_APPHB
#  include <apphb.h>
#endif
/* #include <hb_api.h> */

#include <lrm/lrm_api.h>
#include <lrm/lrm_msg.h>
#include <lrm/raexec.h>

#include <lrmd.h>
#include <lrmd_fdecl.h>

static	gboolean	in_alloc_dump = FALSE;

ProcTrack_ops ManagedChildTrackOps = {
	on_ra_proc_finished,
	on_ra_proc_registered,
	on_ra_proc_query_name
};

/* msg dispatch table */
typedef int (*msg_handler)(lrmd_client_t* client, struct ha_msg* msg);
struct msg_map
{
	const char 	*msg_type;
	int	reply_time;
	msg_handler	handler;
	int min_priv; /* minimum privileges required */
};

/*
 * two ways to handle replies:
 * REPLY_NOW: pack whatever the handler returned and send it
 * NO_MSG: the handler will send the reply itself
 */
#define REPLY_NOW 0
#define NO_MSG 1
#define send_msg_now(p) \
	(p->reply_time==REPLY_NOW)

struct msg_map msg_maps[] = {
	{REGISTER,	REPLY_NOW,	on_msg_register, 0},
	{GETRSCCLASSES,	NO_MSG,	on_msg_get_rsc_classes, 0},
	{GETRSCTYPES,	NO_MSG,	on_msg_get_rsc_types, 0},
	{GETPROVIDERS,	NO_MSG,	on_msg_get_rsc_providers, 0},
	{ADDRSC,	REPLY_NOW,	on_msg_add_rsc, PRIV_ADMIN},
	{GETRSC,	NO_MSG,	on_msg_get_rsc, PRIV_ADMIN},
	{GETLASTOP,	NO_MSG,	on_msg_get_last_op, PRIV_ADMIN},
	{GETALLRCSES,	NO_MSG,	on_msg_get_all, PRIV_ADMIN},
	{DELRSC,	REPLY_NOW,	on_msg_del_rsc, PRIV_ADMIN},
	{FAILRSC,	REPLY_NOW,	on_msg_fail_rsc, PRIV_ADMIN},
	{PERFORMOP,	REPLY_NOW,	on_msg_perform_op, PRIV_ADMIN},
	{FLUSHOPS,	REPLY_NOW,	on_msg_flush_all, PRIV_ADMIN},
	{CANCELOP,	REPLY_NOW,	on_msg_cancel_op, PRIV_ADMIN},
	{GETRSCSTATE,	NO_MSG,	on_msg_get_state, PRIV_ADMIN},
	{GETRSCMETA,	NO_MSG, 	on_msg_get_metadata, 0},
	{SETLRMDPARAM,	REPLY_NOW, 	on_msg_set_lrmd_param, PRIV_ADMIN},
	{GETLRMDPARAM,	NO_MSG, 	on_msg_get_lrmd_param, 0},
};
#define MSG_NR sizeof(msg_maps)/sizeof(struct msg_map)

GHashTable* clients		= NULL;	/* a GHashTable indexed by pid */
GHashTable* resources 		= NULL;	/* a GHashTable indexed by rsc_id */

static GMainLoop* mainloop 		= NULL;
static int call_id 			= 1;
static const char* lrm_system_name 	= "lrmd";
static GHashTable * RAExecFuncs 	= NULL;
static GList* ra_class_list		= NULL;
static gboolean shutdown_in_progress	= FALSE;
static unsigned long apphb_interval 	= 2000; /* Millisecond */
static gboolean reg_to_apphbd		= FALSE;
static int max_child_count		= 4;
static int retry_interval		= 1000; /* Millisecond */
static int child_count			= 0;
static IPC_Auth	* auth = NULL;

static struct {
	int	opcount;
	int	clientcount;
	int	rsccount;
}lrm_objectstats;

/* define indexes into logmsg_ctrl_defs */
#define OP_STAYED_TOO_LONG 0
static struct logspam logmsg_ctrl_defs[] = {
	{ "operation stayed too long in the queue",
		10, 60, 120, /* max 10 messages in 60s, then delay for 120s */
		"configuration advice: reduce operation contention "
		"either by increasing lrmd max_children or by increasing intervals "
		"of monitor operations"
	},
};

#define set_fd_opts(fd,opts) do { \
	int flag; \
	if ((flag = fcntl(fd, F_GETFL)) >= 0) { \
		if (fcntl(fd, F_SETFL, flag|opts) < 0) { \
			cl_perror("%s::%d: fcntl", __FUNCTION__ \
				, __LINE__); \
		} \
	} else { \
		cl_perror("%s::%d: fcntl", __FUNCTION__, __LINE__); \
	} \
	} while(0)

static ra_pipe_op_t *
ra_pipe_op_new(int child_stdout, int child_stderr, lrmd_op_t * lrmd_op)
{
	ra_pipe_op_t * rapop;
	lrmd_rsc_t* rsc = NULL;

	if ( NULL == lrmd_op ) {
		lrmd_log(LOG_WARNING
			, "%s:%d: lrmd_op==NULL, no need to malloc ra_pipe_op"
			, __FUNCTION__, __LINE__);
		return NULL;
	}
	rapop = calloc(sizeof(ra_pipe_op_t), 1);
	if ( rapop == NULL) {
		lrmd_log(LOG_ERR, "%s:%d out of memory" 
			, __FUNCTION__, __LINE__);
		return NULL;
	}
	rapop->first_line_read = FALSE;

	/*
	 * No any obviouse proof of lrmd hang in pipe read yet.
	 * Bug 475 may be a duplicate of bug 499.
	 * Anyway, via test, it's proved that NOBLOCK read will
	 * obviously reduce the RA execution time (bug 553).
	 */
	/* Let the read operation be NONBLOCK */ 
	set_fd_opts(child_stdout,O_NONBLOCK);
	set_fd_opts(child_stderr,O_NONBLOCK);

	/* there's so much code duplication here */
	rapop->ra_stdout_fd = child_stdout;
	if (rapop->ra_stdout_fd <= STDERR_FILENO) {
		lrmd_log(LOG_ERR, "%s: invalid stdout fd [%d]"
			, __FUNCTION__, rapop->ra_stdout_fd);
	}
	rapop->ra_stdout_gsource = G_main_add_fd(G_PRIORITY_HIGH
				, child_stdout, FALSE, handle_pipe_ra_stdout
				, rapop, destroy_pipe_ra_stdout);

	rapop->ra_stderr_fd = child_stderr;
	if (rapop->ra_stderr_fd <= STDERR_FILENO) {
		lrmd_log(LOG_ERR, "%s: invalid stderr fd [%d]"
			, __FUNCTION__, rapop->ra_stderr_fd);
	}
	rapop->ra_stderr_gsource = G_main_add_fd(G_PRIORITY_HIGH
				, child_stderr, FALSE, handle_pipe_ra_stderr
				, rapop, destroy_pipe_ra_stderr);

	rapop->lrmd_op = lrmd_op;

	rapop->op_type = strdup(ha_msg_value(lrmd_op->msg, F_LRM_OP));
	rapop->rsc_id = strdup(lrmd_op->rsc_id);
	rsc = lookup_rsc(lrmd_op->rsc_id);
	if (rsc == NULL) {
		lrmd_debug(LOG_WARNING
			, "%s::%d: the rsc (id=%s) does not exist"
			, __FUNCTION__, __LINE__, lrmd_op->rsc_id);
		rapop->rsc_class = NULL;
	} else {
		rapop->rsc_class = strdup(rsc->class);
	} 

	return rapop;
}

static void
ra_pipe_op_destroy(ra_pipe_op_t * rapop)
{
	CHECK_ALLOCATED(rapop, "ra_pipe_op", );

	if ( NULL != rapop->ra_stdout_gsource) {
		G_main_del_fd(rapop->ra_stdout_gsource);
		rapop->ra_stdout_gsource = NULL;
	}

	if ( NULL != rapop->ra_stderr_gsource) {
		G_main_del_fd(rapop->ra_stderr_gsource);
		rapop->ra_stderr_gsource = NULL;
	}

	if (rapop->ra_stdout_fd >= STDERR_FILENO) {
		close(rapop->ra_stdout_fd);
		rapop->ra_stdout_fd = -1;
	}else if (rapop->ra_stdout_fd >= 0) {
		lrmd_log(LOG_ERR, "%s: invalid stdout fd %d"
		,	__FUNCTION__, rapop->ra_stdout_fd);
	}
	if (rapop->ra_stderr_fd >= STDERR_FILENO) {
		close(rapop->ra_stderr_fd);
		rapop->ra_stderr_fd = -1;
	}else if (rapop->ra_stderr_fd >= 0) {
		lrmd_log(LOG_ERR, "%s: invalid stderr fd %d"
		,	__FUNCTION__, rapop->ra_stderr_fd);
	}
	rapop->first_line_read = FALSE;

	free(rapop->rsc_id);
	free(rapop->op_type);
	rapop->op_type = NULL;
	free(rapop->rsc_class);
	rapop->rsc_class = NULL;

	if (rapop->lrmd_op != NULL) {
		rapop->lrmd_op->rapop = NULL;
		rapop->lrmd_op = NULL;
	}

	free(rapop);
}

static void
lrmd_op_destroy(lrmd_op_t* op)
{
	CHECK_ALLOCATED(op, "op", );
	--lrm_objectstats.opcount;

	if (op->exec_pid > 1) {
		lrmd_log(LOG_CRIT
		,	"%s: lingering operation process %d, op %s"
		,	__FUNCTION__, op->exec_pid, small_op_info(op));	
		return;
	}
	lrmd_debug2(LOG_DEBUG, "%s: free the %s with address %p"
		  ,__FUNCTION__, op_info(op), op);
	ha_msg_del(op->msg);
	op->msg = NULL;
	if( op->rsc_id ) {
		free(op->rsc_id);
		op->rsc_id = NULL;
	}
	op->exec_pid = 0;
	if ( op->rapop != NULL ) {
		op->rapop->lrmd_op = NULL;
		op->rapop = NULL;
	}
	op->first_line_ra_stdout[0] = EOS;

	if( op->repeat_timeout_tag ) {
		Gmain_timeout_remove(op->repeat_timeout_tag);
	}
	free(op);
}

static lrmd_op_t*
lrmd_op_new(void)
{
	lrmd_op_t* op = (lrmd_op_t*)calloc(sizeof(lrmd_op_t),1);

	if (op == NULL) {
		lrmd_log(LOG_ERR, "lrmd_op_new(): out of memory when "
			 "calloc a lrmd_op_t.");
		return NULL;
	}
	op->rsc_id = NULL;
	op->msg = NULL;
	op->exec_pid = -1;
	op->repeat_timeout_tag = 0;
	op->rapop = NULL;
	op->first_line_ra_stdout[0] = EOS;
	op->t_recv = time_longclock();
 	op->t_perform = zero_longclock;
 	op->t_done = zero_longclock;
 	op->t_rcchange = zero_longclock;
 	op->t_lastlogmsg = zero_longclock;
 
	memset(op->killseq, 0, sizeof(op->killseq));
	++lrm_objectstats.opcount;
	return op;
}

static lrmd_op_t* 
lrmd_op_copy(const lrmd_op_t* op)
{
	lrmd_op_t* ret;

	ret = lrmd_op_new();
	if (NULL == ret) {
		return NULL;
	}
	/* Do a "shallow" copy */
	*ret = *op;
	/*
	 * Some things, like timer ids and child pids are duplicated here
	 * but can be destroyed in one copy, but kept intact
	 * in the other, to later be destroyed.
	 * This isn't a complete disaster, since the timer ids aren't
	 * pointers, but it's still untidy at the least.
	 * Be sure and care of this situation when using this function.
	 */
	/* Do a "deep" copy of the message structure */
	ret->rapop = NULL;
	ret->msg = ha_msg_copy(op->msg);
	ret->rsc_id = strdup(op->rsc_id);
	ret->rapop = NULL;
	ret->first_line_ra_stdout[0] = EOS;
	ret->repeat_timeout_tag = 0;
	ret->exec_pid = -1;
	ret->t_recv = op->t_recv;
 	ret->t_perform = op->t_perform;
 	ret->t_done = op->t_done;
 	ret->t_rcchange = op->t_rcchange;
	ret->is_copy = TRUE;
	ret->is_cancelled = FALSE;
	ret->weight = op->weight;
	return ret;
}

static
const char *
op_status_to_str(int op_status)
{
	static char whatwasthat[25];
	switch (op_status) {
		case LRM_OP_DONE:
			return "LRM_OP_DONE";
		case LRM_OP_CANCELLED:
			return "LRM_OP_CANCELLED";
		case LRM_OP_TIMEOUT:
			return "LRM_OP_TIMEOUT";
		case LRM_OP_NOTSUPPORTED:
			return "LRM_OP_NOTSUPPORTED";
		case -1:
			return "N/A (-1)";
		default:
			break;
	}
	snprintf(whatwasthat, sizeof(whatwasthat), "UNDEFINED STATUS: %d?", op_status);
	return whatwasthat;
}
static
const char *
op_target_rc_to_str(int target)
{
	static char whatwasthat[25];
	switch (target) {
		case EVERYTIME:
			return "EVERYTIME";
		case CHANGED:
			return "CHANGED";
		default:
			break;
	}
	snprintf(whatwasthat, sizeof(whatwasthat)
	,"UNDEFINED TARGET_RC: %d", target);
	return whatwasthat;
}

/*
 * We need a separate function to dump out operations for
 * debugging.  Then we wouldn't have to have the code for this
 * inline. In particular, we could then call this from on_op_done()
 * which would shorten and simplify that code - which could use
 * the help :-)
 */


/* Debug oriented funtions */
static gboolean debug_level_adjust(int nsig, gpointer user_data);

static void
lrmd_op_dump(const lrmd_op_t* op, const char * text)
{
	int		op_status = -1;
	int		target_rc = -1;
	const char *	pidstat;
	longclock_t	now = time_longclock();

	CHECK_ALLOCATED(op, "op", );
	if (op->exec_pid < 1
	||	((kill(op->exec_pid, 0) < 0) && ESRCH == errno)) {
		pidstat = "not running";
	}else{
		pidstat = "running";
	}
	ha_msg_value_int(op->msg, F_LRM_OPSTATUS, &op_status);
	ha_msg_value_int(op->msg, F_LRM_TARGETRC, &target_rc);
	lrmd_debug(LOG_DEBUG
	,	"%s: lrmd_op: %s status: %s, target_rc=%s, client pid %d call_id"
	": %d, child pid: %d (%s) %s %s"
	,	text,	op_info(op), op_status_to_str(op_status)
	,	op_target_rc_to_str(target_rc)
	,	op->client_id, op->call_id, op->exec_pid, pidstat
	,	(op->is_copy ? "copy" : "original")
	,	(op->is_cancelled ? "cancelled" : ""));
	lrmd_debug(LOG_DEBUG
	,	"%s: lrmd_op2: rt_tag: %d, interval: %d, delay: %d"
	,	text,  op->repeat_timeout_tag
	,	op->interval, op->delay);
	lrmd_debug(LOG_DEBUG
	,	"%s: lrmd_op3: t_recv: %ldms, t_add: %ldms"
	", t_perform: %ldms, t_done: %ldms, t_rcchange: %ldms"
	,	text, tm2age(op->t_recv), tm2age(op->t_addtolist)
	,	tm2age(op->t_perform), tm2age(op->t_done), tm2age(op->t_rcchange));
	lrmd_rsc_dump(op->rsc_id, text);
}


static void
lrmd_client_destroy(lrmd_client_t* client)
{
	CHECK_ALLOCATED(client, "client", );

	--lrm_objectstats.clientcount;
	/*
	 * Delete direct references to this client
	 * and repeating operations it might have scheduled
	 */
	unregister_client(client);
	if (client->app_name) {
		free(client->app_name);
		client->app_name = NULL;
	}
	free(client);
}

static lrmd_client_t*
lrmd_client_new(void)
{
	lrmd_client_t*	client;
	client = calloc(sizeof(lrmd_client_t), 1);
	if (client == NULL) {
		lrmd_log(LOG_ERR, "lrmd_client_new(): out of memory when "
			 "calloc lrmd_client_t.");
		return NULL;
	}
	client->g_src = NULL;
	client->g_src_cbk = NULL;
	++lrm_objectstats.clientcount;
	return client;
}
static void
lrmd_client_dump(gpointer key, gpointer value, gpointer user_data)
{
	lrmd_client_t * client = (lrmd_client_t*)value;
	CHECK_ALLOCATED(client, "client", );
	if(!client) {
		return;
	}

	lrmd_debug(LOG_DEBUG, "client name: %s, client pid: %d"
		", client uid: %d, gid: %d, last request: %s"
		", last op in: %s, lastop out: %s"
		", last op rc: %s"
		,	lrm_str(client->app_name)
		,	client->pid
		,	client->uid, client->gid
		,	client->lastrequest
		,	ctime(&client->lastreqstart)
		,	ctime(&client->lastreqend)
		,	ctime(&client->lastrcsent)
		);
	if (!client->ch_cmd) {
		lrmd_debug(LOG_DEBUG, "NULL client ch_cmd in %s()", __FUNCTION__);
	}else{
		lrmd_debug(LOG_DEBUG
		,	"Command channel status: %d, read queue addr: %p, write queue addr: %p"
		,	client->ch_cmd->ch_status
		,	client->ch_cmd->recv_queue
		,	client->ch_cmd->send_queue );

		if (client->ch_cmd->recv_queue && client->ch_cmd->send_queue) {
			lrmd_debug(LOG_DEBUG, "read Qlen: %ld, write Qlen: %ld"
			,	(long)client->ch_cmd->recv_queue->current_qlen
			,	(long)client->ch_cmd->send_queue->current_qlen);
		}
	}
	if (!client->ch_cbk) {
		lrmd_debug(LOG_DEBUG, "NULL client ch_cbk in %s()", __FUNCTION__);
	}else{
		lrmd_debug(LOG_DEBUG
		,	"Callback channel status: %d, read Qlen: %ld, write Qlen: %ld"
		,	client->ch_cbk->ch_status
		,	(long)client->ch_cbk->recv_queue->current_qlen
		,	(long)client->ch_cbk->send_queue->current_qlen);
	}
}
static void
lrmd_dump_all_clients(void)
{
	static gboolean	incall = FALSE;

	if (incall) {
		return;
	}

	incall = TRUE;

	lrmd_debug(LOG_DEBUG, "%d clients connected to lrmd"
	 ,	g_hash_table_size(clients)); 

	g_hash_table_foreach(clients, lrmd_client_dump, NULL);
	incall = FALSE;
}

static void
lrmd_rsc_destroy(lrmd_rsc_t* rsc)
{
	LRMAUDIT();
	CHECK_ALLOCATED(rsc, "resource", );
	--lrm_objectstats.rsccount;
	if( rsc->op_list || rsc->repeat_op_list ) {
		lrmd_log(LOG_ERR, "%s: refusing to remove resource %s" 
		" which is still holding operations"
		, __FUNCTION__, lrm_str(rsc->id));
		return;
	} else {
		lrmd_debug(LOG_DEBUG, "%s: removing resource %s" 
		, __FUNCTION__, lrm_str(rsc->id));
	}
	g_hash_table_remove(resources, rsc->id);
	if (rsc->id) {
		free(rsc->id);
		rsc->id = NULL;
	}
	if (rsc->type) {
		free(rsc->type);
		rsc->type = NULL;
	}
	if (rsc->class) {
		free(rsc->class);
		rsc->class = NULL;
	}
	if (rsc->provider) {
		free(rsc->provider);
		rsc->provider = NULL;
	}
	if (NULL != rsc->params) {
		free_str_table(rsc->params);
		rsc->params = NULL;
	}
	if (rsc->last_op_table) {
		g_hash_table_foreach_remove(rsc->last_op_table
		,	 free_str_hash_pair, NULL);
		g_hash_table_destroy(rsc->last_op_table);
		rsc->last_op_table = NULL;
	}
	if (rsc->last_op_done) {
		lrmd_op_destroy(rsc->last_op_done);
		rsc->last_op_done = NULL;
	}

	if (rsc->delay_timeout > 0) {
		Gmain_timeout_remove(rsc->delay_timeout);
		rsc->delay_timeout = (guint)0;
	}

	free(rsc);
	LRMAUDIT();
}

static lrmd_rsc_t*
lrmd_rsc_new(const char * id, struct ha_msg* msg)
{
	lrmd_rsc_t*	rsc;
	rsc = (lrmd_rsc_t *)calloc(sizeof(lrmd_rsc_t),1);
	if (rsc == NULL) {
		lrmd_log(LOG_ERR, "%s: out of memory when calloc "
			 "a lrmd_rsc_t", __FUNCTION__);
		return NULL;
	}
	rsc->delay_timeout = (guint)0;
	if (id) {
		rsc->id = strdup(id);
	}
	if (msg) {
		rsc->type = strdup(ha_msg_value(msg, F_LRM_RTYPE));
		rsc->class = strdup(ha_msg_value(msg, F_LRM_RCLASS));
		if (NULL == ha_msg_value(msg, F_LRM_RPROVIDER)) {
			lrmd_log(LOG_NOTICE, "%s(): No %s field in message"
			, __FUNCTION__, F_LRM_RPROVIDER);
		}else{
			rsc->provider = strdup(ha_msg_value(msg, F_LRM_RPROVIDER));
			if (rsc->provider == NULL) {
				goto errout;
			}
		}
		if (rsc->id == NULL
		||	rsc->type == NULL
		||	rsc->class == NULL) {
			goto errout;
		}
	}
	g_hash_table_insert(resources, strdup(id), rsc);
	++lrm_objectstats.rsccount;
	return rsc;
errout:
	lrmd_rsc_destroy(rsc); /* violated property */ /* Or so BEAM thinks :-) */
	rsc = NULL;
	return rsc;
}

static void
dump_op(gpointer key, gpointer val, gpointer data)
{
	lrmd_op_t* lrmd_op = (lrmd_op_t*) val;

	lrmd_op_dump(lrmd_op, "rsc->last_op_table");
}
static void
dump_op_table(gpointer key, gpointer val, gpointer data)
{
	GHashTable* table = (GHashTable*) val;

	g_hash_table_foreach(table, dump_op, data);
}
static void
lrmd_rsc_dump(char* rsc_id, const char * text)
{
	static gboolean	incall = FALSE;
	GList*		oplist;
	lrmd_rsc_t*	rsc=NULL;

	if( rsc_id ) {
		rsc = lookup_rsc(rsc_id);
	} else {
		lrmd_debug(LOG_INFO
			, "%s:%d: the rsc_id is NULL"
			, __FUNCTION__, __LINE__);
		return;
	}
	CHECK_ALLOCATED(rsc, "rsc", );
	if(!rsc) {
		return;
	}

	/* Avoid infinite recursion loops... */
	if (incall) {
		return;
	}
	incall = TRUE;
	/* TODO: Dump params and last_op_table FIXME */

	lrmd_debug(LOG_DEBUG, "%s: BEGIN resource dump", text);
	lrmd_debug(LOG_DEBUG, "%s: resource %s/%s/%s/%s"
	,	text
	,	lrm_str(rsc->id)
	,	lrm_str(rsc->type)
	,	lrm_str(rsc->class)
	,	lrm_str(rsc->provider));

	lrmd_debug(LOG_DEBUG, "%s: rsc->op_list...", text);
	for(oplist = g_list_first(rsc->op_list); oplist;
		oplist = g_list_next(oplist)) {
		lrmd_op_dump(oplist->data, "rsc->op_list");
	}

	lrmd_debug(LOG_DEBUG, "%s: rsc->repeat_op_list...", text);
	for(oplist = g_list_first(rsc->repeat_op_list); oplist;
		oplist=g_list_next(oplist)) {
		lrmd_op_dump(oplist->data, "rsc->repeat_op_list");
	}
	
	if (rsc->last_op_done != NULL) {
		lrmd_debug(LOG_DEBUG, "%s: rsc->last_op_done...", text);
		lrmd_op_dump(rsc->last_op_done, "rsc->last_op_done");
	}
	else {
		lrmd_debug(LOG_DEBUG, "%s: rsc->last_op_done==NULL", text);
	}
	if (rsc->last_op_table) {
		g_hash_table_foreach(rsc->last_op_table,dump_op_table,NULL);
	}
	else {
		lrmd_debug(LOG_DEBUG, "%s: rsc->last_op_table==NULL", text);
	}
	lrmd_debug(LOG_DEBUG, "%s: END resource dump", text);
	incall = FALSE;
};
static void
dump_id_rsc_pair(gpointer key, gpointer value, gpointer user_data)
{
	char* rid = (char*)key;
	char* text = (char*)user_data;
	lrmd_rsc_dump(rid,text);
}
static void
lrmd_dump_all_resources(void)
{
	static gboolean	incall = FALSE;
	char text[]= "lrmd_dump_all_resources";
	if (incall) {
		return;
	}
	incall = TRUE;

	lrmd_debug(LOG_DEBUG, "%d resources are managed by lrmd"
	,	g_hash_table_size(resources)); 
	g_hash_table_foreach(resources, dump_id_rsc_pair, text);
	incall = FALSE;
}


#if 0
static void
lrm_debug_running_op(lrmd_op_t* op, const char * text)
{
	char	cmd[256];
	lrmd_op_dump(op, text);
	CHECK_ALLOCATED(op, "op", );
	if (op->exec_pid >= 1) {
		/* This really ought to use our logger
		 * So... it might not get forwarded to the central machine
		 * if you're testing with CTS -- FIXME!!!
		 */
		snprintf(cmd, sizeof(cmd)
		,	"ps -l -f -s %d | logger -p daemon.info -t 'T/O PS:'"
		,	op->exec_pid);
		lrmd_debug(LOG_DEBUG, "Running [%s]", cmd);
		if (system(cmd) != 0) {
			lrmd_log(LOG_ERR, "Running [%s] failed", cmd);
		}
		snprintf(cmd, sizeof(cmd)
		,	"ps axww | logger -p daemon.info -t 't/o ps:'");
		lrmd_debug(LOG_DEBUG, "Running [%s]", cmd);
		if (system(cmd) != 0) {
			lrmd_log(LOG_ERR, "Running [%s] failed", cmd);
		}
	}
}
#endif
int
main(int argc, char ** argv)
{
	int req_restart = TRUE;
	int req_status  = FALSE;
	int req_stop    = FALSE;

	int argerr = 0;
	int flag;

	while ((flag = getopt(argc, argv, OPTARGS)) != EOF) {
		switch(flag) {
			case 'h':		/* Help message */
				usage(lrm_system_name, LSB_EXIT_OK);
				break;
			case 'v':		/* Debug mode, more logs*/
				++debug_level;
				break;
			case 's':		/* Status */
				req_status = TRUE;
				break;
			case 'k':		/* Stop (kill) */
				req_stop = TRUE;
				break;
			case 'r':		/* Restart */
				req_restart = TRUE;
				break;
			/* Register to apphbd then monitored by it */
			case 'm':
				reg_to_apphbd = TRUE;
				break;
			case 'i':		/* Get apphb interval */
				if (optarg) {
					apphb_interval = atoi(optarg);
				}
				break;
			default:
				++argerr;
				break;
		}
	}

	if (optind > argc) {
		++argerr;
	}

	if (argerr) {
		usage(lrm_system_name, LSB_EXIT_GENERIC);
	}

	cl_log_set_entity(lrm_system_name);
	cl_log_enable_stderr(debug_level?TRUE:FALSE);
	cl_log_set_facility(HA_LOG_FACILITY);

	/* Use logd if it's enabled by heartbeat */
	cl_inherit_logging_environment(0);

	if (req_status){
		return init_status(PID_FILE, lrm_system_name);
	}

	if (req_stop){
		return init_stop(PID_FILE);
	}

	if (req_restart) {
		init_stop(PID_FILE);
	}

	return init_start();
}

int
init_status(const char *pid_file, const char *client_name)
{
	long	pid =	cl_read_pidfile(pid_file);

	if (pid > 0) {
		fprintf(stderr, "%s is running [pid: %ld]\n"
			,	client_name, pid);
		return LSB_STATUS_OK;
	}
	fprintf(stderr, "%s is stopped.\n", client_name);
	return LSB_STATUS_STOPPED;
}

int
init_stop(const char *pid_file)
{
	long	pid;
	int	rc = LSB_EXIT_OK;



	if (pid_file == NULL) {
		lrmd_log(LOG_ERR, "No pid file specified to kill process");
		return LSB_EXIT_GENERIC;
	}
	pid =	cl_read_pidfile(pid_file);

	if (pid > 0) {
		if (CL_KILL((pid_t)pid, SIGTERM) < 0) {
			rc = (errno == EPERM
			      ?	LSB_EXIT_EPERM : LSB_EXIT_GENERIC);
			fprintf(stderr, "Cannot kill pid %ld\n", pid);
		}else{
			lrmd_log(LOG_INFO,
			       "Signal sent to pid=%ld,"
			       " waiting for process to exit",
			       pid);

			while (CL_PID_EXISTS(pid)) {
				sleep(1);
			}
		}
	}
	return rc;
}

static const char usagemsg[] = "[-srkhv]\n\ts: status\n\tr: restart"
	"\n\tk: kill\n\tm: register to apphbd\n\ti: the interval of apphb\n\t"
	"h: help\n\tv: debug\n";

void
usage(const char* cmd, int exit_status)
{
	FILE* stream;

	stream = exit_status ? stderr : stdout;

	fprintf(stream, "usage: %s %s", cmd, usagemsg);
	fflush(stream);

	exit(exit_status);
}
/*
 * In design, the lrmd should not know the meaning of operation type
 * and the meaning of rc. This function is just for logging.
 */
static void
warning_on_active_rsc(gpointer key, gpointer value, gpointer user_data)
{
	int op_status, rc;
	const char* op_type;
	
	lrmd_rsc_t* rsc = (lrmd_rsc_t*)value;
	if (rsc->last_op_done != NULL) {
		if (HA_OK != ha_msg_value_int(rsc->last_op_done->msg
				,	F_LRM_OPSTATUS, &op_status)) {
			lrmd_debug(LOG_WARNING
			,"resource %s is left in UNKNOWN status." \
			 "(last op done is damaged..)"
			,rsc->id);
			return;
		}		
		op_type = ha_msg_value(rsc->last_op_done->msg, F_LRM_OP);
		if (op_status != LRM_OP_DONE) {
			lrmd_debug(LOG_WARNING
			,"resource %s is left in UNKNOWN status." \
			 "(last op %s finished without LRM_OP_DONE status.)"
			,rsc->id, op_type);
			return;
		}
		if (HA_OK != ha_msg_value_int(rsc->last_op_done->msg
				,	F_LRM_RC, &rc)) {
			lrmd_debug(LOG_WARNING
			,"resource %s is left in UNKNOWN status." \
			 "(last op done is damaged..)"
			,rsc->id);
			return;
		}		
		if((rc == 0) &&
		   (STRNCMP_CONST(op_type,"start") ==0
		    ||STRNCMP_CONST(op_type,"monitor") ==0
		    ||STRNCMP_CONST(op_type,"status") ==0)) {
			lrmd_debug(LOG_WARNING
			,"resource %s is left in RUNNING status." \
			 "(last op %s finished with rc 0.)"
			,rsc->id, op_type);
			return;
		}
		if ((rc !=0 ) &&
		    (STRNCMP_CONST(op_type,"start") ==0
		     ||STRNCMP_CONST(op_type,"stop") ==0)) {
			lrmd_debug(LOG_WARNING
			,"resource %s is left in UNKNOWN status." \
			 "(last op %s finished with rc %d.)"
			,rsc->id, op_type, rc);
			return;
		}
	}
}

static gboolean
lrm_shutdown(void)
{
	lrmd_log(LOG_INFO,"lrmd is shutting down");
	if (mainloop != NULL && g_main_is_running(mainloop)) {
		g_hash_table_foreach(resources, warning_on_active_rsc, NULL);
		g_main_quit(mainloop);
	}else {
		exit(LSB_EXIT_OK);
	}
	return FALSE;
}
static void 
has_pending_op(gpointer key, gpointer value, gpointer user_data)
{
	lrmd_rsc_t* rsc = (lrmd_rsc_t*)value;
	int* result = (int*)user_data;
	if (rsc->op_list != NULL) {
		*result = TRUE;
	}
}
static gboolean
can_shutdown() 
{
	int has_ops = FALSE;
	g_hash_table_foreach(resources, has_pending_op, &has_ops);

	return !has_ops;
}
gboolean
sigterm_action(int nsig, gpointer user_data)
{
	shutdown_in_progress = TRUE;

	if (can_shutdown()) {
		lrm_shutdown();
	} else {
		lrmd_log(LOG_INFO, "sigterm_action: shutdown postponed, some operations are still running");
	}
	return TRUE;
}

static void
register_pid(gboolean do_fork,
	     gboolean (*shutdown)(int nsig, gpointer userdata))
{
	int	j;

	umask(022);

	for (j=0; j < 3; ++j) {
		close(j);
		(void)open("/dev/null", j == 0 ? O_RDONLY : O_WRONLY);
	}
	CL_IGNORE_SIG(SIGINT);
	CL_IGNORE_SIG(SIGHUP);
	CL_DEFAULT_SIG(SIGPIPE);
	G_main_add_SignalHandler(G_PRIORITY_HIGH, SIGTERM
	,	 	shutdown, NULL, NULL);
	cl_signal_set_interrupt(SIGTERM, 1);
	cl_signal_set_interrupt(SIGCHLD, 1);
	/* At least they are harmless, I think. ;-) */
	cl_signal_set_interrupt(SIGINT, 0);
	cl_signal_set_interrupt(SIGHUP, 0);
}

static int
init_using_apphb(void)
{
#ifdef ENABLE_APPHB
	char lrmd_instance[40];

	if (reg_to_apphbd == FALSE) {
		return -1;
	}

	snprintf(lrmd_instance, sizeof(lrmd_instance), "%s_%ld"
	,	lrm_system_name, (long)getpid());
	if (apphb_register(lrm_system_name, lrmd_instance) != 0) {
		lrmd_log(LOG_ERR, "Failed when trying to register to apphbd.");
		lrmd_log(LOG_ERR, "Maybe apphbd is not running. Quit.");
		return -1;
	}
	lrmd_log(LOG_INFO, "Registered to apphbd.");

	apphb_setinterval(apphb_interval);
	apphb_setwarn(apphb_interval*APPHB_WARNTIME_FACTOR);

	Gmain_timeout_add(apphb_interval - APPHB_INTVL_DETLA, emit_apphb, NULL);
#endif
	return 0;
}

static gboolean
emit_apphb(gpointer data)
{
#ifdef ENABLE_APPHB
	if (reg_to_apphbd == FALSE) {
		return FALSE;
	}

	if (apphb_hb() != 0) {
		lrmd_log(LOG_ERR, "emit_apphb: Failed to emit an apphb.");
		reg_to_apphbd = FALSE;
		return FALSE;
	};
#endif
	return TRUE;
}

static void
calc_max_children()
{
#ifdef _SC_NPROCESSORS_ONLN
	int nprocs;

	nprocs = sysconf(_SC_NPROCESSORS_ONLN);
	if( nprocs < 1 ) {
		lrmd_log(LOG_WARNING, "%s: couldn't get the number of processors"
		, __FUNCTION__);
	} else {
		if( nprocs/2 > max_child_count ) {
			max_child_count = nprocs/2;
		}
		lrmd_log(LOG_INFO, "max-children set to %d "
		"(%d processors online)", max_child_count, nprocs);
		return;
	}
#else
	lrmd_log(LOG_WARNING, "%s: cannot get the number of processors "
	"on this platform", __FUNCTION__);
#endif
	lrmd_log(LOG_INFO, "max-children set to %d", max_child_count);
}

/* main loop of the daemon*/
int
init_start ()
{
	DIR* dir = NULL;
	PILPluginUniv * PluginLoadingSystem = NULL;
	struct dirent* subdir;
	char* dot = NULL;
	char* ra_name = NULL;
        int len;
	IPC_WaitConnection* conn_cmd = NULL;
	IPC_WaitConnection* conn_cbk = NULL;

	GHashTable* conn_cmd_attrs;
	GHashTable* conn_cbk_attrs;

	char path[] = IPC_PATH_ATTR;
	char cmd_path[] = LRM_CMDPATH;
	char cbk_path[] = LRM_CALLBACKPATH;

	PILGenericIfMgmtRqst RegisterRqsts[]= {
		{"RAExec", &RAExecFuncs, NULL, NULL, NULL},
		{ NULL, NULL, NULL, NULL, NULL} };

	if( getenv("LRMD_MAX_CHILDREN") ) {
		set_lrmd_param("max-children", getenv("LRMD_MAX_CHILDREN"));
	} else {
		calc_max_children();
	}

	qsort(msg_maps, MSG_NR, sizeof(struct msg_map), msg_type_cmp);

	if (cl_lock_pidfile(PID_FILE) < 0) {
		lrmd_log(LOG_ERR, "already running: [pid %d].", cl_read_pidfile(PID_FILE));
		lrmd_log(LOG_ERR, "Startup aborted (already running).  Shutting down."); 
		exit(100);
	}

	register_pid(FALSE, sigterm_action);

	/* load RA plugins   */
	PluginLoadingSystem = NewPILPluginUniv (HA_PLUGIN_DIR);
	PILLoadPlugin(PluginLoadingSystem, "InterfaceMgr", "generic",
				  &RegisterRqsts);

	/*
	 *	FIXME!!!
	 *	Much of the code through the end of the next loop is
	 *	unnecessary - The plugin system will do this for you quite
	 *	nicely.  And, it does it portably, too...
	 */

	dir = opendir(LRM_PLUGIN_DIR);
	if (NULL == dir) {
		lrmd_log(LOG_ERR, "main: can not open RA plugin dir "LRM_PLUGIN_DIR);
		lrmd_log(LOG_ERR, "Startup aborted (no RA plugin).  Shutting down.");
		exit(100);
	}

	while ( NULL != (subdir = readdir(dir))) {
		/* skip . and .. */
		if ( '.' == subdir->d_name[0]) {
			continue;
		}
		/* skip the other type files */
		if (NULL == strstr(subdir->d_name, ".so")) {
			continue;
		}
		/* remove the ".so" */
		dot = strchr(subdir->d_name,'.');
		if (NULL != dot) {
			len = (int)(dot - subdir->d_name);
			ra_name = g_strndup(subdir->d_name,len);
		}
		else {
			ra_name = g_strdup(subdir->d_name);
		}
		PILLoadPlugin(PluginLoadingSystem , "RAExec", ra_name, NULL);
		ra_class_list = g_list_append(ra_class_list,ra_name);
	}
	closedir(dir); dir = NULL; /* Don't forget to close 'dir' */

	/*
	 *create the waiting connections
	 *one for register the client,
	 *the other is for create the callback channel
	 */

	/*Create a waiting connection to accept command connect from client*/
	conn_cmd_attrs = g_hash_table_new(g_str_hash, g_str_equal);
	g_hash_table_insert(conn_cmd_attrs, path, cmd_path);
	conn_cmd = ipc_wait_conn_constructor(IPC_ANYTYPE, conn_cmd_attrs);
	g_hash_table_destroy(conn_cmd_attrs);
	if (NULL == conn_cmd) {
		lrmd_log(LOG_ERR,
			"main: can not create wait connection for command.");
		lrmd_log(LOG_ERR, "Startup aborted (can't create comm channel).  Shutting down.");

		exit(100);
	}

	/*Create a source to handle new connect rquests for command*/
	G_main_add_IPC_WaitConnection( G_PRIORITY_HIGH, conn_cmd, NULL, FALSE,
				   on_connect_cmd, conn_cmd, NULL);

	/* auth is static, but used when clients register */
	auth = ipc_str_to_auth(ADMIN_UIDS, strlen(ADMIN_UIDS), "", 0);

	/*
	 * Create a waiting connection to accept the callback connect from client
	 */
	conn_cbk_attrs = g_hash_table_new(g_str_hash, g_str_equal);
	g_hash_table_insert(conn_cbk_attrs, path, cbk_path);
	conn_cbk = ipc_wait_conn_constructor( IPC_ANYTYPE, conn_cbk_attrs);
	g_hash_table_destroy(conn_cbk_attrs);

	if (NULL == conn_cbk) {
		lrmd_log(LOG_ERR,
			"main: can not create wait connection for callback.");
		lrmd_log(LOG_ERR, "Startup aborted (can't create comm channel).  Shutting down.");
		exit(100);
	}

	/*Create a source to handle new connect rquests for callback*/
	G_main_add_IPC_WaitConnection( G_PRIORITY_HIGH, conn_cbk, NULL, FALSE,
	                               on_connect_cbk, conn_cbk, NULL);

	/* our child signal handling involves calls with
	 * unpredictable timing; so we raise the limit to
	 * reduce the number of warnings
	 */
	set_sigchld_proctrack(G_PRIORITY_HIGH,10*DEFAULT_MAXDISPATCHTIME);

	lrmd_log(LOG_INFO, "enabling coredumps");
	/* Although lrmd can count on the parent to enable coredump, still
	 * set it here for test, when start manually.
	 */
 	cl_cdtocoredir();
	cl_enable_coredumps(TRUE);

	/* Allow us to always take a "secure" core dump
	 * We might have STONITH logins and passwords, etc. in our address
	 * space - so we need to make sure it's only readable by root.
	 * Calling this function accomplishes that.
	 */
	cl_set_all_coredump_signal_handlers();
	if( drop_privs(0, 0) ) { /* become "nobody" */
		lrmd_log(LOG_WARNING,"%s: failed to drop privileges: %s"
		, __FUNCTION__, strerror(errno));
	}

	/*
	 * Add the signal handler for SIGUSR1, SIGUSR2. 
	 * They are used to change the debug level.
	 */
	G_main_add_SignalHandler(G_PRIORITY_HIGH, SIGUSR1, 
		 	debug_level_adjust, NULL, NULL);
	G_main_add_SignalHandler(G_PRIORITY_HIGH, SIGUSR2, 
		 	debug_level_adjust, NULL, NULL);

	/*
	 * alloc memory for client table and resource table
	 */
	clients = g_hash_table_new(g_int_hash, g_int_equal);
	if (clients == NULL) {
		cl_log(LOG_ERR, "can not new hash table clients");
		exit(100);
	}
	resources = g_hash_table_new_full(g_str_hash
	,		g_str_equal, free, NULL);
	if (resources == NULL) {
		cl_log(LOG_ERR, "can not new hash table resources");
		exit(100);
	}

	/*Create the mainloop and run it*/
	mainloop = g_main_new(FALSE);
	lrmd_debug(LOG_DEBUG, "main: run the loop...");
	lrmd_log(LOG_INFO, "Started.");

	/* apphb initializing */
	init_using_apphb();
	emit_apphb(NULL); /* Avoid warning */

	g_main_run(mainloop);

	emit_apphb(NULL);
        if (reg_to_apphbd == TRUE) {
#ifdef ENABLE_APPHB
                apphb_unregister();
#endif
                reg_to_apphbd = FALSE;
        }
	
	if( return_to_orig_privs() ) {
		cl_perror("%s: failed to raise privileges", __FUNCTION__);
	}
	conn_cmd->ops->destroy(conn_cmd);
	conn_cmd = NULL;

	conn_cbk->ops->destroy(conn_cbk);
	conn_cbk = NULL;

	ipc_destroy_auth(auth);
	if (cl_unlock_pidfile(PID_FILE) == 0) {
		lrmd_debug(LOG_DEBUG, "[%s] stopped", lrm_system_name);
	}
	return 0;
}

/*
 *GLoop Message Handlers
 */
gboolean
on_connect_cmd (IPC_Channel* ch, gpointer user_data)
{
	lrmd_client_t* client = NULL;

	/* check paremeters */
	if (NULL == ch) {
		lrmd_log(LOG_ERR, "on_connect_cmd: channel is null");
		return TRUE;
	}
	/* create new client */
	/* the register will be finished in on_msg_register */
	client = lrmd_client_new();
	if (client == NULL) {
		return TRUE;
	}
	client->app_name = NULL;
	client->ch_cmd = ch;
	client->g_src = G_main_add_IPC_Channel(G_PRIORITY_DEFAULT,
				ch, FALSE, on_receive_cmd, (gpointer)client,
				on_remove_client);


	return TRUE;
}

gboolean
on_connect_cbk (IPC_Channel* ch, gpointer user_data)
{
	/*client connect for create the second channel for call back*/
	pid_t pid;
	const char* type = NULL;
	struct ha_msg* msg = NULL;
	lrmd_client_t* client = NULL;

	if (NULL == ch) {
		lrmd_log(LOG_ERR, "on_connect_cbk: channel is null");
		return TRUE;
	}

	/* Isn't this kind of a tight timing assumption ??
	 * This operation is non-blocking -- IIRC
	 * Maybe this should be moved to the input dispatch function
	 * for this channel when we make a GSource from it.
	 * FIXME
	 */

	/*get the message, ends up in socket_waitin */
	msg = msgfromIPC_noauth(ch);
	if (NULL == msg) {
		lrmd_log(LOG_ERR, "on_connect_cbk: can not receive msg");
		return TRUE;
	}

	/*check if it is a register message*/
	type = ha_msg_value(msg, F_LRM_TYPE);
	if (0 != STRNCMP_CONST(type, REGISTER)) {
		lrmd_log(LOG_ERR, "on_connect_cbk: received a message which is "
			 "not known by lrmd.");
		ha_msg_del(msg);
		send_ret_msg(ch, HA_FAIL);
		return TRUE;
	}

	/*get the pid of client */
	if (HA_OK != ha_msg_value_int(msg, F_LRM_PID, &pid)) {
		lrmd_log(LOG_ERR, "on_connect_cbk: can not get pid from the "
			 "message.");
		ha_msg_del(msg);
		send_ret_msg(ch, HA_FAIL);
		return TRUE;
	}
	ha_msg_del(msg);

	/*get the client in the client list*/
	client = lookup_client(pid);
	if (NULL == client) {
		lrmd_log(LOG_ERR, "on_connect_cbk: donnot find the client "
			"[pid:%d] in internal client list. ", pid);
		send_ret_msg(ch, HA_FAIL);
		return TRUE;
	}
	if (client->ch_cbk != NULL) {
		client->ch_cbk->ops->destroy(client->ch_cbk);
		client->ch_cbk = NULL;
	}
	client->g_src_cbk = G_main_add_IPC_Channel(G_PRIORITY_DEFAULT
	, 	ch, FALSE,NULL,NULL,NULL);

	/*fill the channel of callback field*/
	client->ch_cbk = ch;
	send_ret_msg(ch, HA_OK);
	return TRUE;
}

int
msg_type_cmp(const void *p1, const void *p2)
{

	return strncmp(
		((const struct msg_map *)p1)->msg_type,
		((const struct msg_map *)p2)->msg_type,
		MAX_MSGTYPELEN);
}

gboolean
on_receive_cmd (IPC_Channel* ch, gpointer user_data)
{
	struct msg_map *msgmap_p, in_type;
	lrmd_client_t* client = NULL;
	struct ha_msg* msg = NULL;
	char *msg_s;
	int ret = FALSE;

	client = (lrmd_client_t*)user_data;

	if (IPC_DISCONNECT == ch->ch_status) {
		lrmd_debug(LOG_DEBUG,
			"on_receive_cmd: the IPC to client [pid:%d] disconnected."
		,	client->pid);
		return FALSE;
	}

	if (!ch->ops->is_message_pending(ch)) {
		lrmd_debug(LOG_DEBUG, "on_receive_cmd: no pending message in IPC "
			 "channel.");
		return TRUE;
	}


	/*get the message */
	msg = msgfromIPC(ch, 0);
	if (NULL == msg) {
		lrmd_log(LOG_ERR, "on_receive_cmd: can not receive messages.");
		return TRUE;
	}

	if (TRUE == shutdown_in_progress ) {
		send_ret_msg(ch,HA_FAIL);
		ha_msg_del(msg);
		lrmd_log(LOG_INFO, "%s: new requests denied," \
			" we're about to shutdown", __FUNCTION__);
		return TRUE;
	}

	/*dispatch the message*/
	in_type.msg_type = ha_msg_value(msg, F_LRM_TYPE);
	if( !in_type.msg_type ) {
		LOG_FAILED_TO_GET_FIELD(F_LRM_TYPE);
		ha_msg_del(msg);
		return TRUE;
	}
	msg_s = msg2string(msg);
	if( msg_s ) {
		lrmd_debug2(LOG_DEBUG,"dumping request: %s",msg_s);
		free(msg_s);
	}

	if (!(msgmap_p = bsearch(&in_type, msg_maps,
			MSG_NR, sizeof(struct msg_map), msg_type_cmp)
		)) {

		lrmd_log(LOG_ERR, "on_receive_cmd: received an unknown msg");
	} else {
		if( !client->app_name && msgmap_p->handler != on_msg_register ) {
			ha_msg_del(msg);
			lrmd_log(LOG_ERR, "%s: the client needs to register first", __FUNCTION__);
			return FALSE;
		}

		if( client->priv_lvl < msgmap_p->min_priv ) {
			ha_msg_del(msg);
			lrmd_log(LOG_ERR, "%s: insufficient privileges for %s (pid %d)"
			, __FUNCTION__
			, client->app_name, client->pid);
			return FALSE;
		}
		strncpy(client->lastrequest, in_type.msg_type, sizeof(client->lastrequest));
		client->lastrequest[sizeof(client->lastrequest)-1]='\0';
		client->lastreqstart = time(NULL);
		/*call the handler of the message*/
		ret = msgmap_p->handler(client, msg);
		client->lastreqend = time(NULL);

		/*return rc to client if need*/
		if (send_msg_now(msgmap_p)) {
			send_ret_msg(ch, ret);
			client->lastrcsent = time(NULL);
		}
	}

	/*delete the msg*/
	ha_msg_del(msg);

	return ret;
}
static void
remove_repeat_op_from_client(gpointer key, gpointer value, gpointer user_data)
{
	lrmd_rsc_t* rsc = (lrmd_rsc_t*)value;
	pid_t pid = GPOINTER_TO_UINT(user_data); /* pointer cast as int */

	(void)flush_all(&(rsc->repeat_op_list),pid);
}

/* Remove all direct pointer references to 'client' before destroying it */
static int
unregister_client(lrmd_client_t* client)
{
	CHECK_ALLOCATED(client, "client", HA_FAIL);

	if (NULL == lookup_client(client->pid)) {
		lrmd_log(LOG_ERR,"%s: can not find client %s [pid %d] when try "
			 "to unregister it."
		,	__FUNCTION__
		,	client->app_name, client->pid);
		return HA_FAIL;
	}

	/* Search all resources for repeating ops this client owns */
	g_hash_table_foreach(resources
	,	remove_repeat_op_from_client, GUINT_TO_POINTER(client->pid));

	/* Remove from clients */
	g_hash_table_remove(clients, (gpointer)&client->pid);

	lrmd_debug(LOG_DEBUG, "%s: client %s [pid:%d] is unregistered"
	, 	__FUNCTION__
	,	client->app_name
	,	client->pid);
	return HA_OK;
}

void
on_remove_client (gpointer user_data)
{
	lrmd_client_t* client = (lrmd_client_t*) user_data;

	CHECK_ALLOCATED(client, "client", );
	if (client->g_src != NULL) {
		G_main_del_IPC_Channel(client->g_src);
	}
	if (client->g_src_cbk != NULL) {
		G_main_del_IPC_Channel(client->g_src_cbk);
	}
	lrmd_client_destroy(client);

}


/* This function called when its time to run a repeating operation now */
/* Move op from repeat queue to running queue */
gboolean
on_repeat_op_readytorun(gpointer data)
{
	lrmd_op_t* op = NULL;
	lrmd_rsc_t* rsc = NULL;

	LRMAUDIT();
	op = (lrmd_op_t*)data;
	CHECK_ALLOCATED(op, "op", FALSE );

	if (op->exec_pid == 0) {
		lrmd_log(LOG_ERR, "%s: exec_pid is 0 (internal error)"
		,	__FUNCTION__);
		return FALSE;
	}

	lrmd_debug2(LOG_DEBUG
	, 	"%s: remove operation %s from the repeat operation list and "
		"add it to the operation list"
	, 	__FUNCTION__, op_info(op));

	if( op->rsc_id ) {
		rsc = lookup_rsc(op->rsc_id);
	} else {
		lrmd_debug(LOG_INFO
			, "%s: the rsc_id in op %s is NULL"
			, __FUNCTION__, op_info(op));
		return FALSE;
	}

	rsc->repeat_op_list = g_list_remove(rsc->repeat_op_list, op);
	if (op->repeat_timeout_tag != 0) {
		op->repeat_timeout_tag = (guint)0;
	}

	op->exec_pid = -1;

	if (!shutdown_in_progress) {
		add_op_to_runlist(rsc,op);
	}
	perform_op(rsc);

	LRMAUDIT();
	return FALSE;
}

/*LRM Message Handlers*/
int
on_msg_register(lrmd_client_t* client, struct ha_msg* msg)
{
	lrmd_client_t* exist = NULL;
	const char* app_name = NULL;

	CHECK_ALLOCATED(msg, "register message", HA_FAIL);

	app_name = ha_msg_value(msg, F_LRM_APP);
	if (NULL == app_name) {
		lrmd_log(LOG_ERR, "on_msg_register: no app_name in "
			"the ha message.");
		return HA_FAIL;
	}
	client->app_name = strdup(app_name);

	return_on_no_int_value(msg, F_LRM_PID, &client->pid);
	return_on_no_int_value(msg, F_LRM_GID, (int *)&client->gid);
	return_on_no_int_value(msg, F_LRM_UID, (int *)&client->uid);

	exist = lookup_client(client->pid);
	if (NULL != exist) {
		g_hash_table_remove(clients, (gpointer)&client->pid);
		on_remove_client(exist);
		lrmd_log(LOG_NOTICE,
			"on_msg_register: the client [pid:%d] already exists in "
			"internal client list, let remove it at first."
		, 	client->pid);
	}

	/* everybody can connect, but only certain UIDs can perform
	 * administrative actions
	 */
	if( client->ch_cmd->ops->verify_auth(client->ch_cmd, auth) == IPC_OK )
		client->priv_lvl = PRIV_ADMIN;
	else
		client->priv_lvl = 0;

	g_hash_table_insert(clients, (gpointer)&client->pid, client);
	lrmd_debug(LOG_DEBUG, "on_msg_register:client %s [%d] registered"
	,	client->app_name
	,	client->pid);

	return HA_OK;
}

int
on_msg_get_rsc_classes(lrmd_client_t* client, struct ha_msg* msg)
{
	struct ha_msg* ret = NULL;

	CHECK_ALLOCATED(client, "client", HA_FAIL);
	CHECK_ALLOCATED(msg, "message", HA_FAIL);

	lrmd_debug2(LOG_DEBUG
	, 	"on_msg_get_rsc_classes:client [%d] wants to get rsc classes"
	,	client->pid);

	ret = create_lrm_ret(HA_OK, 4);
	CHECK_RETURN_OF_CREATE_LRM_RET;

	cl_msg_add_list(ret,F_LRM_RCLASS,ra_class_list);
	if (HA_OK != msg2ipcchan(ret, client->ch_cmd)) {
		lrmd_log(LOG_ERR,
			"on_msg_get_rsc_classes: cannot send the ret mesage");
	}
	ha_msg_del(ret);

	return HA_OK;
}

int
on_msg_get_rsc_types(lrmd_client_t* client, struct ha_msg* msg)
{
	struct ha_msg* ret = NULL;
	struct RAExecOps * RAExec = NULL;
	GList* types = NULL;
	GList* type;
	const char* rclass = NULL;

	CHECK_ALLOCATED(client, "client", HA_FAIL);
	CHECK_ALLOCATED(msg, "message", HA_FAIL);

	ret = create_lrm_ret(HA_OK,5);
	CHECK_RETURN_OF_CREATE_LRM_RET;

	rclass = ha_msg_value(msg, F_LRM_RCLASS);
	if (rclass == NULL) {
		lrmd_log(LOG_ERR, "on_msg_get_rsc_types: cannot get the "
		"resource class field from the message.");
		send_ret_msg(client->ch_cmd, HA_FAIL);
		return HA_FAIL;
	}

	lrmd_debug2(LOG_DEBUG, "on_msg_get_rsc_types: the client [pid:%d] "
		 "wants to get resource types of resource class %s"
		, client->pid, rclass);

	RAExec = g_hash_table_lookup(RAExecFuncs,rclass);

	if (NULL == RAExec) {
		lrmd_log(LOG_NOTICE, "on_msg_get_rsc_types: can not find this "
			"RA class %s.", rclass);
	} else {
		if (0 <= RAExec->get_resource_list(&types) && types != NULL) {
			cl_msg_add_list(ret, F_LRM_RTYPES, types);
			while (NULL != (type = g_list_first(types))) {
					types = g_list_remove_link(types, type);
				g_free(type->data);
				g_list_free_1(type);
			}
			g_list_free(types);
		}
	}

	if (HA_OK != msg2ipcchan(ret, client->ch_cmd)) {
		lrmd_log(LOG_ERR,
			"on_msg_get_rsc_types: can not send the ret message.");
	}
	ha_msg_del(ret);

	return HA_OK;
}

int
on_msg_get_rsc_providers(lrmd_client_t* client, struct ha_msg* msg)
{
	struct ha_msg* ret = NULL;
	struct RAExecOps * RAExec = NULL;
	GList* providers = NULL;
	GList* provider = NULL;
	const char* rclass = NULL;
	const char* rtype = NULL;

	CHECK_ALLOCATED(client, "client", HA_FAIL);
	CHECK_ALLOCATED(msg, "message", HA_FAIL);

	ret = create_lrm_ret(HA_OK,5);
	CHECK_RETURN_OF_CREATE_LRM_RET;

	rclass = ha_msg_value(msg, F_LRM_RCLASS);
	rtype = ha_msg_value(msg, F_LRM_RTYPE);
	if( !rclass || !rtype ) {
		lrmd_log(LOG_NOTICE
		, 	"%s: could not retrieve resource class or type"
		,	__FUNCTION__);
		send_ret_msg(client->ch_cmd, HA_FAIL);
		return HA_FAIL;
	}

	lrmd_debug2(LOG_DEBUG
	,	"%s: the client [%d] wants to get rsc privider of %s::%s"
	,	__FUNCTION__
	,	client->pid
	,	rclass
	,	rtype);

	RAExec = g_hash_table_lookup(RAExecFuncs, rclass);

	if (NULL == RAExec) {
		lrmd_log(LOG_NOTICE
		, 	"%s: can not find the class %s."
		,	__FUNCTION__
		,	rclass);
	}
	else {
		if (0 <= RAExec->get_provider_list(rtype, &providers)) {
			if (providers != NULL) {
				cl_msg_add_list(ret, F_LRM_RPROVIDERS, providers);
			}
			while (NULL != (provider = g_list_first(providers))) {
				providers = g_list_remove_link(providers, provider);
				g_free(provider->data);
				g_list_free_1(provider);
			}
			g_list_free(providers);
		}
	}

	if (HA_OK != msg2ipcchan(ret, client->ch_cmd)) {
		lrmd_log(LOG_ERR,
			"on_msg_get_rsc_providers: can not send the ret msg");
	}
	ha_msg_del(ret);

	return HA_OK;
}

int
on_msg_get_metadata(lrmd_client_t* client, struct ha_msg* msg)
{
	struct ha_msg* ret = NULL;
	struct RAExecOps * RAExec = NULL;
	const char* rtype = NULL;
	const char* rclass = NULL;
	const char* provider = NULL;

	CHECK_ALLOCATED(client, "client", HA_FAIL);
	CHECK_ALLOCATED(msg, "message", HA_FAIL);

	rtype = ha_msg_value(msg, F_LRM_RTYPE);
	rclass = ha_msg_value(msg, F_LRM_RCLASS);
	provider = ha_msg_value(msg, F_LRM_RPROVIDER);

	lrmd_debug2(LOG_DEBUG
	,	"%s: the client [pid:%d] wants to get rsc metadata of %s::%s::%s."
	,	__FUNCTION__
	,	client->pid
	,	lrm_str(rclass)
	,	lrm_str(provider)
	,	lrm_str(rtype));

	ret = create_lrm_ret(HA_OK, 5);
	CHECK_RETURN_OF_CREATE_LRM_RET;

	RAExec = g_hash_table_lookup(RAExecFuncs,rclass);
	if (NULL == RAExec) {
		lrmd_log(LOG_NOTICE
		, 	"%s: can not find the class %s."
		,	__FUNCTION__
		,	rclass);
	}
	else {
		char* meta = RAExec->get_resource_meta(rtype,provider);
		if (NULL != meta && strlen(meta) > 0) {
			if (HA_OK != ha_msg_add(ret,F_LRM_METADATA, meta)) {
				LOG_FAILED_TO_ADD_FIELD("metadata");
			}
			g_free(meta);
		}
		else {
			lrmd_log(LOG_WARNING
			, 	"%s: empty metadata for %s::%s::%s."
			,	__FUNCTION__
			,	lrm_str(rclass)
			,	lrm_str(provider)
			,	lrm_str(rtype));
			ha_msg_mod_int(ret, F_LRM_RET, HA_FAIL);
		}
	}

	if (HA_OK != msg2ipcchan(ret, client->ch_cmd)) {
		lrmd_log(LOG_ERR,
			"on_msg_get_metadata: can not send the ret msg");
	}
	ha_msg_del(ret);

	return HA_OK;
}
static void
add_rid_to_msg(gpointer key, gpointer value, gpointer user_data)
{
	char* rid = (char*)key;
	struct ha_msg* msg = (struct ha_msg*)user_data;
	if (HA_OK != cl_msg_list_add_string(msg,F_LRM_RID,rid)) {
		LOG_FAILED_TO_ADD_FIELD("resource id");
	}
}
int
on_msg_get_all(lrmd_client_t* client, struct ha_msg* msg)
{
	struct ha_msg* ret = NULL;

	CHECK_ALLOCATED(client, "client", HA_FAIL);
	CHECK_ALLOCATED(msg, "message", HA_FAIL);

	lrmd_debug2(LOG_DEBUG
	,	"on_msg_get_all:client [%d] want to get all rsc information."
	,	client->pid);

	ret = create_lrm_ret(HA_OK, g_hash_table_size(resources) + 1);
	CHECK_RETURN_OF_CREATE_LRM_RET;

	g_hash_table_foreach(resources, add_rid_to_msg, ret);

	if (HA_OK != msg2ipcchan(ret, client->ch_cmd)) {
		lrmd_log(LOG_ERR, "on_msg_get_all: can not send the ret msg");
	}
	ha_msg_del(ret);

	return HA_OK;
}
int
on_msg_get_rsc(lrmd_client_t* client, struct ha_msg* msg)
{
	struct ha_msg* ret = NULL;
	lrmd_rsc_t* rsc = NULL;
	const char* id = NULL;

	CHECK_ALLOCATED(client, "client", HA_FAIL);
	CHECK_ALLOCATED(msg, "message", HA_FAIL);

	id = ha_msg_value(msg, F_LRM_RID);

	lrmd_debug2(LOG_DEBUG
	,	"on_msg_get_rsc: the client [pid:%d] wants to get "
		"the information of the resource [rsc_id: %s]"
	,	client->pid, lrmd_nullcheck(id));

	rsc = lookup_rsc_by_msg(msg);
	if (NULL == rsc) {
		lrmd_debug2(LOG_DEBUG
		,	"on_msg_get_rsc: no rsc with id %s."
		,	lrmd_nullcheck(id));
		ret = create_lrm_ret(HA_FAIL, 1);
		CHECK_RETURN_OF_CREATE_LRM_RET;
	}
	else {
		ret = create_lrm_ret(HA_OK, 5);
		CHECK_RETURN_OF_CREATE_LRM_RET;

		if (HA_OK != ha_msg_add(ret, F_LRM_RID, rsc->id)
		||  HA_OK != ha_msg_add(ret, F_LRM_RTYPE, rsc->type)
		||  HA_OK != ha_msg_add(ret, F_LRM_RCLASS, rsc->class)) {
			ha_msg_del(ret);
			lrmd_log(LOG_ERR,
				"on_msg_get_rsc: failed to add fields to msg.");
			return HA_FAIL;
		}
		if( rsc->provider ) {
			if (HA_OK != ha_msg_add(ret, F_LRM_RPROVIDER,
							rsc->provider)) {
				ha_msg_del(ret);
				LOG_FAILED_TO_ADD_FIELD("provider");
				return HA_FAIL;
			}
		}

		if ( rsc->params && 
		     HA_OK!=ha_msg_add_str_table(ret,F_LRM_PARAM,rsc->params)) {
			ha_msg_del(ret);
			LOG_FAILED_TO_ADD_FIELD("parameter");
			return HA_FAIL;
		}

	}
	if (HA_OK != msg2ipcchan(ret, client->ch_cmd)) {
		lrmd_log(LOG_ERR, "on_msg_get_rsc: can not send the ret msg");
	}
	ha_msg_del(ret);

	return HA_OK;
}

int
on_msg_get_last_op(lrmd_client_t* client, struct ha_msg* msg)
{
	struct ha_msg* ret = NULL;
	const char* op_type = NULL;
	lrmd_rsc_t* rsc = NULL;
	const char* rid = NULL;

	CHECK_ALLOCATED(client, "client", HA_FAIL);
	CHECK_ALLOCATED(msg, "message", HA_FAIL);

	rid = ha_msg_value(msg, F_LRM_RID);
	op_type = ha_msg_value(msg, F_LRM_OP);

	lrmd_debug2(LOG_DEBUG
	,	"on_msg_get_last_op:client %s[%d] want to get the information "
		"regarding last %s op on %s"
	,	client->app_name, client->pid
	, 	lrmd_nullcheck(op_type), lrmd_nullcheck(rid));
	
	rsc = lookup_rsc_by_msg(msg);
	if (NULL != rsc && NULL != op_type) {
		GHashTable* table = g_hash_table_lookup(rsc->last_op_table
					,	client->app_name);
		if (NULL != table ) {
			lrmd_op_t* op = g_hash_table_lookup(table, op_type);
			if (NULL != op) {
				lrmd_debug(LOG_DEBUG
				, 	"%s: will return op %s"
				,	__FUNCTION__
				,	op_type);

				ret = op_to_msg(op);
				if (NULL == ret) {
					lrmd_log(LOG_ERR
				,	"%s: can't create a message with op_to_msg."
				,	__FUNCTION__);
				
				} else 
				if (HA_OK != ha_msg_add_int(ret
					, 	F_LRM_OPCNT, 1)) {
					LOG_FAILED_TO_ADD_FIELD("operation count");
				}
			}
		}
	}

	if (NULL == ret) {
		lrmd_log(LOG_ERR
		, 	"%s: return ha_msg ret is null, will re-create it again."
		,	__FUNCTION__);
		ret = create_lrm_ret(HA_OK, 1);
		CHECK_RETURN_OF_CREATE_LRM_RET;

		if (HA_OK != ha_msg_add_int(ret, F_LRM_OPCNT, 0)) {
			LOG_FAILED_TO_ADD_FIELD("operation count");
		}
	
	}

	if (HA_OK != msg2ipcchan(ret, client->ch_cmd)) {
		lrmd_log(LOG_ERR, "on_msg_get_last_op: can not send the ret msg");
	}
	ha_msg_del(ret);

	return HA_OK;
}

int
on_msg_del_rsc(lrmd_client_t* client, struct ha_msg* msg)
{
	lrmd_rsc_t* rsc = NULL;
	const char* id = NULL;

	CHECK_ALLOCATED(client, "client", HA_FAIL);
	CHECK_ALLOCATED(msg, "message", HA_FAIL);

	id = ha_msg_value(msg, F_LRM_RID);
	lrmd_debug2(LOG_DEBUG
	,	"%s: client [%d] wants to delete rsc %s"
	,	__FUNCTION__, client->pid, lrmd_nullcheck(id));

	rsc = lookup_rsc_by_msg(msg);
	if (NULL == rsc) {
		lrmd_log(LOG_ERR, "%s: no rsc with id %s.",__FUNCTION__,id);
		return -1;
	}
	LRMAUDIT();
	(void)flush_all(&(rsc->repeat_op_list),0);
	if( flush_all(&(rsc->op_list),0) ) {
		set_rsc_removal_pending(rsc);
		lrmd_log(LOG_INFO, "resource %s busy, removal pending", rsc->id);
		LRMAUDIT();
		return HA_RSCBUSY; /* resource is busy, removal delayed */
	}
	lrmd_rsc_destroy(rsc);
	LRMAUDIT();
	return HA_OK;
}

static int
prepare_failmsg(struct ha_msg* msg, int fail_rc, const char *fail_reason)
{
	call_id++; /* use the next id */
	if (HA_OK != ha_msg_mod(msg,F_LRM_OP,ASYNC_OP_NAME)
		|| HA_OK != ha_msg_add(msg,F_LRM_FAIL_REASON,fail_reason)
		|| HA_OK != ha_msg_mod_int(msg,F_LRM_ASYNCMON_RC,fail_rc)
		|| HA_OK != ha_msg_mod_int(msg,F_LRM_RC,fail_rc)
		|| HA_OK != ha_msg_mod_int(msg,F_LRM_OPSTATUS,(int)LRM_OP_DONE)
		|| HA_OK != ha_msg_mod_int(msg,F_LRM_CALLID,call_id)
		|| HA_OK != ha_msg_mod_int(msg,F_LRM_TIMEOUT,0)
		|| HA_OK != ha_msg_mod_int(msg,F_LRM_INTERVAL,0)
		|| HA_OK != ha_msg_mod_int(msg,F_LRM_TARGETRC,EVERYTIME)
		|| HA_OK != ha_msg_mod_int(msg,F_LRM_DELAY,0)
	) {
		lrmd_log(LOG_ERR,"%s:%d: cannot add field to a message"
		,	__FUNCTION__, __LINE__);
		return 1;
	}
	return 0;
}

static void
async_notify(gpointer key, gpointer val, gpointer data)
{
	struct ha_msg* msg = (struct ha_msg*)data;
	lrmd_client_t* client;

	client = lookup_client_by_name((char *)key);
	if (!client) {
		lrmd_log(LOG_INFO,
			"%s: client %s not found, probably signed out", __FUNCTION__, (char *)key);
	} else {
		send_msg(msg, client);
	}
}

int
on_msg_fail_rsc(lrmd_client_t* client, struct ha_msg* msg)
{
	lrmd_rsc_t* rsc;
	const char* id;
	int fail_rc = -1;
	const char *fail_reason;

	CHECK_ALLOCATED(client, "client", HA_FAIL);
	CHECK_ALLOCATED(msg, "message", HA_FAIL);

	id = ha_msg_value(msg, F_LRM_RID);
	lrmd_debug2(LOG_DEBUG
	,	"%s: client [%d] wants to fail rsc %s"
	,	__FUNCTION__, client->pid, lrmd_nullcheck(id));

	rsc = lookup_rsc_by_msg(msg);
	if (!rsc) {
		lrmd_log(LOG_ERR, "%s: no resource with id %s."
		,	__FUNCTION__, lrmd_nullcheck(id));
		return HA_FAIL;
	}
	fail_reason = ha_msg_value(msg,F_LRM_FAIL_REASON);
	if (!fail_reason || *fail_reason == '\0') {
		fail_reason = DEFAULT_FAIL_REASON;
	}
	if (HA_OK != ha_msg_value_int(msg,F_LRM_ASYNCMON_RC,&fail_rc) || fail_rc <= 0) {
		fail_rc = DEFAULT_FAIL_RC;
	}
	if (prepare_failmsg(msg,fail_rc,fail_reason))
		return HA_FAIL;
	lrmd_log(LOG_WARNING
	,	"received asynchronous failure for rsc %s (rc: %d, reason: %s)"
	,	lrmd_nullcheck(id), fail_rc, fail_reason);
	/* notify all clients from last_op table about the failure */
	if (rsc->last_op_table) {
		g_hash_table_foreach(rsc->last_op_table,async_notify,msg);
	} else {
		lrmd_log(LOG_INFO
		,	"rsc to be failed %s had no operations so far",	lrmd_nullcheck(id));
		send_msg(msg, client);
	}
	return HA_OK;
}

static gboolean
free_str_hash_pair(gpointer key, gpointer value, gpointer user_data)
{
	GHashTable* table = (GHashTable*) value;
	free(key);
	g_hash_table_foreach_remove(table, free_str_op_pair, NULL);
	g_hash_table_destroy(table);
	return TRUE;
}

static gboolean
free_str_op_pair(gpointer key, gpointer value, gpointer user_data)
{
	lrmd_op_t* op = (lrmd_op_t*)value;

	if (NULL == op) {
		lrmd_log(LOG_ERR, "%s(): NULL op in op_pair(%s)" , __FUNCTION__
		,	(const char *)key);
	}else{
		lrmd_op_destroy(op);
	}
	return TRUE;
}

int
on_msg_add_rsc(lrmd_client_t* client, struct ha_msg* msg)
{
	GList* node;
	gboolean ra_type_exist = FALSE;
	char* class = NULL;
	lrmd_rsc_t* rsc = NULL;
	const char* id = NULL;

	CHECK_ALLOCATED(client, "client", HA_FAIL);
	CHECK_ALLOCATED(msg, "message", HA_FAIL);

	return_on_no_value(msg, F_LRM_RID,id);

	lrmd_debug(LOG_DEBUG
	,	"on_msg_add_rsc:client [%d] adds resource %s"
	,	client->pid, lrmd_nullcheck(id));
	
	if (RID_LEN <= strlen(id))	{
		lrmd_log(LOG_ERR, "on_msg_add_rsc: rsc_id is too long.");
		return HA_FAIL;
	}

	if (NULL != lookup_rsc(id)) {
		lrmd_log(LOG_ERR, "on_msg_add_rsc: same id resource exists.");
		return HA_FAIL;
	}

	LRMAUDIT();
	rsc = lrmd_rsc_new(id, msg);
	if (rsc == NULL) {
		return HA_FAIL;
	}
	
	ra_type_exist = FALSE;
	for(node=g_list_first(ra_class_list); NULL!=node; node=g_list_next(node)){
		class = (char*)node->data;
		if (0 == strncmp(class, rsc->class, MAX_CLASSNAMELEN)) {
			ra_type_exist = TRUE;
			break;
		}
	}
	if (!ra_type_exist) {
		lrmd_log(LOG_ERR
		,	"on_msg_add_rsc: RA class [%s] does not exist."
		,	rsc->class);
		lrmd_rsc_destroy(rsc);
		rsc = NULL;
		LRMAUDIT();
		return HA_FAIL;
	}
	
	rsc->last_op_done = NULL;
	rsc->params = ha_msg_value_str_table(msg,F_LRM_PARAM);
	rsc->last_op_table = g_hash_table_new(g_str_hash, g_str_equal);
	g_hash_table_insert(resources, strdup(rsc->id), rsc);
 
	LRMAUDIT();
	return HA_OK;
}

static int
cancel_op(GList** listp,int cancel_op_id)
{
	GList* node = NULL;
	lrmd_op_t* op = NULL;
	int rc = HA_FAIL;

	for( node = g_list_first(*listp)
	; node; node = g_list_next(node) ) {
		op = (lrmd_op_t*)node->data;
		if( op->call_id == cancel_op_id ) {
			lrmd_log(LOG_INFO
			,"%s: %s cancelled"
			, __FUNCTION__, op_info(op));
			rc = flush_op(op);
			if( rc != HA_RSCBUSY && rc != HA_FAIL ) {
				notify_client(op); /* send notification now */
				*listp = g_list_remove(*listp, op);
				remove_op_history(op);
				lrmd_op_destroy(op);
			}
			return rc;
		}
	}
	return rc;
}

int
on_msg_cancel_op(lrmd_client_t* client, struct ha_msg* msg)
{
	lrmd_rsc_t* rsc = NULL;
	int cancel_op_id = 0;
	int op_cancelled = HA_OK;

	LRMAUDIT();
	CHECK_ALLOCATED(client, "client", HA_FAIL);
	CHECK_ALLOCATED(msg, "message", HA_FAIL);

	rsc = lookup_rsc_by_msg(msg);
	if (NULL == rsc) {
		lrmd_log(LOG_ERR,
			"%s: no resource with such id.", __FUNCTION__);
		return HA_FAIL;
	}

	return_on_no_int_value(msg, F_LRM_CALLID, &cancel_op_id);

	lrmd_debug2(LOG_DEBUG
	,	"%s:client [pid:%d] cancel the operation [callid:%d]"
	,	__FUNCTION__
	,	client->pid
	, 	cancel_op_id);

	if( cancel_op(&(rsc->repeat_op_list), cancel_op_id) != HA_OK ) {
		op_cancelled = cancel_op(&(rsc->op_list), cancel_op_id);
	}
	if( op_cancelled == HA_FAIL ) {
		lrmd_log(LOG_INFO, "%s: no operation with id %d",
			__FUNCTION__, cancel_op_id);
	} else if( op_cancelled == HA_RSCBUSY ) {
		lrmd_log(LOG_INFO, "%s: operation %d running, cancel pending",
			__FUNCTION__, cancel_op_id);
	} else {
		lrmd_debug(LOG_DEBUG, "%s: operation %d cancelled",
			__FUNCTION__, cancel_op_id);
	}
	LRMAUDIT();
	return op_cancelled;
}

static gboolean
flush_all(GList** listp, int client_pid)
{
	GList* node = NULL;
	lrmd_op_t* op = NULL;
	gboolean rsc_busy = FALSE;

	node = g_list_first(*listp);
	while( node ) {
		op = (lrmd_op_t*)node->data;
		if (client_pid && op->client_id != client_pid) {
			node = g_list_next(node);
			continue; /* not the client's operation */
		}
		if( flush_op(op) == HA_RSCBUSY ) {
			rsc_busy = TRUE;
			node = g_list_next(node);
		} else if (!client_pid || op->client_id == client_pid) {
			node = *listp = g_list_remove(*listp, op);
			remove_op_history(op);
			lrmd_op_destroy(op);
		} else {
			node = g_list_next(node);
		}
	}
	return rsc_busy;
}

int
on_msg_flush_all(lrmd_client_t* client, struct ha_msg* msg)
{
	lrmd_rsc_t* rsc = NULL;
	const char* id = NULL;

	LRMAUDIT();
	CHECK_ALLOCATED(client, "client", HA_FAIL);
	CHECK_ALLOCATED(msg, "message", HA_FAIL);

	return_on_no_value(msg, F_LRM_RID,id);
	rsc = lookup_rsc_by_msg(msg);
	if (NULL == rsc) {
		lrmd_log(LOG_ERR,
			"%s: no resource with id %s.", __FUNCTION__,id);
		LRMAUDIT();
		return -1;
	}

	/* when a flush request arrived, flush all pending ops */
	lrmd_debug2(LOG_DEBUG
		,	"%s:client [%d] flush operations"
		,	__FUNCTION__, client->pid);
	(void)flush_all(&(rsc->repeat_op_list),0);
	if( flush_all(&(rsc->op_list),0) ) {
		set_rsc_flushing_ops(rsc); /* resource busy */
		lrmd_log(LOG_INFO, "resource %s busy, all flush pending", rsc->id);
		LRMAUDIT();
		return HA_RSCBUSY;
	}
	LRMAUDIT();
	return HA_OK;
}

int
on_msg_perform_op(lrmd_client_t* client, struct ha_msg* msg)
{
	lrmd_rsc_t* rsc = NULL;
	lrmd_op_t* op;
	const char* id = NULL;
	int timeout = 0;
	int interval = 0;
	int delay = 0;

	LRMAUDIT();
	CHECK_ALLOCATED(client, "client", HA_FAIL);
	CHECK_ALLOCATED(msg, "message", HA_FAIL);

	return_on_no_value(msg, F_LRM_RID,id);
	return_on_no_int_value(msg, F_LRM_INTERVAL, &interval);
	return_on_no_int_value(msg, F_LRM_TIMEOUT, &timeout);
	return_on_no_int_value(msg, F_LRM_DELAY, &delay);

	rsc = lookup_rsc_by_msg(msg);
	if (NULL == rsc) {
		lrmd_log(LOG_ERR,
			"%s: no resource with such id.", __FUNCTION__);
		return -1;
	}
	if( rsc_frozen(rsc) ) {
		lrmd_log(LOG_NOTICE, "%s: resource %s is frozen, "
		"no ops can run.", __FUNCTION__, rsc->id);
		return -1;
	}

	call_id++;
	if( !(rsc->id) ) {
		lrmd_debug(LOG_ERR
			, "%s:%d: the resource id is NULL"
			, __FUNCTION__, __LINE__);
		return -1;
	}
	if (HA_OK != ha_msg_add_int(msg, F_LRM_CALLID, call_id)) {
		LOG_FAILED_TO_ADD_FIELD("callid");
		return -1;
	}
	if (HA_OK !=ha_msg_mod(msg, F_LRM_APP, client->app_name)) {
		LOG_FAILED_TO_ADD_FIELD("app_name");
		return -1;
	}

	op = lrmd_op_new();
	if (op == NULL) {
		return -1;
	}
	op->call_id = call_id;
	op->client_id = client->pid;
	op->rsc_id = strdup(rsc->id);
	op->interval = interval;
	op->delay = delay;
	op->weight = no_child_count(rsc) ? 0 : 1;

	op->msg = ha_msg_copy(msg);

	if( ha_msg_value_int(msg,F_LRM_COPYPARAMS,&op->copyparams) == HA_OK
			&& op->copyparams ) {
		lrmd_debug(LOG_DEBUG
			, "%s:%d: copying parameters for rsc %s"
			, __FUNCTION__, __LINE__,rsc->id);
		if (rsc->params) {
			free_str_table(rsc->params);
		}
		rsc->params = ha_msg_value_str_table(msg, F_LRM_PARAM);
	}
	
	lrmd_debug2(LOG_DEBUG
	, "%s: client [%d] want to add an operation %s on resource %s."
	,	__FUNCTION__
	,	client->pid
	,	op_info(op)
	,	NULL!=op->rsc_id ? op->rsc_id : "#EMPTY#");

	if ( 0 < op->delay ) {
		op->repeat_timeout_tag = Gmain_timeout_add(op->delay
						,on_repeat_op_readytorun, op);
		rsc->repeat_op_list = 
			g_list_append (rsc->repeat_op_list, op);
		lrmd_debug(LOG_DEBUG
		, "%s: an operation %s is added to the repeat "
		  "operation list for delay execution" 
		, __FUNCTION__
		, op_info(op));
	} else {
		lrmd_debug(LOG_DEBUG
		, "%s: add an operation %s to the operation list."
		, __FUNCTION__
		, op_info(op));
		add_op_to_runlist(rsc,op);
	}

	perform_op(rsc);

	LRMAUDIT();
	return call_id;
}

static void 
send_last_op(gpointer key, gpointer value, gpointer user_data)
{
	IPC_Channel* ch = NULL;
	lrmd_op_t* op = NULL;
	struct ha_msg* msg = NULL;
	
	ch = (IPC_Channel*)user_data;
	op = (lrmd_op_t*)value; 
	msg = op_to_msg(op);
	if (msg == NULL) {
		lrmd_log(LOG_ERR, "send_last_op: failed to convert an operation "
			"information to a ha_msg.");
		return;
	}
	if (HA_OK != msg2ipcchan(msg, ch)) {
		lrmd_log(LOG_ERR, "send_last_op: can not send a message.");
	}
	ha_msg_del(msg);
}

int
on_msg_get_state(lrmd_client_t* client, struct ha_msg* msg)
{
	int op_count = 0;
	lrmd_rsc_t* rsc = NULL;
	GList* node;
	struct ha_msg* ret = NULL;
	lrmd_op_t* op = NULL;
	struct ha_msg* op_msg = NULL;
	const char* id = NULL;
	GHashTable* last_ops = NULL;
	
	CHECK_ALLOCATED(client, "client", HA_FAIL);
	CHECK_ALLOCATED(msg, "message", HA_FAIL);

	id = ha_msg_value(msg,F_LRM_RID);
	lrmd_debug2(LOG_DEBUG
	,	"%s: client [%d] want to get the state of resource %s"
	,	__FUNCTION__, client->pid, lrmd_nullcheck(id));

	rsc = lookup_rsc_by_msg(msg);
	if (NULL == rsc) {
		lrmd_log(LOG_ERR, "on_msg_get_state: no resource with id %s."
		,	lrmd_nullcheck(id));
		send_ret_msg(client->ch_cmd, HA_FAIL);
		return HA_FAIL;
	}
	
	ret = ha_msg_new(5);
	if (NULL == ret) {
		lrmd_log(LOG_ERR, "on_msg_get_state: can't create a ha_msg.");
		return HA_FAIL;
	}
	/* add the F_LRM_STATE field */
	if (HA_OK != ha_msg_add_int(ret, F_LRM_STATE
			, rsc->op_list ? LRM_RSC_BUSY : LRM_RSC_IDLE)) {
		LOG_FAILED_TO_ADD_FIELD("state");
		ha_msg_del(ret);
		return HA_FAIL;
	}
	lrmd_debug(LOG_DEBUG
	,	"on_msg_get_state:state of rsc %s is %s"
	,	lrmd_nullcheck(id)
	,	rsc->op_list ? "LRM_RSC_BUSY" : "LRM_RSC_IDLE" );
	/* calculate the count of ops being returned */
	last_ops = g_hash_table_lookup(rsc->last_op_table, client->app_name);
	if (last_ops == NULL) {
		op_count = g_list_length(rsc->op_list) 
			+  g_list_length(rsc->repeat_op_list);
	}
	else {
		op_count = g_hash_table_size(last_ops)
			+  g_list_length(rsc->op_list) 
			+  g_list_length(rsc->repeat_op_list);
	}					 
	/* add the count of ops being returned */	
	if (HA_OK != ha_msg_add_int(ret, F_LRM_OPCNT, op_count)) {
		LOG_FAILED_TO_ADD_FIELD("operation count");
		ha_msg_del(ret);
		return HA_FAIL;
	}
	/* send the first message to client */	
	if (HA_OK != msg2ipcchan(ret, client->ch_cmd)) {
		lrmd_log(LOG_ERR,
			"on_msg_get_state: can not send the ret message.");
		ha_msg_del(ret);
		return HA_FAIL;
	}
	ha_msg_del(ret);

	/* send the ops in last ops table */
	if(last_ops != NULL) {
		g_hash_table_foreach(last_ops, send_last_op, client->ch_cmd);
	}

	/* send the ops in op list */
	for(node = g_list_first(rsc->op_list)
	;	NULL != node; node = g_list_next(node)){
		op = (lrmd_op_t*)node->data;
		op_msg = op_to_msg(op);
		if (NULL == op_msg) {
			lrmd_log(LOG_ERR,
				"on_msg_get_state: failed to make a message "
				"from a operation: %s", op_info(op));
			continue;
		}
		if (HA_OK != msg2ipcchan(op_msg, client->ch_cmd)) {
			lrmd_log(LOG_ERR,
				"on_msg_get_state: failed to send a message.");
		}
		ha_msg_del(op_msg);
	}
	
	/* send the ops in repeat op list */
	for(node = g_list_first(rsc->repeat_op_list)
	;	NULL != node; node = g_list_next(node)){
		op = (lrmd_op_t*)node->data;
		op_msg = op_to_msg(op);
		if (NULL == op_msg) {
			lrmd_log(LOG_ERR,
				"on_msg_get_state: failed to make a message "
				"from a operation: %s", op_info(op));
			continue;
		}
		if (HA_OK != msg2ipcchan(op_msg, client->ch_cmd)) {
			lrmd_log(LOG_ERR,
				"on_msg_get_state: failed to send a message.");
		}
		ha_msg_del(op_msg);
	}
	return HA_OK;
}

#define safe_len(s) (s ? strlen(s) : 0)

static char *
lrm_concat(const char *prefix, const char *suffix, char join) 
{
	int len = 2;
	char *new_str = NULL;
	len += safe_len(prefix);
	len += safe_len(suffix);

	new_str = malloc(sizeof(char)*len);
	if (NULL == new_str) {
		lrmd_log(LOG_ERR,"%s:%d: malloc failed"
			 , __FUNCTION__, __LINE__);
		return NULL;
	}

	memset(new_str, 0, len);
	sprintf(new_str, "%s%c%s", prefix?prefix:"", join, suffix?suffix:"");
	new_str[len-1] = 0;
	return new_str;
}

/* /////////////////////op functions////////////////////// */

#define mk_op_id(op,id) do { \
	const char *op_type = ha_msg_value(op->msg, F_LRM_OP); \
	const char *op_interval = ha_msg_value(op->msg, F_LRM_INTERVAL); \
	id = lrm_concat(op_type, op_interval, '_'); \
} while(0)

/* find the last operation for the client
 * replace it with the new one (if requested)
 */
static void
replace_last_op(lrmd_client_t* client, lrmd_rsc_t* rsc, lrmd_op_t* op)
{
	char *op_hash_key;
	GHashTable *client_last_op;
	lrmd_op_t *old_op, *new_op;

	if (!client || !rsc || !op)
		return;
	client_last_op = g_hash_table_lookup(rsc->last_op_table, client->app_name);
	if (!client_last_op) {
		lrmd_debug2(LOG_DEBUG
		, "%s: new last op table for client %s"
		, __FUNCTION__, client->app_name);
		client_last_op = g_hash_table_new_full(	g_str_hash
		, 	g_str_equal, free, NULL);
		g_hash_table_insert(rsc->last_op_table
		,	(gpointer)strdup(client->app_name)
		,	(gpointer)client_last_op);
	}
	mk_op_id(op,op_hash_key);
	old_op = (lrmd_op_t*)g_hash_table_lookup(client_last_op, op_hash_key);

	/* make a copy of op and insert it into client_last_op */
	if (!(new_op = lrmd_op_copy(op))) {
		lrmd_log(LOG_ERR, "%s:%d out of memory" 
			, __FUNCTION__, __LINE__);
	}
	if (old_op) {
		lrmd_debug2(LOG_DEBUG
		, "%s: replace last op %s for client %s"
		, __FUNCTION__, op_hash_key, client->app_name);
		g_hash_table_replace(client_last_op,op_hash_key,(gpointer)new_op);
		lrmd_op_destroy(old_op);
	} else {
		lrmd_debug2(LOG_DEBUG
		, "%s: add last op %s for client %s"
		, __FUNCTION__, op_hash_key, client->app_name);
		g_hash_table_insert(client_last_op,op_hash_key,(gpointer)new_op);
	}
}

static int
record_op_completion(lrmd_rsc_t* rsc, lrmd_op_t* op)
{
	lrmd_client_t* client;

	LRMAUDIT();
	/*save the op in the last op finished*/
	if (rsc->last_op_done != NULL) {
		lrmd_op_destroy(rsc->last_op_done);
	}
	if (!(rsc->last_op_done = lrmd_op_copy(op))) {
		lrmd_log(LOG_ERR, "%s:%d out of memory" 
			, __FUNCTION__, __LINE__);
		return 1;
	}
	rsc->last_op_done->repeat_timeout_tag = (guint)0;

	client = lookup_client(op->client_id);
	if (!client) {
		lrmd_log(LOG_INFO, "%s: cannot record %s: the client is gone"
		,	__FUNCTION__, small_op_info(op)); 
		LRMAUDIT();
		return 1;
	}
	/* insert (or replace) the new op in last_op_table for the client */
	replace_last_op(client,rsc,op);
	LRMAUDIT();
	return 0;
}

static void
to_repeatlist(lrmd_rsc_t* rsc, lrmd_op_t* op)
{
	lrmd_op_t *repeat_op;

	if (!(repeat_op = lrmd_op_copy(op))) {
		lrmd_log(LOG_ERR, "%s:%d out of memory" 
			, __FUNCTION__, __LINE__);
	}
	reset_timestamps(repeat_op);
	repeat_op->is_copy = FALSE;
	repeat_op->repeat_timeout_tag = 
		Gmain_timeout_add(op->interval,	
				on_repeat_op_readytorun, repeat_op);
	rsc->repeat_op_list = 
		g_list_append (rsc->repeat_op_list, repeat_op);
	lrmd_debug2(LOG_DEBUG
	, "%s: repeat %s is added to repeat op list to wait" 
	, __FUNCTION__, op_info(op));
}

static void 
remove_op_history(lrmd_op_t* op)
{
	lrmd_client_t* client = lookup_client(op->client_id);
	lrmd_rsc_t* rsc = NULL;
	char *op_id, *last_op_id;
	lrmd_op_t* old_op = NULL;
	GHashTable* client_last_op = NULL;

	LRMAUDIT();
	if( !(rsc = lookup_rsc(op->rsc_id)) ) {
		return;
	}
	lrmd_debug2(LOG_DEBUG, "%s: remove history of the op %s"
		  ,__FUNCTION__, op_info(op));
	mk_op_id(op,op_id);
	if (rsc->last_op_done != NULL ) {
		mk_op_id(rsc->last_op_done,last_op_id);
		if( !strcmp(op_id,last_op_id) ) {
			lrmd_debug2(LOG_DEBUG, "%s: remove history of the last op done %s"
				  ,__FUNCTION__, op_info(rsc->last_op_done));
			lrmd_op_destroy(rsc->last_op_done);
			rsc->last_op_done = NULL;
		}
		free(last_op_id);
	}
	if( client &&
		(client_last_op = g_hash_table_lookup(rsc->last_op_table
			, 			client->app_name)) ) {
		lrmd_debug2(LOG_DEBUG, "%s: found client %s in the last op table"
			  ,__FUNCTION__, client->app_name);
		old_op = g_hash_table_lookup(client_last_op, op_id);
		if (old_op) {
			g_hash_table_remove(client_last_op,	op_id);
			lrmd_debug2(LOG_DEBUG, "%s: remove history of the client's last %s"
				  ,__FUNCTION__, op_info(old_op));
			lrmd_op_destroy(old_op);
		}
	}
	free(op_id);
	LRMAUDIT();
}

static void
add_op_to_runlist(lrmd_rsc_t* rsc, lrmd_op_t* op)
{
	op->t_addtolist = time_longclock();
	rsc->op_list = g_list_append(rsc->op_list, op);
	if (g_list_length(rsc->op_list) >= 4) {
		lrmd_log(LOG_WARNING
		,	"operations list for %s is suspiciously"
		" long [%d]"
		,	rsc->id
		,	g_list_length(rsc->op_list));
		lrmd_rsc_dump(rsc->id, "rsc->op_list: too many ops");
	}
}

/* 1. this function sends a message to the client:
 *   a) on operation instance exit using the callback channel
 *   b) in case a client requested that operation to be cancelled,
 *      using the command channel
 *   c) in case a client requested a resource removal or flushing
 *      all ops and this is the last operation that finished, again
 *      using the command channel
 * 2. if the op was not cancelled:
 *   a) it is copied to the last_op_done field of rsc
 *   b) if it's a repeating op, it is put in the repeat_op_list
 *   c) the outcome is recorded for future reference
 * 3. op is destroyed and removed from the op_list
 */
int
on_op_done(lrmd_rsc_t* rsc, lrmd_op_t* op)
{
	int rc = HA_OK;
	int target_rc, last_rc, op_rc;
	int rc_changed;
	op_status_t op_status;

	LRMAUDIT();
	CHECK_ALLOCATED(op, "op", HA_FAIL );
	if (op->exec_pid == 0) {
		lrmd_log(LOG_ERR, "%s: op->exec_pid == 0",__FUNCTION__);
		return HA_FAIL;
	}
	op->t_done = time_longclock();

	if (debug_level >= 2) {
		lrmd_debug(LOG_DEBUG, "%s: %s",__FUNCTION__, op_info(op));
		lrmd_op_dump(op, __FUNCTION__);
	}

	return_on_no_int_value(op->msg,F_LRM_TARGETRC,&target_rc);
	return_on_no_int_value(op->msg,F_LRM_OPSTATUS,(int *)&op_status);

	last_rc = op_rc = -1; /* set all rc to -1 */
	ha_msg_value_int(op->msg,F_LRM_RC,&op_rc);
	ha_msg_value_int(op->msg,F_LRM_LASTRC,&last_rc);
	rc_changed = (
		op_status == LRM_OP_DONE
		&& op_rc != -1
		&& ((last_rc == -1) || (last_rc != op_rc))
	);
	if (rc_changed) {
		if (HA_OK != ha_msg_mod_int(op->msg, F_LRM_LASTRC, op_rc)) {
			lrmd_log(LOG_ERR,"%s: cannot save status to msg",__FUNCTION__);
			return HA_FAIL;
		}
		op->t_rcchange = op->t_perform;
	}
	if (store_timestamps(op))
		return HA_FAIL;

	/* remove the op from op_list */
	rsc->op_list = g_list_remove(rsc->op_list,op);
	lrmd_debug2(LOG_DEBUG
	, 	"%s:%s is removed from op list"
	,	__FUNCTION__, op_info(op));

	if (!op->is_cancelled) {
		if( !record_op_completion(rsc,op) ) { /*record the outcome of the op */
			if (op->interval) /* copy op to the repeat list */
				to_repeatlist(rsc,op);
		}
	} else {
		if (HA_OK != ha_msg_mod_int(op->msg,F_LRM_OPSTATUS,(int)LRM_OP_CANCELLED)) {
			LOG_FAILED_TO_ADD_FIELD(F_LRM_OPSTATUS);
			return HA_FAIL;
		}
		op_status = LRM_OP_CANCELLED;
		remove_op_history(op);
	}

	if (rsc_removal_pending(rsc)) {
		if (HA_OK != ha_msg_add_int(op->msg,F_LRM_RSCDELETED,1)) {
			LOG_FAILED_TO_ADD_FIELD(F_LRM_RSCDELETED);
		}
	}
	if (op_status != LRM_OP_DONE
		|| (op_rc == -1)
		|| (op_rc == target_rc)
		|| (target_rc == EVERYTIME)
		|| ((target_rc == CHANGED) && rc_changed)
		|| rsc_removal_pending(rsc)
	) {
		notify_client(op);
	}
	lrmd_op_destroy(op);
	if( !rsc->op_list ) {
		if( rsc_removal_pending(rsc) ) {
			lrmd_log(LOG_INFO, "late removal of resource %s", rsc->id);
			lrmd_rsc_destroy(rsc);
			rc = -1; /* let the caller know that the rsc is gone */
		} else {
			rsc_reset_state(rsc);
		}
	}
	LRMAUDIT();
	if (shutdown_in_progress && can_shutdown()) {
		lrm_shutdown();
	}
	return rc;
}

/*
 * an operation is flushed only in case there is
 * no process running initiated by this operation
 * NB: the caller has to destroy the operation itself
 */
int
flush_op(lrmd_op_t* op)
{
	CHECK_ALLOCATED(op, "op", HA_FAIL );
	if (op->exec_pid == 0) {
		lrmd_debug(LOG_ERR, "%s: op->exec_pid == 0",__FUNCTION__);
		return HA_FAIL;
	}

	if (HA_OK != ha_msg_mod_int(op->msg, F_LRM_RC, HA_FAIL)) {
		LOG_FAILED_TO_ADD_FIELD("F_LRM_RC");
		return HA_FAIL;
	}

	if( op->exec_pid == -1 ) {
		if (HA_OK != ha_msg_mod_int(op->msg,F_LRM_OPSTATUS,(int)LRM_OP_CANCELLED)){
			LOG_FAILED_TO_ADD_FIELD("opstatus");
			return HA_FAIL;
		}
		return HA_OK;
	} else {
		op->is_cancelled = TRUE; /* mark the op as cancelled */
		lrmd_log(LOG_INFO, "%s: process for %s still "
			"running, flush delayed"
			,__FUNCTION__,small_op_info(op));
		return HA_RSCBUSY;
	}
}

/* Resume the execution of ops of the resource */
static gboolean
rsc_execution_freeze_timeout(gpointer data)
{
	lrmd_rsc_t* rsc = (lrmd_rsc_t*)data;

	if (rsc == NULL) {
		return FALSE;
	}

	if (rsc->delay_timeout > 0) {
		rsc->delay_timeout = (guint)0;
	}

	perform_op(rsc);

	return FALSE;
}

/* this function gets the first op in the rsc op list and execute it*/
int
perform_op(lrmd_rsc_t* rsc)
{
	GList* node = NULL;
	lrmd_op_t* op = NULL;

	LRMAUDIT();
	CHECK_ALLOCATED(rsc, "resource", HA_FAIL);
	if (shutdown_in_progress && can_shutdown()) {
		lrm_shutdown();
	}

	if (rsc_frozen(rsc)) {
		lrmd_log(LOG_INFO,"%s: resource %s is frozen, "
		"no ops allowed to run"
		, __FUNCTION__, rsc->id);
		return HA_OK;
	}

	if (NULL == rsc->op_list) {
		lrmd_debug2(LOG_DEBUG,"%s: no op to perform?", __FUNCTION__);
		return HA_OK;
	}

	node = g_list_first(rsc->op_list);
	while (NULL != node) {
		op = node->data;
		if (-1 != op->exec_pid)	{
			if (!g_list_next(node)) {
				/* this is the only operation, no need to do
				 * anything further */
				break;
			}
			lrmd_log(LOG_INFO, "%s:%d: %s for rsc is already running."
			, __FUNCTION__, __LINE__, op_info(op));
			if( rsc->delay_timeout > 0 ) {
				lrmd_log(LOG_INFO
				,	"%s:%d: operations on resource %s already delayed"
				, __FUNCTION__, __LINE__, lrm_str(rsc->id));
			} else {
				lrmd_log(LOG_INFO
				, 	"%s:%d: postponing "
					"all ops on resource %s by %d ms"
				, __FUNCTION__, __LINE__
				, 	lrm_str(rsc->id), retry_interval);
				rsc->delay_timeout = Gmain_timeout_add(retry_interval
					, rsc_execution_freeze_timeout, rsc);
			}
			break;
		}
		if (op->weight && child_count >= max_child_count) {
			if ((int)rsc->delay_timeout > 0) {
				lrmd_log(LOG_INFO
				,	"%s:%d: max_child_count (%d) reached and operations on resource %s already delayed"
				, __FUNCTION__, __LINE__, max_child_count, lrm_str(rsc->id));
			} else {
				lrmd_debug(LOG_NOTICE
				, 	"max_child_count (%d) reached, postponing "
					"execution of %s by %d ms"
				, 	max_child_count, op_info(op), retry_interval);
				rsc->delay_timeout = Gmain_timeout_add(retry_interval
						, rsc_execution_freeze_timeout, rsc);
			}
			break;
		}

		if (HA_OK != perform_ra_op(op)) {
			lrmd_log(LOG_ERR
			,	"unable to perform_ra_op on %s"
			,	op_info(op));
			if (HA_OK != ha_msg_add_int(op->msg, F_LRM_OPSTATUS,
						LRM_OP_ERROR)) {
				LOG_FAILED_TO_ADD_FIELD("opstatus");
			}
			on_op_done(rsc,op);
			node = g_list_first(rsc->op_list);
		}
		else {
			break;
		}
	}

	LRMAUDIT();
	return HA_OK;
}

static int
store_timestamps(lrmd_op_t* op)
{
	struct ha_msg* msg = op->msg;
	longclock_t	now = time_longclock(), /* tm2unix() needs this */
		exec_time = zero_longclock,
		queue_time = zero_longclock;

	if (op->t_perform) {
		queue_time =
			longclockto_ms(sub_longclock(op->t_perform,op->t_addtolist));
		if (op->t_done) {
			exec_time =
				longclockto_ms(sub_longclock(op->t_done,op->t_perform));
		}
	}
	if ((HA_OK!=ha_msg_mod_ul(msg,F_LRM_T_RUN,tm2unix(op->t_perform)))
		|| (HA_OK!=ha_msg_mod_ul(msg,F_LRM_T_RCCHANGE,tm2unix(op->t_rcchange)))
		|| (HA_OK!=ha_msg_mod_ul(msg,F_LRM_EXEC_TIME,exec_time))
		|| (HA_OK!=ha_msg_mod_ul(msg,F_LRM_QUEUE_TIME,queue_time))
	) {
		lrmd_log(LOG_ERR,"%s: can not save timestamps to msg",__FUNCTION__);
		return 1;
	}
	return 0;
}

static void
reset_timestamps(lrmd_op_t* op)
{
	op->t_perform = zero_longclock;
	op->t_done = zero_longclock;
	cl_msg_remove(op->msg, F_LRM_T_RUN);
	cl_msg_remove(op->msg, F_LRM_T_RCCHANGE);
	cl_msg_remove(op->msg, F_LRM_EXEC_TIME);
	cl_msg_remove(op->msg, F_LRM_QUEUE_TIME);
}

struct ha_msg*
op_to_msg(lrmd_op_t* op)
{
	struct ha_msg* msg = NULL;

	CHECK_ALLOCATED(op, "op", NULL);
	if (op->exec_pid == 0) {
		lrmd_log(LOG_ERR, "%s: op->exec_pid is 0",__FUNCTION__);
		return NULL;
	}
	msg = ha_msg_copy(op->msg);
	if (NULL == msg) {
		lrmd_log(LOG_ERR,"%s: can not copy the msg",__FUNCTION__);
		return NULL;
	}
	if ((HA_OK!=ha_msg_mod_int(msg,F_LRM_CALLID,op->call_id))) {
		lrmd_log(LOG_ERR,"%s: can not save F_LRM_CALLID to msg",__FUNCTION__);
		ha_msg_del(msg);
		msg = NULL;
	}
	return msg;
}

/* //////////////////////////////RA wrap funcs/////////////////////////////////// */
int
perform_ra_op(lrmd_op_t* op)
{
	int stdout_fd[2];
	int stderr_fd[2];
	pid_t pid;
	int timeout;
	struct RAExecOps * RAExec = NULL;
	const char* op_type = NULL;
        GHashTable* params = NULL;
        GHashTable* op_params = NULL;
	lrmd_rsc_t* rsc = NULL;
	ra_pipe_op_t * rapop;

	LRMAUDIT();
	CHECK_ALLOCATED(op, "op", HA_FAIL);
	rsc = (lrmd_rsc_t*)lookup_rsc(op->rsc_id);
	CHECK_ALLOCATED(rsc, "rsc", HA_FAIL);
	
	if ( pipe(stdout_fd) < 0 ) {
		cl_perror("%s::%d: pipe", __FUNCTION__, __LINE__);
	}

	if ( pipe(stderr_fd) < 0 ) {
		cl_perror("%s::%d: pipe", __FUNCTION__, __LINE__);
	}

	if (op->exec_pid == 0) {
		lrmd_log(LOG_ERR, "%s::%d: op->exec_pid == 0.", __FUNCTION__, __LINE__);
		return HA_FAIL;
	}

	op_type = ha_msg_value(op->msg, F_LRM_OP);
	op->t_perform = time_longclock();
	check_queue_duration(op);

	if(HA_OK != ha_msg_value_int(op->msg, F_LRM_TIMEOUT, &timeout)){
		timeout = 0;
		lrmd_log(LOG_ERR,"%s::%d: failed to get timeout for %s"
		, __FUNCTION__, __LINE__, small_op_info(op));
	}
	
	if( return_to_orig_privs() ) {
		cl_perror("%s::%d: failed to raise privileges"
		, __FUNCTION__, __LINE__);
	}
	switch(pid=fork()) {
		case -1:
			cl_perror("%s::%d: fork", __FUNCTION__, __LINE__);
			close(stdout_fd[0]);
			close(stdout_fd[1]);
			close(stderr_fd[0]);
			close(stderr_fd[1]);
			if( return_to_dropped_privs() ) {
				cl_perror("%s::%d: failed to drop privileges"
				, __FUNCTION__, __LINE__);
			}
			return HA_FAIL;

		default:	/* Parent */
			child_count += op->weight;
			NewTrackedProc(pid, 1
			,	debug_level ?
				((op->interval && !is_logmsg_due(op)) ? PT_LOGNORMAL : PT_LOGVERBOSE) : PT_LOGNONE
			,	op, &ManagedChildTrackOps);

			if (!op->interval || is_logmsg_due(op)) { /* log non-repeating ops */
				lrmd_log(LOG_INFO,"rsc:%s %s[%d] (pid %d)",
					rsc->id,probe_str(op,op_type),op->call_id,pid);
			} else {
				lrmd_debug(LOG_DEBUG,"rsc:%s %s[%d] (pid %d)",
					rsc->id,op_type,op->call_id,pid);
			}
			close(stdout_fd[1]);
			close(stderr_fd[1]);
			rapop = ra_pipe_op_new(stdout_fd[0], stderr_fd[0], op);
			op->rapop = rapop;
			op->exec_pid = pid;
			if (0 < timeout ) {

				/* Wait 'timeout' ms then send SIGTERM */
				/* allow for extra 15 seconds for stonith,
				 * because stonithd handles its children with the
				 * same timeout; in this case the lrmd child
				 * should never timeout, but return the timeout
				 * reported by stonithd
				 */
				op->killseq[0].mstimeout = timeout
					+ (!strcmp(rsc->class,"stonith") ? 15000 : 0);
				op->killseq[0].signalno  = SIGTERM;

				/* Wait 5 seconds then send SIGKILL */
				op->killseq[1].mstimeout = 5000;
				op->killseq[1].signalno  = SIGKILL;

				/* Wait 5 more seconds then moan and complain */
				op->killseq[2].mstimeout = 5000;
				op->killseq[2].signalno  = 0;

				SetTrackedProcTimeouts(pid, op->killseq);
			}
			if( return_to_dropped_privs() ) {
				lrmd_log(LOG_WARNING,"%s::%d: failed to drop privileges: %s"
				, __FUNCTION__, __LINE__, strerror(errno));
			}

			if ( rapop == NULL) {
				return HA_FAIL;
			}
			LRMAUDIT();
			return HA_OK;

		case 0:		/* Child */
#ifdef DEFAULT_REALTIME_POLICY
			if (sched_getscheduler(0) != SCHED_OTHER) {
				struct sched_param sp;
				lrmd_debug(LOG_DEBUG,
					"perform_ra_op: resetting scheduler class to SCHED_OTHER");
				sp.sched_priority = 0;
				if (sched_setscheduler(0, SCHED_OTHER, &sp) == -1)
					cl_perror("%s::%d: sched_setscheduler",
						__FUNCTION__, __LINE__);
			}
#endif
			/* Man: The call setpgrp() is equivalent to setpgid(0,0)
			 * _and_ compiles on BSD variants too
			 * need to investigate if it works the same too.
			 */
			setpgid(0,0);
			close(stdout_fd[0]);
			close(stderr_fd[0]);
			if (STDOUT_FILENO != stdout_fd[1]) {
				if (dup2(stdout_fd[1], STDOUT_FILENO)!=STDOUT_FILENO) {
					cl_perror("%s::%d: dup2"
						, __FUNCTION__, __LINE__);
				}
				close(stdout_fd[1]);
			}
			if (STDERR_FILENO != stderr_fd[1]) {
				if (dup2(stderr_fd[1], STDERR_FILENO)!=STDERR_FILENO) {
					cl_perror("%s::%d: dup2", __FUNCTION__, __LINE__);
				}
				close(stderr_fd[1]);
			}
			RAExec = g_hash_table_lookup(RAExecFuncs,rsc->class);
			if (NULL == RAExec) {
				close(stdout_fd[1]);
				close(stderr_fd[1]);
				lrmd_log(LOG_ERR,"%s::%d: can't find RAExec for class %s"
				, __FUNCTION__, __LINE__, rsc->class);
				exit(EXECRA_EXEC_UNKNOWN_ERROR);
			}
			
			/*should we use logging daemon or not in script*/
			setenv(HALOGD, cl_log_get_uselogd()?"yes":"no",1);

			/* Name of the resource and some others also
			 * need to be passed in. Maybe pass through the
			 * entire lrm_op_t too? */
			lrmd_debug2(LOG_DEBUG
			,	"perform_ra_op:calling RA plugin to perform %s, pid: [%d]"
			,	op_info(op), getpid());		

			op_params = ha_msg_value_str_table(op->msg, F_LRM_PARAM);
			params = merge_str_tables(rsc->params,op_params);
			if (op_params) {
				free_str_table(op_params);
				op_params = NULL;
			}

			if (replace_secret_params(rsc->id, params) < 0) {
				/* replacing secrets failed! */
				if (!strcmp(op_type,"stop")) {
					/* don't fail on stop! */
					lrmd_log(LOG_INFO
					, "%s:%d: proceeding with the stop operation for %s"
					, __FUNCTION__, __LINE__, rsc->id);
				} else {
					lrmd_log(LOG_ERR
					, "%s:%d: failed to get secrets for %s, "
					"considering resource not configured"
					, __FUNCTION__, __LINE__, rsc->id);
					exit(EXECRA_NOT_CONFIGURED);
				}
			}
			RAExec->execra (rsc->id,
					rsc->type,
					rsc->provider,
					op_type,
					timeout,
					params);

			/* execra should never return. */
			exit(EXECRA_EXEC_UNKNOWN_ERROR);

	}
	lrmd_log(LOG_ERR, "perform_ra_op: end(impossible).");
	return HA_OK;
}

static void
on_ra_proc_registered(ProcTrack* p)
{
}

/* Handle one of our ra child processes finished*/
static void
on_ra_proc_finished(ProcTrack* p, int status, int signo, int exitcode
,	int waslogged)
{
	lrmd_op_t* op = NULL;
	lrmd_rsc_t* rsc = NULL;
	struct RAExecOps * RAExec = NULL;
	const char* op_type;
        int rc = EXECRA_EXEC_UNKNOWN_ERROR;
        int ret;
	int op_status;

	LRMAUDIT();

	CHECK_ALLOCATED(p, "ProcTrack p", );
	op = proctrack_data(p);

	child_count -= op->weight;
	if (child_count < 0) {
		lrmd_log(LOG_ERR, "%s:%d: child count is less than zero: %d"
			, __FUNCTION__, __LINE__, child_count);
		child_count = 0;
	}

	lrmd_debug2(LOG_DEBUG, "on_ra_proc_finished: accessing the op whose "
		  "address is %p", op);
	CHECK_ALLOCATED(op, "op", );
	if (op->exec_pid == 0) {
		lrmd_log(LOG_ERR, "on_ra_proc_finished: the op was freed.");
		dump_data_for_debug();
		return;
	}
	RemoveTrackedProcTimeouts(op->exec_pid);
	op->exec_pid = -1;

	rsc = lookup_rsc(op->rsc_id);
	if (rsc == NULL) {
		lrmd_log(LOG_ERR, "%s: the rsc (id=%s) does not exist"
		, __FUNCTION__, lrm_str(op->rsc_id));
		lrmd_op_dump(op, __FUNCTION__);
		lrmd_dump_all_resources();
		/* delete the op */
		lrmd_op_destroy(op);
		reset_proctrack_data(p);
		LRMAUDIT();
		return;
	}

	RAExec = g_hash_table_lookup(RAExecFuncs,rsc->class);
	if (NULL == RAExec) {
		lrmd_log(LOG_ERR,"on_ra_proc_finished: can not find RAExec for"
			" resource class <%s>", rsc->class);
		dump_data_for_debug();
		return;
	}

	op_type = ha_msg_value(op->msg, F_LRM_OP);

	if ( (NULL == strchr(op->first_line_ra_stdout, '\n')) 
	    && (0==STRNCMP_CONST(rsc->class, "heartbeat"))
	    && (   (0==STRNCMP_CONST(op_type, "monitor")) 
		 ||(0==STRNCMP_CONST(op_type, "status")))  ) {
		if ( ( op->rapop != NULL ) 
		    && (op->rapop->ra_stdout_fd >= 0) ) {
			handle_pipe_ra_stdout(op->rapop->ra_stdout_fd
						, op->rapop);
		} else {
			lrmd_log(LOG_WARNING, "There is something wrong: the "
				"first line isn't read in. Maybe the heartbeat "
				"does not ouput string correctly for status "
				"operation. Or the code (myself) is wrong.");
		}
	}

	if( signo ) {
		if( proctrack_timedout(p) ) {
			lrmd_log(LOG_WARNING,	"%s: pid %d timed out"
			, small_op_info(op), proctrack_pid(p));
			op_status = LRM_OP_TIMEOUT;
		} else {
			op_status = LRM_OP_ERROR;
		}
	} else {
		rc = RAExec->map_ra_retvalue(exitcode, op_type
						 , op->first_line_ra_stdout);
		if (!op->interval || is_logmsg_due(op) || debug_level > 0) { /* log non-repeating ops */
			if (rc == exitcode) {
				lrmd_log(LOG_INFO
				,	"%s: pid %d exited with"
				" return code %d", small_op_info(op), proctrack_pid(p), rc);
			}else{
				lrmd_log(LOG_INFO
				,	"%s: pid %d exited with"
				" return code %d (mapped from %d)"
				,	small_op_info(op), proctrack_pid(p), rc, exitcode);
			}
		}
		if (EXECRA_EXEC_UNKNOWN_ERROR == rc || EXECRA_NO_RA == rc) {
			op_status = LRM_OP_ERROR;
			lrmd_log(LOG_CRIT
			,	"on_ra_proc_finished: the exit code indicates a problem.");
		} else {
			op_status = LRM_OP_DONE;
		}
	}
	if (op->interval && is_logmsg_due(op)) {
		op->t_lastlogmsg = time_longclock();
	}
	if (HA_OK !=
			ha_msg_mod_int(op->msg, F_LRM_OPSTATUS, op_status)) {
		LOG_FAILED_TO_ADD_FIELD("opstatus");
		return ;
	}
	if (HA_OK != ha_msg_mod_int(op->msg, F_LRM_RC, rc)) {
		LOG_FAILED_TO_ADD_FIELD("F_LRM_RC");
		return ;
	}

	if ( 0 < strlen(op->first_line_ra_stdout) ) {
		if (NULL != cl_get_string(op->msg, F_LRM_DATA)) {
			cl_msg_remove(op->msg, F_LRM_DATA);
		}
		ret = ha_msg_add(op->msg, F_LRM_DATA, op->first_line_ra_stdout);
		if (HA_OK != ret) {
			LOG_FAILED_TO_ADD_FIELD("data");
		}
	}

	if (on_op_done(rsc,op) >= 0) {
		perform_op(rsc);
	}
	reset_proctrack_data(p);
	LRMAUDIT();
}

/* Handle the death of one of our managed child processes */
static const char *
on_ra_proc_query_name(ProcTrack* p)
{
	static char proc_name[MAX_PROC_NAME];
	lrmd_op_t* op = NULL;
	lrmd_rsc_t* rsc = NULL;
	const char* op_type = NULL;

	LRMAUDIT();
	op = (lrmd_op_t*)(proctrack_data(p));
	if (NULL == op || op->exec_pid == 0) {
		return "*unknown*";
	}

	op_type = ha_msg_value(op->msg, F_LRM_OP);
	rsc = lookup_rsc(op->rsc_id);
	if (rsc == NULL) {
		snprintf(proc_name
		, MAX_PROC_NAME
		, "unknown rsc(%s):%s maybe deleted"
		, op->rsc_id, op_type);
	}else {
		snprintf(proc_name, MAX_PROC_NAME, "%s:%s", rsc->id, op_type);
	}
	LRMAUDIT();
	return proc_name;
}

static int
get_lrmd_param(const char *name, char *value, int maxstring)
{
	if (!name) {
		lrmd_log(LOG_ERR, "%s: empty name", __FUNCTION__);
		return HA_FAIL;
	}
	if (!strcmp(name,"max-children")) {
		snprintf(value, maxstring, "%d", max_child_count);
		return HA_OK;
	} else {
		lrmd_log(LOG_ERR, "%s: unknown lrmd parameter %s", __FUNCTION__, name);
		return HA_FAIL;
	}
}

static int
set_lrmd_param(const char *name, const char *value)
{
	int ival;

	if (!name) {
		lrmd_log(LOG_ERR, "%s: empty name", __FUNCTION__);
		return HA_FAIL;
	}
	if (!value) {
		lrmd_log(LOG_ERR, "%s: empty value", __FUNCTION__);
		return HA_FAIL;
	}
	if (!strcmp(name,"max-children")) {
		ival = atoi(value);
		if (ival <= 0) {
			lrmd_log(LOG_ERR, "%s: invalid value for lrmd parameter %s"
				, __FUNCTION__, name);
			return HA_FAIL;
		} else if (ival == max_child_count) {
			lrmd_log(LOG_INFO, "max-children already set to %d", ival);
			return HA_OK;
		}
		lrmd_log(LOG_INFO, "setting max-children to %d", ival);
		max_child_count = ival;
		return HA_OK;
	} else {
		lrmd_log(LOG_ERR, "%s: unknown lrmd parameter %s"
			, __FUNCTION__, name);
		return HA_FAIL;
	}
}

int
on_msg_set_lrmd_param(lrmd_client_t* client, struct ha_msg* msg)
{
	const char *name, *value;

	CHECK_ALLOCATED(client, "client", HA_FAIL);
	CHECK_ALLOCATED(msg, "message", HA_FAIL);

	name = ha_msg_value(msg,F_LRM_LRMD_PARAM_NAME);
	value = ha_msg_value(msg,F_LRM_LRMD_PARAM_VAL);
	if (!name || !value) {
		lrmd_log(LOG_ERR, "%s: no parameter defined"
			, __FUNCTION__);
		return HA_FAIL;
	}
	return set_lrmd_param(name,value);
}

int
on_msg_get_lrmd_param(lrmd_client_t* client, struct ha_msg* msg)
{
	struct ha_msg* ret = NULL;
	const char *name;
	char value[MAX_NAME_LEN];

	CHECK_ALLOCATED(client, "client", HA_FAIL);
	CHECK_ALLOCATED(msg, "message", HA_FAIL);

	ret = create_lrm_ret(HA_OK, 1);
	CHECK_RETURN_OF_CREATE_LRM_RET;

	name = ha_msg_value(msg,F_LRM_LRMD_PARAM_NAME);
	if (get_lrmd_param(name, value, MAX_NAME_LEN) != HA_OK) {
		return HA_FAIL;
	}
	if (HA_OK != ha_msg_add(ret, F_LRM_LRMD_PARAM_VAL, value)) {
		ha_msg_del(ret);
		LOG_FAILED_TO_ADD_FIELD(F_LRM_LRMD_PARAM_VAL);
		return HA_FAIL;
	}
	if (HA_OK != msg2ipcchan(ret, client->ch_cmd)) {
		lrmd_log(LOG_ERR, "%s: can not send the ret msg",__FUNCTION__);
	}
	ha_msg_del(ret);
	return HA_OK;
}


/* /////////////////Util Functions////////////////////////////////////////////// */
int
send_ret_msg (IPC_Channel* ch, int ret)
{
	struct ha_msg* msg = NULL;

	msg = create_lrm_ret(ret, 1);
	CHECK_RETURN_OF_CREATE_LRM_RET;

	if (HA_OK != msg2ipcchan(msg, ch)) {
		lrmd_log(LOG_ERR, "send_ret_msg: can not send the ret msg");
	}
	ha_msg_del(msg);
	return HA_OK;
}

static void
send_cbk_msg(struct ha_msg* msg, lrmd_client_t* client)
{
	if (!client) {
		lrmd_log(LOG_WARNING,
			"%s: zero client", __FUNCTION__);
		return;
	}
	if (!client->ch_cbk) {
		lrmd_log(LOG_WARNING,
			"%s: callback channel is null", __FUNCTION__);
	} else if (HA_OK != msg2ipcchan(msg, client->ch_cbk)) {
		lrmd_log(LOG_WARNING,
			"%s: can not send the ret msg", __FUNCTION__);
	}
}

static void
send_msg(struct ha_msg* msg, lrmd_client_t* client)
{
	if (!client) {
		lrmd_log(LOG_WARNING,
			"%s: zero client", __FUNCTION__);
		return;
	}
	if (HA_OK != ha_msg_mod(msg,F_LRM_APP,client->app_name)) {
		lrmd_log(LOG_ERR,"%s:%d: cannot add field to a message"
		,	__FUNCTION__, __LINE__);
		return;
	}
	send_cbk_msg(msg, client);
}

void
notify_client(lrmd_op_t* op)
{
	lrmd_client_t* client = lookup_client(op->client_id);

	if (client) {
		/* send the result to client */
		send_cbk_msg(op->msg, client);
	} else {
		lrmd_log(LOG_WARNING
		,	"%s: client for the operation %s does not exist"
			" and client requested notification."
		,	__FUNCTION__,	op_info(op));
	}
}

lrmd_client_t*
lookup_client (pid_t pid)
{
	return (lrmd_client_t*) g_hash_table_lookup(clients, &pid);
}

static gboolean
client_cmp_name(gpointer key, gpointer val, gpointer app_name)
{
	return strcmp(((lrmd_client_t*)val)->app_name,(char *)app_name) ?
		FALSE : TRUE;
}

static lrmd_client_t*
lookup_client_by_name(char *app_name)
{
	return (lrmd_client_t*)g_hash_table_find(clients,client_cmp_name,app_name);
}

lrmd_rsc_t*
lookup_rsc (const char* rid)
{
	return rid ?
		(lrmd_rsc_t*)g_hash_table_lookup(resources, rid) :
		NULL;
}

lrmd_rsc_t*
lookup_rsc_by_msg (struct ha_msg* msg)
{
	const char* id = NULL;
	lrmd_rsc_t* rsc = NULL;

	CHECK_ALLOCATED(msg, "msg", NULL);
	id = ha_msg_value(msg, F_LRM_RID);
	if (id == NULL) {
		lrmd_log(LOG_ERR, "lookup_rsc_by_msg: got a NULL resource id.");
		return NULL;
	}
	if (RID_LEN <= strnlen(id, RID_LEN+2))	{
		lrmd_log(LOG_ERR, "lookup_rsc_by_msg: resource id is too long.");
		return NULL;
	}
	rsc = lookup_rsc(id);
	return rsc;
}

static void
destroy_pipe_ra_stdout(gpointer user_data)
{
	ra_pipe_op_t * rapop = (ra_pipe_op_t *)user_data;

	CHECK_ALLOCATED(rapop, "ra_pipe_op",);
	if (rapop->ra_stderr_fd < 0) {
		ra_pipe_op_destroy(rapop);
	}
}

static void
destroy_pipe_ra_stderr(gpointer user_data)
{
	ra_pipe_op_t * rapop = (ra_pipe_op_t *)user_data;

	CHECK_ALLOCATED(rapop, "ra_pipe_op",);
	if (rapop->ra_stdout_fd < 0) {
		ra_pipe_op_destroy(rapop);
	}
}

static gboolean
handle_pipe_ra_stdout(int fd, gpointer user_data)
{
	gboolean rc = TRUE;
	ra_pipe_op_t * rapop = (ra_pipe_op_t *)user_data;
	char * data = NULL;
	lrmd_op_t* lrmd_op = NULL;

	CHECK_ALLOCATED(rapop, "ra_pipe_op", FALSE);

	if (rapop->lrmd_op == NULL) {
		lrmd_debug2(LOG_DEBUG, "%s:%d: Unallocated lrmd_op 0x%lx!!"
		,	__FUNCTION__, __LINE__
		,	(unsigned long)rapop->lrmd_op);
	} else {
		lrmd_op = rapop->lrmd_op;
	}

	if (fd <= STDERR_FILENO) {
		lrmd_log(LOG_CRIT, "%s:%d: Attempt to read from "
			"closed/invalid file descriptor %d."
		,	__FUNCTION__, __LINE__, fd);
		return FALSE;
	}

	if (0 != read_pipe(fd, &data, rapop)) {
		/* error or reach the EOF */
		if (fd > STDERR_FILENO) {
			close(fd);
			if (fd == rapop->ra_stdout_fd) {
				rapop->ra_stdout_fd = -1;
			}
		}
		if ( NULL != rapop->ra_stdout_gsource) {
			/*
			 * Returning FALSE will trigger ipc code to release
			 * the GFDSource, so donn't release it here.
			 */
			rapop->ra_stdout_gsource = NULL;
		}
		rc = FALSE;
	}

	if ( data!=NULL ) {
		if (  (0==STRNCMP_CONST(rapop->op_type, "meta-data"))
		    ||(0==STRNCMP_CONST(rapop->op_type, "monitor")) 
		    ||(0==STRNCMP_CONST(rapop->op_type, "status")) ) {
			lrmd_debug(LOG_DEBUG, "RA output: (%s:%s:stdout) %s"
				, lrm_str(rapop->rsc_id), rapop->op_type, data);
		} else {
			lrmd_log(LOG_INFO, "RA output: (%s:%s:stdout) %s"
				, lrm_str(rapop->rsc_id), rapop->op_type, data);
		}

		/*
		 * This code isn't good enough, it produces erratic and hard-to
		 * read messages in the logs. But this does not affect the 
		 * function correctness, since the first line output is ensured
		 * to be collected into the buffer completely.
		 * Anyway, the meta-data (which is _many_  lines long) can be 
		 * handled by another function, see raexec.h
		 */
		if ( (rapop->first_line_read == FALSE)
                    && (0==STRNCMP_CONST(rapop->rsc_class, "heartbeat"))
		    && ( lrmd_op != NULL )
	    	    && ( (0==STRNCMP_CONST(rapop->op_type, "monitor")) 
			  ||(0==STRNCMP_CONST(rapop->op_type, "status")) )) {
			if (lrmd_op != NULL) {
				strncat(lrmd_op->first_line_ra_stdout, data
				  , sizeof(lrmd_op->first_line_ra_stdout) -
				    strlen(lrmd_op->first_line_ra_stdout)-1);
				if (strchr(lrmd_op->first_line_ra_stdout, '\n')
					!= NULL) {
					rapop->first_line_read = TRUE;
				}
			} else {
				lrmd_log(LOG_CRIT
				   , "Before read the first line, the RA "
				   "execution child quitted and waited.");
			}
		}
		
		g_free(data);
	}

	return rc;
}

static gboolean 
handle_pipe_ra_stderr(int fd, gpointer user_data)
{
	gboolean rc = TRUE;
	char * data = NULL;
	ra_pipe_op_t * rapop = (ra_pipe_op_t *)user_data;

	CHECK_ALLOCATED(rapop, "ra_pipe_op", FALSE);

	if (fd <= STDERR_FILENO) {
		lrmd_log(LOG_CRIT, "%s:%d: Attempt to read from "
			" closed/invalid file descriptor %d."
		,	__FUNCTION__, __LINE__, fd);
		return FALSE;
	}

	if (0 != read_pipe(fd, &data, rapop)) {
		/* error or reach the EOF */
		if (fd > STDERR_FILENO) {
			close(fd);
			if (fd == rapop->ra_stderr_fd) {
				rapop->ra_stderr_fd = -1;
			}
		}
		if ( NULL != rapop->ra_stderr_gsource) {
			/*
			 * G_main_del_fd will trigger
			 *	destroy_pipe_ra_stderr
			 *	ra_pipe_op_destroy
			 *
			 * Returning FALSE will trigger ipc code to release
			 * the GFDSource, so donn't release it here.
			 */
			rapop->ra_stderr_gsource = NULL;
		}
		rc = FALSE;
	}

	if (data!=NULL) { 
		lrmd_log(LOG_INFO, "RA output: (%s:%s:stderr) %s"
			, lrm_str(rapop->rsc_id), probe_str(rapop->lrmd_op,rapop->op_type), data);
		g_free(data);
	}

	return rc;
}

int
read_pipe(int fd, char ** data, void * user_data)
{
	const int BUFFLEN = 81;
	char buffer[BUFFLEN];
	int readlen;
	GString * gstr_tmp;
	int rc = 0;
	lrmd_op_t * op = NULL;
	ra_pipe_op_t * rapop = (ra_pipe_op_t *)user_data;

	lrmd_debug3(LOG_DEBUG, "%s begin.", __FUNCTION__);

	CHECK_ALLOCATED(rapop, "ra_pipe_op", FALSE);

	op = (lrmd_op_t *)rapop->lrmd_op;
	if (NULL == op) {
		lrmd_debug2(LOG_DEBUG, "%s:%d: Unallocated lrmd_op 0x%lx!!"
		,	__FUNCTION__, __LINE__
		,	(unsigned long)op);
	}

	*data = NULL;
	gstr_tmp = g_string_new("");

	do {
		errno = 0;
		readlen = read(fd, buffer, BUFFLEN - 1);
		if (NULL == op) {
			lrmd_debug2(LOG_NOTICE
				, "read's ret: %d when lrmd_op finished"
				, readlen);
		}
		if ( readlen > 0 ) {
			buffer[readlen] = EOS;
			g_string_append(gstr_tmp, buffer);
		}
	} while (readlen == BUFFLEN - 1 || errno == EINTR);

	if (errno == EINTR || errno == EAGAIN) {
		errno = 0;
	}
	
	/* Reach the EOF */
	if (readlen == 0) { 
		rc = -1;
	}

	if ((readlen < 0) && (errno !=0)) {
		rc = -1;
		switch (errno) {
		default:
			cl_perror("%s:%d read error: fd %d errno=%d"
			,	__FUNCTION__, __LINE__
			,	fd, errno);
			if (NULL != op) {
				lrmd_op_dump(op, "op w/bad errno");
			} else {
				lrmd_log(LOG_NOTICE
					, "%s::%d: lrmd_op has been freed"
					, __FUNCTION__, __LINE__);
			}
			break;

		case EBADF:
			lrmd_log(LOG_CRIT
			,	"%s:%d"
			" Attempt to read from closed file descriptor %d."
			,	__FUNCTION__, __LINE__,	fd);
			if (NULL != op) {
				lrmd_op_dump(op, "op w/bad errno");
			} else {
				lrmd_log(LOG_NOTICE
					, "%s::%d: lrmd_op has been freed"
					, __FUNCTION__, __LINE__);
			}
			break;
		}	
	}

	if ( gstr_tmp->len == 0 ) {
		g_string_free(gstr_tmp, TRUE);
	} else {
		*data = gstr_tmp->str;
		g_string_free(gstr_tmp, FALSE);
	}

	lrmd_debug3(LOG_DEBUG, "%s end.", __FUNCTION__);
	return rc;
}


static gboolean 
debug_level_adjust(int nsig, gpointer user_data)
{
	char s[16];

	switch (nsig) {
		case SIGUSR1:
			debug_level++;
			dump_data_for_debug();
			break;

		case SIGUSR2:
			dump_data_for_debug();
			debug_level--;
			if (debug_level < 0) {
				debug_level = 0;
			}
			break;

		default:
			lrmd_log(LOG_WARNING, "debug_level_adjust: Received an "
				"unexpected signal(%d). Something wrong?.",nsig);
	}

	snprintf(s, sizeof(s), "%d", debug_level);
	setenv(HADEBUGVAL, s, 1);
	return TRUE;
}

static void
dump_data_for_debug(void)
{
	lrmd_debug(LOG_DEBUG, "begin to dump internal data for debugging.");
	lrmd_dump_all_clients();
	lrmd_dump_all_resources();
	lrmd_debug(LOG_DEBUG, "end to dump internal data for debugging.");
}

const char* 
gen_op_info(const lrmd_op_t* op, gboolean add_params)
{
	static char info[512];
	lrmd_rsc_t* rsc = NULL;
	const char * op_type;
	GString * param_gstr;
	GHashTable* op_params = NULL;

	if (NULL == op) {
		lrmd_log(LOG_ERR, "%s:%d: op==NULL"
			 , __FUNCTION__, __LINE__);
		return NULL;
	}
	rsc = lookup_rsc(op->rsc_id);
	op_type = ha_msg_value(op->msg, F_LRM_OP);

	if (rsc == NULL) {
		snprintf(info,sizeof(info)
		,"operation %s[%d] on unknown rsc(maybe deleted) for client %d"
		,lrm_str(op_type)
		,op->call_id ,op->client_id);

	}else{
		if (op->exec_pid > 1) {
			snprintf(info, sizeof(info)
			,"operation %s[%d] with pid %d on %s for client %d"
			,lrm_str(op_type), op->call_id, op->exec_pid, lrm_str(rsc->id)
			,op->client_id);
		} else {
			snprintf(info, sizeof(info)
			,"operation %s[%d] on %s for client %d"
			,lrm_str(op_type), op->call_id, lrm_str(rsc->id)
			,op->client_id);
		}

		if( add_params ) {
			param_gstr = g_string_new("");
			op_params = ha_msg_value_str_table(op->msg, F_LRM_PARAM);
			hash_to_str(op_params, param_gstr);
			if (op_params) {
				free_str_table(op_params);
				op_params = NULL;
			}

			snprintf(info+strlen(info), sizeof(info)-strlen(info)
				,", its parameters: %s",param_gstr->str);

			g_string_free(param_gstr, TRUE);
		}
	}
	return info;
}

static void
hash_to_str(GHashTable * params , GString * str)
{
	if (params) {
		g_hash_table_foreach(params, hash_to_str_foreach, str);
	}
}

static void
hash_to_str_foreach(gpointer key, gpointer value, gpointer user_data)
{
	char buffer_tmp[80];
	GString * str = (GString *)user_data;

	g_snprintf(buffer_tmp, sizeof(buffer_tmp), "%s=[%s] "
		, (char *)key, (char *)value);
	str = g_string_append(str, buffer_tmp);
}

static void 
check_queue_duration(lrmd_op_t* op)
{
	unsigned long t_stay_in_list = 0;
	static struct msg_ctrl *ml;

	CHECK_ALLOCATED(op, "op", );
	t_stay_in_list = longclockto_ms(op->t_perform - op->t_addtolist);
	if ( t_stay_in_list > WARNINGTIME_IN_LIST)
	{
		if (!ml)
			ml = cl_limit_log_new(logmsg_ctrl_defs + OP_STAYED_TOO_LONG);
		cl_limit_log(ml, LOG_WARNING
		,	"perform_ra_op: the %s stayed in operation "
			"list for %lu ms (longer than %d ms)"
		,	small_op_info(op), t_stay_in_list
		,	WARNINGTIME_IN_LIST
		);
		if (debug_level >= 2) {
			dump_data_for_debug();
		}
	}
}

