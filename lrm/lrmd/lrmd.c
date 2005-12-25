/* $Id: lrmd.c,v 1.192 2005/12/25 23:23:41 alan Exp $ */
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

#include <config.h>
#include <portability.h>
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
#include <heartbeat.h>
#include <pils/plugin.h>
#include <pils/generic.h>
#include <clplumbing/cl_log.h>
#include <clplumbing/cl_syslog.h>
#include <clplumbing/ipc.h>
#include <clplumbing/GSource.h>
#include <clplumbing/lsb_exitcodes.h>
#include <clplumbing/cl_signal.h>
#include <clplumbing/proctrack.h>
#include <clplumbing/coredumps.h>
#include <clplumbing/uids.h>
#include <clplumbing/Gmain_timeout.h>
#include <clplumbing/cl_pidfile.h>
#include <ha_msg.h>
#include <apphb.h>
#include <lrm/lrm_api.h>
#include <lrm/lrm_msg.h>
#include <lrm/raexec.h>

#define	MAX_PID_LEN 256
#define	MAX_PROC_NAME 256
#define	MAX_MSGTYPELEN 32
#define	MAX_CLASSNAMELEN 32
#define WARNINGTIME_IN_LIST 5000
#define OPTARGS		"skrhvmi:"
#define PID_FILE 	HA_VARRUNDIR"/lrmd.pid"
#define LRMD_COREDUMP_ROOT_DIR HA_COREDIR
#define APPHB_WARNTIME_FACTOR	3
#define APPHB_INTVL_DETLA 	30  /* Millisecond */

/* Donnot directly use the definition in heartbeat.h/hb_api.h for fewer
 * dependency, but need to keep identical with them.
 */
#define ENV_PREFIX "HA_"
#define KEY_LOGDAEMON   "use_logd"
#define HADEBUGVAL	"HA_DEBUG"
#define lrmd_log(priority, fmt...); \
		cl_log(priority, fmt); \

#define lrmd_debug(priority, fmt...); \
        if ( debug_level == 1 ) { \
                cl_log(priority, fmt); \
        }

#define lrmd_debug2(priority, fmt...); \
        if ( debug_level >= 2 ) { \
                cl_log(priority, fmt); \
        }

#define lrmd_debug3(priority, fmt...); \
        if ( debug_level >= 3 ) { \
                cl_log(priority, fmt); \
        }

#define	lrmd_nullcheck(p)	((p) ? (p) : "<null>")
#define	lrm_str(p)	(lrmd_nullcheck(p))

static	gboolean	in_alloc_dump = FALSE;
#define	CHECK_ALLOCATED(thing, name, result)				\
	if (!cl_is_allocated(thing)) {					\
		lrmd_log(LOG_ERR					\
		,	"%s: %s pointer 0x%lx is not allocated."	\
		,	__FUNCTION__, name, (unsigned long)thing);	\
		if (!in_alloc_dump) {					\
			in_alloc_dump = TRUE;				\
			dump_mem_stats();				\
			dump_data_for_debug();				\
			in_alloc_dump = FALSE;				\
			return result;					\
		}							\
	}

#define CHECK_RETURN_OF_CREATE_LRM_RET					\
	if (NULL == msg) {						\
		lrmd_log(LOG_ERR					\
		, 	"%s: can not create a ret message with create_lrm_ret."	\
		, 	__FUNCTION__);					\
		return HA_FAIL;						\
	}

#define LOG_FAILED_TO_ADD_FIELD(field)					\
			lrmd_log(LOG_ERR				\
			,	"%s:%d: can not add the field %s to a message." \
			,	__FUNCTION__				\
			,	__LINE__				\
			,	field);

#define LRMD_APPHB_HB				\
        if (reg_to_apphb == TRUE) {		\
                if (apphb_hb() != 0) {		\
                        reg_to_apphb = FALSE;	\
                }				\
        }

/*
 * The basic objects in our world:
 *
 *	lrmd_client_t:
 *	Client - a process which has connected to us for service.
 *
 *	lrmd_rsc_t:
 *	Resource - an abstract HA cluster resource implemented by a
 *		resource agent through our RA plugins
 *		It has two list of operations (lrmd_op_t) associated with it
 *			op_list - operations to be run as soon as they're ready
 *			repeat_op_list - operations to be run later
 *		It maintains the following tracking structures:
 *			last_op        Last operation performed on this resource
 *			last_op_table  Last operations of each type done per client
 *
 *	lrmd_op_t:
 *	Resource operation - an operation on a resource -- requested
 *	by a client.
 *
 *	ProcTrack - tracks a currently running resource operation.
 *		It points back to the lrmd_op_t that started it.
 *
 * Global structures containing these things:
 *
 *	clients - a hash table of all (currently connected) clients
 *
 *	resources - a hash table of all (currently configured) resources
 *
 *	Proctrack keeps its own private data structures to keep track of
 *	child processes that it created.  They in turn point to the
 *	lrmd_op_t objects that caused us to fork the child process.
 *
 *
 */

typedef struct
{
	char*		app_name;
	pid_t		pid;
	gid_t		gid;
	uid_t		uid;

	IPC_Channel*	ch_cmd;
	IPC_Channel*	ch_cbk;

	GCHSource*	g_src;
	GCHSource*	g_src_cbk;
	char		lastrequest[MAX_MSGTYPELEN];
	time_t		lastreqstart;
	time_t		lastreqend;
	time_t		lastrcsent;
}lrmd_client_t;

typedef struct lrmd_rsc lrmd_rsc_t;
typedef struct lrmd_op	lrmd_op_t;


struct lrmd_rsc
{
	char*		id;		/* Unique resource identifier	*/
	char*		type;		/* 				*/
	char*		class;		/*				*/
	char*		provider;	/* Resource provider (optional)	*/
	GHashTable* 	params;		/* Parameters to this resource	*/
					/* as name/value pairs		*/
	GList*		op_list;	/* Queue of operations to run	*/
	GList*		repeat_op_list;	/* Unordered list of repeating	*/
					/* ops They will run later	*/
	GHashTable*	last_op_table;	/* Last operation of each type	*/
};

struct lrmd_op
{
	char*		rsc_id;	
	gboolean	is_copy;
	pid_t		client_id;
	int		call_id;
	int		exec_pid;
	char		first_line_ra_stdout[80]; /* only for heartbeat RAs */
	guint		timeout_tag;
	guint		repeat_timeout_tag;
	int		interval;
	int		delay;
	struct ha_msg*	msg;
	/* For read the output from RAs */
	int		ra_stdout_fd;
	int		ra_stderr_fd;
	GFDSource *	ra_stdout_gsource;
	GFDSource *	ra_stderr_gsource;
	/*time stamp*/
	longclock_t	t_recv;
	longclock_t	t_addtolist;
	longclock_t	t_perform;
	longclock_t	t_done;
};

/* Debug oriented funtions */
static gboolean debug_level_adjust(int nsig, gpointer user_data);
static void dump_data_for_debug(void);

/* glib loop call back functions */
static gboolean on_connect_cmd(IPC_Channel* ch_cmd, gpointer user_data);
static gboolean on_connect_cbk(IPC_Channel* ch_cbk, gpointer user_data);
static gboolean on_receive_cmd(IPC_Channel* ch_cmd, gpointer user_data);
static gboolean on_op_timeout_expired(gpointer data);
static gboolean on_repeat_op_readytorun(gpointer data);
static void on_remove_client(gpointer user_data);

/* message handlers */
static int on_msg_register(lrmd_client_t* client, struct ha_msg* msg);
static int on_msg_get_rsc_classes(lrmd_client_t* client, struct ha_msg* msg);
static int on_msg_get_rsc_types(lrmd_client_t* client, struct ha_msg* msg);
static int on_msg_get_rsc_providers(lrmd_client_t* client, struct ha_msg* msg);
static int on_msg_get_metadata(lrmd_client_t* client, struct ha_msg* msg);
static int on_msg_add_rsc(lrmd_client_t* client, struct ha_msg* msg);
static int on_msg_get_rsc(lrmd_client_t* client, struct ha_msg* msg);
static int on_msg_get_last_op(lrmd_client_t* client, struct ha_msg* msg);
static int on_msg_get_all(lrmd_client_t* client, struct ha_msg* msg);
static int on_msg_del_rsc(lrmd_client_t* client, struct ha_msg* msg);
static int on_msg_perform_op(lrmd_client_t* client, struct ha_msg* msg);
static int on_msg_get_state(lrmd_client_t* client, struct ha_msg* msg);
static gboolean sigterm_action(int nsig, gpointer unused);

/* functions wrap the call to ra plugins */
static int perform_ra_op(lrmd_op_t* op);

/* Apphb related functions */
static int init_using_apphb(void);
static gboolean emit_apphb(gpointer data);

/* Utility functions */
static int flush_op(lrmd_op_t* op);
static int perform_op(lrmd_rsc_t* rsc);
static int unregister_client(lrmd_client_t* client);
static int on_op_done(lrmd_op_t* op);
static const char* op_info(const lrmd_op_t* op);
static int send_ret_msg ( IPC_Channel* ch, int rc);
static lrmd_client_t* lookup_client (pid_t pid);
static lrmd_rsc_t* lookup_rsc (const char* rid);
static lrmd_rsc_t* lookup_rsc_by_msg (struct ha_msg* msg);
static int read_pipe(int fd, char ** data, gpointer user_data);
static gboolean handle_pipe_ra_stdout(int fd, gpointer user_data);
static gboolean handle_pipe_ra_stderr(int fd, gpointer user_data);
static struct ha_msg* op_to_msg(lrmd_op_t* op);
static gboolean lrm_shutdown(void);
static gboolean can_shutdown(void);
static gboolean free_str_hash_pair(gpointer key
,	 gpointer value, gpointer user_data);
static gboolean free_str_op_pair(gpointer key
,	 gpointer value, gpointer user_data);
static lrmd_op_t* lrmd_op_copy(const lrmd_op_t* op);
static void send_last_op(gpointer key, gpointer value, gpointer user_data);
static void record_op_completion(lrmd_client_t* client, lrmd_op_t* op);
static void hash_to_str(GHashTable * , GString *);
static void hash_to_str_foreach(gpointer key, gpointer value, gpointer userdata);

/*
 * following functions are used to monitor the exit of ra proc
 */
static void on_ra_proc_registered(ProcTrack* p);
static void on_ra_proc_finished(ProcTrack* p, int status
,			int signo, int exitcode, int waslogged);
static const char* on_ra_proc_query_name(ProcTrack* p);

ProcTrack_ops ManagedChildTrackOps = {
	on_ra_proc_finished,
	on_ra_proc_registered,
	on_ra_proc_query_name
};

/* msg dispatch table */
typedef int (*msg_handler)(lrmd_client_t* client, struct ha_msg* msg);
struct msg_map
{
	const char* 	msg_type;
	gboolean	need_return_ret;
	msg_handler	handler;
};

struct msg_map msg_maps[] = {
	{REGISTER,	TRUE,	on_msg_register},
	{GETRSCCLASSES,	FALSE,	on_msg_get_rsc_classes},
	{GETRSCTYPES,	FALSE,	on_msg_get_rsc_types},
	{GETPROVIDERS,	FALSE,	on_msg_get_rsc_providers},
	{ADDRSC,	TRUE,	on_msg_add_rsc},
	{GETRSC,	FALSE,	on_msg_get_rsc},
	{GETLASTOP,	FALSE,	on_msg_get_last_op},
	{GETALLRCSES,	FALSE,	on_msg_get_all},
	{DELRSC,	TRUE,	on_msg_del_rsc},
	{PERFORMOP,	TRUE,	on_msg_perform_op},
	{FLUSHOPS,	TRUE,	on_msg_perform_op},
	{CANCELOP,	TRUE,	on_msg_perform_op},
	{GETRSCSTATE,	FALSE,	on_msg_get_state},
	{GETRSCMETA,	FALSE, 	on_msg_get_metadata},
};

static GMainLoop* mainloop 		= NULL;
static GHashTable* clients		= NULL;	/* a GHashTable indexed by pid */
static GHashTable* resources 		= NULL;	/* a GHashTable indexed by rsc_id */
static int call_id 			= 1;
static const char* lrm_system_name 	= "lrmd";
static GHashTable * RAExecFuncs 	= NULL;
static GList* ra_class_list		= NULL;
static gboolean shutdown_in_progress	= FALSE;
static unsigned long apphb_interval 	= 2000; /* Millisecond */
static gboolean reg_to_apphbd		= FALSE;

/*
 * Daemon functions
 *
 * copy from the code of Andrew Beekhof <andrew@beekhof.net>
 */
static void usage(const char* cmd, int exit_status);
static int init_start(void);
static int init_stop(const char *pid_file);
static int init_status(const char *pid_file, const char *client_name);
static lrmd_op_t* lrmd_op_copy(const lrmd_op_t* op);
static void lrmd_rsc_dump(char* rsc_id, const char * text);

static struct {
	int	opcount;
	int	clientcount;
	int	rsccount;
}lrm_objectstats;

static void
dump_mem_stats(void)
{
	volatile cl_mem_stats_t * ms = cl_malloc_getstats();
	lrmd_debug(LOG_DEBUG
	,	"MEM STATS: pending alloc %ld, pending size %ld"
	,	ms->numalloc - ms->numfree
	,	ms->nbytes_alloc);
	
	lrmd_debug(LOG_DEBUG
	,	"STATS: OP Count: %d, Client Count: %d, Resource Count: %d"
	,	lrm_objectstats.opcount
	,	lrm_objectstats.clientcount
	,	lrm_objectstats.rsccount);
}

static void
lrmd_op_destroy(lrmd_op_t* op)
{

	CHECK_ALLOCATED(op, "op", );
	--lrm_objectstats.opcount;

	/*
	 * FIXME!
	 * This seems WAY dangerous as a way to process this.
	 * If we expect this to really be freed, then we should
	 * wipe out ALL references to this data - and then
	 * we will have a memory leak.
	 * If we expect this *might* be freed, then we need
	 * to leave it around for someone else to free
	 * and hopefully they'll really free it.
	 * But if these events happen in the other order
	 * and the process dies before we remove it from our tables
	 * then we are leaving it in our tables after it really exists.
	 *
	 * Some kind of a reference count strategy seems like a better
	 * deal - and then I think we *probably* wouldn't have to copy it
	 * for our various purposes, and it wouldn't matter what order
	 * the various events happened in.
	 *
	 * Although reference counts would work fine for this code,
	 * where it would really work well would be for the resources
	 * since we copy the operations whenever we need to.
	 *
	 * On the other hand if we switched from a pointer to an rsc_id
	 * then we would eliminate all possibilities of dangling pointers
	 * This idea has some merit.  If we do that, then switch
	 * the resource table to be hashed on rsc_id.
	 */
	if (op->exec_pid > 1) {
		return_to_orig_privs();	
		if (kill(-op->exec_pid, SIGKILL) < 0 && errno != ESRCH) {
			cl_perror("Cannot kill pid %d", op->exec_pid);
		}
		return_to_dropped_privs();
		return;
	}

	if ((int)op->repeat_timeout_tag > 0) {
		Gmain_timeout_remove(op->repeat_timeout_tag);
		op->repeat_timeout_tag = -1;
	}

	if ((int)op->timeout_tag > 0) {
		Gmain_timeout_remove(op->timeout_tag);
		op->timeout_tag = -1;
	}

	ha_msg_del(op->msg);
	op->msg = NULL;
	cl_free(op->rsc_id);
	op->rsc_id = NULL;
	op->exec_pid = 0;
	if (op->ra_stdout_fd != -1) {
		close(op->ra_stdout_fd);
		op->ra_stdout_fd = -1;
	}
	if (op->ra_stderr_fd != -1) {
		close(op->ra_stderr_fd);
		op->ra_stderr_fd = -1;
	}
	if ( NULL != op->ra_stdout_gsource) {
		G_main_del_fd(op->ra_stdout_gsource);
		op->ra_stdout_gsource = NULL;
	}
	if ( NULL != op->ra_stderr_gsource) {
		G_main_del_fd(op->ra_stderr_gsource);
		op->ra_stderr_gsource = NULL;
	}
	memset(op->first_line_ra_stdout, 0, sizeof(op->first_line_ra_stdout));

	lrmd_debug2(LOG_DEBUG, "lrmd_op_destroy: free the op whose address is %p"
		  , op);
	cl_free(op);
}

static lrmd_op_t*
lrmd_op_new(void)
{
	lrmd_op_t* op = (lrmd_op_t*)cl_calloc(sizeof(lrmd_op_t),1);

	if (op == NULL) {
		lrmd_log(LOG_ERR, "lrmd_op_new(): out of memory when "
			 "cl_calloc a lrmd_op_t.");
		dump_mem_stats();
		return NULL;
	}
	op->rsc_id = NULL;
	op->msg = NULL;
	op->exec_pid = -1;
	op->timeout_tag = -1;
	op->repeat_timeout_tag = -1;
	op->ra_stdout_fd = -1;
	op->ra_stderr_fd = -1;
	op->ra_stdout_gsource = NULL;
	op->ra_stderr_gsource = NULL;
	memset(op->first_line_ra_stdout, 0, sizeof(op->first_line_ra_stdout));
	op->t_recv = time_longclock();
	++lrm_objectstats.opcount;
	return op;
}

static lrmd_op_t* 
lrmd_op_copy(const lrmd_op_t* op)
{
	lrmd_op_t* ret = lrmd_op_new();

	if (NULL == ret) {
		return NULL;
	}
	/* Do a "shallow" copy */
	*ret = *op;
	/* Do a "deep" copy of the message structure */
	ret->msg = ha_msg_copy(op->msg);
	ret->rsc_id = cl_strdup(op->rsc_id);
	ret->ra_stdout_fd = -1;
	ret->ra_stderr_fd = -1;
	ret->ra_stdout_gsource = NULL;
	ret->ra_stderr_gsource = NULL;
	memset(ret->first_line_ra_stdout, 0, sizeof(ret->first_line_ra_stdout));
	ret->is_copy = TRUE;
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
	snprintf(whatwasthat, sizeof(whatwasthat), "?status=%d?", op_status);
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
	snprintf(whatwasthat, sizeof(whatwasthat), "?target_rc=%d?", target);
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
	long		t_recv;
	long		t_addtolist;
	long		t_perform;
	long		t_done;

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
	": %d, child pid: %d (%s) %s"
	,	text,	op_info(op), op_status_to_str(op_status)
	,	op_target_rc_to_str(target_rc)
	,	op->client_id, op->call_id, op->exec_pid, pidstat
	,	(op->is_copy ? "copy" : "original"));
	lrmd_debug(LOG_DEBUG
	,	"%s: lrmd_op2: to_tag: %u rt_tag: %d, interval: %d, delay: %d"
	,	text, op->timeout_tag, op->repeat_timeout_tag
	,	op->interval, op->delay);
	if (cmp_longclock(op->t_recv, zero_longclock) <= 0) {
		t_recv = -1;
	}else{
		t_recv = longclockto_ms(sub_longclock(now, op->t_recv));
	}
	if (cmp_longclock(op->t_addtolist, zero_longclock) <= 0) {
		t_addtolist = -1;
	}else{
		t_addtolist = longclockto_ms(sub_longclock(now, op->t_addtolist));
	}
	if (cmp_longclock(op->t_perform, zero_longclock) <= 0) {
		t_perform = -1;
	}else{
		t_perform = longclockto_ms(sub_longclock(now, op->t_perform));
	}
	if (cmp_longclock(op->t_done, zero_longclock) <= 0) {
		t_done = -1;
	}else{
		t_done = longclockto_ms(sub_longclock(now, op->t_recv));
	}
	lrmd_debug(LOG_DEBUG
	,	"%s: lrmd_op3: t_recv: %ldms, t_add: %ldms"
	", t_perform: %ldms, t_done: %ldms"
	,	text, t_recv, t_addtolist, t_perform, t_done);
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
		cl_free(client->app_name);
		client->app_name = NULL;
	}
	cl_free(client);
}

static lrmd_client_t*
lrmd_client_new(void)
{
	lrmd_client_t*	client;
	client = cl_calloc(sizeof(lrmd_client_t), 1);
	if (client == NULL) {
		lrmd_log(LOG_ERR, "lrmd_client_new(): out of memory when "
			 "cl_calloc lrmd_client_t.");
		dump_mem_stats();
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
	
	lrmd_debug(LOG_DEBUG, "client name: %s, client pid: %d"
		", client uid: %d, gid: %d, last request: %s"
		", last op in: %s, lastop out: %s"
		", last op rc: %s"
		,	lrm_str(client->app_name)
		,	client->pid
		,	client->uid, client->gid
		,	lrm_str(client->lastrequest)
		,	ctime(&client->lastreqstart)
		,	ctime(&client->lastreqend)
		,	ctime(&client->lastrcsent)
		);
	if (!client->ch_cmd) {
		lrmd_debug(LOG_DEBUG, "NULL client ch_cmd in dump_data_for_debug()");
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

	lrmd_debug(LOG_DEBUG, "%d clients are connecting to lrmd."
	 ,	g_hash_table_size(clients)); 
	
	g_hash_table_foreach(clients, lrmd_client_dump, NULL);
	incall = FALSE;
}

static void
lrmd_rsc_destroy(lrmd_rsc_t* rsc)
{
	CHECK_ALLOCATED(rsc, "resource", );
	--lrm_objectstats.rsccount;
	g_hash_table_remove(resources, rsc->id);
	if (rsc->id) {
		cl_free(rsc->id);
		rsc->id = NULL;
	}
	if (rsc->type) {
		cl_free(rsc->type);
		rsc->type = NULL;
	}
	if (rsc->class) {
		cl_free(rsc->class);
		rsc->class = NULL;
	}
	if (rsc->provider) {
		cl_free(rsc->provider);
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
	cl_free(rsc);
}

static lrmd_rsc_t*
lrmd_rsc_new(const char * id, struct ha_msg* msg)
{
	lrmd_rsc_t*	rsc;
	rsc = (lrmd_rsc_t *)cl_calloc(sizeof(lrmd_rsc_t),1);
	if (rsc == NULL) {
		lrmd_log(LOG_ERR, "lrmd_rsc_new(): out of memory when cl_calloc "
			 "a lrmd_rsc_t");
		dump_mem_stats();
		return NULL;
	}
	if (id) {
		rsc->id = cl_strdup(id);
	}
	if (msg) {
		rsc->type = cl_strdup(ha_msg_value(msg, F_LRM_RTYPE));
		rsc->class = cl_strdup(ha_msg_value(msg, F_LRM_RCLASS));
		if (NULL == ha_msg_value(msg, F_LRM_RPROVIDER)) {
			lrmd_log(LOG_NOTICE, "%s(): No %s field in message"
			, __FUNCTION__, F_LRM_RPROVIDER);
		}else{
			rsc->provider = cl_strdup(ha_msg_value(msg, F_LRM_RPROVIDER));
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
	g_hash_table_insert(resources, cl_strdup(id), rsc);
	++lrm_objectstats.rsccount;
	return rsc;
errout:
	lrmd_rsc_destroy(rsc); /* violated property */ /* Or so BEAM thinks :-) */
	rsc = NULL;
	return rsc;
}
static void
lrmd_rsc_dump(char* rsc_id, const char * text)
{
	static gboolean	incall = FALSE;
	GList*		oplist;
	lrmd_rsc_t*	rsc;
	
	rsc = (lrmd_rsc_t*) g_hash_table_lookup(resources, rsc_id);
	CHECK_ALLOCATED(rsc, "rsc", );
	/* TODO: Dump params and last_op_table FIXME */

	lrmd_debug(LOG_DEBUG, "%s: resource %s/%s/%s/%s"
	,	text
	,	lrm_str(rsc->id)
	,	lrm_str(rsc->type)
	,	lrm_str(rsc->class)
	,	lrm_str(rsc->provider));

	/* Avoid infinite recursion loops... */
	if (incall) {
		return;
	}
	incall = TRUE;

	lrmd_debug(LOG_DEBUG, "%s: rsc->op_list...", text);
	oplist = g_list_first(rsc->op_list);
	for(;NULL!=oplist; oplist=g_list_next(oplist)) {
		lrmd_op_dump(oplist->data, "rsc->op_list");
	}

	lrmd_debug(LOG_DEBUG, "%s: rsc->repeat_op_list...", text);
	oplist = g_list_first(rsc->repeat_op_list);
	for(; NULL!=oplist; oplist=g_list_next(oplist)) {
		lrmd_op_dump(oplist->data, "rsc->repeat_op_list");
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

	lrmd_debug(LOG_DEBUG, "%d resources are managed by lrmd."
	,	g_hash_table_size(resources)); 
	g_hash_table_foreach(resources, dump_id_rsc_pair, text);
	incall = FALSE;
}


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
		if (system(cmd) < 0) {
			lrmd_log(LOG_ERR, "Running [%s] failed", cmd);
		}
		snprintf(cmd, sizeof(cmd)
		,	"ps axww | logger -p daemon.info -t 't/o ps:'");
		lrmd_debug(LOG_DEBUG, "Running [%s]", cmd);
		if (system(cmd) < 0) {
			lrmd_log(LOG_ERR, "Running [%s] failed", cmd);
		}
	}
}
int
main(int argc, char ** argv)
{
	int req_restart = FALSE;
	int req_status  = FALSE;
	int req_stop    = FALSE;
	
	int argerr = 0;
	int flag;
	char * inherit_debuglevel;

	cl_malloc_forced_for_glib();
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

	inherit_debuglevel = getenv(HADEBUGVAL);
	if (inherit_debuglevel != NULL) {
		debug_level = atoi(inherit_debuglevel);
	}

	cl_log_set_entity(lrm_system_name);
	cl_log_enable_stderr(debug_level?TRUE:FALSE);
	cl_log_set_facility(LOG_DAEMON);

	/* Use logd if it's enabled by heartbeat */
	cl_inherit_use_logd(ENV_PREFIX""KEY_LOGDAEMON, 0);

	inherit_logconfig_from_environment();

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

static const char usagemsg[] = "[-srkhV]\n\ts: status\n\tr: restart"
	"\n\tk: kill\n\tm: register to apphbd\n\ti: the interval of apphb\n\t"
	"h: help\n\tV: debug\n";

void
usage(const char* cmd, int exit_status)
{
	FILE* stream;

	stream = exit_status ? stderr : stdout;

	fprintf(stream, "usage: %s %s", cmd, usagemsg);
	fflush(stream);

	exit(exit_status);
}

static gboolean
lrm_shutdown(void)
{
	lrmd_log(LOG_INFO,"lrmd is shutting down");
	if (mainloop != NULL && g_main_is_running(mainloop)) {
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
		lrmd_debug(LOG_DEBUG, "sigterm_action: can't shutdown now.");
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
		(void)open("/dev/null", j == 0 ? O_RDONLY : O_RDONLY);
	}
	CL_IGNORE_SIG(SIGINT);
	CL_IGNORE_SIG(SIGHUP);
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
	char lrmd_instance[40];

	if (reg_to_apphbd == FALSE) {
		return -1;
	}

	sprintf(lrmd_instance, "%s_%ld", lrm_system_name, (long)getpid());
	if (apphb_register(lrm_system_name, lrmd_instance) != 0) {
		lrmd_log(LOG_ERR, "Failed when trying to register to apphbd.");
		lrmd_log(LOG_ERR, "Maybe apphd isnot running. Quit.");
		return -1;
	}
	lrmd_log(LOG_INFO, "Registered to apphbd.");

	apphb_setinterval(apphb_interval);
	apphb_setwarn(apphb_interval*APPHB_WARNTIME_FACTOR);

	Gmain_timeout_add(apphb_interval - APPHB_INTVL_DETLA, emit_apphb, NULL);

	return 0;
}

static gboolean
emit_apphb(gpointer data)
{
	if (reg_to_apphbd == FALSE) {
		return FALSE;
	}

	if (apphb_hb() != 0) {
		lrmd_log(LOG_ERR, "emit_apphb: Failed to emit an apphb.");
		reg_to_apphbd = FALSE;
		return FALSE;
	};

	return TRUE;
}

/* main loop of the daemon*/
int
init_start ()
{
	long pid;
	DIR* dir = NULL;
	PILPluginUniv * PluginLoadingSystem = NULL;
	struct dirent* subdir;
	struct passwd*	pw_entry;
	char* dot = NULL;
	char* ra_name = NULL;
        int len;
	IPC_Auth	* auth = NULL;
	int		one = 1;
	GHashTable*	uidlist;
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
	
	if ((pid = cl_lock_pidfile(PID_FILE)) < 0) {
		lrmd_log(LOG_ERR, "already running: [pid %d].", cl_read_pidfile(PID_FILE));
		lrmd_log(LOG_ERR, "Startup aborted (already running).  Shutting down."); 
		exit(100);
	}
	
	register_pid(FALSE, sigterm_action);

	/* load RA plugins   */
	PluginLoadingSystem = NewPILPluginUniv (PLUGIN_DIR);
	PILLoadPlugin(PluginLoadingSystem, "InterfaceMgr", "generic",
				  &RegisterRqsts);

	/*
	 *	FIXME!!!
	 *	Much of the code through the end of the next loop is
	 *	unnecessary - The plugin system will do this for you quite
	 *	nicely.  And, it does it portably, too...
	 */

	dir = opendir(RA_PLUGIN_DIR);
	if (NULL == dir) {
		lrmd_log(LOG_ERR, "main: can not open RA plugin dir "RA_PLUGIN_DIR);
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

	uidlist = g_hash_table_new(g_direct_hash, g_direct_equal);
	/* Add root's uid */
	g_hash_table_insert(uidlist, GUINT_TO_POINTER(0), &one); 

	pw_entry = getpwnam(HA_CCMUSER);
	if (pw_entry == NULL) {
		lrmd_log(LOG_ERR, "Cannot get the uid of HACCMUSER");
	} else {
		g_hash_table_insert(uidlist, GUINT_TO_POINTER(pw_entry->pw_uid)
				    , &one); 
	}

	if ( NULL == (auth = MALLOCT(struct IPC_AUTH)) ) {
		lrmd_log(LOG_ERR, "init_start: MALLOCT (IPC_AUTH) failed.");
	} else {
		auth->uid = uidlist;
		auth->gid = NULL;
	}

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
	G_main_add_IPC_WaitConnection( G_PRIORITY_HIGH, conn_cmd, auth, FALSE,
				   on_connect_cmd, conn_cmd, NULL);

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
	G_main_add_IPC_WaitConnection( G_PRIORITY_HIGH, conn_cbk, auth, FALSE,
	                               on_connect_cbk, conn_cbk, NULL);
	
	set_sigchld_proctrack(G_PRIORITY_HIGH);

	lrmd_debug(LOG_DEBUG, "Enabling coredumps");
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
	drop_privs(0, 0); /* become "nobody" */
	
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
	,		g_str_equal, cl_free, NULL);
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
                apphb_unregister();
                reg_to_apphbd = FALSE;
        }

	return_to_orig_privs();
	conn_cmd->ops->destroy(conn_cmd);
	conn_cmd = NULL;

	conn_cbk->ops->destroy(conn_cbk);
	conn_cbk = NULL;

	g_hash_table_destroy(uidlist);
	if ( NULL != auth ) {
		cl_free(auth);
	}
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

	/*get the message */
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

gboolean
on_receive_cmd (IPC_Channel* ch, gpointer user_data)
{
	int i;
	lrmd_client_t* client = NULL;
	struct ha_msg* msg = NULL;
	const char* type = NULL;

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
	msg = msgfromIPC_noauth(ch);
	if (NULL == msg) {
		lrmd_log(LOG_ERR, "on_receive_cmd: can not receive messages.");
		return TRUE;
	}
	
	if (TRUE == shutdown_in_progress ) {
		send_ret_msg(ch,HA_FAIL);
		ha_msg_del(msg);
		lrmd_debug(LOG_DEBUG, "on_receive_cmd: return HA_FAIL because"\
			 " lrmd is in shutdown.");
		return TRUE;
	}	
	
	/*dispatch the message*/
	type = ha_msg_value(msg, F_LRM_TYPE);

	for (i=0; i<DIMOF(msg_maps); i++) {
		if (0 == strncmp(type, msg_maps[i].msg_type, MAX_MSGTYPELEN)) {
			int ret;

			strncpy(client->lastrequest, type, sizeof(client->lastrequest));
			client->lastreqstart = time(NULL);
			/*call the handler of the message*/
			ret = msg_maps[i].handler(client, msg);
			client->lastreqend = time(NULL);

			/*return rc to client if need*/
			if (msg_maps[i].need_return_ret) {
				send_ret_msg(ch, ret);
				client->lastrcsent = time(NULL);
			}
			break;
		}
	}
	if (i == DIMOF(msg_maps)) {
		lrmd_log(LOG_ERR, "on_receive_cmd: received an unknown msg");
	}

	/*delete the msg*/
	ha_msg_del(msg);

	return TRUE;
}
static void
remove_repeat_op_from_client(gpointer key, gpointer value, gpointer user_data)
{
	lrmd_rsc_t* rsc = (lrmd_rsc_t*)value;
	pid_t pid = GPOINTER_TO_UINT(user_data); /* pointer cast as int */
	GList* op_node = NULL;
	lrmd_op_t* op = NULL;
		
	op_node = g_list_first(rsc->repeat_op_list);
	while (NULL != op_node) {
		op = (lrmd_op_t*)op_node->data;
		if (NULL == op) {
			lrmd_log(LOG_ERR
			,	"%s (): repeat_op_list node has NULL data."
			,	__FUNCTION__);
		}
		else if (op->client_id == pid) {
			op_node = g_list_next(op_node);
			rsc->repeat_op_list = g_list_remove(rsc->repeat_op_list, op);
			lrmd_op_destroy(op);
		}
		else {
			op_node = g_list_next(op_node);
		}
	}
	
		
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
	/* Remove from clients */
	g_hash_table_remove(clients, (gpointer)&client->pid);
	
	/* Search all resources for repeating ops this client owns */
	g_hash_table_foreach(resources
	,	remove_repeat_op_from_client, GUINT_TO_POINTER(client->pid));
	
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

/*
 * This function is called when the operation timeout expired without
 * the operation completing normally.
 */
gboolean
on_op_timeout_expired(gpointer data)
{
	lrmd_op_t* op = NULL;
	lrmd_rsc_t* rsc = NULL;
	
	op = (lrmd_op_t*)data;
	CHECK_ALLOCATED(op, "op", FALSE);

	if (op->exec_pid == 0) {
		lrmd_log(LOG_ERR, "on_op_timeout_expired: op->exec_pid is an "
			"invalid value. An internal error!");
		return FALSE;
	}

	if (HA_OK != ha_msg_mod_int(op->msg, F_LRM_OPSTATUS, LRM_OP_TIMEOUT)) {
		LOG_FAILED_TO_ADD_FIELD("opstatus")
	}

	lrmd_log(LOG_WARNING, "%s: TIMEOUT: %s."
	,	__FUNCTION__,  op_info(op));
	if (debug_level) {
		lrm_debug_running_op(op, __FUNCTION__);
	}
	
	rsc = lookup_rsc(op->rsc_id);
	on_op_done(op);
	if (rsc != NULL) {
		perform_op(rsc);
	}
	return FALSE;
}

/* This function called when its time to run a repeating operation now */
/* Move op from repeat queue to running queue */
gboolean
on_repeat_op_readytorun(gpointer data)
{
	lrmd_op_t* op = NULL;
	lrmd_rsc_t* rsc = NULL;
	
	op = (lrmd_op_t*)data;
	CHECK_ALLOCATED(op, "op", FALSE );

	if (op->exec_pid == 0) {
		lrmd_log(LOG_ERR, "%s: exec_pid is 0. A internal error!"
		,	__FUNCTION__);
		return FALSE;
	}

	lrmd_debug2(LOG_DEBUG
	, 	"%s: remove an operation %s from the repeat operation list and "
		"add it to the operation list."
	, 	__FUNCTION__, op_info(op));

	rsc = lookup_rsc(op->rsc_id);
	if (rsc == NULL) {
		return FALSE;
	}
	rsc->repeat_op_list = g_list_remove(rsc->repeat_op_list, op);
	Gmain_timeout_remove(op->repeat_timeout_tag);

	op->repeat_timeout_tag = -1;
	op->exec_pid = -1;
	op->timeout_tag = -1;
	
	if (!shutdown_in_progress) {
		op->t_addtolist = time_longclock();
		rsc->op_list = g_list_append(rsc->op_list, op);
		if (g_list_length(rsc->op_list) >= 4) {
			lrmd_log(LOG_WARNING
			,	"%s: Operations list for %s is suspicously"
			" long [%d]"
			,	__FUNCTION__, rsc->id
			,	g_list_length(rsc->op_list));
			lrmd_rsc_dump(rsc->id, "rsc->op_list: too many ops");
		}
	}
	perform_op(rsc);

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
		lrmd_log(LOG_ERR, "on_msg_register: didnot get app_name from "
			"the ha message.");
		return HA_FAIL;
	}
	client->app_name = cl_strdup(app_name);

	if (HA_OK != ha_msg_value_int(msg, F_LRM_PID, &client->pid)) {
		lrmd_log(LOG_ERR,
			"on_msg_register: didnot get pid from the ha message.");
		return HA_FAIL;
	}

	if (HA_OK != ha_msg_value_int(msg, F_LRM_GID, (int *)&client->gid)) {
		lrmd_log(LOG_ERR,
			"on_msg_register: didnot get gid from the ha message.");
		return HA_FAIL;
	}

	if (HA_OK != ha_msg_value_int(msg, F_LRM_UID, (int *)&client->uid)) {
		lrmd_log(LOG_ERR,
			"on_msg_register: didnot get uid from the ha message.");
		return HA_FAIL;
	}

	exist = lookup_client(client->pid);
	if (NULL != exist) {
		g_hash_table_remove(clients, (gpointer)&client->pid);
		on_remove_client(exist);
		lrmd_log(LOG_NOTICE,
			"on_msg_register: the client [pid:%d] already exists in "
			"internal client list, let remove it at first."
		, 	client->pid);
	}

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

 lrmd_debug(LOG_DEBUG
	, 	"on_msg_get_rsc_classes:client [%d] wants to get rsc classes"
	,	client->pid);
	
	ret = create_lrm_ret(HA_OK, 4);
	CHECK_RETURN_OF_CREATE_LRM_RET

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
	CHECK_RETURN_OF_CREATE_LRM_RET

	rclass = ha_msg_value(msg, F_LRM_RCLASS);
	if (rclass == NULL) {
		lrmd_log(LOG_ERR, "on_msg_get_rsc_types: cannot get the "
			"resource class field from the message.");
		return HA_FAIL;
	}
	
	lrmd_debug(LOG_DEBUG, "on_msg_get_rsc_types: the client [pid:%d] "
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
	CHECK_RETURN_OF_CREATE_LRM_RET

	rclass = ha_msg_value(msg, F_LRM_RCLASS);
	rtype = ha_msg_value(msg, F_LRM_RTYPE);
	
	lrmd_debug(LOG_DEBUG
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
			cl_msg_add_list(ret, F_LRM_RPROVIDERS, providers);
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
	
	lrmd_debug(LOG_DEBUG
	,	"%s: the client [pid:%d] want to get rsc metadata of %s::%s."
	,	__FUNCTION__
	,	client->pid
	,	rclass
	,	rtype);

	ret = create_lrm_ret(HA_OK, 5);
	CHECK_RETURN_OF_CREATE_LRM_RET
	
	RAExec = g_hash_table_lookup(RAExecFuncs,rclass);
	if (NULL == RAExec) {
		lrmd_log(LOG_NOTICE
		, 	"%s: can not find the class %s."
		,	__FUNCTION__
		,	rclass);
	}
	else {
		char* meta = RAExec->get_resource_meta(rtype,provider);
		if (NULL != meta) {
			if (HA_OK != ha_msg_add(ret,F_LRM_METADATA, meta)) {
				LOG_FAILED_TO_ADD_FIELD("metadata")
			}
			g_free(meta);
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
		LOG_FAILED_TO_ADD_FIELD("resource id")
	}	
}
int
on_msg_get_all(lrmd_client_t* client, struct ha_msg* msg)
{
	struct ha_msg* ret = NULL;

	CHECK_ALLOCATED(client, "client", HA_FAIL);
	CHECK_ALLOCATED(msg, "message", HA_FAIL);
	
	lrmd_debug(LOG_DEBUG
	,	"on_msg_get_all:client [%d] want to get all rsc information."
	,	client->pid);

	ret = create_lrm_ret(HA_OK, g_hash_table_size(resources) + 1);
	CHECK_RETURN_OF_CREATE_LRM_RET

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

	lrmd_debug(LOG_DEBUG
	,	"on_msg_get_rsc: the client [pid:%d] wants to get "
		"the information of the resource [rsc_id: %s]"
	,	client->pid, lrmd_nullcheck(id));
	
	rsc = lookup_rsc_by_msg(msg);
	if (NULL == rsc) {
		lrmd_debug(LOG_DEBUG
		,	"on_msg_get_rsc: no rsc with id %s."
		,	lrmd_nullcheck(id));
		ret = create_lrm_ret(HA_FAIL, 1);
		CHECK_RETURN_OF_CREATE_LRM_RET
	}
	else {
		ret = create_lrm_ret(HA_OK, 5);
		CHECK_RETURN_OF_CREATE_LRM_RET

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
				LOG_FAILED_TO_ADD_FIELD("provider")
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

	lrmd_debug(LOG_DEBUG
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
					LOG_FAILED_TO_ADD_FIELD("operation count")
				}
			}
		}
	}

	if (NULL == ret) {
		lrmd_log(LOG_ERR
		, 	"%s: return ha_msg ret is null, will re-create it again."
		,	__FUNCTION__);
		ret = create_lrm_ret(HA_OK, 1);
		CHECK_RETURN_OF_CREATE_LRM_RET

		if (HA_OK != ha_msg_add_int(ret, F_LRM_OPCNT, 0)) {
			LOG_FAILED_TO_ADD_FIELD("operation count")
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
	GList* op_node = NULL;
	lrmd_op_t* op = NULL;
	const char* id = NULL;

	CHECK_ALLOCATED(client, "client", HA_FAIL);
	CHECK_ALLOCATED(msg, "message", HA_FAIL);

	id = ha_msg_value(msg, F_LRM_RID);

	lrmd_debug(LOG_DEBUG
	,	"on_msg_del_rsc: client [%d] want to delete rsc %s"
	,	client->pid, lrmd_nullcheck(id));

	rsc = lookup_rsc_by_msg(msg);

	if (NULL == rsc) {
		lrmd_debug(LOG_DEBUG, "on_msg_del_rsc: no rsc with such id.");
		return HA_FAIL;
	}
	/* remove pending ops */
	op_node = g_list_first(rsc->op_list);
	while (NULL != op_node) {
		op = (lrmd_op_t*)op_node->data;
		op_node = g_list_next(op_node);
		rsc->op_list = g_list_remove(rsc->op_list, op);
		lrmd_op_destroy(op);
	}
	/* remove repeat ops */
	op_node = g_list_first(rsc->repeat_op_list);
	while (NULL != op_node) {
		op = (lrmd_op_t*)op_node->data;
		op_node = g_list_next(op_node);
		rsc->repeat_op_list = 
			g_list_remove(rsc->repeat_op_list, op);
		flush_op(op);
	}
	/* remove from hash table */
	g_hash_table_remove(resources, rsc->id);
	
	/* free the memory of rsc */
	lrmd_rsc_destroy(rsc);

	return HA_OK;
}

static gboolean
free_str_hash_pair(gpointer key, gpointer value, gpointer user_data)
{
	GHashTable* table = (GHashTable*) value;
	cl_free(key);
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

	id = ha_msg_value(msg, F_LRM_RID);
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
		return HA_FAIL;
	}

	rsc->params = ha_msg_value_str_table(msg,F_LRM_PARAM);
	rsc->last_op_table = g_hash_table_new(g_str_hash, g_str_equal);
	g_hash_table_insert(resources, cl_strdup(rsc->id), rsc);
 
	return HA_OK;
}

int
on_msg_perform_op(lrmd_client_t* client, struct ha_msg* msg)
{
	lrmd_rsc_t* rsc = NULL;
	GList* node = NULL;
	const char* type = NULL;
	lrmd_op_t* op = NULL;
	int timeout = 0;

	CHECK_ALLOCATED(client, "client", HA_FAIL);
	CHECK_ALLOCATED(msg, "message", HA_FAIL);

	rsc = lookup_rsc_by_msg(msg);
	if (NULL == rsc) {
		lrmd_log(LOG_ERR,
			"on_msg_perform_op: no resource with such id.");
		return -1;
	}

	call_id++;
	type = ha_msg_value(msg, F_LRM_TYPE);
	/* when a flush request arrived, flush all pending ops */
	if (0 == STRNCMP_CONST(type, FLUSHOPS)) {
	lrmd_debug(LOG_DEBUG
		,	"on_msg_perform_op:client [%d] flush operations"
		,	client->pid);
		
		node = g_list_first(rsc->op_list);
		while (NULL != node ) {
			op = (lrmd_op_t*)node->data;
			node = g_list_next(node);
			rsc->op_list = g_list_remove(rsc->op_list, op);
			flush_op(op);
		}
		node = g_list_first(rsc->repeat_op_list);
		while (NULL != node ) {
			op = (lrmd_op_t*)node->data;
			node = g_list_next(node);
			rsc->repeat_op_list =
					g_list_remove(rsc->repeat_op_list, op);
			flush_op(op);
		}
	}
	else
	if (0 == STRNCMP_CONST(type, CANCELOP)) {
		int cancel_op_id;
		ha_msg_value_int(msg, F_LRM_CALLID, &cancel_op_id);
		
		lrmd_debug(LOG_DEBUG
		,	"%s:client [pid:%d] cancel the operation [callid:%d]"
		,	__FUNCTION__
		,	client->pid
		, 	cancel_op_id);
		
		node = g_list_first(rsc->op_list);
		while (NULL != node ) {
			op = (lrmd_op_t*)node->data;
			node = g_list_next(node);
			if ( op->call_id == cancel_op_id) {
				lrmd_debug(LOG_DEBUG
				,"%s: cancel the operation %s from the internal"
					" operation list)"
				, __FUNCTION__
				,op_info(op));
				rsc->op_list = g_list_remove(rsc->op_list, op);
				flush_op(op);
				return call_id;
			}
		}
		node = g_list_first(rsc->repeat_op_list);
		while (NULL != node ) {
			op = (lrmd_op_t*)node->data;
			node = g_list_next(node);
			if ( op->call_id == cancel_op_id) {
				lrmd_debug(LOG_DEBUG
				, "%s: cancel the operation %s from the "
					"internal repeat operation list)"
				, __FUNCTION__
				, op_info(op));
				rsc->repeat_op_list =
					g_list_remove(rsc->repeat_op_list, op);
				flush_op(op);
				return call_id;
			}
		}
		return -1;		
	}
	else {
		if (HA_OK != ha_msg_add_int(msg, F_LRM_CALLID, call_id)) {
			LOG_FAILED_TO_ADD_FIELD("callid")
			return -1;
		}
		if (HA_OK !=ha_msg_add(msg, F_LRM_APP, client->app_name)) {
			LOG_FAILED_TO_ADD_FIELD("app_name");
			return -1;
		}

		op = lrmd_op_new();
		if (op == NULL) {
			return -1;
		}
		op->call_id = call_id;
		op->exec_pid = -1;
		op->client_id = client->pid;
		op->timeout_tag = -1;
		op->rsc_id = cl_strdup(rsc->id);
		op->msg = ha_msg_copy(msg);
		op->t_recv = time_longclock();
		
		lrmd_debug(LOG_DEBUG
		, "%s: client [%d] want to add an operation %s on resource %s."
		,	__FUNCTION__
		,	client->pid
		,	op_info(op)
		,	NULL!=op->rsc_id ? op->rsc_id : "#EMPTY#");

		if (HA_OK!=ha_msg_value_int(op->msg, F_LRM_INTERVAL,
						 &op->interval)) {
			LOG_FAILED_TO_ADD_FIELD("interval")
			goto getout;
		}
		if (HA_OK!=ha_msg_value_int(op->msg, F_LRM_TIMEOUT, &timeout)) {
			LOG_FAILED_TO_ADD_FIELD("timeout");
			goto getout;
		}		
		if (HA_OK!=ha_msg_value_int(op->msg, F_LRM_DELAY,
						 &op->delay)) {
			LOG_FAILED_TO_ADD_FIELD("delay")
			goto getout;
		}
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
			op->t_addtolist = time_longclock();
			rsc->op_list = g_list_append(rsc->op_list, op);

			if (g_list_length(rsc->op_list) >= 4) {
				lrmd_log(LOG_ERR
				,	"%s: Operations list for %s is suspicously"
				" long [%d]"
				,	__FUNCTION__, rsc->id
				,	g_list_length(rsc->op_list));
				lrmd_rsc_dump(rsc->id, "rsc->op_list: too many ops");
			}
		}

		perform_op(rsc);
	}

	return call_id;
getout:
	/* FIXME.
	  The following code just for make BEAM happy, since I cannot change
	  beam.tcl to void this warning. Is it a BEAM bug?
	*/
	ha_msg_del(op->msg);
	op->msg = NULL;
	if (op->rsc_id !=NULL ) {
		cl_free(op->rsc_id);
		op->rsc_id = NULL;
	}

	lrmd_op_destroy(op);
	return -1;
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
	lrmd_debug(LOG_DEBUG
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
	if ( NULL == rsc->op_list )
	{
		if (HA_OK != ha_msg_add_int(ret, F_LRM_STATE, LRM_RSC_IDLE)) {
			LOG_FAILED_TO_ADD_FIELD("state")
			ha_msg_del(ret);
			return HA_FAIL;
		}
		lrmd_debug(LOG_DEBUG
		,	"on_msg_get_state:state of rsc %s is LRM_RSC_IDLE"
		,	lrmd_nullcheck(id));
		
	}
	else {
		if (HA_OK != ha_msg_add_int(ret, F_LRM_STATE, LRM_RSC_BUSY)) {
			LOG_FAILED_TO_ADD_FIELD("state")
			ha_msg_del(ret);
			return HA_FAIL;
		}
		lrmd_debug(LOG_DEBUG
		,	"on_msg_get_state:state of rsc %s is LRM_RSC_BUSY"
		,	lrmd_nullcheck(id));
	}	
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
		LOG_FAILED_TO_ADD_FIELD("operation count")
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
/* /////////////////////op functions//////////////////////////////////////////// */
static void 
record_op_completion(lrmd_client_t* client, lrmd_op_t* op)
{
	lrmd_rsc_t* rsc = NULL;
	lrmd_op_t* old_op = NULL;
	lrmd_op_t* new_op = NULL;
	GHashTable* client_last_op = NULL;
	const char* op_type = NULL;
	
	rsc = lookup_rsc(op->rsc_id);
	if (rsc == NULL) {
		lrmd_log(LOG_ERR, "record_op_completion: cannot find the "
			"resource %s regarding the operation %s"
		,	op->rsc_id, op_info(op));
		return;
	}
	/*find the hash table for the client*/
	client_last_op = g_hash_table_lookup(rsc->last_op_table
	, 			client->app_name);
	if (NULL == client_last_op) {
		client_last_op = g_hash_table_new_full(	g_str_hash
		, 	g_str_equal, cl_free, NULL);
		g_hash_table_insert(rsc->last_op_table
		,	(gpointer)cl_strdup(client->app_name)
		,	(gpointer)client_last_op);
	}
		
	/* Insert the op into the hash table for the client*/
	op_type = ha_msg_value(op->msg, F_LRM_OP);
	old_op = g_hash_table_lookup(client_last_op, op_type);
	new_op = lrmd_op_copy(op);
	if (NULL != old_op) {
		g_hash_table_replace(client_last_op
		, 	cl_strdup(op_type)
		,	(gpointer)new_op);
		lrmd_op_destroy(old_op);
	}
	else {
		g_hash_table_insert(client_last_op
		, 	cl_strdup(op_type)
		,	(gpointer)new_op);
	}

}
/* this function return the op result to client if it is generated by client.
 * or do some monitor check if it is generated by monitor.
 * then remove it from the op list and put it into the lastop field of rsc.
 */
int
on_op_done(lrmd_op_t* op)
{
	int target_rc = 0;
	int last_rc = 0;
	int op_rc = 0;
	op_status_t op_status;
	int op_status_int;
	int need_notify = 0;
	lrmd_client_t* client = NULL;
	lrmd_rsc_t* rsc = NULL;

	
	CHECK_ALLOCATED(op, "op", HA_FAIL );
	if (op->exec_pid == 0) {
		lrmd_log(LOG_ERR, "on_op_done: op->exec_pid == 0.");
		return HA_FAIL;
	}
	op->t_done = time_longclock();
	
	lrmd_debug2(LOG_DEBUG, "on_op_done: %s", op_info(op));
	lrmd_debug2(LOG_DEBUG
		 ,"TimeStamp:  Recv:%ld,Add to List:%ld,Perform:%ld, Done %ld"
		 ,longclockto_ms(op->t_recv)
		 ,longclockto_ms(op->t_addtolist)
		 ,longclockto_ms(op->t_perform)
		 ,longclockto_ms(op->t_done));

	/*  we should check if the resource exists. */
	rsc = lookup_rsc(op->rsc_id);
	if (rsc == NULL) {
		if( op->timeout_tag > 0 ) {
			Gmain_timeout_remove(op->timeout_tag);
		}
		lrmd_log(LOG_ERR
		,	"%s: the resource for the operation %s does not exist."
		,	__FUNCTION__, op_info(op));
		lrmd_op_dump(op, __FUNCTION__);
		lrmd_dump_all_resources();
		/* delete the op */
		lrmd_op_destroy(op);

		return HA_FAIL;

	}

	if (HA_OK != ha_msg_value_int(op->msg,F_LRM_TARGETRC,&target_rc)){
		lrmd_log(LOG_ERR
		,	"%s: can not get target status field from a message"
		,	__FUNCTION__);
		return HA_FAIL;
	}
	if (HA_OK !=
		ha_msg_value_int(op->msg, F_LRM_OPSTATUS, &op_status_int)) {
		lrmd_log(LOG_ERR
		,	"%s: can not get operation status field from a message"
		,	__FUNCTION__);
		return HA_FAIL;
	}
	op_status = (op_status_t)op_status_int;
	
	if (debug_level >= 2) {
		lrmd_op_dump(op, __FUNCTION__);
	}
	if (LRM_OP_DONE != op_status) {
		need_notify = 1;
	} else if (HA_OK != ha_msg_value_int(op->msg,F_LRM_RC,&op_rc)){
		lrmd_debug(LOG_DEBUG, "on_op_done: will callback due to not "
			"finding F_LRM_RC field in the message op->msg.");
		need_notify = 1;
	} else if (EVERYTIME == target_rc) {
		lrmd_debug(LOG_DEBUG, "on_op_done: will callback for being "
			"asked to callback everytime.");
		need_notify = 1;
	} else if (CHANGED == target_rc) {
		if (HA_OK != ha_msg_value_int(op->msg,F_LRM_LASTRC,
						&last_rc)){
			lrmd_debug(LOG_DEBUG ,"on_op_done: will callback because "
				"this is first execution [rc: %d].", op_rc);
			need_notify = 1;
		} else {
			if (last_rc != op_rc) {
				lrmd_debug(LOG_DEBUG, "on_op_done: will callback "
					" for this rc %d != last rc %d"
				, 	op_rc, last_rc);
				need_notify = 1;
			}
		}
		if (HA_OK != ha_msg_mod_int(op->msg, F_LRM_LASTRC,
						op_rc)){
			lrmd_log(LOG_ERR,"on_op_done: can not save status to "
				"the message op->msg.");
			return HA_FAIL;
		}
	}
	else {
		if ( op_rc==target_rc ) {
			lrmd_debug(LOG_DEBUG
			,"on_op_done: will callback for target rc %d reached"
			,op_rc);
			
			need_notify = 1;
		}
	}

	/*
	 * The code above is way too complicated. It needs work to
	 * simplify it correctly.  FIXME.
	 * Suggest factoring out the debug/dump code among other things.
	 * -- it should go in lrmd_op_dump()
	 */

	/*
	 *	If I understand the code above correctly...
	 *	need_notify is set to false in only one case:
	 *
	 *	op_status ==  LRM_DONE
	 * and	target_rc == CHANGED
	 * and 	F_LRM_RC field == F_LRM_LASTRC field
	 *	(with both present)
	 *
	 * Side-effects:
	 *	set F_LRM_LASTRC to the value from F_LRM_RC field
	 *		when target_rc == CHANGED and F_LRM_RC present
	 *
	 *	I think this code does the same thing, but is easier
	 *	to understand.
	 *
	 *	op_rc = -1;
	 *	ha_msg_value_int(op->msg,F_LRM_LRM_RC, &op_rc);
	 *	last_rc = -1;
	 *	ha_msg_value_int(op->msg,F_LRM_LASTRC, &last_rc);
	 *
	 *	if (CHANGED == target_rc && op_rc != -1
	 *	&&	HA_OK != ha_msg_mod_int(op->msg,F_LRM_LASTRC, op_rc)){
	 *		lrmd_log(LOG_ERR, "on_op_done: can not save status ");
	 *		return HA_FAIL;
	 *	}
	 *	need_notify = TRUE;
	 *	if (LRM_DONE == op_status && CHANGED == target_rc
	 *	&&	-1 != op_rc && op_rc == last_rc) {
	 *		need_notify = FALSE;
	 *	}
	 *
	 */


	if ( need_notify ) {

		/* send the result to client */
		/* we have to check whether the client still exists */
		/* for the client may signoff during the op running. */
		client = lookup_client(op->client_id);
		if (NULL != client) {
			/* the client still exists */
			if (NULL == client->ch_cbk) {
				lrmd_log(LOG_ERR,
					"on_op_done: client->ch_cbk is null");
			} else if (HA_OK != msg2ipcchan(op->msg, client->ch_cbk)) {
				lrmd_log(LOG_ERR,
					"on_op_done: can not send the ret msg");
			}
		} else {	
			lrmd_log(LOG_ERR
			,	"%s: client for the operation %s does not exist"
				" and client requested notification."
			,	__FUNCTION__,	op_info(op));
			lrmd_op_dump(op, "lrmd_op_done: no client");
		}
			

	}
	
	/* remove the op from op_list and copy to last_op */
	rsc->op_list = g_list_remove(rsc->op_list,op);
	lrmd_debug(LOG_DEBUG
	, 	"on_op_done:%s is removed from op list" 
	,	op_info(op));

	if( op->timeout_tag > 0 ) {
		Gmain_timeout_remove(op->timeout_tag);
		op->timeout_tag = -1;
	}
	
	
	/*
	 * I SUGGEST MOVING THIS CODE TO A SEPARATE FUNCTION FIXME
	 * perhaps name it record_op_completion() or something
	 *
	 * if (null != client) {
	 *	record_op_completion(client, op);
	 * }
	 */
	/*save the op in the last op hash table*/
	client = lookup_client(op->client_id);
	if (NULL != client) {
		record_op_completion(client, op);
	}
	
	/*copy the repeat op to repeat list to wait next perform */
	if ( 0 != op->interval && NULL != lookup_client(op->client_id)
	&&   LRM_OP_CANCELLED != op_status) {
		lrmd_op_t* repeat_op = lrmd_op_copy(op);
		repeat_op->exec_pid = -1;
		repeat_op->timeout_tag = -1;
		repeat_op->is_copy = FALSE;
		repeat_op->repeat_timeout_tag = 
			Gmain_timeout_add(op->interval,	
					on_repeat_op_readytorun, repeat_op);
		rsc->repeat_op_list = 
			g_list_append (rsc->repeat_op_list, repeat_op);
		lrmd_debug2(LOG_DEBUG
		, "on_op_done:repeat %s is added to repeat op list to wait" 
		, op_info(op));
		
	}
	lrmd_op_destroy(op);

	return HA_OK;
}
/* this function flush one op */
int
flush_op(lrmd_op_t* op)
{
	lrmd_debug(LOG_DEBUG, "flush_op: start.");
	CHECK_ALLOCATED(op, "op", HA_FAIL );
	if (op->exec_pid == 0) {
		lrmd_debug(LOG_ERR, "flush_op: op->exec_pid == 0.");
		return HA_FAIL;
	}

	if (HA_OK != ha_msg_add_int(op->msg, F_LRM_RC, HA_FAIL)) {
		LOG_FAILED_TO_ADD_FIELD("F_LRM_RC")
		return HA_FAIL;
	}

	if (HA_OK != ha_msg_mod_int(op->msg,F_LRM_OPSTATUS,(int)LRM_OP_CANCELLED)){
		LOG_FAILED_TO_ADD_FIELD("opstatus")
		return HA_FAIL;
	}

	on_op_done(op);
	lrmd_debug(LOG_DEBUG, "flush_op: end.");
	return HA_OK;
}

/* this function gets the first op in the rsc op list and execute it*/
int
perform_op(lrmd_rsc_t* rsc)
{
	GList* node = NULL;
	lrmd_op_t* op = NULL;

	CHECK_ALLOCATED(rsc, "resource", HA_FAIL );
	if (TRUE == shutdown_in_progress && can_shutdown()) {
		lrm_shutdown();
	}
	
	if (NULL == rsc->op_list) {
		lrmd_debug2(LOG_DEBUG,"perform_op: no op to perform");
		return HA_OK;
	}

	node = g_list_first(rsc->op_list);
	while ( NULL != node ) {
		op = node->data;
		if (-1 != op->exec_pid )	{
			lrmd_debug(LOG_DEBUG, "perform_op: current op is performing.");
			lrmd_debug(LOG_DEBUG, "perform_op: its information: %s."
			,	  op_info(op));
			break;
		}
		if ( HA_OK != perform_ra_op(op)) {
			lrmd_log(LOG_ERR
			,	"unable to perform_ra_op on %s"
			,	op_info(op));
			if (HA_OK != ha_msg_add_int(op->msg, F_LRM_OPSTATUS,
						LRM_OP_ERROR)) {
				LOG_FAILED_TO_ADD_FIELD("opstatus")
			}
			on_op_done(op);
			node = g_list_first(rsc->op_list);
		}
		else {
			break;
		}
	}

	return HA_OK;
}

		

struct ha_msg*
op_to_msg(lrmd_op_t* op)
{
	struct ha_msg* msg = NULL;

	CHECK_ALLOCATED(op, "op", NULL);
	if (op->exec_pid == 0) {
		lrmd_log(LOG_ERR, "op_to_msg: op->exec_pid is 0.");
		return NULL;
	}
	msg = ha_msg_copy(op->msg);
	if (NULL == msg) {
		lrmd_log(LOG_ERR,"op_to_msg: can not copy the msg");
		return NULL;
	}
	if (HA_OK != ha_msg_add_int(msg, F_LRM_CALLID, op->call_id)) {
		ha_msg_del(msg);
		LOG_FAILED_TO_ADD_FIELD("call_id")
		return NULL;
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
	unsigned long t_stay_in_list = 0;
	lrmd_rsc_t* rsc = NULL;
	int flag;
	
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
		lrmd_log(LOG_ERR, "perform_ra_op: op->exec_pid == 0.");
		return HA_FAIL;
	}

	op_params = ha_msg_value_str_table(op->msg, F_LRM_PARAM);
	params = merge_str_tables(rsc->params,op_params);
	free_str_table(op_params);
	free_str_table(rsc->params);
	rsc->params = params;
	op->t_perform = time_longclock();
	t_stay_in_list = longclockto_ms(op->t_perform - op->t_addtolist);
	if ( t_stay_in_list > WARNINGTIME_IN_LIST) 
	{
		lrmd_log(LOG_ERR
		,	"perform_ra_op: the operation %s stayed in operation "
			"list for %lu ms (longer than %d ms)"
		,	op_info(op), t_stay_in_list
		,	WARNINGTIME_IN_LIST
		);
		dump_data_for_debug();
	}
	if(HA_OK != ha_msg_value_int(op->msg, F_LRM_TIMEOUT, &timeout)){
		timeout = 0;
		lrmd_log(LOG_ERR,"perform_ra_op: failed to get timeout from "
			"the message op->msg.");
	}
	if (0 < timeout ) {
		op->timeout_tag = Gmain_timeout_add(timeout
				, on_op_timeout_expired, op);
	}
	
	return_to_orig_privs();
	switch(pid=fork()) {
		case -1:
			lrmd_log(LOG_ERR
			,	"perform_ra_op:start_a_child_client: Cannot fork.");
			return_to_dropped_privs();
			return HA_FAIL;

		default:	/* Parent */
			NewTrackedProc(pid, 1, PT_LOGNONE, op, &ManagedChildTrackOps);
			close(stdout_fd[1]);
			close(stderr_fd[1]);
			/*
			 * No any obviouse proof of lrmd hang in pipe read yet.
			 * Bug 475 may be a duplicate of bug 499.
			 * Anyway, via test, it's proved that NOBLOCK read will
			 * obviously reduce the RA execution time (bug 553).
			 */
			/* Let the read operation be NONBLOCK */ 
			if ((flag = fcntl(stdout_fd[0], F_GETFL)) >= 0) {
				if (fcntl(stdout_fd[0], F_SETFL, flag|O_NONBLOCK) < 0) {
					cl_perror("%s::%d: fcntl", __FUNCTION__
						, __LINE__);
				}
			} else {
				cl_perror("%s::%d: fcntl", __FUNCTION__, __LINE__);
			}
			if ((flag = fcntl(stderr_fd[0], F_GETFL)) >= 0) {
				if (fcntl(stderr_fd[0], F_SETFL, flag|O_NONBLOCK) < 0) {
					cl_perror("%s::%d: fcntl", __FUNCTION__
						, __LINE__);
				}
			} else {
				cl_perror("%s::%d: fcntl", __FUNCTION__, __LINE__);
			}
	
			op->ra_stdout_fd = stdout_fd[0];
			op->ra_stderr_fd = stderr_fd[0];
			op->ra_stdout_gsource = G_main_add_fd(G_PRIORITY_HIGH
				, stdout_fd[0], FALSE, handle_pipe_ra_stdout
				, op, NULL);
			op->ra_stderr_gsource = G_main_add_fd(G_PRIORITY_HIGH
				, stderr_fd[0], FALSE, handle_pipe_ra_stderr
				, op, NULL);
			
			op->exec_pid = pid;
			
			return_to_dropped_privs();
			return HA_OK;

		case 0:		/* Child */
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
			}
			if (STDERR_FILENO != stderr_fd[1]) {
				if (dup2(stderr_fd[1], STDERR_FILENO)!=STDERR_FILENO) {
					cl_perror("%s::%d: dup2"
						, __FUNCTION__, __LINE__);
				}
			}
			close(stdout_fd[1]);
			close(stderr_fd[1]);
			RAExec = g_hash_table_lookup(RAExecFuncs,rsc->class);
			if (NULL == RAExec) {
				lrmd_log(LOG_ERR,"perform_ra_op: can not find RAExec");
				return HA_FAIL;
			}
			op_type = ha_msg_value(op->msg, F_LRM_OP);
			/*should we use logging daemon or not in script*/
			setenv(HALOGD, cl_log_get_uselogd()?"yes":"no",1);

			/* Name of the resource and some others also
			 * need to be passed in. Maybe pass through the
			 * entire lrm_op_t too? */
			lrmd_debug2(LOG_DEBUG
			,	"perform_ra_op:calling RA plugin to perform %s, pid: [%d]"
			,	op_info(op), getpid());		
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

/* Handle the  one of our ra child processes finsihed*/
static void
on_ra_proc_finished(ProcTrack* p, int status, int signo, int exitcode
,	int waslogged)
{
	lrmd_op_t* op = NULL;
        lrmd_rsc_t* rsc = NULL;
	struct RAExecOps * RAExec = NULL;
	const char* op_type;
        int rc;
        int ret;
	int op_status;

	CHECK_ALLOCATED(p, "ProcTrack p", );
	op = p->privatedata;
	lrmd_debug2(LOG_DEBUG, "on_ra_proc_finished: accessing the op whose "
		  "address is %p", op);
	CHECK_ALLOCATED(op, "op", );
	if (op->exec_pid == 0) {
		lrmd_log(LOG_ERR, "on_ra_proc_finished: the op was freed.");
		dump_data_for_debug();
		return;
	}

	op->exec_pid = -1;
	if (SIGKILL == signo) {
		lrmd_debug(LOG_DEBUG, "on_ra_proc_finished: this op %s is killed."
			, op_info(op));
		lrmd_op_destroy(op);
		p->privatedata = NULL;
		dump_data_for_debug();
lrmd_log(LOG_ERR, "RETURNING from %s line %d", __FUNCTION__, __LINE__);
		return;
	}

	if (HA_OK == ha_msg_value_int(op->msg, F_LRM_OPSTATUS, &op_status)) {
		if ( LRM_OP_CANCELLED == (op_status_t)op_status ) {
			lrmd_debug(LOG_DEBUG, "on_ra_proc_finished: "
				"this op %s is cancelled.", op_info(op));
			lrmd_op_destroy(op);
			p->privatedata = NULL;
			dump_data_for_debug();
lrmd_log(LOG_ERR, "RETURNING from %s line %d", __FUNCTION__, __LINE__);
			return;
		}
	}

	rsc = lookup_rsc(op->rsc_id);
	if (rsc == NULL) {
		lrmd_debug(LOG_DEBUG, "on_ra_proc_finished: the rsc (id=%s) does"
		" not exist", op->rsc_id);
		on_op_done(op);
		p->privatedata = NULL;
lrmd_log(LOG_ERR, "RETURNING from %s line %d", __FUNCTION__, __LINE__);
		return;
	}	
	RAExec = g_hash_table_lookup(RAExecFuncs,rsc->class);
	if (NULL == RAExec) {
		lrmd_log(LOG_ERR,"on_ra_proc_finished: can not find RAExec for"
			"resource class <%s>", rsc->class);
		dump_data_for_debug();
lrmd_log(LOG_ERR, "RETURNING from %s line %d", __FUNCTION__, __LINE__);
		return;
	}

	op_type = ha_msg_value(op->msg, F_LRM_OP);
lrmd_log(LOG_ERR, "Mapping return value from plugin in %s() line %d", __FUNCTION__, __LINE__);
	rc = RAExec->map_ra_retvalue(exitcode, op_type, op->first_line_ra_stdout);
	if (rc != EXECRA_OK || debug_level > 1) {
		lrmd_log(rc == EXECRA_OK ? LOG_DEBUG : LOG_ERR
		,	"Resource Agent (%s): process [%d], "
			"exitcode %d, rc %d, with signo %d, the RA output: %s"
		,	op_info(op)
		,	p->pid, exitcode, rc, signo
		,	op->first_line_ra_stdout);
	}
lrmd_log(LOG_ERR, "Mapping of return value complete in %s() line %d", __FUNCTION__, __LINE__);
lrmd_log(LOG_ERR, "Resource Agent (%s): process [%d], "
"exitcode %d, rc %d, with signo %d, the RA output: %s"
,	op_info(op), p->pid, exitcode, rc, signo, op->first_line_ra_stdout);

	if (EXECRA_EXEC_UNKNOWN_ERROR == rc || EXECRA_NO_RA == rc) {
		if (HA_OK != ha_msg_mod_int(op->msg, F_LRM_OPSTATUS,
							LRM_OP_ERROR)) {
			LOG_FAILED_TO_ADD_FIELD("opstatus")
			return ;
		}
		lrmd_log(LOG_ERR
		, "on_ra_proc_finished: the exit code shows something wrong");
		
	} else {
		if (HA_OK != ha_msg_mod_int(op->msg, F_LRM_OPSTATUS,
								LRM_OP_DONE)) {
			LOG_FAILED_TO_ADD_FIELD("opstatus")
			return ;
		}
		if (HA_OK != ha_msg_mod_int(op->msg, F_LRM_RC, rc)) {
			LOG_FAILED_TO_ADD_FIELD("F_LRM_RC")
			return ;
		}
	}

	if ( 0 < strlen(op->first_line_ra_stdout) ) {
		if (NULL != cl_get_string(op->msg, F_LRM_DATA)) {
			cl_msg_remove(op->msg, F_LRM_DATA);
		}
		ret = ha_msg_add(op->msg, F_LRM_DATA, op->first_line_ra_stdout);
		if (HA_OK != ret) {
			LOG_FAILED_TO_ADD_FIELD("data")
		}
	}

	on_op_done(op);
	perform_op(rsc);
	p->privatedata = NULL;
}

/* Handle the death of one of our managed child processes */
static const char *
on_ra_proc_query_name(ProcTrack* p)
{
	static char proc_name[MAX_PROC_NAME];
	lrmd_op_t* op = NULL;
        lrmd_rsc_t* rsc = NULL;
	const char* op_type = NULL;

	op = (lrmd_op_t*)(p->privatedata);
	if (NULL == op || op->exec_pid == 0) {
		return "*unknown*";
	}

	op_type = ha_msg_value(op->msg, F_LRM_OP);
	rsc = lookup_rsc(op->rsc_id);
	if (rsc == NULL) {
		snprintf(proc_name
		, MAX_PROC_NAME
		, "unknown rsc(may deleted):%s"
		, op_type);
	}else {	
		snprintf(proc_name, MAX_PROC_NAME, "%s:%s", rsc->id, op_type);
	}
	return proc_name;
}


/* /////////////////Util Functions////////////////////////////////////////////// */
int
send_ret_msg (IPC_Channel* ch, int ret)
{
	struct ha_msg* msg = NULL;

	msg = create_lrm_ret(ret, 1);
	CHECK_RETURN_OF_CREATE_LRM_RET

	if (HA_OK != msg2ipcchan(msg, ch)) {
		lrmd_log(LOG_ERR, "send_ret_msg: can not send the ret msg");
	}
	ha_msg_del(msg);
	return HA_OK;
}

lrmd_client_t*
lookup_client (pid_t pid)
{
	return (lrmd_client_t*) g_hash_table_lookup(clients, &pid);
}

lrmd_rsc_t*
lookup_rsc (const char* rid)
{
	return (lrmd_rsc_t*)g_hash_table_lookup(resources, rid);
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


static gboolean
handle_pipe_ra_stdout(int fd, gpointer user_data)
{
	static gboolean first_line = TRUE;
	gboolean rc = TRUE;
	lrmd_op_t* op = (lrmd_op_t *)user_data;
	const char* op_type = NULL; 
	char * data = NULL;

	if (0 != read_pipe(fd, &data, op)) {
		rc = FALSE;
	}
	if (data!=NULL) { 
		op_type = ha_msg_value(op->msg, F_LRM_OP);
		if (  (0==STRNCMP_CONST(op_type, "meta-data"))
		    ||(0==STRNCMP_CONST(op_type, "monitor")) 
		    ||(0==STRNCMP_CONST(op_type, "status")) ) {
			lrmd_debug(LOG_DEBUG, "RA output: (%s:%s:stdout) %s"
				, op->rsc_id, op_type, data);
		} else {
			lrmd_log(LOG_INFO, "RA output: (%s:%s:stdout) %s"
				, op->rsc_id, op_type, data);
		}
		if (first_line == TRUE) {
			memset(op->first_line_ra_stdout, 0
				, sizeof(op->first_line_ra_stdout));
			strncpy(op->first_line_ra_stdout, data
				, sizeof(op->first_line_ra_stdout) - 1);
			first_line = FALSE;
		}
		g_free(data);
	}

	return rc;
}

static gboolean 
handle_pipe_ra_stderr(int fd, gpointer user_data)
{
	gboolean rc = TRUE;
	lrmd_op_t* op = (lrmd_op_t *)user_data;
	const char* op_type = NULL; 
	char * data = NULL;

	if (0 != read_pipe(fd, &data, op)) {
		rc = FALSE;
	}
	if (data!=NULL) { 
		op_type = ha_msg_value(op->msg, F_LRM_OP);
		lrmd_log(LOG_INFO, "RA output: (%s:%s:stderr) %s", op->rsc_id
			, op_type, data);
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
	const char* op_type = NULL; 
	int rc = 0;
	lrmd_rsc_t* rsc = NULL;
	lrmd_op_t* op = (lrmd_op_t *)user_data;

	lrmd_debug3(LOG_DEBUG, "%s begin.", __FUNCTION__);

	*data = NULL;
	gstr_tmp = g_string_new("");
	
	/* the log is only for analysing bug 475, or should remove it. */
	do {
		errno = 0;
		readlen = read(fd, buffer, BUFFLEN - 1);
		if ( readlen > 0 ) {
			buffer[readlen] = EOS;
			g_string_append(gstr_tmp, buffer);
		}
	} while (readlen == BUFFLEN - 1 || errno == EINTR);

	if (errno == EINTR) {
		errno = 0;
	}
	if ((readlen < 0) && (errno !=0)) {
		rc = -1;
		if (errno != EAGAIN) {
			cl_perror("%s::%d errno=%d, read"
				,	__FUNCTION__, __LINE__, errno);
		}

		if (errno == EAGAIN) {
			rsc = lookup_rsc(op->rsc_id);
			op_type = ha_msg_value(op->msg, F_LRM_OP);
			lrmd_log(LOG_ERR, "RA %s:%s:%s (process %d) failed to "
				"redirect %s for its background child (daemon) "
				"processes. This will likely cause those "
				"processes to die mysteriously at some later "
				"time (terminated by signal SIGPIPE)."
				, (rsc!=NULL)?rsc->class:"<NULL>"
				, (rsc!=NULL)?rsc->type:"<NULL>"
				, (op_type!=NULL)?op_type:"<NULL>"
				, op->exec_pid
				, (op->ra_stdout_fd==fd)?"stdout":"stderr");
		}
	}
	/* the log is only for analysing bug 475, or should remove it. */

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
	switch (nsig) {
		case SIGUSR1:
			debug_level++;
			dump_data_for_debug();
			break;

		case SIGUSR2:
			debug_level--;
			if (debug_level < 0) {
				debug_level = 0;
			}
			break;
		
		default:
			lrmd_log(LOG_WARNING, "debug_level_adjust: Received an "
				"unexpected signal(%d). Something wrong?.",nsig);
	}

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

static const char* 
op_info(const lrmd_op_t* op)
{
	static char info[255];
	lrmd_rsc_t* rsc = NULL;
	const char * op_type;
	GString * param_gstr;
	
	rsc = lookup_rsc(op->rsc_id);
	op_type = ha_msg_value(op->msg, F_LRM_OP);
	
	if (rsc == NULL) {
		snprintf(info,sizeof(info)
		,"operation %s[%d] on unknown rsc(may deleted) for client %d"
		,lrmd_nullcheck(op_type)
		,op->call_id
		,op->client_id);
		
	}else{
		param_gstr = g_string_new("");	
		hash_to_str(rsc->params, param_gstr);

		snprintf(info, sizeof(info)
		,"operation %s[%d] on %s::%s::%s for client %d, its parameters: %s"
		,lrmd_nullcheck(op_type)
		,op->call_id
		,lrmd_nullcheck(rsc->class)
		,lrmd_nullcheck(rsc->type)
		,lrmd_nullcheck(rsc->id)
		,op->client_id
		,param_gstr->str);

		g_string_free(param_gstr, TRUE);
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
/*
 * $Log: lrmd.c,v $
 * Revision 1.192  2005/12/25 23:23:41  alan
 * Put in some temporary debugging code to just help me figure out
 * why the permanent debugging code I put in isn't working...
 *
 * Revision 1.191  2005/12/25 14:40:35  alan
 * More debugging output.
 *
 * Revision 1.190  2005/12/25 04:33:51  alan
 * Made some error-only output come out when debug level is high enough
 *
 * Revision 1.189  2005/12/25 03:45:00  alan
 * Dropped two log messages to debug level 3 because they just produce
 * WAY too much output.
 *
 * Revision 1.188  2005/11/24 10:27:01  sunjd
 * add a log output function for level2 debug
 *
 * Revision 1.187  2005/11/17 10:32:56  sunjd
 * Polish the log message to be more detailed
 *
 * Revision 1.186  2005/11/17 07:00:27  sunjd
 * The fix for bug756
 *
 * Revision 1.185  2005/11/15 01:46:06  zhenh
 * change the way of logger to make BEAM happy
 *
 * Revision 1.184  2005/09/29 02:30:41  zhenh
 * remove local debug_level in lrmd
 *
 * Revision 1.183  2005/09/28 20:29:56  gshi
 * change the variable debug to debug_level
 * define it in cl_log
 * move a common function definition from lrmd/mgmtd/stonithd to cl_log
 *
 * Revision 1.182  2005/09/26 02:06:49  sunjd
 * Bug 894:decrease the debug log in debug 1 mode; polish some logs
 *
 * Revision 1.181  2005/09/15 00:04:42  gshi
 * the ipc channel will be destroyed by main loop
 * we should not destroy it here
 *
 * Revision 1.180  2005/08/12 05:05:55  zhenh
 * 1,fix a memory leak, the key of hash table is not released. 2, improve the memdump
 *
 * Revision 1.179  2005/07/27 08:40:54  panjiam
 * fixed GPL license version
 *
 * Revision 1.178  2005/07/27 02:09:04  panjiam
 * changed license to GPL
 *
 * Revision 1.177  2005/07/26 08:17:10  sunjd
 * log message polish
 *
 * Revision 1.176  2005/07/21 08:12:59  sunjd
 * let the detailed action log output when EAGAIN happens
 *
 * Revision 1.175  2005/07/19 05:12:25  sunjd
 * make read_pipe return void, suggested by Lars; other polish: remove the redundant error checkings
 *
 * Revision 1.174  2005/07/18 16:04:36  sunjd
 * regard EAGAIN as an error
 *
 * Revision 1.173  2005/07/18 08:38:34  sunjd
 * bug 495: add a detailed log for RA action failure
 *
 * Revision 1.172  2005/07/13 14:55:42  lars
 * Compile warnings: Ignored return values from sscanf/fgets/system etc,
 * minor signedness issues.
 *
 * Revision 1.171  2005/07/07 03:26:42  zhenh
 * upgrade the log of on_op_done
 *
 * Revision 1.170  2005/07/06 08:58:38  sunjd
 * enable the NOBLOCK pipe read which not break BSC anymore
 *
 * Revision 1.169  2005/07/05 15:34:59  andrew
 * Printing size_t on Darwin
 *
 * Revision 1.168  2005/07/04 23:54:06  alan
 * BasicSanityCheck fix in lrmd:  the code for NODELAY reading appears to be breaking BSC.
 * If not, I'll revert it.
 *
 * Revision 1.167  2005/07/04 04:27:48  sunjd
 * add log for bug 475
 *
 * Revision 1.166  2005/06/30 10:49:33  sunjd
 * bug 553: let the pipe reading be NOBLOCK
 *
 * Revision 1.165  2005/06/30 09:42:41  zhenh
 * show call id of op to make it more clear
 *
 * Revision 1.164  2005/06/30 08:22:03  zhenh
 * Fixed a bug. the t_stay_in_list has been in ms already
 *
 * Revision 1.163  2005/06/30 07:12:16  sunjd
 * Bug 499: SIGCHLD should interrupt the system calls
 *
 * Revision 1.162  2005/06/15 14:13:27  davidlee
 * common code for syslog facility name/value conversion
 *
 * Revision 1.161  2005/06/08 08:29:38  sunjd
 * make GCC4 happy. unsigned->signed
 *
 * Revision 1.160  2005/06/07 07:39:21  sunjd
 * Bug 317. support to emit apphb
 *
 * Revision 1.159  2005/06/02 07:49:54  sunjd
 * for a const char array, use STRNCMP_CONST instead
 *
 * Revision 1.158  2005/06/02 07:28:52  sunjd
 * donnot use mod op, let the loglevel reflects what the user really want
 *
 * Revision 1.157  2005/06/02 06:35:57  sunjd
 * use the accurate loglevel from the environment variable
 *
 * Revision 1.156  2005/06/02 01:07:33  zhenh
 * 1. improve some names of internal functions.
 * 2. remove the useless "unregister" message.
 *
 * Revision 1.155  2005/06/01 10:36:57  sunjd
 * log tweak
 *
 * Revision 1.154  2005/05/31 11:29:38  sunjd
 * Bug 495:log tweak; other little polish
 *
 * Revision 1.153  2005/05/31 02:03:52  sunjd
 * remove the using of strcmp
 *
 * Revision 1.152  2005/05/30 08:11:52  sunjd
 * remove the abuse of STRNCMP_CONST.
 *
 * Revision 1.151  2005/05/23 03:49:38  alan
 * Added another occurance of the warning about too many ops.
 *
 * Revision 1.150  2005/05/22 15:18:20  alan
 * Put in a change to make long operations lists print out one line
 * as an ERROR
 *
 * Revision 1.149  2005/05/20 16:24:52  sunjd
 * Bug 557:LRM performs previously cancelled operation
 *
 * Revision 1.148  2005/05/20 13:23:47  alan
 * Put some comments into lrmd.c explaining why we need to take secure core dumps.
 *
 * Revision 1.147  2005/05/20 06:43:39  sunjd
 * Bug 479: fixed with prctl system call
 *
 * Revision 1.146  2005/05/19 06:47:12  sunjd
 * Bug 553: add more debug output
 *
 * Revision 1.145  2005/05/18 08:36:21  sunjd
 * BEAM : not a real fix
 *
 * Revision 1.144  2005/05/13 23:18:58  gshi
 * use cl_unlock_pid_file() instead of  unlink()
 *
 * Revision 1.143  2005/05/13 21:19:13  gshi
 * use cl_read_pidfile() and cl_lock_pidfile()
 * to handler pid file
 *
 * Revision 1.142  2005/05/10 17:43:05  gshi
 * fix a compiler complain
 *
 * Revision 1.141  2005/05/07 16:39:52  alan
 * Put in a few BEAM fixes.
 *
 * Revision 1.140  2005/05/05 15:36:21  zhenh
 * 1. using set_sigchld_proctrack(). 2. add record_op_completion() to reduce on_op_done(). 3. call G_main_add_IPC_Channel() for callback channel to avoid deadlock
 *
 * Revision 1.139  2005/05/05 14:35:18  alan
 * Fixed some portability warnings.
 *
 * Revision 1.138  2005/05/05 13:39:15  zhenh
 * 1. change the resource list and client list to hashtable. 2. remove the rsc->last_op
 *
 * Revision 1.137  2005/05/04 20:53:22  alan
 * Made an error message slightly more succinct.
 *
 * Revision 1.136  2005/05/04 20:45:03  alan
 * Put in a little debugging code to make sure we're dealing with originals/copies of
 * 'op's correctly.
 *
 * Revision 1.135  2005/05/04 16:14:03  alan
 * Put in a small lrmd debugging enhancement for Andrew.
 *
 * Revision 1.134  2005/05/04 14:01:49  alan
 * More debugging code.
 * Including checking for allocated pointers in debugging code :-)
 *
 * Revision 1.133  2005/05/03 23:32:27  alan
 * Put the -pid change back into the lrmd.
 *
 * Revision 1.132  2005/05/03 21:19:15  alan
 * Fixed up an error message to not come out inappropriately
 * changed signal 9 to SIGKILL
 *
 * Revision 1.131  2005/05/03 19:43:03  alan
 * Added lrm_rsc_dump() and called it from lrm_op_dump()
 *
 * Revision 1.130  2005/05/03 17:38:55  zhenh
 * Change the function of get_cur_state(). Now it returns an op list including last ops, pending ops, and waiting recurring ops. the list is sorted by call_id
 *
 * Revision 1.129  2005/05/03 16:33:36  alan
 * Put in a good bit more debug information for when
 * an operation times out.
 * In the process wrote a lrmd_dump_op() function useful for other
 * places - and used it to replace some older debug code
 * that wasn't as thorough.
 *
 * Revision 1.128  2005/05/01 07:12:57  sunjd
 * BEAM fix: void to operate a NULL pointer
 *
 * Revision 1.127  2005/05/01 03:53:16  alan
 * Moved all client unregistration work to the destructor for the client
 * object.  We never want to destroy a client without doing this, and we
 * also never want to do this without also destroying the client - since
 * an unregistered client is useless.  So doing them both in the destructor
 * makes the most sense.
 *
 * Revision 1.126  2005/04/30 13:34:07  alan
 * Added which pid couldn't be found to the message.
 *
 * Revision 1.125  2005/04/30 08:06:52  alan
 * Fixed a few bona-fide bugs:
 *    STRLEN_CONST can only be called on a string literal
 *    Didn't do everything that needed doing when freeing a resource.
 * 		(Alan's fault)
 * Did LOTS of commenting about how to improve things.
 * Discovered a theoretical deadlock
 *
 * Revision 1.124  2005/04/29 17:47:34  alan
 * Fixed a bug in the LRM where it tried to do something complicated
 * in a signal handler.  This type of behavior will work most of the time
 * but eventually it will fail - depending on exactly when the SIGTERM
 * comes in.
 *
 * Revision 1.123  2005/04/29 17:08:47  alan
 * Added a missing closedir()
 * Added some FIXME type comments to the code to mark where some things
 * needed to change.
 *
 * Revision 1.122  2005/04/29 07:45:00  zhenh
 * make the timeout of op as the timeout of RA running only
 *
 * Revision 1.121  2005/04/29 07:24:49  zhenh
 * 1. print resources and operatios information out in dump_data_for_debug(); 2. dump data when an op stay in op list longer than 5s
 *
 * Revision 1.120  2005/04/29 05:19:34  zhenh
 * fix a mistype error
 *
 * Revision 1.119  2005/04/29 01:48:36  zhenh
 * fixed two mistype
 *
 * Revision 1.118  2005/04/29 01:45:56  sunjd
 * readd cl_malloc_forced_for_glib -- sorry for not noticing alan's removing
 *
 * Revision 1.117  2005/04/29 01:41:27  sunjd
 * remove the redundant cl_malloc_forced_for_glib; degrade one log to none-error level
 *
 * Revision 1.116  2005/04/28 22:16:09  alan
 * Removed a superfluous call to set up cl_malloc() as allocator for glib.
 *
 * Revision 1.115  2005/04/28 21:55:55  alan
 * Removed an incorrect check for allocation statement.
 *
 * Revision 1.114  2005/04/28 21:30:27  alan
 * Added comments.
 * Turned it to use the cl_malloc() calls for the glib memory areas.
 *
 * Revision 1.113  2005/04/28 20:52:20  sunjd
 * avoid segfault
 *
 * Revision 1.112  2005/04/28 18:52:43  alan
 * Changed the print format slightly for unallocated storage messages.
 *
 * Revision 1.111  2005/04/28 17:55:18  alan
 * Fixed a stupid format mismatch error.
 *
 * Revision 1.110  2005/04/28 17:42:31  alan
 * Decided to change the last WARNING back into an ERR.
 *
 * Revision 1.109  2005/04/28 17:40:41  alan
 * Turned on_op_done non-existent client message back to a warning.
 *
 * Revision 1.108  2005/04/28 17:21:32  alan
 * Lots more self-checking code and moved some warnings to ERRORs.
 *
 * Revision 1.107  2005/04/28 16:24:30  alan
 * Put in two new checks for NULL ops when freeing them.
 *
 * Revision 1.106  2005/04/28 15:08:47  alan
 * Changed lrmd.c so that it checks for missing fields before trying to copy them.
 *
 * Revision 1.105  2005/04/28 14:16:12  alan
 * Put in some more code to detect what's going wrong with
 * the LRM memory management model and print out LOUD messages
 * when things aren't allocated that we're trying to free.
 * Also keep and memory statistics.  Print them on memory allocation
 * errors.
 *
 * Revision 1.104  2005/04/28 09:49:03  zhenh
 * the client structure has been released in lrmd_client_destroy() functions
 *
 * Revision 1.103  2005/04/28 02:57:56  zhenh
 * when the resource was deleted during the operation performing, this would cause core dump.
 *
 * Revision 1.102  2005/04/27 21:59:37  alan
 * Added more caution in handling pointers, more conservative comparators,
 * checked to see if structure was still allocated
 * and in various circumstances call dump_data_for_debug()
 *
 * Revision 1.101  2005/04/27 21:50:51  alan
 * A tiny bit more caution...
 *
 * Revision 1.100  2005/04/27 21:48:08  alan
 * Fixed a few things:
 *   should have used cl_calloc instead of cl_malloc
 *   Got more cautious about destroying improperly constructed objects.
 *
 * Revision 1.99  2005/04/27 21:38:15  alan
 * Reorganized the way storage was being used by the LRM - slightly.
 * Marked something suspicous as FIXME.
 *
 * Revision 1.98  2005/04/27 16:38:05  alan
 * Fixed a non-ANSI-ism I accidentally introduced :-(
 *
 * Revision 1.97  2005/04/27 15:03:25  alan
 *
 * CV: strncmp that should have been a strncpy :-)
 *
 * Revision 1.96  2005/04/27 15:02:03  alan
 * Added more debug info for the SIGUSR1 call.
 *
 * Revision 1.95  2005/04/27 07:22:35  zhenh
 * change some logs
 *
 * Revision 1.93  2005/04/26 11:00:24  zhenh
 * add get_last_result(), it will record the last op for every op type and every client.
 *
 * Revision 1.92  2005/04/25 09:05:32  zhenh
 * add timestamp to operation, fix #494
 *
 * Revision 1.91  2005/04/25 05:45:26  zhenh
 * add start delay for operations in LRM
 *
 * Revision 1.90  2005/04/20 07:25:20  zhenh
 * fix memory leak in new logs, found by BEAM
 *
 * Revision 1.88  2005/04/19 07:41:33  sunjd
 * BEAM fixes.
 *
 * Revision 1.87  2005/04/19 07:30:55  sunjd
 * 1) Now support multiple debug level (0, 1, 2).
 * 2) Support debug_level adjustment via signals SIGUSR1 and SIGUSR2
 * 3) Support internal data dumping when getting a SIGUSR1 ( need to continue enhancing then )
 * 4) Log message adjustment.
 *
 * Revision 1.86  2005/04/18 01:44:36  zhenh
 * Fix a BEAM bug.
 *
 * Revision 1.85  2005/04/15 09:11:30  zhenh
 * fix bug 467, LRM segfault. In the old code, the repeat operations share only one op structure. Now change to every repeat operation has its own op structure.
 *
 * Revision 1.84  2005/04/15 08:15:31  sunjd
 * bug 467 LRM Segfault
 *
 * Revision 1.83  2005/04/15 07:29:38  zhenh
 * we need assign value to op before we use it. BEAM
 *
 * Revision 1.82  2005/04/15 06:37:44  sunjd
 * bug 467 LRM Segfault
 *
 * Revision 1.81  2005/04/14 18:00:38  alan
 * Changed lrmd to use Gmain_timeout_add() instead of g_timeout_add().
 *
 * Revision 1.80  2005/04/14 01:23:11  alan
 * Put in a temporary, yucky workaround to help debug a problem which
 * Andrew has been seeing.  It resulted in a process getting a segfault,
 * but not dumping any core files.
 * This fix is temporary.  I filed a bug reminding us to remove it.
 *
 * Revision 1.79  2005/04/08 07:49:35  sunjd
 * Replace log function with macro to improve the running efficiency.
 * Inherit configurations from environment variables set by heartbeat.
 *
 * Revision 1.78  2005/04/07 07:07:17  sunjd
 * replace with STRLEN_CONST&STRNCMP_CONST; remove some redundant logs
 *
 * Revision 1.77  2005/04/07 06:23:50  sunjd
 * inherit the debuglevel from heartbeat
 *
 * Revision 1.76  2005/04/06 03:27:49  sunjd
 * use the new function cl_inherit_use_logd
 *
 * Revision 1.75  2005/04/04 10:21:09  zhenh
 * the first result of monitor should be return
 *
 * Revision 1.74  2005/03/18 12:18:25  sunjd
 * changes for returning correct RC for heartbeat RA by check its string output to stdout
 *
 * Revision 1.73  2005/03/16 02:13:27  zhenh
 * replace 'extern XXX' with new log functions, thx gshi
 *
 * Revision 1.72  2005/03/15 19:52:24  gshi
 * changed cl_log_send_to_logging_daemon() to cl_log_set_uselogd()
 * added cl_log_get_uselogd()
 *
 * Revision 1.71  2005/03/07 06:22:48  zhenh
 * replace ha_msg_add_str_list with the new one cl_msg_add_list
 *
 * Revision 1.70  2005/03/04 15:59:09  alan
 * Put in a largish number of signed/unsigned fixes
 *
 * Revision 1.69  2005/03/01 08:41:29  zhenh
 * make lrmd and the scripts started by lrmd log to log daemon if the daemon is running
 *
 * Revision 1.68  2005/02/24 10:34:49  zhenh
 * when lrm deletes a resource, notifies the clients who are monitoring the resource
 *
 * Revision 1.67  2005/02/24 06:54:15  sunjd
 * return to nobody privilege after forking failed
 *
 * Revision 1.66  2005/02/23 09:04:25  zhenh
 * make lrmd exiting just after all non-monitor operations finished when it received SIGTERM
 *
 * Revision 1.65  2005/02/23 05:31:25  zhenh
 * replace the code of storing binary data in ha_msg. (BEAM bug)
 *
 * Revision 1.64  2005/02/22 01:30:40  sunjd
 * Degrade running privilege to 'nobody' as more as possible;
 * Add authority verification data to the IPC channel which is used to communicate with clients.
 *
 * Revision 1.63  2005/02/18 05:43:09  sunjd
 * Fix the bugs BEAM found
 *
 * Revision 1.62  2005/02/17 16:19:17  alan
 * BEAM found that lookup_rsc had a memory leak in it.  It was right.
 * But, the resource allocation was unnecessary, so I fixed the leak by
 * getting rid of the allocation.  I had to change an argument from
 * char * to const char *, but that was right anyway ;-)
 *
 * Revision 1.61  2005/02/16 06:59:55  zhenh
 * add cl_malloc_forced_for_glib() to lrmd.
 *
 * Revision 1.60  2005/02/16 05:28:09  zhenh
 * Fix a bug.
 * Free operation data in on_ra_proc_finished() instead of lrmd_op_destroy()
 * if the child process of the operation is running.
 * So on_ra_proc_query_name() has chance to get some information of the operation.
 *
 * Revision 1.59  2005/01/31 06:26:22  sunjd
 * Change its coredump rootdir to HA_COREDIR and try to make user specific subdir
 *
 * Revision 1.58  2005/01/28 10:14:29  sunjd
 * turn on coredump on lrmd
 *
 * Revision 1.57  2005/01/27 01:39:37  zhenh
 * make it pass gcc 3.4.3. Thanks gshi.
 *
 * Revision 1.56  2005/01/03 19:35:00  msoffen
 * Moved var declaration from assignment
 *
 * Revision 1.55  2004/12/08 08:46:37  zhenh
 * let lrmd pass timeout to RA.
 *
 * Revision 1.54  2004/12/07 06:35:00  zhenh
 * fix a bug, mistype
 *
 * Revision 1.53  2004/12/05 19:15:21  andrew
 * "man" says these are equivalent.  The advantage is that this form compiles
 *  on BSD variants.
 *
 * Revision 1.52  2004/12/01 09:09:55  zhenh
 * make the lrmd continue read from pipe after interupted by signal
 *
 * Revision 1.51  2004/12/01 02:20:30  zhenh
 * set RA to different process group with lrmd to avoid being interupted by heartbeat
 *
 * Revision 1.50  2004/11/30 00:42:33  zhenh
 * make lrm wait a while when catch the SIGTERM signal for some cleanup work
 *
 * Revision 1.49  2004/11/25 03:27:31  zhenh
 * 1. Let the resource save the param of last operation.
 * 2. Let LRM execute  the pending operations from disconnected client.
 *
 * Revision 1.47  2004/10/22 02:47:16  zhenh
 * rename the stop_op() to cancel_op()
 *
 * Revision 1.46  2004/10/21 03:13:07  zhenh
 * call callback function with op_status==LRM_OP_CANCELLED when we stop an operation
 *
 * Revision 1.45  2004/10/10 02:42:03  zhenh
 * remove the call to enable log deamon
 *
 * Revision 1.44  2004/10/09 01:48:41  zhenh
 * change the failure logs from LOG_INFO to LOG_ERR
 *
 * Revision 1.43  2004/10/08 21:54:27  alan
 * BEAM FIX:  Got rid of an freeing-null-pointer-error.
 *
 * Revision 1.42  2004/10/08 09:22:51  zhenh
 * change the log levels to make the logs more clear
 *
 * Revision 1.41  2004/10/08 05:34:27  zhenh
 * add log entry to indicate the startup was successful
 *
 * Revision 1.40  2004/10/08 04:56:14  zhenh
 * According to the Bugzilla Bug 74.
 * 1. change the logging setting of lrm.
 * 2. remove the hardcode of pathname in the code.
 *
 * Revision 1.39  2004/09/30 13:26:57  alan
 * Redeclared signal_pending as volatile.
 *
 * Revision 1.38  2004/09/27 08:29:07  zhenh
 * apply the new cl_msg_list_xxx() funcions in lrm
 *
 * Revision 1.37  2004/09/16 09:14:14  zhenh
 * fix some memory leaks
 * add more return value checking
 * change HA_FAIL == ... TO HA_OK != ...
 *
 * Revision 1.36  2004/09/14 15:07:30  gshi
 * change glib API to glib2 API
 *
 * Revision 1.35  2004/09/13 15:01:18  sunjd
 * correct a silly careless error
 *
 * Revision 1.34  2004/09/13 10:49:13  sunjd
 * change for setting OCF environment variables
 *
 * Revision 1.33  2004/09/10 02:15:40  zhenh
 * make names of functions more clear,fix some bug
 *
 * Revision 1.32  2004/09/09 03:30:24  zhenh
 * remove the unused struct
 *
 * Revision 1.31  2004/09/06 12:41:52  lars
 * Add some additional required mandatory OCF environment variables.
 *
 * Revision 1.30  2004/09/06 04:36:18  zhenh
 * fix a bug
 *
 * Revision 1.29  2004/09/03 01:41:15  zhenh
 * add provider for resource
 *
 * Revision 1.28  2004/08/30 15:04:47  sunjd
 * polish/fix as Lars' reminding
 *
 * Revision 1.27  2004/08/30 03:17:40  msoffen
 * Fixed more comments from // to standard C comments
 *
 * Revision 1.26  2004/08/29 04:40:02  msoffen
 * Added missing Id and Log
 *
 */
