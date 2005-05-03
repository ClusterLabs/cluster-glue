/* $Id: lrmd.c,v 1.130 2005/05/03 17:38:55 zhenh Exp $ */
/*
 * Local Resource Manager Daemon
 *
 * Author: Huang Zhen <zhenhltc@cn.ibm.com>
 * Partly contributed by Andrew Beekhof <andrew@beekhof.net> 
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
/* Should copy the facilitynames struct here? */
#define SYSLOG_NAMES
#include <syslog.h>

#include <glib.h>
#include <heartbeat.h>
#include <pils/plugin.h>
#include <pils/generic.h>
#include <clplumbing/cl_log.h>
#include <clplumbing/ipc.h>
#include <clplumbing/GSource.h>
#include <clplumbing/lsb_exitcodes.h>
#include <clplumbing/cl_signal.h>
#include <clplumbing/proctrack.h>
#include <clplumbing/coredumps.h>
#include <clplumbing/uids.h>
#include <clplumbing/Gmain_timeout.h>

#include <ha_msg.h>
#include <lrm/lrm_api.h>
#include <lrm/lrm_msg.h>
#include <lrm/raexec.h>

#define	MAX_PID_LEN 256
#define	MAX_PROC_NAME 256
#define	MAX_MSGTYPELEN 32
#define WARMINGTIME_IN_LIST 5000
#define OPTARGS		"skrhv"
#define PID_FILE 	HA_VARRUNDIR"/lrmd.pid"
#define LRMD_COREDUMP_ROOT_DIR HA_COREDIR

/* Donnot directly use the definition in heartbeat.h/hb_api.h for fewer
 * dependency, but need to keep identical with them.
 */
#define ENV_PREFIX "HA_"
#define KEY_LOGDAEMON   "use_logd"
#define HADEBUGVAL	"HA_DEBUG"
#define lrmd_log(priority, fmt...); \
        if ( debug_level == 0 && priority == LOG_DEBUG ) { \
                ; \
        } else { \
                cl_log(priority, fmt); \
        }

#define lrmd_log2(priority, fmt...); \
        if ( debug_level == 2 && priority == LOG_DEBUG ) { \
                cl_log(priority, fmt); \
        }

#define	lrmd_nullcheck(p)	((p) ? (p) : "<null>")

#define	CHECK_ALLOCATED(thing, name, result)				\
	if (!cl_is_allocated(thing)) {					\
		lrmd_log(LOG_ERR, "%s: %s pointer 0x%lx is not allocated."		\
		,	__FUNCTION__, name, (unsigned long)thing);	\
		dump_mem_stats();					\
		return result;						\
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
 *	client_list - a linked list of all (currently connected) clients
 *
 *	rsc_list - a linked list of all (currently configured) resources
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
	lrmd_op_t*	last_op;	/* Last operation performed on	*/
					/* this resource		*/
	GHashTable*	last_op_table;	/* Last operation of each type	*/
};

struct lrmd_op
{
	lrmd_rsc_t*	rsc;		/* should this be rsc_id?	*/
	pid_t		client_id;
	int		call_id;
	int		exec_pid;
	int		output_fd;
	guint		timeout_tag;
	guint		repeat_timeout_tag;
	int		interval;
	int		delay;
	struct ha_msg*	msg;
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
static int on_msg_unregister(lrmd_client_t* client, struct ha_msg* msg);
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

/* Utility functions */
static int flush_op(lrmd_op_t* op);
static int perform_op(lrmd_rsc_t* rsc);
static int unregister_client(lrmd_client_t* client);
static int on_op_done(lrmd_op_t* op);
static const char* op_info(const lrmd_op_t* op);
static int send_rc_msg ( IPC_Channel* ch, int rc);
static lrmd_client_t* lookup_client (pid_t pid);
static lrmd_rsc_t* lookup_rsc (const char* rid);
static lrmd_rsc_t* lookup_rsc_by_msg (struct ha_msg* msg);
static int read_pipe(int fd, char ** data);
static struct ha_msg* op_to_msg(lrmd_op_t* op);
static gboolean lrm_shutdown(void);
static gboolean can_shutdown(void);
static void inherit_config_from_environment(void);
static int facility_name_to_value(const char * name);
static gboolean free_str_hash_pair(gpointer key
,	 gpointer value, gpointer user_data);
static gboolean free_str_op_pair(gpointer key
,	 gpointer value, gpointer user_data);
static lrmd_op_t* lrmd_op_copy(const lrmd_op_t* op);
static void send_last_op(gpointer key, gpointer value, gpointer user_data);
/*
 * following functions are used to monitor the exit of ra proc
 */
static void set_child_signal(void);
static void child_signal_handler(int sig);

static gboolean	on_polled_input_prepare(GSource* source,
					gint* timeout);
static gboolean	on_polled_input_check(GSource* source);
static gboolean	on_polled_input_dispatch(GSource* source,
					 GSourceFunc callback,
					 gpointer user_data);

static GSourceFuncs polled_input_SourceFuncs = {
	on_polled_input_prepare,
	on_polled_input_check,
	on_polled_input_dispatch,
	NULL,
};
static void on_ra_proc_registered(ProcTrack* p);
static void on_ra_proc_finished(ProcTrack* p, int status
,			int signo, int exitcode, int waslogged);
static const char* on_ra_proc_query_name(ProcTrack* p);
static volatile unsigned int signal_pending = 0;
static int debug_level = 0;

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
	gboolean	need_return_rc;
	msg_handler	handler;
};

struct msg_map msg_maps[] = {
	{UNREGISTER,	TRUE,	on_msg_unregister},
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

GMainLoop* mainloop 		= NULL;
GList* client_list 		= NULL;	/* should this be a GHashTable? FIXME?? */
					/* indexed by pid ?? */
GList* rsc_list 		= NULL;	/* should this be a GHashTable? FIXME?? */
					/* indexed by rsc_id ?? */
static int call_id 		= 1;
const char* lrm_system_name 	= "lrmd";
GHashTable * RAExecFuncs 	= NULL;
GList* ra_class_list		= NULL;
gboolean shutdown_in_progress	= FALSE;
/*
 * Daemon functions
 *
 * copy from the code of Andrew Beekhof <andrew@beekhof.net>
 */
static void usage(const char* cmd, int exit_status);
static int init_start(void);
static int init_stop(const char *pid_file);
static int init_status(const char *pid_file, const char *client_name);
static long get_running_pid(const char *pid_file, gboolean* anypidfile);
static void register_pid(const char *pid_file, gboolean do_fork,
			gboolean (*shutdown)(int nsig, gpointer userdata));

static struct {
	int	opcount;
	int	clientcount;
	int	rsccount;
}lrm_objectstats;

static void
dump_mem_stats(void)
{
	lrmd_log(LOG_INFO
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
		/* Kill the entire process group */
		if (kill(-op->exec_pid, 9) < 0) {
			cl_perror("Cannot kill pid %d", op->exec_pid);
		}
		return_to_dropped_privs();
		return;
	}

	if ((int)op->repeat_timeout_tag > 0) {
		g_source_remove(op->repeat_timeout_tag);
		op->repeat_timeout_tag = -1;
	}

	if ((int)op->timeout_tag > 0) {
		g_source_remove(op->timeout_tag);
		op->timeout_tag = -1;
	}

	ha_msg_del(op->msg);
	op->msg = NULL;
	op->exec_pid = 0;
	cl_free(op);
}

static lrmd_op_t*
lrmd_op_new(void)
{
	lrmd_op_t*	op = (lrmd_op_t*)cl_calloc(sizeof(lrmd_op_t),1);

	if (op == NULL) {
		lrmd_log(LOG_ERR, "lrmd_op_new(): out of memory");
		dump_mem_stats();
		return NULL;
	}
	op->exec_pid = -1;
	op->timeout_tag = -1;
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

#if 0
	lrmd_rsc_t*	rsc;		/* should this be rsc_id?	*/
#endif

	if (op->exec_pid < 1
	||	((kill(op->exec_pid, 0) < 0) && ESRCH == errno)) {
		pidstat = "not running";
	}else{
		pidstat = "running";
	}
	ha_msg_value_int(op->msg, F_LRM_OPSTATUS, &op_status);
	ha_msg_value_int(op->msg, F_LRM_TARGETRC, &target_rc);
	lrmd_log(LOG_INFO
	,	"%s: lrmd_op: %s status: %s, target_rc=%s, client pid %d call_id"
	": %d, child pid: %d (%s)"
	,	text,	op_info(op), op_status_to_str(op_status)
	,	op_target_rc_to_str(target_rc)
	,	op->client_id, op->call_id, op->exec_pid, pidstat);
	lrmd_log(LOG_INFO
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
	lrmd_log(LOG_INFO
	,	"%s: lrmd_op3: t_recv: %ldms, t_add: %ldms"
	", t_perform: %ldms, t_done: %ldms"
	,	text, t_recv, t_addtolist, t_perform, t_done);
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
	if (client->ch_cbk) {
		client->ch_cbk->ops->destroy(client->ch_cbk);
		client->ch_cbk = NULL;
	}
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
		lrmd_log(LOG_ERR, "lrmd_client_new(): out of memory");
		dump_mem_stats();
		return NULL;
	}
	++lrm_objectstats.clientcount;
	return client;
}

static void
lrmd_rsc_destroy(lrmd_rsc_t* rsc)
{
	CHECK_ALLOCATED(rsc, "resource", );
	--lrm_objectstats.rsccount;
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
		lrmd_log(LOG_ERR, "lrmd_rsc_new(): out of memory");
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
	++lrm_objectstats.rsccount;
	return rsc;
errout:
	lrmd_rsc_destroy(rsc);
	rsc = NULL;
	return rsc;
}

static void
lrm_debug_running_op(lrmd_op_t* op, const char * text)
{
	char	cmd[256];
	lrmd_op_dump(op, text);
	if (op->exec_pid >= 1) {
		/* This really ought to use our logger
		 * So... it might not get forwarded to the central machine
		 * if you're testing with CTS -- FIXME
		 */
		snprintf(cmd, sizeof(cmd)
		,	"ps -l -f -s %d | logger -p daemon.info -t 'T/O PS:'"
		,	op->exec_pid);
		lrmd_log(LOG_INFO, "Running [%s]", cmd);
		system(cmd);
		snprintf(cmd, sizeof(cmd)
		,	"ps axww | logger -p daemon.info -t 't/o ps:'");
		lrmd_log(LOG_INFO, "Running [%s]", cmd);
		system(cmd);
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
	if (inherit_debuglevel != NULL &&  atoi(inherit_debuglevel) != 0 ) {
		debug_level++;
	}

	cl_log_set_entity(lrm_system_name);
	cl_log_enable_stderr(debug_level?TRUE:FALSE);
	cl_log_set_facility(LOG_DAEMON);

	/* Use logd if it's enabled by heartbeat */
	cl_inherit_use_logd(ENV_PREFIX""KEY_LOGDAEMON, 0);

	inherit_config_from_environment();

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
	gboolean	anypidfile;
	long	pid =	get_running_pid(pid_file, &anypidfile);

	if (pid > 0) {
		fprintf(stderr, "%s is running [pid: %ld]\n"
			,	client_name, pid);
		return LSB_STATUS_OK;
	}
	if (anypidfile) {
		fprintf(stderr, "%s is stopped [pidfile exists]\n"
			,	client_name);
		return LSB_STATUS_VAR_PID;
	}
	fprintf(stderr, "%s is stopped.\n", client_name);
	return LSB_STATUS_STOPPED;
}


long
get_running_pid(const char *pid_file, gboolean* anypidfile)
{
	long    pid;
	FILE *  lockfd;
	lockfd = fopen(pid_file, "r");

	if (anypidfile) {
		*anypidfile = (lockfd != NULL);
	}

	if (lockfd != NULL && fscanf(lockfd, "%ld", &pid) == 1 && pid > 0) {
		if (CL_PID_EXISTS((pid_t)pid)) {
			fclose(lockfd);
			return(pid);
		}
	}
	if (lockfd != NULL) {
		fclose(lockfd);
	}
	return(-1L);
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
	pid =	get_running_pid(pid_file, NULL);

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

static const char usagemsg[] = "[-srkhV]\n\ts:status\n\tr:restart"
	"\n\tk:kill\n\th:help\n\tV:debug\n";

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
/*
 * This logic is close - but you should wait for any repeating
 * operations which have already been started to complete.
 * Maybe even if they're already been queued.  FIXME.
 *
 */
static gboolean
can_shutdown() 
{
	lrmd_op_t* op = NULL;
	lrmd_rsc_t* rsc = NULL;
	GList* op_node = NULL;
	
	GList* rsc_node = g_list_first(rsc_list);
	
	for(; NULL!=rsc_node; rsc_node=g_list_next(rsc_node)){
		rsc = (lrmd_rsc_t*)rsc_node->data;
		op_node = g_list_first(rsc->op_list);
		for(; NULL!=op_node; op_node = g_list_next(op_node)) {
			op = (lrmd_op_t*)op_node->data;
			if (0 == op->interval) {
				return FALSE;
			}
		}
	}
	return TRUE;
}
gboolean
sigterm_action(int nsig, gpointer user_data)
{
	shutdown_in_progress = TRUE;		
	if (can_shutdown()) {
		 lrm_shutdown();
	}
	return TRUE;
}

void
register_pid(const char *pid_file,gboolean do_fork
,		gboolean (*shutdown)(int nsig, gpointer userdata))
{
	int	j;
	long	pid;
	FILE *	lockfd;

	pid = getpid();
	lockfd = fopen(pid_file, "w");
	if (lockfd == NULL) {
		lrmd_log(LOG_ERR, "cannot create pid file: %s", pid_file);
		exit(100);
	}else{
		pid = getpid();
		fprintf(lockfd, "%ld\n", pid);
		fclose(lockfd);
	}

	umask(022);

	for (j=0; j < 3; ++j) {
		close(j);
		(void)open("/dev/null", j == 0 ? O_RDONLY : O_RDONLY);
	}
	CL_IGNORE_SIG(SIGINT);
	CL_IGNORE_SIG(SIGHUP);
	G_main_add_SignalHandler(G_PRIORITY_LOW, SIGTERM
	,	 	shutdown, NULL, NULL);
	cl_signal_set_interrupt(SIGTERM, 1);
	/* At least they are harmless, I think. ;-) */
	cl_signal_set_interrupt(SIGINT, 0);
	cl_signal_set_interrupt(SIGHUP, 0);

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

	if ((pid = get_running_pid(PID_FILE, NULL)) > 0) {
		lrmd_log(LOG_ERR, "already running: [pid %ld].", pid);
		lrmd_log(LOG_ERR, "Startup aborted (already running).  Shutting down."); 
		exit(100);
	}

	register_pid(PID_FILE, FALSE, sigterm_action);

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
		lrmd_log(LOG_ERR, "init_start: MALLOCT failed.");
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
	 *Create a waiting connection to accept the callback connect from client
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

	if (G_main_add_input(G_PRIORITY_HIGH, FALSE, 
			     &polled_input_SourceFuncs) ==NULL){
		cl_log(LOG_ERR, "main: G_main_add_input failed");
		lrmd_log(LOG_ERR, "Startup aborted (G_main_add_input failed). "
				  " Shutting down.");
	}
	
	set_child_signal();

	lrmd_log(LOG_DEBUG, "Enabling coredumps");
	/* Althugh lrmd can count on the parent to enable coredump, still
	 * set it here for test, when start manually.
	 */
 	cl_cdtocoredir();
	cl_enable_coredumps(TRUE);	

#ifdef RUN_AS_NOBODY
	/* I commented this out so that andrew can get a core dump for a
	 * a current bug - so that it can be fixed.  I tried lots of other
	 * things, then I read the kernel code.  This is the only way.
	 * FIXME!!  -- Alan R.
	 *
	 * This is now fixable by user code - when we are willing...
	 */
	drop_privs(0, 0); /* become "nobody" */
#endif
	
	/*
	 * Add the signal handler for SIGUSR1, SIGUSR2. 
	 * They are used to change the debug level.
	 */
	G_main_add_SignalHandler(G_PRIORITY_HIGH, SIGUSR1, 
		 	debug_level_adjust, NULL, NULL);
	G_main_add_SignalHandler(G_PRIORITY_HIGH, SIGUSR2, 
		 	debug_level_adjust, NULL, NULL);

	/*Create the mainloop and run it*/
	mainloop = g_main_new(FALSE);
	lrmd_log(LOG_DEBUG, "main: run the loop...");
	lrmd_log(LOG_INFO, "Started.");
	g_main_run(mainloop);

	return_to_orig_privs();
	conn_cmd->ops->destroy(conn_cmd);
	conn_cmd = NULL;

	conn_cbk->ops->destroy(conn_cbk);
	conn_cbk = NULL;

	g_hash_table_destroy(uidlist);
	if ( NULL != auth ) {
		cl_free(auth);
	}
	if (unlink(PID_FILE) == 0) {
		lrmd_log(LOG_DEBUG, "[%s] stopped", lrm_system_name);
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
		/* Will returning FALSE destroy ch? FIXME? */
		return FALSE;
	}
	client->app_name = NULL;
	client->ch_cmd = ch;
	client->g_src = G_main_add_IPC_Channel(G_PRIORITY_DEFAULT,
				ch, FALSE, on_receive_cmd, (gpointer)client,
				on_remove_client);


	return TRUE;
}

/* There is the possibility of delayed messages or even deadlock
 * on the ch_cbk channel under the following circumstances:
 *    Do lots of output on the ch_cbk channel
 *    The OS stops accepting output on it
 *    This output then just sits in the out queue until the
 *	the next time we send a message on the ch_cbk channel
 *
 *    If the client won't get any more messages on the ch_cbk
 *    channel until we send the ones that are there, then
 *    deadlock may occur.
 *
 *    The cure for this is to (strangely enough) call
 *    G_main_add_IPC_channel() for it.  This will cause
 *    its output to be automatically resumed as soon as the OS
 *    will take more data from us.  FIXME
 */
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
		lrmd_log(LOG_ERR, "on_connect_cbk: msg is not register");
		ha_msg_del(msg);
		send_rc_msg(ch, HA_FAIL);
		return TRUE;
	}

	/*get the pid of client */
	if (HA_OK != ha_msg_value_int(msg, F_LRM_PID, &pid)) {
		lrmd_log(LOG_ERR, "on_connect_cbk: can not get pid");
		ha_msg_del(msg);
		send_rc_msg(ch, HA_FAIL);
		return TRUE;
	}
	ha_msg_del(msg);

	/*get the client in the client list*/
	client = lookup_client(pid);
	if (NULL == client) {
		lrmd_log(LOG_ERR,
			"on_connect_cbk: can not find client in client list");
		send_rc_msg(ch, HA_FAIL);
		return TRUE;
	}
	/* FIXME: Should verify that client->ch_cbk is NULL */

	/*fill the channel of callback field*/
	client->ch_cbk = ch;
	send_rc_msg(ch, HA_OK);
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
		lrmd_log(LOG_DEBUG,
			"on_receive_cmd: client %d disconnected."
		,	client->pid);
		return FALSE;
	}

	if (!ch->ops->is_message_pending(ch)) {
		lrmd_log(LOG_DEBUG, "on_receive_cmd: no pending message");
		return TRUE;
	}


	/*get the message */
	msg = msgfromIPC_noauth(ch);
	if (NULL == msg) {
		lrmd_log(LOG_ERR, "on_receive_cmd: can not receive msg");
		return TRUE;
	}
	
	if (TRUE == shutdown_in_progress ) {
		send_rc_msg(ch,HA_FAIL);
		ha_msg_del(msg);
		lrmd_log(LOG_DEBUG, "on_receive_cmd: return HA_FAIL because"\
			 " lrmd is in shutdown.");
		return TRUE;
	}	
	
	/*dispatch the message*/
	type = ha_msg_value(msg, F_LRM_TYPE);

	for (i=0; i<DIMOF(msg_maps); i++) {
		if (0 == STRNCMP_CONST(type, msg_maps[i].msg_type)) {
			int rc;

			strncpy(client->lastrequest, type, sizeof(client->lastrequest));
			client->lastreqstart = time(NULL);
			/*call the handler of the message*/
			rc = msg_maps[i].handler(client, msg);
			client->lastreqend = time(NULL);

			/*return rc to client if need*/
			if (msg_maps[i].need_return_rc) {
				send_rc_msg(ch, rc);
				client->lastrcsent = time(NULL);
			}
			break;
		}
	}
	if (i == DIMOF(msg_maps)) {
		lrmd_log(LOG_ERR, "on_receive_cmd: unknown msg");
	}

	/*delete the msg*/
	ha_msg_del(msg);

	return TRUE;
}

/* Remove all direct pointer references to 'client' before destroying it */
static int
unregister_client(lrmd_client_t* client)
{
	lrmd_rsc_t* rsc = NULL;
	GList* rsc_node = NULL;
	GList* op_node = NULL;
	lrmd_op_t* op = NULL;

	CHECK_ALLOCATED(client, "client", HA_FAIL);

	if (NULL == client_list || NULL == lookup_client(client->pid)) {
		lrmd_log(LOG_ERR,"%s: can not find client %s pid %d"
		,	__FUNCTION__
	,	client->app_name, client->pid);
		return HA_FAIL;
	}
	/* Remove from client_list */
	client_list = g_list_remove(client_list, client);
	
	/* Search all resources for repeating ops this client owns */
	for(rsc_node = g_list_first(rsc_list);
		NULL != rsc_node; rsc_node = g_list_next(rsc_node)){
		rsc = (lrmd_rsc_t*)rsc_node->data;

		/* Remove repeating ops belonging to this client */
		op_node = g_list_first(rsc->repeat_op_list);
		while (NULL != op_node) {
			op = (lrmd_op_t*)op_node->data;
			if (op->client_id == client->pid) {
				op_node = g_list_next(op_node);
				rsc->repeat_op_list = g_list_remove(rsc->repeat_op_list, op);
				if (NULL == op) {
					lrmd_log(LOG_ERR
					,	"%s (): repeat_op_list node has NULL data."
					,	__FUNCTION__);
				}else{
					lrmd_op_destroy(op);
				}
			}
			else {
				op_node = g_list_next(op_node);
			}

		}
	}
	lrmd_log(LOG_DEBUG, "%s: client %s [%d] unregistered", __FUNCTION__
	,	client->app_name
	,	client->pid);
	return HA_OK;
}

void
on_remove_client (gpointer user_data)
{
	lrmd_client_t* client = NULL;

	client = (lrmd_client_t*) user_data;

	CHECK_ALLOCATED(client, "client", );

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
		lrmd_log(LOG_ERR, "on_op_timeout_expired: op has no pid.");
		return FALSE;
	}

	if (HA_OK != ha_msg_mod_int(op->msg, F_LRM_OPSTATUS, LRM_OP_TIMEOUT)) {
		lrmd_log(LOG_ERR,
			"on_op_timeout_expired: can not add opstatus to msg");
	}

	lrmd_log(LOG_WARNING, "%s: TIMEOUT: %s."
	,	__FUNCTION__,  op_info(op));
	if (debug_level) {
		lrm_debug_running_op(op, __FUNCTION__);
	}
	
	on_op_done(op);
	rsc = op->rsc;
	perform_op(rsc);	/* COULD BE NULL - FIXME?? */

	return TRUE;
}

/* This function called when its time to run a repeating operation now */
/* Move op from repeat queue to running queue */
gboolean
on_repeat_op_readytorun(gpointer data)
{
	lrmd_op_t* op = NULL;

	op = (lrmd_op_t*)data;
	CHECK_ALLOCATED(op, "op", FALSE );
	CHECK_ALLOCATED(op->rsc, "op->rsc", FALSE );

	if (op->exec_pid == 0) {
		lrmd_log(LOG_ERR, "%s: exec_pid is 0.",	__FUNCTION__);
		return FALSE;
	}

	lrmd_log2(LOG_DEBUG
	, 	"%s:remove %s from repeat op list and add it to op list"
	, 	__FUNCTION__, op_info(op));

	/* verify rsc isn't NULL.  FIXME! */
	op->rsc->repeat_op_list = g_list_remove(op->rsc->repeat_op_list, op);
	g_source_remove(op->repeat_timeout_tag);

	op->repeat_timeout_tag = -1;
	op->exec_pid = -1;
	op->timeout_tag = -1;

	op->t_addtolist = time_longclock();
	op->rsc->op_list = g_list_append(op->rsc->op_list, op);

	perform_op(op->rsc);

	return TRUE;
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
		lrmd_log(LOG_ERR, "on_msg_register: app_name is null.");
		return HA_FAIL;
	}
	client->app_name = cl_strdup(app_name);

	if (HA_OK != ha_msg_value_int(msg, F_LRM_PID, &client->pid)) {
		lrmd_log(LOG_ERR,
			"on_msg_register: can not find pid field.");
		return HA_FAIL;
	}

	if (HA_OK != ha_msg_value_int(msg, F_LRM_GID, &client->gid)) {
		lrmd_log(LOG_ERR,
			"on_msg_register: can not find gid field.");
		return HA_FAIL;
	}

	if (HA_OK != ha_msg_value_int(msg, F_LRM_UID, &client->uid)) {
		lrmd_log(LOG_ERR,
			"on_msg_register: can not find uid field.");
		return HA_FAIL;
	}

	exist = lookup_client(client->pid);
	if (NULL != exist) {
		client_list = g_list_remove(client_list, exist);
		on_remove_client(exist);
		lrmd_log(LOG_ERR,
			"on_msg_register: client exist, remove first.");

	}

	client_list = g_list_append (client_list, client);
	lrmd_log(LOG_DEBUG, "on_msg_register:client %s [%d] registered"
	,	client->app_name
	,	client->pid);
	
	return HA_OK;
}

int
on_msg_unregister(lrmd_client_t* client, struct ha_msg* msg)
{
	/*
	 * All the work is now done on socket close.
	 * The unregister function is useful, but the message
	 * sent to us here doesn't do anything useful
	 */

	return HA_OK;
}

int
on_msg_get_rsc_classes(lrmd_client_t* client, struct ha_msg* msg)
{
	struct ha_msg* ret = NULL;

	CHECK_ALLOCATED(client, "client", HA_FAIL);
	CHECK_ALLOCATED(msg, "message", HA_FAIL);

	lrmd_log(LOG_DEBUG
	, 	"on_msg_get_rsc_classes:client [%d] gets rsc classes"
	,	client->pid);
	
	ret = create_lrm_ret(HA_OK, 4);
	if (NULL == ret) {
		lrmd_log(LOG_ERR,
			"on_msg_get_rsc_classes: can not create msg.");
		return HA_FAIL;
	}

	cl_msg_add_list(ret,F_LRM_RCLASS,ra_class_list);
	if (HA_OK != msg2ipcchan(ret, client->ch_cmd)) {
		lrmd_log(LOG_ERR,
			"on_msg_get_rsc_classes: can not send the ret msg");
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

	rclass = ha_msg_value(msg, F_LRM_RCLASS);
	
	lrmd_log(LOG_DEBUG
	,	"on_msg_get_rsc_types:client [%d] gets rsc type of %s"
	,	client->pid
	,	rclass);
	
	
	RAExec = g_hash_table_lookup(RAExecFuncs,rclass);

	if (NULL == RAExec) {
		lrmd_log(LOG_DEBUG,"on_msg_get_rsc_types: can not find class");
	}
	else {
		if (NULL == ret) {
			lrmd_log(LOG_ERR,
				"on_msg_get_rsc_types: can not create msg.");
			return HA_FAIL;
		}
		if (0 <= RAExec->get_resource_list(&types)) {
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
			"on_msg_get_rsc_types: can not send the ret msg");
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

	rclass = ha_msg_value(msg, F_LRM_RCLASS);
	rtype = ha_msg_value(msg, F_LRM_RTYPE);
	
	lrmd_log(LOG_DEBUG
	,	"on_msg_get_rsc_providers:client [%d] gets rsc privider of %s::%s"
	,	client->pid
	,	rclass
	,	rtype);

	RAExec = g_hash_table_lookup(RAExecFuncs,rclass);

	if (NULL == RAExec) {
		lrmd_log(LOG_DEBUG,"on_msg_get_rsc_providers: can not find class");
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
	
	lrmd_log(LOG_DEBUG
	,	"on_msg_get_metadata:client [%d] gets rsc metadata of %s::%s"
	,	client->pid
	,	rclass
	,	rtype);


	ret = create_lrm_ret(HA_OK, 5);
	if (NULL == ret) {
		lrmd_log(LOG_ERR,
			"on_msg_get_metadata: can not create msg.");
		return HA_FAIL;
	}
	
	RAExec = g_hash_table_lookup(RAExecFuncs,rclass);
	if (NULL == RAExec) {
		lrmd_log(LOG_DEBUG,"on_msg_get_metadata: can not find class");
	}
	else {
		char* meta = RAExec->get_resource_meta(rtype,provider);
		if (NULL != meta) {
			if (HA_OK != ha_msg_add(ret,F_LRM_METADATA, meta)) {
				lrmd_log(LOG_ERR,
				"on_msg_get_metadata: can not add metadata.");
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

int
on_msg_get_all(lrmd_client_t* client, struct ha_msg* msg)
{
	GList* node;
	int i = 1;
	struct ha_msg* ret = NULL;

	CHECK_ALLOCATED(client, "client", HA_FAIL);
	CHECK_ALLOCATED(msg, "message", HA_FAIL);
	
	lrmd_log(LOG_DEBUG
	,	"on_msg_get_all:client [%d] gets all rsc"
	,	client->pid);

	ret = create_lrm_ret(HA_OK, g_list_length(rsc_list) + 1);
	if (NULL == ret) {
		lrmd_log(LOG_ERR, "on_msg_get_all: can not create msg.");
		return HA_FAIL;
	}

	for(node=g_list_first(rsc_list); NULL!=node; node=g_list_next(node)) {
		lrmd_rsc_t* rsc = (lrmd_rsc_t*)node->data;
		if (HA_OK != cl_msg_list_add_string(ret,F_LRM_RID,rsc->id)) {
			lrmd_log(LOG_ERR,
				"on_msg_get_all: can not add resource id.");
		}	
		i++;
	}

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

	lrmd_log(LOG_DEBUG
	,	"on_msg_get_rsc:client [%d] gets rsc %s"
	,	client->pid, lrmd_nullcheck(id));
	
	rsc = lookup_rsc_by_msg(msg);
	if (NULL == rsc) {
		lrmd_log(LOG_DEBUG
		,	"on_msg_get_rsc: no rsc with id %s."
		,	lrmd_nullcheck(id));
		ret = create_lrm_ret(HA_FAIL, 1);
		if (NULL == ret) {
			lrmd_log(LOG_ERR,
				"on_msg_get_rsc: can not create msg.");
			return HA_FAIL;
		}
	}
	else {
		ret = create_lrm_ret(HA_OK, 5);
		if (NULL == ret) {
			lrmd_log(LOG_ERR,
				"on_msg_get_rsc: can not create msg.");
			return HA_FAIL;
		}
		if (HA_OK != ha_msg_add(ret, F_LRM_RID, rsc->id)
		||  HA_OK != ha_msg_add(ret, F_LRM_RTYPE, rsc->type)
		||  HA_OK != ha_msg_add(ret, F_LRM_RCLASS, rsc->class)) {
			ha_msg_del(ret);
			lrmd_log(LOG_ERR,
				"on_msg_get_rsc: can not add field to msg.");
			return HA_FAIL;
		}
		if( rsc->provider ) {
			if (HA_OK != ha_msg_add(ret, F_LRM_RPROVIDER,
							rsc->provider)) {
				ha_msg_del(ret);
				lrmd_log(LOG_ERR,
				"on_msg_get_rsc: can not add provider to msg.");
				return HA_FAIL;
			}
		}
		
		if (rsc->params && HA_OK!=ha_msg_add_str_table(ret,F_LRM_PARAM,rsc->params)){
			ha_msg_del(ret);
			lrmd_log(LOG_ERR,
				"on_msg_get_rsc: can not add field to msg.");
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

	lrmd_log(LOG_DEBUG
	,"on_msg_get_last_op:client %s[%d] gets last %s op on %s"
	,	client->app_name, client->pid
	, 	lrmd_nullcheck(op_type), lrmd_nullcheck(rid));
	
	rsc = lookup_rsc_by_msg(msg);
	if (NULL != rsc && NULL != op_type) {
		GHashTable* table = g_hash_table_lookup(rsc->last_op_table
					,	client->app_name);
		if (NULL != table ) {
			lrmd_op_t* op = g_hash_table_lookup(table, op_type);
			if (NULL != op) {
				lrmd_log(LOG_ERR
				, "on_msg_get_last_op:return op %s",op_type);
				ret = op_to_msg(op);
				
				if (NULL == ret) {
					lrmd_log(LOG_ERR,
					"on_msg_get_last_op: can't create msg.");
				} else 
				if (HA_OK != ha_msg_add_int(ret
					, 	F_LRM_OPCNT, 1)) {
					lrmd_log(LOG_ERR,
					"on_msg_get_last_op: can't add op count.");
				}
			}
		}
	}
	if (NULL == ret) {
		
		lrmd_log(LOG_ERR, "on_msg_get_last_op:return null");
		ret = create_lrm_ret(HA_OK, 1);
		if (NULL == ret) {
			lrmd_log(LOG_ERR,
				"on_msg_get_last_op: can not create msg.");
			return HA_FAIL;
		}
		if (HA_OK != ha_msg_add_int(ret, F_LRM_OPCNT, 0)) {
			lrmd_log(LOG_ERR, "on_msg_get_last_op: can't add op count.");
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

	lrmd_log(LOG_DEBUG
	,	"on_msg_del_rsc:client [%d] deletes rsc %s"
	,	client->pid, lrmd_nullcheck(id));

	rsc = lookup_rsc_by_msg(msg);

	if (NULL == rsc) {
		lrmd_log(LOG_DEBUG, "on_msg_del_rsc: no rsc with such id.");
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
	/* free the last_op */
	if ( NULL != rsc->last_op) {
		lrmd_op_destroy(rsc->last_op);
	}
	
	rsc_list = g_list_remove(rsc_list, rsc);
	/* free the memory of rsc */
	lrmd_rsc_destroy(rsc);

	return HA_OK;
}

static gboolean
free_str_hash_pair(gpointer key, gpointer value, gpointer user_data)
{
	GHashTable* table = (GHashTable*) value;
	/* FIXME - change of g_strdup()/g_free to cl_ functions */
	g_free(key);
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
	/* FIXME - get rid of g_strdup()/g_free */
	g_free(key);
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
	lrmd_log(LOG_DEBUG
	,	"on_msg_add_rsc:client [%d] adds rsc %s"
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
		if (0 == strcmp(class, rsc->class)) {
			ra_type_exist = TRUE;
			break;
		}
	}
	if (!ra_type_exist) {
		lrmd_log(LOG_ERR
		,	"on_msg_add_rsc: ra class [%s] does not exist."
		,	rsc->class);
		lrmd_rsc_destroy(rsc);
		rsc = NULL;
		return HA_FAIL;
	}

	rsc->params = ha_msg_value_str_table(msg,F_LRM_PARAM);
	rsc->last_op_table = g_hash_table_new(g_str_hash, g_str_equal);
	rsc_list = g_list_append(rsc_list, rsc);

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
			"on_msg_perform_op: no rsc with such id.");
		return -1;
	}

	call_id++;
	type = ha_msg_value(msg, F_LRM_TYPE);
	/* when a flush request arrived, flush all pending ops */
	if (0 == STRNCMP_CONST(type, FLUSHOPS)) {
		lrmd_log(LOG_DEBUG
		,	"on_msg_perform_op:client [%d] flush ops"
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
		
		lrmd_log(LOG_DEBUG
		,	"on_msg_perform_op:client [%d] cancel op callid:%d"
		,	client->pid
		, 	cancel_op_id);
		
		node = g_list_first(rsc->op_list);
		while (NULL != node ) {
			op = (lrmd_op_t*)node->data;
			node = g_list_next(node);
			if ( op->call_id == cancel_op_id) {
				lrmd_log(LOG_DEBUG
				,"on_msg_perform_op:CANCEL:%s(from op list)"
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
				lrmd_log(LOG_DEBUG
				,"on_msg_perform_op:CANCEL:%s(from repeat op list)"
				,op_info(op));
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
			lrmd_log(LOG_ERR,
				"on_msg_perform_op: can not add callid.");
			return -1;
		}
		if (HA_OK !=ha_msg_add(msg, F_LRM_APP, client->app_name)) {
			lrmd_log(LOG_ERR,
				"on_msg_perform_op: can not add app_name.");
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
		op->rsc = rsc;
		op->msg = ha_msg_copy(msg);
		op->t_recv = time_longclock();
		
		lrmd_log(LOG_DEBUG, "on_msg_perform_op:client [%d] add %s"
		,	client->pid
		,	op_info(op));

		if (HA_OK!=ha_msg_value_int(op->msg, F_LRM_INTERVAL,
						 &op->interval)) {
			lrmd_log(LOG_ERR,
				"on_msg_perform_op: can not get interval.");
			goto getout;
		}
		if (HA_OK!=ha_msg_value_int(op->msg, F_LRM_TIMEOUT, &timeout)) {
			lrmd_log(LOG_ERR,
				"on_msg_perform_op: can not get timeout.");
			goto getout;
		}		
		if (HA_OK!=ha_msg_value_int(op->msg, F_LRM_DELAY,
						 &op->delay)) {
			lrmd_log(LOG_ERR,
				"on_msg_perform_op: can not get delay.");
			goto getout;
		}
		if ( 0 < op->delay ) {
			op->repeat_timeout_tag = Gmain_timeout_add(op->delay
					        ,on_repeat_op_readytorun, op);
			op->rsc->repeat_op_list = 
			    g_list_append (op->rsc->repeat_op_list, op);
			lrmd_log2(LOG_DEBUG
			, "on_op_done: %s is added to repeat op list for delay" 
			, op_info(op));
		} else {
			lrmd_log2(LOG_DEBUG
			,	"on_msg_perform_op:add %s to op list"
			,	op_info(op));
			op->t_addtolist = time_longclock();
			rsc->op_list = g_list_append(rsc->op_list, op);
		}

		perform_op(rsc);
	}

	return call_id;
getout:
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
		lrmd_log(LOG_ERR,
			"send_last_op: convert op to msg failed.");
		return;
	}
	if (HA_OK != msg2ipcchan(msg, ch)) {
		lrmd_log(LOG_ERR, "send_last_op: can not send msg");
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
	lrmd_log(LOG_DEBUG, "on_msg_get_state:client [%d] gets state of rsc %s"
	,	client->pid, lrmd_nullcheck(id));

	rsc = lookup_rsc_by_msg(msg);
	if (NULL == rsc) {
		lrmd_log(LOG_ERR, "on_msg_get_state: no rsc with id %s."
		,	lrmd_nullcheck(id));
		send_rc_msg(client->ch_cmd, HA_FAIL);
		return HA_FAIL;
	}
	
	ret = ha_msg_new(5);
	/* add the F_LRM_STATE field */
	if ( NULL == rsc->op_list )
	{
		if (HA_OK != ha_msg_add_int(ret, F_LRM_STATE, LRM_RSC_IDLE)) {
			lrmd_log(LOG_ERR,
				"on_msg_get_state: can not add state to msg.");
			ha_msg_del(ret);
			return HA_FAIL;
		}
		lrmd_log(LOG_DEBUG
		,	"on_msg_get_state:state of rsc %s is LRM_RSC_IDLE"
		,	lrmd_nullcheck(id));
		
	}
	else {
		if (HA_OK != ha_msg_add_int(ret, F_LRM_STATE, LRM_RSC_BUSY)) {
			lrmd_log(LOG_ERR,
				"on_msg_get_state: can not add state to msg.");
			ha_msg_del(ret);
			return HA_FAIL;
		}
		lrmd_log(LOG_DEBUG
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
		lrmd_log(LOG_ERR,
			"on_msg_get_state: can not add state count.");
		ha_msg_del(ret);
		return HA_FAIL;
	}
	/* send the first message to client */	
	if (HA_OK != msg2ipcchan(ret, client->ch_cmd)) {
		lrmd_log(LOG_ERR,
			"on_msg_get_state: can not send the ret msg");
		ha_msg_del(ret);
		return HA_FAIL;
	}
	ha_msg_del(ret);

	/* send the ops in last ops table */
	if(last_ops != NULL) {
		g_hash_table_foreach(last_ops
		,	send_last_op
		,	(gpointer) client->ch_cmd);
	}
	/* send the ops in op list */
	for(node = g_list_first(rsc->op_list)
	;	NULL != node; node = g_list_next(node)){
		op = (lrmd_op_t*)node->data;
		op_msg = op_to_msg(op);
		if (NULL == op_msg) {
			lrmd_log(LOG_ERR,
				"on_msg_get_state: convert op to msg failed.");
			continue;
		}
		if (HA_OK != msg2ipcchan(op_msg, client->ch_cmd)) {
			lrmd_log(LOG_ERR,
				"on_msg_get_state: can not send msg");
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
				"on_msg_get_state: can not add repeat op.");
			continue;
		}
		if (HA_OK != msg2ipcchan(op_msg, client->ch_cmd)) {
			lrmd_log(LOG_ERR,
				"on_msg_get_state: can not send msg");
		}
		ha_msg_del(op_msg);
	}
	return HA_OK;
}
/* /////////////////////op functions//////////////////////////////////////////// */

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
	const char* op_type = NULL;
	GHashTable* client_last_op = NULL;
	lrmd_client_t* client = NULL;

	
	CHECK_ALLOCATED(op, "op", HA_FAIL );
	if (op->exec_pid == 0) {
		lrmd_log(LOG_ERR, "on_op_done: op->exec_pid == 0.");
		return HA_FAIL;
	}
	op->t_done = time_longclock();
	
	lrmd_log2(LOG_DEBUG, "on_op_done:DONE:%s", op_info(op));
	lrmd_log2(LOG_DEBUG
		 ,"TimeStamp:  Recv:%ld,Add to List:%ld,Perform:%ld, Done %ld"
		 ,longclockto_ms(op->t_recv)
		 ,longclockto_ms(op->t_addtolist)
		 ,longclockto_ms(op->t_perform)
		 ,longclockto_ms(op->t_done));

	/*  we should check if the resource exists. */
	if (NULL == g_list_find(rsc_list, op->rsc)) {
		if( op->timeout_tag > 0 ) {
			g_source_remove(op->timeout_tag);
		}
		lrmd_log(LOG_ERR,
			"on_op_done: the resource of this op does not exists");
		/* delete the op */
		lrmd_op_destroy(op);

		return HA_FAIL;

	}

	if (HA_OK != ha_msg_value_int(op->msg,F_LRM_TARGETRC,&target_rc)){
		lrmd_log(LOG_ERR,"on_op_done: can not get tgt status from msg");
		return HA_FAIL;
	}
	if (HA_OK !=
		ha_msg_value_int(op->msg, F_LRM_OPSTATUS, &op_status_int)) {
		lrmd_log(LOG_ERR,
			"on_op_done: can not get op status from msg.");
		return HA_FAIL;
	}
	op_status = (op_status_t)op_status_int;
	
	if (debug_level >= 2) {
		lrmd_op_dump(op, __FUNCTION__);
	}
	if (LRM_OP_DONE != op_status) {
		need_notify = 1;
	} else if (HA_OK != ha_msg_value_int(op->msg,F_LRM_RC,&op_rc)){
		lrmd_log(LOG_DEBUG
		,	"on_op_done:will callback for can not find rc");
		need_notify = 1;
	} else if (EVERYTIME == target_rc) {
		lrmd_log(LOG_DEBUG
		,	"on_op_done:will callback for asked callback everytime");
		need_notify = 1;
	} else if (CHANGED == target_rc) {
		if (HA_OK != ha_msg_value_int(op->msg,F_LRM_LASTRC,
						&last_rc)){
			lrmd_log(LOG_DEBUG
			,"on_op_done:will callback for this is first rc %d"
			,op_rc);
			need_notify = 1;
		} else {
			if (last_rc != op_rc) {
				lrmd_log(LOG_DEBUG
				, "on_op_done:will callback for this rc %d != last rc %d"
				, op_rc, last_rc);
				need_notify = 1;
			}
		}
		if (HA_OK != ha_msg_mod_int(op->msg,F_LRM_LASTRC,
						op_rc)){
			lrmd_log(LOG_ERR,"on_op_done: can not save status ");
			return HA_FAIL;
		}
	}
	else {
		if ( op_rc==target_rc ) {
			lrmd_log(LOG_DEBUG
			,"on_op_done:will callback for target rc %d reached"
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
			,	"%s: the client [%d] of this op does not exist"
			" and client requested notification."
			,	__FUNCTION__, op->client_id);
		}
			

	}
	/* release the old last_op */
	if ( NULL != op->rsc->last_op) {
		lrmd_op_destroy(op->rsc->last_op);
	}
	/* remove the op from op_list and copy to last_op */
	op->rsc->op_list = g_list_remove(op->rsc->op_list,op);
	lrmd_log2(LOG_DEBUG
	, 	"on_op_done:%s is removed from op list" 
	,	op_info(op));

	if( op->timeout_tag > 0 ) {
		g_source_remove(op->timeout_tag);
		op->timeout_tag = -1;
	}
	
	op->rsc->last_op = lrmd_op_copy(op);
	
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
		lrmd_op_t* old_op;
		lrmd_op_t* new_op;
		/*find the hash table for the client*/
		client_last_op = g_hash_table_lookup(op->rsc->last_op_table
		, 			client->app_name);
		if (NULL == client_last_op) {
			client_last_op = g_hash_table_new(g_str_hash, g_str_equal);
			g_hash_table_insert(op->rsc->last_op_table
			,	(gpointer)g_strdup(client->app_name)
			,	(gpointer)client_last_op);
		}
		
		/* Insert the op into the hash table for the client*/
		op_type = ha_msg_value(op->msg, F_LRM_OP);
		old_op = g_hash_table_lookup(client_last_op, op_type);
		new_op = lrmd_op_copy(op);
		if (NULL != old_op) {
			g_hash_table_replace(client_last_op
			, 	g_strdup(op_type)
			,	(gpointer)new_op);
			lrmd_op_destroy(old_op);
		}
		else {
			g_hash_table_insert(client_last_op
			, 	g_strdup(op_type)
			,	(gpointer)new_op);
		}
	}
	
	/*copy the repeat op to repeat list to wait next perform */
	if ( 0 != op->interval && NULL != lookup_client(op->client_id)
	&&   LRM_OP_CANCELLED != op_status) {
		lrmd_op_t* repeat_op = lrmd_op_copy(op);
		repeat_op->exec_pid = -1;
		repeat_op->output_fd = -1;
		repeat_op->timeout_tag = -1;
		repeat_op->repeat_timeout_tag = 
			Gmain_timeout_add(op->interval,	
					on_repeat_op_readytorun, repeat_op);
		op->rsc->repeat_op_list = 
			g_list_append (op->rsc->repeat_op_list, repeat_op);
		lrmd_log2(LOG_DEBUG
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
	CHECK_ALLOCATED(op, "op", HA_FAIL );
	if (op->exec_pid == 0) {
		lrmd_log2(LOG_ERR, "flush_op: op->exec_pid == 0.");
		return HA_FAIL;
	}

	if (HA_OK != ha_msg_add_int(op->msg, F_LRM_RC, HA_FAIL)) {
		lrmd_log(LOG_ERR,"flush_op: can not add rc ");
		return HA_FAIL;
	}

	if (HA_OK != ha_msg_mod_int(op->msg,F_LRM_OPSTATUS,(int)LRM_OP_CANCELLED)){
		lrmd_log(LOG_ERR,"flush_op: can not add op status");
		return HA_FAIL;
	}

	on_op_done(op);

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
	if (NULL == g_list_find(rsc_list, rsc)) {
		lrmd_log(LOG_DEBUG,
			"perform_op: the resource of this op does not exists");
		return HA_FAIL;

	}
	if (NULL == rsc->op_list) {
		lrmd_log2(LOG_DEBUG,"perform_op: no op to perform");
		return HA_OK;
	}

	node = g_list_first(rsc->op_list);
	while ( NULL != node ) {
		op = node->data;
		if (-1 != op->exec_pid )	{
			lrmd_log(LOG_DEBUG, "perform_op: current op is performing");
			break;
		}
		if ( HA_OK != perform_ra_op(op)) {
			lrmd_log(LOG_ERR
			,	"perform_ra_op failed on %s"
			,	op_info(op));
			if (HA_OK != ha_msg_add_int(op->msg, F_LRM_OPSTATUS,
						LRM_OP_ERROR)) {
				lrmd_log(LOG_ERR, "perform_op: can not add opstatus to msg");
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
		lrmd_log(LOG_ERR,"op_to_msg: can not add call_id");
		return NULL;
	}
	return msg;
}

/* //////////////////////////////RA wrap funcs/////////////////////////////////// */
int
perform_ra_op(lrmd_op_t* op)
{
	int fd[2];
	pid_t pid;
	int timeout;
	struct RAExecOps * RAExec = NULL;
	const char* op_type = NULL;
        GHashTable* params = NULL;
        GHashTable* op_params = NULL;
	longclock_t t_stay_in_list = 0;
	CHECK_ALLOCATED(op, "op", HA_FAIL);

	if ( pipe(fd) < 0 ) {
		lrmd_log(LOG_ERR,"perform_ra_op:pipe create error.");
	}

	CHECK_ALLOCATED(op, "op", HA_FAIL);

	if (op->exec_pid == 0) {
		lrmd_log(LOG_ERR, "perform_ra_op: op->exec_pid == 0.");
		return HA_FAIL;
	}

	op_params = ha_msg_value_str_table(op->msg, F_LRM_PARAM);
	params = merge_str_tables(op->rsc->params,op_params);
	free_str_table(op_params);
	free_str_table(op->rsc->params);
	op->rsc->params = params;
	op->t_perform = time_longclock();
	t_stay_in_list = longclockto_ms(op->t_perform - op->t_addtolist);
	if ( t_stay_in_list > WARMINGTIME_IN_LIST) 
	{
		lrmd_log(LOG_ERR
		,	"perform_ra_op: op %s stay in op list longer than %dms"
		,	op_info(op), WARMINGTIME_IN_LIST
		);
		dump_data_for_debug();
	}
	if(HA_OK != ha_msg_value_int(op->msg, F_LRM_TIMEOUT, &timeout)){
		timeout = 0;
		lrmd_log(LOG_ERR,"perform_ra_op: can not find timeout");
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
			close(fd[1]);
			op->output_fd = fd[0];
			op->exec_pid = pid;

			return_to_dropped_privs();
			return HA_OK;

		case 0:		/* Child */
			/* Man: The call setpgrp() is equivalent to setpgid(0,0)
			 * _and_ compiles on BSD variants too
			 * need to investigate if it works the same too.
			 */
			setpgid(0,0);
			close(fd[0]);
			if ( STDOUT_FILENO != fd[1]) {
				if (dup2(fd[1], STDOUT_FILENO)!=STDOUT_FILENO) {
					lrmd_log(LOG_ERR,"dup2 error.");
				}
			}
			close(fd[1]);
			RAExec = g_hash_table_lookup(RAExecFuncs,op->rsc->class);
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
			lrmd_log(LOG_DEBUG
			,	"perform_ra_op:call RA plugin to perform %s, pid: [%d]"
			,	op_info(op), getpid());		
			RAExec->execra (op->rsc->id,
					op->rsc->type,
					op->rsc->provider,
					op_type,
					timeout,
					params);

			/* execra should never return. */
			exit(EXECRA_EXEC_UNKNOWN_ERROR);

	}
	lrmd_log(LOG_ERR, "perform_ra_op: end(impossible).");
	return HA_OK;
}

/*
 * FIXME:
 *	The next 3 functions can be replaced by a single call to
 *	set_sigchld_proctrack().  To be perfectly fair, this is
 *	a fairly new capability
 */
/*g_source_add */
static gboolean
on_polled_input_prepare(GSource* source,
			gint* timeout)
{
	return signal_pending != 0;
}


static gboolean
on_polled_input_check(GSource* source)
{
	return signal_pending != 0;
}

static gboolean
on_polled_input_dispatch(GSource* source,
			 GSourceFunc callback,
			 gpointer	user_data)
{
	unsigned long	handlers;
	int status;
	pid_t pid;

	while (signal_pending) {
		handlers = signal_pending;
		signal_pending=0;

		while((pid=wait3(&status, WNOHANG, NULL)) > 0
			||(pid == -1 && errno == EINTR)) {

			if (pid > 0) {
				ReportProcHasDied(pid, status);
			}
		}
	}
	return TRUE;
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
	char* data = NULL;
        int rc;
        int ret;

	CHECK_ALLOCATED(p, "ProcTrack p", );
	op = p->privatedata;
	CHECK_ALLOCATED(op, "op", );
	if (op->exec_pid == 0) {
		lrmd_log(LOG_ERR, "on_ra_proc_finished: op was freed.");
		dump_data_for_debug();
		return;
	}
	lrmd_log(LOG_DEBUG
	, "on_ra_proc_finished: process [%d],exitcode %d, with signo %d, %s"
	, p->pid, exitcode, signo, op_info(op));		

	op->exec_pid = -1;
	if (9 == signo) {
		lrmd_op_destroy(op);
		p->privatedata = NULL;
		lrmd_log(LOG_DEBUG, "on_ra_proc_finished: this op is killed.");
		dump_data_for_debug();
		return;
	}

	rsc = op->rsc;
	if (NULL == g_list_find(rsc_list, op->rsc)) {
		lrmd_log(LOG_DEBUG,"on_ra_proc_finished: the rsc does not exist");
		on_op_done(op);
		p->privatedata = NULL;
		return;
	}	
	RAExec = g_hash_table_lookup(RAExecFuncs,op->rsc->class);
	if (NULL == RAExec) {
		lrmd_log(LOG_ERR,"on_ra_proc_finished: can not find RAExec");
		dump_data_for_debug();
		return;
	}

	op_type = ha_msg_value(op->msg, F_LRM_OP);
	data = NULL;
	/* We hope we never have to read too much data from a child process */
	/* Or they will hang waiting for us to read and never die :-) */
	read_pipe(op->output_fd, &data);
	rc = RAExec->map_ra_retvalue(exitcode, op_type, data);
	if (EXECRA_EXEC_UNKNOWN_ERROR == rc || EXECRA_NO_RA == rc) {
		if (HA_OK != ha_msg_mod_int(op->msg, F_LRM_OPSTATUS,
							LRM_OP_ERROR)) {
			lrmd_log(LOG_ERR,
			"on_ra_proc_finished: can not add opstatus to msg");
			if (data!=NULL) {
				g_free(data);
			}
			return ;
		}
		lrmd_log(LOG_ERR
		, "on_ra_proc_finished: the exit code shows something wrong");
		
	} else {
		if (HA_OK != ha_msg_mod_int(op->msg, F_LRM_OPSTATUS,
								LRM_OP_DONE)) {
			lrmd_log(LOG_ERR,
			"on_ra_proc_finished: can not add opstatus to msg");
			if (data!=NULL) {
				g_free(data);
			}
			return ;
		}
		if (HA_OK != ha_msg_mod_int(op->msg, F_LRM_RC, rc)) {
			lrmd_log(LOG_ERR,
				"on_ra_proc_finished: can not add rc to msg");
			if (data!=NULL) {
				g_free(data);
			}
			return ;
		}
	}

	if (NULL != data) {
		if (NULL != cl_get_string(op->msg, F_LRM_DATA)) {
			cl_msg_remove(op->msg, F_LRM_DATA);
		}
		ret = ha_msg_add(op->msg, F_LRM_DATA, data);
		if (HA_OK != ret) {
			lrmd_log(LOG_ERR,"on_ra_proc_finished: can not add data to msg");
		}
		g_free(data);
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
	const char* op_type = NULL;

	op = (lrmd_op_t*)(p->privatedata);
	if (NULL == op || op->exec_pid == 0) {
		return "*unknown*";
	}

	op_type = ha_msg_value(op->msg, F_LRM_OP);
	if (NULL == g_list_find(rsc_list, op->rsc)) {
		snprintf(proc_name
		, MAX_PROC_NAME
		, "unknown rsc(may deleted):%s"
		, op_type);
	}else {	
		snprintf(proc_name, MAX_PROC_NAME, "%s:%s", op->rsc->id, op_type);
	}
	return proc_name;
}


/*
 * FIXME:
 *	The next 2 functions can be replaced by a single call to
 *	set_sigchld_proctrack().  To be fair to the authors, this is
 *	a fairly new capability
 */
static void
child_signal_handler(int sig)
{
	signal_pending = 1;
}

void
set_child_signal()
{
	sigset_t our_set;

	const cl_signal_mode_t mode [] =
	{
		{SIGCHLD,	child_signal_handler,	1}
	,	{0,		0,			0}
	};


	if (CL_SIGEMPTYSET(&our_set) < 0) {
		lrmd_log(LOG_ERR, "hb_signal_set_common(): "
			"CL_SIGEMPTYSET(): %s", strerror(errno));
		return;
	}

	if (cl_signal_set_handler_mode(mode, &our_set) < 0) {
		lrmd_log(LOG_ERR, "hb_signal_set_common(): "
			"cl_signal_set_handler_mode()");
		return;
	}
}

/* /////////////////Util Functions////////////////////////////////////////////// */
int
send_rc_msg (IPC_Channel* ch, int rc)
{
	struct ha_msg* ret = NULL;

	ret = create_lrm_ret(rc, 1);
	if (NULL == ret) {
		lrmd_log(LOG_ERR, "send_rc_msg: can not create ret msg");
		return HA_FAIL;
	}

	if (HA_OK != msg2ipcchan(ret, ch)) {
		lrmd_log(LOG_ERR, "send_rc_msg: can not send the ret msg");
	}
	ha_msg_del(ret);
	return HA_OK;
}

lrmd_client_t*
lookup_client (pid_t pid)
{
	GList* node;
	lrmd_client_t* client;
	for(node = g_list_first(client_list);
		NULL != node; node = g_list_next(node)){
		client = (lrmd_client_t*)node->data;
		CHECK_ALLOCATED(client, "client", NULL);
		if (pid == client->pid) {
			return client;
		}
	}

	return NULL;
}

lrmd_rsc_t*
lookup_rsc (const char* rid)
{
	GList* node;
	lrmd_rsc_t* rsc = NULL;

	for(node=g_list_first(rsc_list); NULL!=node; node=g_list_next(node)){
		rsc = (lrmd_rsc_t*)node->data;
		CHECK_ALLOCATED(rsc, "rsc (node->data)", NULL);
		if (0 == strncmp(rid, rsc->id, RID_LEN)) {
			return rsc;
		}
	}

	return NULL;
}

lrmd_rsc_t*
lookup_rsc_by_msg (struct ha_msg* msg)
{
	const char* id = NULL;
	lrmd_rsc_t* rsc = NULL;

	CHECK_ALLOCATED(msg, "msg", NULL);
	id = ha_msg_value(msg, F_LRM_RID);
	if (id == NULL) {
		lrmd_log(LOG_ERR, "lookup_rsc_by_msg: NULL F_LRM_RID");
		return NULL;
	}
	if (RID_LEN <= strlen(id))	{
		lrmd_log(LOG_ERR, "lookup_rsc_by_msg: rsc id is too long.");
		return NULL;
	}
	rsc = lookup_rsc(id);
	return rsc;
}

int
read_pipe(int fd, char ** data)
{
	const int BUFFLEN = 81;
	char buffer[BUFFLEN];
	int readlen;
	GString * gstr_tmp;

	*data = NULL;
	gstr_tmp = g_string_new("");
	do {
		memset(buffer, 0, BUFFLEN);
		errno = 0;
		readlen = read(fd, buffer, BUFFLEN - 1);
		if ( readlen > 0 ) {
			g_string_append(gstr_tmp, buffer);
		}
	} while (readlen == BUFFLEN - 1 || errno == EINTR);
	close(fd);

	if (readlen < 0) {
		lrmd_log(LOG_ERR, "read pipe error when execute RA.");
		return -1;
	}
	if ( gstr_tmp->len == 0 ) {
		lrmd_log(LOG_DEBUG, "read 0 byte from this pipe when execute RA.");
		return 0;
	}

	*data = g_malloc(gstr_tmp->len + 1);
	if ( *data == NULL ) {
		lrmd_log(LOG_ERR, "malloc error in read_pipe.");
		return -1;
	}

	(*data)[0] = '\0';
	(*data)[gstr_tmp->len] = '\0';
	g_strlcpy(*data, gstr_tmp->str, gstr_tmp->len);
	g_string_free(gstr_tmp, TRUE);
	return 0;
}

static void
inherit_config_from_environment(void)
{
	char * inherit_env = NULL;

	/* Donnot need to free the return pointer from getenv */
	inherit_env = getenv(LOGFENV);
	if (inherit_env != NULL) {
		cl_log_set_logfile(inherit_env);
		inherit_env = NULL;
	}

	inherit_env = getenv(DEBUGFENV);
	if (inherit_env != NULL) {
		cl_log_set_debugfile(inherit_env);
		inherit_env = NULL;
	}

	inherit_env = getenv(LOGFACILITY);
	if (inherit_env != NULL) {
		int facility = -1;
		facility = facility_name_to_value(inherit_env);
		if ( facility != -1 ) {
			cl_log_set_facility(facility);
		}
		inherit_env = NULL;
	}
}

static gboolean 
debug_level_adjust(int nsig, gpointer user_data)
{
	switch (nsig) {
		case SIGUSR1:
			debug_level++;
			if (debug_level > 2) {
				debug_level = 2;
			}
			dump_data_for_debug();
			break;

		case SIGUSR2:
			debug_level--;
			if (debug_level < 0) {
				debug_level = 0;
			}
			break;
		
		default:
			lrmd_log(LOG_WARNING, "debug_level_adjust: "
				"Something wrong?.");
	}

	return TRUE;
}

static void
dump_data_for_debug(void)
{
	GList* node;
	GList* opnode;
	lrmd_client_t* client;
	lrmd_rsc_t* rsc;
	lrmd_op_t* op;
	lrmd_log(LOG_DEBUG, "begin dump internal data for debugging."); 

	lrmd_log(LOG_DEBUG, "%d clients are connecting to lrmd."
		 , g_list_length(client_list)); 
	for (node = g_list_first(client_list);
		NULL != node; node = g_list_next(node)){
		client = (lrmd_client_t*)node->data;
		if (client != NULL) {
			lrmd_log(LOG_DEBUG, "client name: %s, client pid: %d"
				", client uid: %d, gid: %d, last request: %s"
				", last op in: %s, lastop out: %s"
				", last op rc: %s"
				,	client->app_name, client->pid
				,	client->uid, client->gid
				,	client->lastrequest
				,	ctime(&client->lastreqstart)
				,	ctime(&client->lastreqend)
				,	ctime(&client->lastrcsent)
				);
			if (!client->ch_cmd) {
				lrmd_log(LOG_DEBUG, "NULL client ch_cmd in dump_data_for_debug()");
			}else{
				lrmd_log(LOG_DEBUG
				,	"Command channel status: %d, read queue addr: %p, write queue addr: %p"
				,	client->ch_cmd->ch_status
				,	client->ch_cmd->recv_queue
				,	client->ch_cmd->send_queue );

				if (client->ch_cmd->recv_queue && client->ch_cmd->send_queue) {
					lrmd_log(LOG_DEBUG, "read Qlen: %d, write Qlen: %d"
					,	client->ch_cmd->recv_queue->current_qlen
					,	client->ch_cmd->send_queue->current_qlen);
				}
			}
			if (!client->ch_cbk) {
				lrmd_log(LOG_DEBUG, "NULL client ch_cbk in dump_data_for_debug()");
			}else{
				lrmd_log(LOG_DEBUG
				,	"Callback channel status: %d, read Qlen: %d, write Qlen: %d"
				,	client->ch_cbk->ch_status
				,	client->ch_cbk->recv_queue->current_qlen
				,	client->ch_cbk->send_queue->current_qlen);
			}
		}else{
			lrmd_log(LOG_DEBUG, "NULL client in dump_data_for_debug()");
		}
	}
	
	lrmd_log(LOG_DEBUG, "%d resources are managed by lrmd."
		 , g_list_length(rsc_list)); 
	for (node = g_list_first(rsc_list);
		NULL != node; node = g_list_next(node)){
		rsc = (lrmd_rsc_t*)node->data;
		if (rsc != NULL) {
			lrmd_log(LOG_DEBUG, "rsc id: %s, type: %s"
				", class: %s, provider: %s"
				,	rsc->id, rsc->type
				,	rsc->class,rsc->provider
				);
			lrmd_log(LOG_DEBUG, "%d op are in op list."
			,	g_list_length(rsc->op_list));
			for (opnode = g_list_first(rsc->op_list);
				NULL != opnode; opnode = g_list_next(opnode)){
				op = (lrmd_op_t*)opnode->data;
				lrmd_log(LOG_DEBUG, "%s", op_info(op));
			}
			
			lrmd_log(LOG_DEBUG, "%d op are in repeat op list."
			,	g_list_length(rsc->repeat_op_list));
			for (opnode = g_list_first(rsc->repeat_op_list);
				NULL != opnode; opnode = g_list_next(opnode)){
				op = (lrmd_op_t*)opnode->data;
				lrmd_log(LOG_DEBUG, "%s", op_info(op));
			}
						
		}else{
			lrmd_log(LOG_DEBUG, "NULL rsc in dump_data_for_debug()");
		}
	}
	
	lrmd_log(LOG_DEBUG, "end dump internal data for debugging."); 
}

static int
facility_name_to_value(const char * name)
{
	int i;
	for (i = 0; facilitynames[i].c_name != NULL; i++) {
		if (strcmp(name, facilitynames[i].c_name) == 0) {
			return facilitynames[i].c_val;
		}
	}
	return -1;
}
static const char* 
op_info(const lrmd_op_t* op)
{
	static char info[255];
	lrmd_rsc_t* rsc = NULL;
	const char * op_type;
	
	rsc = op->rsc;
	op_type = ha_msg_value(op->msg, F_LRM_OP);
	if (NULL == g_list_find(rsc_list, op->rsc)) {
		snprintf(info,sizeof(info)
		,"operation %s on unknown rsc(may deleted) for client %d"
		,lrmd_nullcheck(op_type)
		,op->client_id);
		
	}else{
		snprintf(info, sizeof(info)
		,	"operation %s on %s::%s::%s for client %d"
		,	lrmd_nullcheck(op_type)
		,	lrmd_nullcheck(rsc->class)
		,	lrmd_nullcheck(rsc->type)
		,	lrmd_nullcheck(rsc->id)
		,	op->client_id);
	}
	return info;
}
/*
 * $Log: lrmd.c,v $
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
