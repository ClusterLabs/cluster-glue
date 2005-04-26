/* $Id: lrmd.c,v 1.93 2005/04/26 11:00:24 zhenh Exp $ */
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

typedef struct
{
	char*		app_name;
	pid_t		pid;
	gid_t		gid;
	uid_t		uid;

	IPC_Channel*	ch_cmd;
	IPC_Channel*	ch_cbk;

	GCHSource*	g_src;
}lrmd_client_t;

typedef struct lrmd_rsc lrmd_rsc_t;
typedef struct lrmd_op	lrmd_op_t;

struct lrmd_op
{
	lrmd_rsc_t*	rsc;
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

struct lrmd_rsc
{
	char*		id;
	char*		type;
	char*		class;
	char*		provider;
	GHashTable* 	params;

	GList*		op_list;
	GList*		repeat_op_list;
	lrmd_op_t*	last_op;
	GHashTable*	last_op_table;
};

/* Debug oriented funtions */
static gboolean debug_level_adjust(int nsig, gpointer user_data);
static void dump_data_for_debug(void);

/* glib loop call back functions */
static gboolean on_connect_cmd(IPC_Channel* ch_cmd, gpointer user_data);
static gboolean on_connect_cbk(IPC_Channel* ch_cbk, gpointer user_data);
static gboolean on_receive_cmd(IPC_Channel* ch_cmd, gpointer user_data);
static gboolean on_timeout_op_done(gpointer data);
static gboolean on_repeat_op_done(gpointer data);
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
static void sigterm_action(int nsig);

/* functions wrap the call to ra plugins */
static int perform_ra_op(lrmd_op_t* op);

/* Utility functions */
static int flush_op(lrmd_op_t* op);
static int perform_op(lrmd_rsc_t* rsc);
static int on_op_done(lrmd_op_t* op);
static const char* op_info(lrmd_op_t* op);
static int send_rc_msg ( IPC_Channel* ch, int rc);
static lrmd_client_t* lookup_client (pid_t pid);
static lrmd_rsc_t* lookup_rsc (const char* rid);
static lrmd_rsc_t* lookup_rsc_by_msg (struct ha_msg* msg);
static int read_pipe(int fd, char ** data);
static struct ha_msg* op_to_msg(lrmd_op_t* op);
static void free_op(lrmd_op_t* op);
static gboolean lrm_shutdown(gpointer data);
static gboolean can_shutdown(void);
static void inherit_config_from_environment(void);
static int facility_name_to_value(const char * name);

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
GList* client_list 		= NULL;
GList* rsc_list 		= NULL;
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
			void (*shutdown)(int nsig));
static gboolean free_str_hash_pair(gpointer key
,	 gpointer value, gpointer user_data);
static gboolean free_str_op_pair(gpointer key
,	 gpointer value, gpointer user_data);
static lrmd_op_t* copy_op(lrmd_op_t* op);
int
main(int argc, char ** argv)
{
	int req_restart = FALSE;
	int req_status  = FALSE;
	int req_stop    = FALSE;
	
	int argerr = 0;
	int flag;
	char * inherit_debuglevel;

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

	cl_malloc_forced_for_glib();
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

void
usage(const char* cmd, int exit_status)
{
	FILE* stream;

	stream = exit_status ? stderr : stdout;

	fprintf(stream, "usage: %s [-srkhV]\n\ts:status\n\tr:restart\n\tk:kill\n\th:help\n\tV:debug\n", cmd);
	fflush(stream);

	exit(exit_status);
}

static gboolean
lrm_shutdown(gpointer data)
{
	lrmd_log(LOG_INFO,"lrmd is shutting down");
	if (mainloop != NULL && g_main_is_running(mainloop)) {
		g_main_quit(mainloop);
	}else {
		exit(LSB_EXIT_OK);
	}
	return FALSE;
}
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
void
sigterm_action(int nsig)
{
	CL_SIGNAL(nsig, sigterm_action);
	shutdown_in_progress = TRUE;		
	if (can_shutdown()) {
		 Gmain_timeout_add(1, lrm_shutdown, NULL);
	}
}

void
register_pid(const char *pid_file,gboolean do_fork,void (*shutdown)(int nsig))
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
	CL_SIGNAL(SIGTERM, shutdown);
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

	/*
	 *create the waiting connections
	 *one for register the client,
	 *the other is for create the callback channel
	 */

	uidlist = g_hash_table_new(g_direct_hash, g_direct_equal);
	/* Add root;s uid */
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
	 */
	drop_privs(0, 0); /* become "nobody" */
#endif
	
	/* Add the signal handler for SIGUSR1, SIGUSR2. 
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
	client = g_new(lrmd_client_t, 1);
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
			"on_receive_cmd: channel status is disconnect");
		return FALSE;
	}

	if (!ch->ops->is_message_pending(ch)) {
		lrmd_log(LOG_DEBUG, "on_receive_cmd: no pending message");
		return TRUE;
	}


	/*get the message */
	msg = msgfromIPC_noauth(ch);
	if (NULL == msg) {
		lrmd_log(LOG_DEBUG, "on_receive_cmd: can not receive msg");
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

			/*call the handler of the message*/
			int rc = msg_maps[i].handler(client, msg);

			/*return rc to client if need*/
			if (msg_maps[i].need_return_rc) {
				send_rc_msg(ch, rc);
			}
			break;
		}
	}
	if (i == DIMOF(msg_maps)) {
		lrmd_log(LOG_DEBUG, "on_receive_cmd: unknown msg");
	}

	/*delete the msg*/
	ha_msg_del(msg);

	return TRUE;
}

void
on_remove_client (gpointer user_data)
{
	lrmd_client_t* client = NULL;

	client = (lrmd_client_t*) user_data;
	if (NULL != lookup_client(client->pid)) {
		on_msg_unregister(client,NULL);
	}
	client->ch_cbk->ops->destroy(client->ch_cbk);
	g_free(client->app_name);
	g_free(client);
}

gboolean
on_timeout_op_done(gpointer data)
{
	lrmd_op_t* op = NULL;
	lrmd_rsc_t* rsc = NULL;
	
	op = (lrmd_op_t*)data;
	if (op == NULL) {
		lrmd_log(LOG_ERR, "on_timeout_op_done: op==NULL.");
		return FALSE;
	}
	if (op->exec_pid == 0) {
		lrmd_log2(LOG_WARNING, "on_timeout_op_done: op was freed.");
		return FALSE;
	}

	if (HA_OK != ha_msg_mod_int(op->msg, F_LRM_OPSTATUS, LRM_OP_TIMEOUT)) {
		lrmd_log(LOG_ERR,
			"on_timeout_op_done: can not add opstatus to msg");
	}

	rsc = op->rsc;
	lrmd_log(LOG_WARNING, "TIMEOUT: %s.", op_info(op));
	
	on_op_done(op);
	perform_op(rsc);

	return TRUE;
}
gboolean
on_repeat_op_done(gpointer data)
{
	lrmd_op_t* op = NULL;
	int timeout = 0;

	op = (lrmd_op_t*)data;
	if (op == NULL) {
		lrmd_log(LOG_WARNING, "on_repeat_op_done: op==NULL.");
		return FALSE;
	}
	if (op->exec_pid == 0) {
		lrmd_log(LOG_WARNING, "on_repeat_op_done: op was freed.");
		return FALSE;
	}

	lrmd_log2(LOG_DEBUG
	, 	"on_repeat_op_done:remove %s from repeat op list and add it to op list"
	, 	op_info(op));
	op->rsc->repeat_op_list = g_list_remove(op->rsc->repeat_op_list, op);
	g_source_remove(op->repeat_timeout_tag);

	op->repeat_timeout_tag = -1;
	op->exec_pid = -1;
	op->timeout_tag = -1;

	op->t_addtolist = time_longclock();
	op->rsc->op_list = g_list_append(op->rsc->op_list, op);
	
	if (HA_OK != ha_msg_value_int(op->msg, F_LRM_TIMEOUT, &timeout)) {
		lrmd_log(LOG_ERR,
			"on_repeat_op_done: can not get timeout value");
		return FALSE;
	}
	if (0 < timeout ) {
		op->timeout_tag = Gmain_timeout_add(timeout,
			on_timeout_op_done, op);
	}

	perform_op(op->rsc);

	return TRUE;
}

/*LRM Message Handlers*/
int
on_msg_register(lrmd_client_t* client, struct ha_msg* msg)
{
	lrmd_client_t* exist = NULL;
	const char* app_name = NULL;

	app_name = ha_msg_value(msg, F_LRM_APP);
	if (NULL == app_name) {
		lrmd_log(LOG_ERR, "on_msg_register: app_name is null.");
		return HA_FAIL;
	}
	client->app_name = g_strdup(app_name);

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
	lrmd_rsc_t* rsc = NULL;
	GList* rsc_node = NULL;
	GList* op_node = NULL;
	lrmd_op_t* op = NULL;

	if (NULL == client_list || NULL == lookup_client(client->pid)) {
		lrmd_log(LOG_ERR,
			"on_msg_unregister: can not find the client.");
		return HA_FAIL;
	}
	/* remove from client_list */
	client_list = g_list_remove(client_list, client);
	
	/* remove all ops */
	for(rsc_node = g_list_first(rsc_list);
		NULL != rsc_node; rsc_node = g_list_next(rsc_node)){
		rsc = (lrmd_rsc_t*)rsc_node->data;

		/* remove repeat ops belong to this client */
		op_node = g_list_first(rsc->repeat_op_list);
		while (NULL != op_node) {
			op = (lrmd_op_t*)op_node->data;
			if (op->client_id == client->pid) {
				op_node = g_list_next(op_node);
				rsc->repeat_op_list = g_list_remove(rsc->repeat_op_list, op);
				free_op(op);
			}
			else {
				op_node = g_list_next(op_node);
			}

		}
	}
	lrmd_log(LOG_DEBUG, "on_msg_unregister:client %s [%d] unregistered"
	,	client->app_name
	,	client->pid);
	return HA_OK;
}

int
on_msg_get_rsc_classes(lrmd_client_t* client, struct ha_msg* msg)
{
	struct ha_msg* ret = NULL;

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

	id = ha_msg_value(msg, F_LRM_RID);

	lrmd_log(LOG_DEBUG
	,	"on_msg_del_rsc:client [%d] deletes rsc %s"
	,	client->pid, lrmd_nullcheck(id));

	rsc = lookup_rsc_by_msg(msg);

	if (NULL == rsc) {
		lrmd_log(LOG_DEBUG, "on_msg_del_rsc: no rsc with such id.");
		return HA_FAIL;
	}
	else {
		/* remove pending ops */
		op_node = g_list_first(rsc->op_list);
		while (NULL != op_node) {
			op = (lrmd_op_t*)op_node->data;
			op_node = g_list_next(op_node);
			rsc->op_list = g_list_remove(rsc->op_list, op);
			free_op(op);
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
		if ( NULL!=rsc->last_op) {
			free_op(rsc->last_op);
		}
		
		rsc_list = g_list_remove(rsc_list, rsc);
		/* free the memeroy of rsc */
		g_free(rsc->id);
		g_free(rsc->type);
		g_free(rsc->class);
		g_free(rsc->provider);
		if (NULL != rsc->params) {
			free_str_table(rsc->params);
		}
		g_hash_table_foreach_remove(rsc->last_op_table
		,	 free_str_hash_pair, NULL);
		g_hash_table_destroy(rsc->last_op_table);
		g_free(rsc);
	}

	return HA_OK;
}

static gboolean
free_str_hash_pair(gpointer key, gpointer value, gpointer user_data)
{
	GHashTable* table = (GHashTable*) value;
	g_free(key);
	g_hash_table_foreach_remove(table, free_str_op_pair, NULL);
	g_hash_table_destroy(table);
	return TRUE;
}

static gboolean
free_str_op_pair(gpointer key, gpointer value, gpointer user_data)
{
	lrmd_op_t* op = (lrmd_op_t*)user_data;
	g_free(key);
	free_op(op);
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

	id = ha_msg_value(msg,F_LRM_RID);
	lrmd_log(LOG_DEBUG
	,	"on_msg_add_rsc:client [%d] adds rsc %s"
	,	client->pid, lrmd_nullcheck(id));
	
	if (RID_LEN <= STRLEN_CONST(id))	{
		lrmd_log(LOG_ERR, "on_msg_add_rsc: rsc_id is too long.");
		return HA_FAIL;
	}

	if (NULL != lookup_rsc(id)) {
		lrmd_log(LOG_ERR, "on_msg_add_rsc: same id resource exists.");
		return HA_FAIL;
	}

	rsc = g_new(lrmd_rsc_t,1);
	rsc->id = g_strdup(id);
	rsc->type = g_strdup(ha_msg_value(msg, F_LRM_RTYPE));
	rsc->class = g_strdup(ha_msg_value(msg, F_LRM_RCLASS));
	rsc->provider = g_strdup(ha_msg_value(msg, F_LRM_RPROVIDER));
	
	ra_type_exist = FALSE;
	for(node=g_list_first(ra_class_list); NULL!=node; node=g_list_next(node)){
		class = (char*)node->data;
		if (0 == strcmp(class, rsc->class)) {
			ra_type_exist = TRUE;
			break;
		}
	}
	if (!ra_type_exist) {
		g_free(rsc->id);
		g_free(rsc->type);
		g_free(rsc->class);
		g_free(rsc->provider);
		g_free(rsc);
		lrmd_log(LOG_ERR,
				"on_msg_add_rsc: ra class does not exist.");
		return HA_FAIL;
	}

	rsc->op_list = NULL;
	rsc->repeat_op_list = NULL;
	rsc->last_op = NULL;
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

	rsc = lookup_rsc_by_msg(msg);
	if (NULL == rsc) {
		lrmd_log(LOG_ERR,
			"on_msg_perform_op: no rsc with such id.");
		return HA_FAIL;
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
				return HA_OK;
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
				return HA_OK;
			}
		}
		return HA_FAIL;		
	}
	else {
		if (HA_OK != ha_msg_add_int(msg, F_LRM_CALLID, call_id)) {
			lrmd_log(LOG_ERR,
				"on_msg_perform_op: can not add callid.");
		}
		if (HA_OK !=ha_msg_add(msg, F_LRM_APP, client->app_name)) {
			lrmd_log(LOG_ERR,
				"on_msg_perform_op: can not add app_name.");
		}

		op = g_new(lrmd_op_t, 1);
		op->call_id = call_id;
		op->exec_pid = -1;
		op->client_id = client->pid;
		op->timeout_tag = -1;
		op->rsc = rsc;
		op->msg = ha_msg_copy(msg);
		op->t_recv = time_longclock();
		op->t_addtolist = 0;
		op->t_perform = 0;
		op->t_done = 0;
		
		lrmd_log(LOG_DEBUG, "on_msg_perform_op:client [%d] add %s"
		,	client->pid
		,	op_info(op));

		if (HA_OK!=ha_msg_value_int(op->msg, F_LRM_INTERVAL,
						 &op->interval)) {
			lrmd_log(LOG_ERR,
				"on_msg_perform_op: can not get interval.");
		}
		if (HA_OK!=ha_msg_value_int(op->msg, F_LRM_TIMEOUT, &timeout)) {
			lrmd_log(LOG_ERR,
				"on_msg_perform_op: can not get timeout.");
		}		
		if (HA_OK!=ha_msg_value_int(op->msg, F_LRM_DELAY,
						 &op->delay)) {
			lrmd_log(LOG_ERR,
				"on_msg_perform_op: can not get delay.");
		}
		if ( 0 < op->delay ) {
			op->repeat_timeout_tag = Gmain_timeout_add(op->delay
					        ,on_repeat_op_done, op);
			op->rsc->repeat_op_list = 
			    g_list_append (op->rsc->repeat_op_list, op);
			lrmd_log2(LOG_DEBUG
			, "on_op_done: %s is added to repeat op list for delay" 
			, op_info(op));
		} else {
 			if (0 < timeout ) {
				op->timeout_tag = Gmain_timeout_add(timeout
						, on_timeout_op_done, op);
			}
			lrmd_log2(LOG_DEBUG
			,	"on_msg_perform_op:add %s to op list"
			,	op_info(op));
			op->t_addtolist = time_longclock();
			rsc->op_list = g_list_append(rsc->op_list, op);
		}

		perform_op(rsc);
	}

	return call_id;
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
	if ( NULL == rsc->op_list )
	{
		if (NULL != rsc->last_op) {
			ret = op_to_msg(rsc->last_op);
		} else {
			ret = ha_msg_new(5);
		}

		if (HA_OK != ha_msg_add_int(ret, F_LRM_STATE, LRM_RSC_IDLE)) {
			lrmd_log(LOG_ERR,
				"on_msg_get_state: can not add state to msg.");
			ha_msg_del(ret);
			return HA_FAIL;
		}
		if (HA_OK != msg2ipcchan(ret, client->ch_cmd)) {
			lrmd_log(LOG_ERR,
				"on_msg_get_state: can not send the ret msg");
		}
		ha_msg_del(ret);
		lrmd_log(LOG_DEBUG
		,	"on_msg_get_state:state of rsc %s is LRM_RSC_IDLE"
		,	lrmd_nullcheck(id));
		
	}
	else {
		ret = ha_msg_new(5);

		if (HA_OK != ha_msg_add_int(ret, F_LRM_STATE, LRM_RSC_BUSY)) {
			lrmd_log(LOG_ERR,
				"on_msg_get_state: can not add state to msg.");
			ha_msg_del(ret);
			return HA_FAIL;
		}
		op_count = g_list_length(rsc->op_list);
		if (HA_OK != ha_msg_add_int(ret, F_LRM_OPCNT, op_count)) {
			lrmd_log(LOG_ERR,
				"on_msg_get_state: can not add state count.");
			ha_msg_del(ret);
			return HA_FAIL;
		}
		if (HA_OK != msg2ipcchan(ret, client->ch_cmd)) {
			lrmd_log(LOG_ERR,
				"on_msg_get_state: can not send the ret msg");
			ha_msg_del(ret);
			return HA_FAIL;
		}
		ha_msg_del(ret);

		for(node = g_list_first(rsc->op_list);
			NULL != node; node = g_list_next(node)){
			op = (lrmd_op_t*)node->data;
			op_msg = op_to_msg(op);
			if (NULL == op_msg) {
				lrmd_log(LOG_ERR,
					"on_msg_get_state: can not add op.");
				continue;
			}
			if (HA_OK != msg2ipcchan(op_msg, client->ch_cmd)) {
				lrmd_log(LOG_ERR,
					"on_msg_get_state: can not send msg");
			}
			ha_msg_del(op_msg);
		}
		lrmd_log(LOG_DEBUG
		,	"on_msg_get_state:state of rsc %s is LRM_RSC_BUSY"
		,	lrmd_nullcheck(id));
		
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
	
	if (op == NULL) {
		lrmd_log(LOG_WARNING, "on_op_done: op==NULL.");
		return HA_FAIL;
	}
	if (op->exec_pid == 0) {
		lrmd_log(LOG_WARNING, "on_op_done: op was freed.");
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
		lrmd_log(LOG_WARNING,
			"on_op_done: the resource of this op does not exists");
		/* delete the op */
		free_op(op);

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
	
	switch (op_status) {
		case LRM_OP_DONE:
			lrmd_log2(LOG_DEBUG
			, "on_op_done:done with status LRM_OP_DONE");
			break;			
		case LRM_OP_CANCELLED:
			lrmd_log(LOG_DEBUG
			, "on_op_done:done with status LRM_OP_CANCELLED");
			break;			
		case LRM_OP_TIMEOUT:
			lrmd_log(LOG_DEBUG
			, "on_op_done:done with status LRM_OP_TIMEOUT");
			break;			
		case LRM_OP_NOTSUPPORTED:
			lrmd_log(LOG_DEBUG
			, "on_op_done:done with status LRM_OP_NOTSUPPORTED");
			break;			
		case LRM_OP_ERROR:
			lrmd_log(LOG_DEBUG
			, "on_op_done:done with status LRM_OP_ERROR");
			break;			
		default:
			lrmd_log(LOG_WARNING
			, "on_op_done:done with unkown status ");
			break;			
	}			
	if (LRM_OP_DONE!= op_status) {
		lrmd_log(LOG_DEBUG
		,	"on_op_done:will callback for done without LRM_OP_DONE");
		need_notify = 1;
	}
	else
	if (HA_OK != ha_msg_value_int(op->msg,F_LRM_RC,&op_rc)){
		lrmd_log(LOG_DEBUG
		,	"on_op_done:will callback for can not find rc");
		need_notify = 1;
	}
	else
	if (EVERYTIME == target_rc) {
		lrmd_log(LOG_DEBUG
		,	"on_op_done:will callback for asked callback everytime");
		need_notify = 1;
	}
	else
	if (CHANGED == target_rc) {
		if (HA_OK != ha_msg_value_int(op->msg,F_LRM_LASTRC,
						&last_rc)){
			lrmd_log(LOG_DEBUG
			,"on_op_done:will callback for this is first rc %d"
			,op_rc);
			need_notify = 1;
		}
		else {
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
			}
			else
			if (HA_OK != msg2ipcchan(op->msg, client->ch_cbk)) {
				lrmd_log(LOG_ERR,
					"on_op_done: can not send the ret msg");
			}
		}
		else {	
			lrmd_log(LOG_WARNING
			,	"on_op_done:the client [%d] of this op does not exist"
			,	op->client_id);
		}
			

	}
	/* release the old last_op */
	if ( NULL!=op->rsc->last_op) {
		free_op(op->rsc->last_op);
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
	
	op->rsc->last_op = copy_op(op);
	
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
		
		/*insert the op to the hash table for the client*/
		op_type = ha_msg_value(op->msg, F_LRM_OP);
		old_op = g_hash_table_lookup(client_last_op, op_type);
		new_op = copy_op(op);
		if (NULL != old_op) {
			g_hash_table_replace(client_last_op
			, 	g_strdup(op_type)
			,	(gpointer)new_op);
			free_op(old_op);
		}
		else {
			g_hash_table_insert(client_last_op
			, 	g_strdup(op_type)
			,	(gpointer)new_op);
		}
	}
	
	/*copy the repeat op to repeat list to wait next perform */
	if ( 0!=op->interval && NULL != lookup_client(op->client_id)
	&&   LRM_OP_CANCELLED != op_status) {
		lrmd_op_t* repeat_op = copy_op(op);
		repeat_op->exec_pid = -1;
		repeat_op->output_fd = -1;
		repeat_op->timeout_tag = -1;
		repeat_op->repeat_timeout_tag = 
			Gmain_timeout_add(op->interval,	
					on_repeat_op_done, repeat_op);
		op->rsc->repeat_op_list = 
			g_list_append (op->rsc->repeat_op_list, repeat_op);
		lrmd_log2(LOG_DEBUG
		, "on_op_done:repeat %s is added to repeat op list to wait" 
		, op_info(op));
		
	}
	free_op(op);

	return HA_OK;
}
/* this function flush one op */
int
flush_op(lrmd_op_t* op)
{
	if (op == NULL) {
		lrmd_log(LOG_ERR, "flush_op: op==NULL.");
		return HA_FAIL;
	}
	if (op->exec_pid == 0) {
		lrmd_log2(LOG_WARNING, "flush_op: op was freed.");
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

	if (TRUE == shutdown_in_progress && can_shutdown()) {
		lrm_shutdown(NULL);
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

	if (op == NULL) {
		lrmd_log(LOG_ERR, "op_to_msg: op==NULL.");
		return NULL;
	}
	if (op->exec_pid == 0) {
		lrmd_log(LOG_WARNING, "op_to_msg: op was freed.");
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

	if ( pipe(fd) < 0 ) {
		lrmd_log(LOG_ERR,"perform_ra_op:pipe create error.");
	}

	if (op == NULL) {
		lrmd_log(LOG_WARNING, "perform_ra_op: op==NULL.");
		return HA_FAIL;
	}
	if (op->exec_pid == 0) {
		lrmd_log(LOG_WARNING, "perform_ra_op: op was freed.");
		return HA_FAIL;
	}

	op_params = ha_msg_value_str_table(op->msg, F_LRM_PARAM);
	params = merge_str_tables(op->rsc->params,op_params);
	free_str_table(op_params);
	free_str_table(op->rsc->params);
	op->rsc->params = params;
	op->t_perform = time_longclock();
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
			if(HA_OK != ha_msg_value_int(op->msg, F_LRM_TIMEOUT, &timeout)){
				timeout = 0;
				lrmd_log(LOG_ERR,"perform_ra_op: can not find timeout");
			}
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

	op = p->privatedata;
	if (op == NULL) {
		lrmd_log(LOG_WARNING, "on_ra_proc_finished: op==NULL.");
		return;
	}
	if (op->exec_pid == 0) {
		lrmd_log(LOG_WARNING, "on_ra_proc_finished: op was freed.");
		return;
	}
	lrmd_log(LOG_DEBUG
	, "on_ra_proc_finished: process [%d],exitcode %d, with signo %d, %s"
	, p->pid, exitcode, signo, op_info(op));		

	op->exec_pid = -1;
	if (9 == signo) {
		free_op(op);
		p->privatedata = NULL;
		lrmd_log(LOG_DEBUG, "on_ra_proc_finished: this op is killed.");
		return;
	}

	rsc = op->rsc;
	RAExec = g_hash_table_lookup(RAExecFuncs,op->rsc->class);
	if (NULL == RAExec) {
		lrmd_log(LOG_ERR,"on_ra_proc_finished: can not find RAExec");
		return;
	}

	op_type = ha_msg_value(op->msg, F_LRM_OP);
	data = NULL;
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
		lrmd_log(LOG_WARNING
		, "on_ra_proc_finishedthe exit code shows something wrong");
		
	}
	else {
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

	snprintf(proc_name, MAX_PROC_NAME, "%s:%s", op->rsc->id, op_type);
	return proc_name;
}


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

	id = ha_msg_value(msg, F_LRM_RID);
	if (id == NULL) {
		lrmd_log(LOG_ERR, "lookup_rsc_by_msg: NULL F_LRM_RID");
		return NULL;
	}
	if (RID_LEN <= STRLEN_CONST(id))	{
		lrmd_log(LOG_ERR, "lookup_rsc_by_msg: rsc id is too long.");
		return NULL;
	}
	rsc = lookup_rsc(id);
	return rsc;
}
void
free_op(lrmd_op_t* op)
{
	if (op == NULL) {
		return;
	}
	
	if ( 0 == op->exec_pid ) {
		lrmd_log(LOG_DEBUG, "free_op: donnot need to free a "
			"freed struct.");
		lrmd_log(LOG_DEBUG, "free_op: op->msg address: %p", op->msg);
		return;
	}

	if (-1 != op->exec_pid ) {
		return_to_orig_privs();	
		kill(op->exec_pid, 9);
		return_to_dropped_privs();
		return;
	}

	if (-1 != (int)op->repeat_timeout_tag) {
		g_source_remove(op->repeat_timeout_tag);
		op->repeat_timeout_tag = -1;
	}

	if (-1 != (int)op->timeout_tag) {
		g_source_remove(op->timeout_tag);
		op->timeout_tag = -1;
	}

	ha_msg_del(op->msg);
	op->msg = NULL;
	op->exec_pid = 0;
	g_free(op);
}
static lrmd_op_t* 
copy_op(lrmd_op_t* op)
{
	lrmd_op_t* ret = g_new(lrmd_op_t, 1);
	if ( NULL == ret) {
		return NULL;
	}
	ret->rsc = op->rsc;
	ret->client_id = op->client_id;
	ret->call_id = op->call_id;
	ret->exec_pid = op->exec_pid;
	ret->output_fd = op->output_fd;
	ret->timeout_tag = op->timeout_tag;
	ret->repeat_timeout_tag = op->repeat_timeout_tag;
	ret->interval = op->interval;
	ret->msg = ha_msg_copy(op->msg);
	ret->t_recv = op->t_recv;
	ret->t_addtolist = op->t_addtolist;
	ret->t_perform = op->t_perform;
	ret->t_done = op->t_done;
	return ret;
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
	lrmd_client_t* client;
	
	lrmd_log(LOG_DEBUG, "Dump internal data for debugging."); 

	lrmd_log(LOG_DEBUG, "%d clients are connecting to lrmd."
		 , g_list_length(client_list)); 
	for (node = g_list_first(client_list);
		NULL != node; node = g_list_next(node)){
		client = (lrmd_client_t*)node->data;
		if (client != NULL) {
			lrmd_log(LOG_DEBUG, "client name: %s, client pid: %d, "
				"client uid: %d, client gid: %d"
				, client->app_name, client->pid
				, client->uid, client->gid);
		}
	}
	
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
op_info(lrmd_op_t* op)
{
	static char info[255];
	lrmd_rsc_t* rsc = NULL;
	const char * op_type;
	
	rsc = op->rsc;
	op_type = ha_msg_value(op->msg, F_LRM_OP);
	
	snprintf(info,sizeof(info)
	,	"operation %s on %s::%s::%s for client %d"
	,	lrmd_nullcheck(op_type)
	,	lrmd_nullcheck(rsc->class)
	,	lrmd_nullcheck(rsc->type)
	,	lrmd_nullcheck(rsc->id)
	,	op->client_id);
	
	return info;
}
/*
 * $Log: lrmd.c,v $
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
 * Free operation data in on_ra_proc_finished() instead of free_op()
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
