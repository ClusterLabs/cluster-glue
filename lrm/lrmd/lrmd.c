
/*
 * Local Resource Manager Daemon
 *
 * Author: Huang Zhen <zhenh@cn.ibm.com>
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
#include <wait.h>
#include <dirent.h>

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

#include <ha_msg.h>
#include <lrm/lrm_api.h>
#include <lrm/lrm_msg.h>
#include <lrm/raexec.h>

#define	MAX_PID_LEN 256

#define OPTARGS		"kh"
#define PID_FILE 	"/var/run/lrmd.pid"
#define DAEMON_LOG   	"/var/log/lrmd.log"
#define DAEMON_DEBUG 	"/var/log/lrmd.debug"
#define PLUGIN_DIR	"/usr/lib/heartbeat/plugins"
#define RA_PLUGIN_DIR	"/usr/lib/heartbeat/plugins/RAExec"

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
typedef struct lrmd_mon lrmd_mon_t;
typedef struct lrmd_op	lrmd_op_t;

struct lrmd_op
{
	lrmd_rsc_t*	rsc;
	lrmd_client_t*	client;
	char*		app_name;
	int		call_id;
	int		exec_pid;
	int		output_fd;
	guint		timeout_tag;
	lrmd_mon_t*	mon;
	struct ha_msg*	msg;
};

struct lrmd_mon
{
	mon_mode_t	mode;
	lrmd_rsc_t*	rsc;
	lrmd_client_t*	client;
	char*		app_name;
	int		call_id;
	int		interval;
	int		target;
	guint		timeout_tag;
	int		pending_op;
	gboolean	is_deleted;
	int		last_status;
	struct ha_msg*	msg;
};

struct lrmd_rsc
{
	rsc_id_t	id;
	char*		type;
	char*		class;
	GHashTable* 	params;

	GList*		op_list;
	GList*		mon_list;
	lrmd_op_t*	last_op;
};

//glib loop call back functions
static gboolean on_connect_cmd(IPC_Channel* ch_cmd, gpointer user_data);
static gboolean on_connect_cbk(IPC_Channel* ch_cbk, gpointer user_data);
static gboolean on_receive_cmd(IPC_Channel* ch_cmd, gpointer user_data);
static gboolean on_timeout_monitor(gpointer data);
static gboolean on_timeout_op_done(gpointer data);
static void on_remove_client(gpointer user_data);

//message handlers
static int on_msg_unregister(lrmd_client_t* client, struct ha_msg* msg);
static int on_msg_register(lrmd_client_t* client, struct ha_msg* msg);
static int on_msg_get_rsc_classes(lrmd_client_t* client, struct ha_msg* msg);
static int on_msg_get_rsc_types(lrmd_client_t* client, struct ha_msg* msg);
static int on_msg_add_rsc(lrmd_client_t* client, struct ha_msg* msg);
static int on_msg_get_rsc(lrmd_client_t* client, struct ha_msg* msg);
static int on_msg_get_all(lrmd_client_t* client, struct ha_msg* msg);
static int on_msg_del_rsc(lrmd_client_t* client, struct ha_msg* msg);
static int on_msg_perform_op(lrmd_client_t* client, struct ha_msg* msg);
static int on_msg_set_monitor(lrmd_client_t* client, struct ha_msg* msg);
static int on_msg_get_state(lrmd_client_t* client, struct ha_msg* msg);

//functions wrap the call to ra plugins
static int perform_ra_op(lrmd_op_t* op);

//Utility functions
static int flush_op(lrmd_op_t* op);
static int perform_op(lrmd_rsc_t* rsc);
static int op_done(lrmd_op_t* op);
static void free_mon(lrmd_mon_t* mon);
static void free_rsc(lrmd_rsc_t* rsc);
static int send_rc_msg ( IPC_Channel* ch, int rc);
static lrmd_client_t* lookup_client (pid_t pid);
static lrmd_rsc_t* lookup_rsc (rsc_id_t rid);
static struct ha_msg* op_to_msg(lrmd_op_t* op);
static int read_pipe(int fd, char ** data);


/*
 * following functions are used to monitor the exit of ra proc
 */
static void set_child_signal(void);
static void child_signal_handler(int sig);

static gboolean	on_polled_input_prepare(gpointer source_data
,			GTimeVal* current_time
,			gint* timeout, gpointer user_data);
static gboolean	on_polled_input_check(gpointer source_data
,			GTimeVal* current_time
,			gpointer user_data);
static gboolean	on_polled_input_dispatch(gpointer source_data
,			GTimeVal* current_time
,			gpointer user_data);

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
static unsigned int signal_pending = 0;

ProcTrack_ops ManagedChildTrackOps = {
	on_ra_proc_finished,
	on_ra_proc_registered,
	on_ra_proc_query_name
};


//msg dispatch table
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
	{ADDRSC,	TRUE,	on_msg_add_rsc},
	{GETRSC,	FALSE,	on_msg_get_rsc},
	{GETALLRCSES,	FALSE,	on_msg_get_all},
	{DELRSC,	TRUE,	on_msg_del_rsc},
	{PERFORMOP,	TRUE,	on_msg_perform_op},
	{FLUSHOPS,	TRUE,	on_msg_perform_op},
	{SETMONITOR,	TRUE,	on_msg_set_monitor},
	{GETRSCSTATE,	FALSE,	on_msg_get_state},
};

GMainLoop* mainloop 		= NULL;
GList* client_list 		= NULL;
GList* rsc_list 		= NULL;
static int call_id 		= 1;
const char* lrm_system_name 	= "lrmd";
GHashTable * RAExecFuncs 	= NULL;
GList* ra_list			= NULL;

/*
 * Daemon functions
 *
 * copy from the code of Andrew Beekhof <andrew@beekhof.net>
 */
void usage(const char* cmd, int exit_status);
int init_start(void);
void lrmd_shutdown(int nsig);
int init_stop(const char *pid_file);
long get_running_pid(const char *pid_file, gboolean* anypidfile);
void register_pid(const char *pid_file, gboolean do_fork,
			void (*shutdown)(int nsig));

int
main(int argc, char ** argv)
{
	int argerr = 0;
	int flag;

	cl_log_set_entity(lrm_system_name);
	cl_log_enable_stderr(TRUE);
	cl_log_set_facility(LOG_USER);


	while ((flag = getopt(argc, argv, OPTARGS)) != EOF) {
		switch(flag) {
			case 'h':		/* Help message */
				usage(lrm_system_name, LSB_EXIT_OK);
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
		usage(lrm_system_name,LSB_EXIT_OK);
	}

	return init_start();
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

void
usage(const char* cmd, int exit_status)
{
	FILE* stream;

	stream = exit_status ? stderr : stdout;

	fprintf(stream, "usage: %s [-h]\n", cmd);
	fflush(stream);

	exit(exit_status);
}

void
lrmd_shutdown(int nsig)
{
	static int shuttingdown = 0;
	CL_SIGNAL(nsig, lrmd_shutdown);

	if (!shuttingdown) {
		shuttingdown = 1;
	}
	if (mainloop != NULL && g_main_is_running(mainloop)) {
		g_main_quit(mainloop);
	}else {
		exit(LSB_EXIT_OK);
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
		cl_log(LOG_CRIT, "cannot create pid file: %s", pid_file);
		exit(LSB_EXIT_GENERIC);
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
}

/* main loop of the daemon*/
int
init_start ()
{
	long pid;
	DIR* dir = NULL;
	PILPluginUniv * PluginLoadingSystem = NULL;
	struct dirent* subdir;
	char* dot = NULL;
	char* ra_name = NULL;
        int len;
	IPC_Auth	auth;
	guint		id = 100;
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
		cl_log(LOG_CRIT, "already running: [pid %ld].", pid);
		exit(LSB_EXIT_OK);
	}

	register_pid(PID_FILE, TRUE, FALSE);

	cl_log_set_logfile(DAEMON_LOG);
	cl_log_set_debugfile(DAEMON_DEBUG);

	//load RA plugins


	PluginLoadingSystem = NewPILPluginUniv (PLUGIN_DIR);
	PILLoadPlugin(PluginLoadingSystem, "InterfaceMgr", "generic",
				  &RegisterRqsts);

	dir = opendir(RA_PLUGIN_DIR);
	if (NULL == dir) {
		cl_log(LOG_ERR, "main: can not open RA plugin dir.");
		return 1;
	}

	while ( NULL != (subdir = readdir(dir))) {
		//skip . and ..
		if ( '.' == subdir->d_name[0]) {
			continue;
		}
		//skip the other type files
		if (NULL == strstr(subdir->d_name, ".so")) {
			continue;
		}
		//remove the ".so"
		dot = strchr(subdir->d_name,'.');
		if (NULL != dot) {
			len = (int)(dot - subdir->d_name);
			ra_name = strndup(subdir->d_name,len);
		}
		else {
			ra_name = g_strdup(subdir->d_name);
		}
		PILLoadPlugin(PluginLoadingSystem , "RAExec", ra_name, NULL);
		ra_list = g_list_append(ra_list,ra_name);
	}

	/*
	 *create the waiting connections
	 *one for register the client,
	 *the other is for create the callback channel
	 */

	uidlist = g_hash_table_new(g_direct_hash, g_direct_equal);
	g_hash_table_insert(uidlist, GUINT_TO_POINTER(id), &one);
	auth.uid = uidlist;
	auth.gid = NULL;


	cl_log(LOG_INFO, "main: start.");

	/*Create a waiting connection to accept command connect from client*/
	conn_cmd_attrs = g_hash_table_new(g_str_hash, g_str_equal);
	g_hash_table_insert(conn_cmd_attrs, path, cmd_path);
	conn_cmd = ipc_wait_conn_constructor(IPC_ANYTYPE, conn_cmd_attrs);
	if (NULL == conn_cmd) {
		cl_log(LOG_ERR,
			"main: can not create wait connection for command.");
		return 1;
	}

	/*Create a source to handle new connect rquests for command*/
	G_main_add_IPC_WaitConnection( G_PRIORITY_HIGH, conn_cmd, NULL, FALSE,
				   on_connect_cmd, conn_cmd, NULL);

	/*
	 *Create a waiting connection to accept the callback connect from client
	*/
	conn_cbk_attrs = g_hash_table_new(g_str_hash, g_str_equal);
	g_hash_table_insert(conn_cbk_attrs, path, cbk_path);
	conn_cbk = ipc_wait_conn_constructor( IPC_ANYTYPE, conn_cbk_attrs);
	if (NULL == conn_cbk) {
		cl_log(LOG_ERR,
			"main: can not create wait connection for callback.");
		return 1;
	}

	/*Create a source to handle new connect rquests for callback*/
	G_main_add_IPC_WaitConnection( G_PRIORITY_HIGH, conn_cbk, NULL, FALSE,
	                               on_connect_cbk, conn_cbk, NULL);

	g_source_add(G_PRIORITY_HIGH, FALSE, &polled_input_SourceFuncs, NULL, NULL, NULL);

	set_child_signal();

	/*Create the mainloop and run it*/
	mainloop = g_main_new(FALSE);
	cl_log(LOG_INFO, "main: run the loop...");
	g_main_run(mainloop);

	conn_cmd->ops->destroy(conn_cmd);
	conn_cmd = NULL;

	conn_cbk->ops->destroy(conn_cbk);
	conn_cbk = NULL;

	if (unlink(PID_FILE) == 0) {
		cl_log(LOG_INFO, "[%s] stopped", lrm_system_name);
	}

	cl_log(LOG_INFO, "main: end.");

	return 0;
}

/*
 *GLoop Message Handlers
 */
gboolean
on_connect_cmd (IPC_Channel* ch, gpointer user_data)
{
	lrmd_client_t* client = NULL;

	cl_log(LOG_INFO, "on_connect_cmd: start.");
	//check paremeters
	if (NULL == ch) {
		cl_log(LOG_ERR, "on_connect_cmd: channel is null");
		return TRUE;
	}
	//create new client
	//the register will be finished in on_msg_register
	client = g_new(lrmd_client_t, 1);
	client->app_name = NULL;
	client->ch_cmd = ch;
	client->g_src = G_main_add_IPC_Channel(G_PRIORITY_DEFAULT,
				ch, FALSE, on_receive_cmd, (gpointer)client,
				on_remove_client);

	cl_log(LOG_INFO, "on_connect_cmd: end.");

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

	cl_log(LOG_INFO, "on_connect_cbk: start.");
	if (NULL == ch) {
		cl_log(LOG_INFO, "on_connect_cbk: channel is null");
		return TRUE;
	}

	/*get the message */
	msg = msgfromIPC_noauth(ch);
	if (NULL == msg) {
		cl_log(LOG_ERR, "on_connect_cbk: can not receive msg");
		return TRUE;
	}

	/*check if it is a register message*/
	type = ha_msg_value(msg, F_LRM_TYPE);
	if (0 != strncmp(type, REGISTER, strlen(REGISTER))) {
		cl_log(LOG_ERR, "on_connect_cbk: msg is not register");
		send_rc_msg(ch, HA_FAIL);
		return TRUE;
	}

	/*get the pid of client */
	if (HA_OK != ha_msg_value_int(msg, F_LRM_PID, &pid)) {
		cl_log(LOG_ERR, "on_connect_cbk: can not get pid");
		send_rc_msg(ch, HA_FAIL);
		return TRUE;
	}

	/*get the client in the client list*/
	client = lookup_client(pid);
	if (NULL == client) {
		cl_log(LOG_ERR,
			"on_connect_cbk: can not find client in client list");
		send_rc_msg(ch, HA_FAIL);
		return TRUE;
	}

	/*fill the channel of callback field*/
	client->ch_cbk = ch;
	send_rc_msg(ch, HA_OK);
	cl_log(LOG_INFO, "on_connect_cbk: end.");
	return TRUE;
}

gboolean
on_receive_cmd (IPC_Channel* ch, gpointer user_data)
{
	int i;
	lrmd_client_t* client = NULL;
	struct ha_msg* msg = NULL;
	const char* type = NULL;

	cl_log(LOG_INFO, "on_receive_cmd: start.");

	client = (lrmd_client_t*)user_data;
	if (IPC_DISCONNECT == ch->ch_status) {
		cl_log(LOG_INFO,
			"on_receive_cmd: channel status is disconnect");
		return FALSE;
	}

	if (!ch->ops->is_message_pending(ch)) {
		cl_log(LOG_INFO, "on_receive_cmd: no pending message");
		return TRUE;
	}


	/*get the message */
	msg = msgfromIPC_noauth(ch);
	if (NULL == msg) {
		cl_log(LOG_INFO, "on_receive_cmd: can not receive msg");
		return TRUE;
	}

	/*dispatch the message*/
	type = ha_msg_value(msg, F_LRM_TYPE);

	for (i=0; i<DIMOF(msg_maps); i++) {
		if (0 == strncmp(type, msg_maps[i].msg_type,
				 strlen(msg_maps[i].msg_type))) {

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
		cl_log(LOG_INFO, "on_receive_cmd: unknown msg");
	}

	/*delete the msg*/
	ha_msg_del(msg);

	cl_log(LOG_INFO, "on_receive_cmd: end.");

	return TRUE;
}

void
on_remove_client (gpointer user_data)
{
	cl_log(LOG_INFO, "on_remove_client: start.");
	lrmd_client_t* client = (lrmd_client_t*) user_data;
	if (NULL != lookup_client(client->pid)) {
		on_msg_unregister(client,NULL);
	}

	g_free(client->app_name);
	g_free(client);

	cl_log(LOG_INFO, "on_remove_client: end.");
}

gboolean
on_timeout_op_done(gpointer data)
{
	lrmd_op_t* op = NULL;
	lrmd_rsc_t* rsc = NULL;

	cl_log(LOG_INFO, "on_timeout_op_done: start.");
	op = (lrmd_op_t*)data;
	if (HA_FAIL==ha_msg_add_int(op->msg, F_LRM_OPSTATUS, LRM_OP_TIMEOUT)) {
		cl_log(LOG_ERR,
			"on_timeout_op_done: can not add opstatus to msg");
	}
	kill(op->exec_pid, 9);
	rsc = op->rsc;	if (NULL != rsc->params ) {
		cl_log(LOG_ERR, "rsc->params:%p\n",rsc->params);
		cl_log(LOG_ERR, "rsc->params:%d\n",g_hash_table_size(rsc->params));
		cl_log(LOG_ERR, "lookup:%s\n",(char*)g_hash_table_lookup(rsc->params,strdup("1")));
	}

	op_done(op);
	perform_op(rsc);
	cl_log(LOG_INFO, "on_timeout_op_done: end.");
	return TRUE;
}

gboolean
on_timeout_monitor(gpointer data)
{
	lrmd_mon_t* mon = NULL;
	lrmd_op_t* op = NULL;
	int timeout = 0;

	cl_log(LOG_INFO, "on_timeout_monitor: start.");
	mon = (lrmd_mon_t*)data;
	mon->pending_op++;
	//create a op
	op = g_new(lrmd_op_t, 1);
	op->call_id = mon->call_id;
	op->exec_pid = -1;
	op->client = NULL;
	op->timeout_tag = -1;
	op->rsc = mon->rsc;
	op->mon	= mon;
	op->app_name = mon->app_name;
	op->msg = ha_msg_copy(mon->msg);
	mon->rsc->op_list = g_list_append(mon->rsc->op_list, op);

	if (HA_FAIL == ha_msg_add(op->msg, F_LRM_APP, mon->app_name)) {
		cl_log(LOG_ERR, "on_timeout_monitor: can not add app_name.");
	}

	ha_msg_value_int(op->msg, F_LRM_TIMEOUT, &timeout);
	if( 0 < timeout ) {
		op->timeout_tag = g_timeout_add(timeout*1000,
						on_timeout_op_done, op);
	}

	perform_op(mon->rsc);
	cl_log(LOG_INFO, "on_timeout_monitor: end.");
	return TRUE;
}

/*LRM Message Handlers*/
int
on_msg_register(lrmd_client_t* client, struct ha_msg* msg)
{
	lrmd_client_t* exist = NULL;
	const char* app_name = NULL;
	cl_log(LOG_INFO, "on_msg_register: start.");

	app_name = ha_msg_value(msg, F_LRM_APP);
	if (NULL == app_name) {
		cl_log(LOG_ERR, "on_msg_register: app_name is null.");
		return HA_FAIL;
	}
	client->app_name = g_strdup(app_name);

	if (HA_OK != ha_msg_value_int(msg, F_LRM_PID, &client->pid)) {
		cl_log(LOG_ERR,
			"on_msg_register: can not find pid field.");
		return HA_FAIL;
	}

	if (HA_OK != ha_msg_value_int(msg, F_LRM_GID, &client->gid)) {
		cl_log(LOG_ERR,
			"on_msg_register: can not find gid field.");
		return HA_FAIL;
	}

	if (HA_OK != ha_msg_value_int(msg, F_LRM_UID, &client->uid)) {
		cl_log(LOG_ERR,
			"on_msg_register: can not find uid field.");
		return HA_FAIL;
	}

	exist = lookup_client(client->pid);
	if (NULL != exist) {
		client_list = g_list_remove(client_list, exist);
		on_remove_client(exist);
		cl_log(LOG_ERR,
			"on_msg_register: client exist, remove first.");

	}

	client_list = g_list_append (client_list, client);
	cl_log(LOG_INFO, "on_msg_register: end.");
	return HA_OK;
}

int
on_msg_unregister(lrmd_client_t* client, struct ha_msg* msg)
{
	lrmd_rsc_t* rsc = NULL;
	lrmd_mon_t* mon = NULL;
	GList* rsc_node = NULL;
	GList* mon_node = NULL;
	GList* op_node = NULL;
	lrmd_op_t* op = NULL;

	cl_log(LOG_INFO, "on_msg_unregister: start.");

	if (NULL == client_list || NULL == lookup_client(client->pid)) {
		cl_log(LOG_ERR,
			"on_msg_unregister: can not find the client.");
		return HA_FAIL;
	}
	//remove from client_list
	client_list = g_list_remove(client_list, client);
	//remove all monitors and pending ops
	for(rsc_node = g_list_first(rsc_list);
		NULL != rsc_node; rsc_node = g_list_next(rsc_node)){
		rsc = (lrmd_rsc_t*)rsc_node->data;
		//remove monitors belong to this client
		mon_node = g_list_first(rsc->mon_list);
		while (NULL != mon_node) {
			mon = (lrmd_mon_t*)mon_node->data;
			if (mon->client == client) {
				mon_node = g_list_next(mon_node);
				rsc->mon_list =
					 g_list_remove(rsc->mon_list, mon);
				free_mon(mon);
			}
			else {
				mon_node = g_list_next(mon_node);
			}

		}
		//remove pending ops belong to this client
		op_node = g_list_first(rsc->op_list);
		op_node = g_list_next(op_node);
		while (NULL != op_node) {
			op = (lrmd_op_t*)op_node->data;
			if (op->client == client) {
				op_node = g_list_next(op_node);
				rsc->op_list = g_list_remove(rsc->op_list, op);
				ha_msg_del(op->msg);
				g_free(op);
			}
			else {
				op_node = g_list_next(op_node);
			}

		}
	}
	cl_log(LOG_INFO, "on_msg_unregister: end.");
	return HA_OK;
}

int
on_msg_get_rsc_classes(lrmd_client_t* client, struct ha_msg* msg)
{
	struct ha_msg* ret = NULL;
	cl_log(LOG_INFO, "on_msg_get_rsc_classes: start.");

	ret = create_lrm_ret(HA_OK, 4);
	if (NULL == ret) {
		cl_log(LOG_ERR,
			"on_msg_get_rsc_classes: can not create msg.");
		return HA_FAIL;
	}

	ha_msg_add_list(ret,F_LRM_RCLASS,ra_list);
	if (HA_OK != msg2ipcchan(ret, client->ch_cmd)) {
		cl_log(LOG_ERR,
			"on_msg_get_rsc_classes: can not send the ret msg");
	}
	ha_msg_del(ret);

	cl_log(LOG_INFO, "on_msg_get_rsc_classes: end.");
	return HA_OK;
}

int
on_msg_get_rsc_types(lrmd_client_t* client, struct ha_msg* msg)
{
	struct ha_msg* ret = NULL;
	struct RAExecOps * RAExec = NULL;
	GList* typeinfos = NULL;
	GList* types = NULL;
	GList* typeinfo;

	cl_log(LOG_INFO, "on_msg_get_rsc_types: start.");

	const char* rclass = ha_msg_value(msg, F_LRM_RCLASS);

	ret = create_lrm_ret(HA_OK, 4);
	if (NULL == ret) {
		cl_log(LOG_ERR,
			"on_msg_get_rsc_types: can not create msg.");
		return HA_FAIL;
	}

	RAExec = g_hash_table_lookup(RAExecFuncs,rclass);
	if (NULL == RAExec) {
		cl_log(LOG_INFO,"on_msg_get_rsc_types: can not find class");
	}
	else {
		if (0 <= RAExec->get_resource_list(&typeinfos)) {
			for ( 	typeinfo = g_list_first(typeinfos);
				NULL != typeinfo;
				typeinfo = g_list_next(typeinfo)) {
				rsc_info_t* info = typeinfo->data;
				types = g_list_append(types, info->rsc_type);
cl_log(LOG_INFO,"TYPE:%s\n",info->rsc_type);			
				
			}
		}
		ha_msg_add_list(ret, F_LRM_RTYPES, types);
	}


	if (HA_OK != msg2ipcchan(ret, client->ch_cmd)) {
		cl_log(LOG_ERR,
			"on_msg_get_rsc_types: can not send the ret msg");
	}
	ha_msg_del(ret);

	cl_log(LOG_INFO, "on_msg_get_rsc_types: end.");
	return HA_OK;
}

int
on_msg_get_all(lrmd_client_t* client, struct ha_msg* msg)
{
	GList* node;
	int i = 1;
	struct ha_msg* ret = NULL;
	char value[UUID_SLEN];
	char key[MAX_NAME_LEN];

	cl_log(LOG_INFO, "on_msg_get_all: start.");
	ret = create_lrm_ret(HA_OK, g_list_length(rsc_list) + 1);
	if (NULL == ret) {
		cl_log(LOG_ERR, "on_msg_get_all: can not create msg.");
		return HA_FAIL;
	}

	for(node=g_list_first(rsc_list); NULL!=node; node=g_list_next(node)) {
		lrmd_rsc_t* rsc = (lrmd_rsc_t*)node->data;
		uuid_unparse(rsc->id, value);
		snprintf(key,MAX_NAME_LEN,"%s%d",F_LRM_RID,i);
		ha_msg_add(ret,key,value);
		i++;
	}

	if (HA_OK != msg2ipcchan(ret, client->ch_cmd)) {
		cl_log(LOG_ERR, "on_msg_get_all: can not send the ret msg");
	}
	ha_msg_del(ret);

	cl_log(LOG_INFO, "on_msg_get_all: end.");
	return HA_OK;
}
int
on_msg_get_rsc(lrmd_client_t* client, struct ha_msg* msg)
{
	rsc_id_t id;
	struct ha_msg* ret = NULL;
	lrmd_rsc_t* rsc = NULL;
	cl_log(LOG_INFO, "on_msg_get_rsc: start.");

	ha_msg_value_uuid(msg,F_LRM_RID,id);
	rsc = lookup_rsc(id);

	if (NULL == rsc) {
		cl_log(LOG_INFO, "on_msg_get_rsc: no rsc with such id.");
		ret = create_lrm_ret(HA_FAIL, 1);
		if (NULL == ret) {
			cl_log(LOG_ERR,
				"on_msg_get_rsc: can not create msg.");
			return HA_FAIL;
		}
	}
	else {
		ret = create_lrm_ret(HA_OK, 5);
		if (NULL == ret) {
			cl_log(LOG_ERR,
				"on_msg_get_rsc: can not create msg.");
			return HA_FAIL;
		}
		if (HA_FAIL == ha_msg_add_uuid(ret, F_LRM_RID, rsc->id)) {
			return HA_FAIL;
		}

		if (HA_FAIL == ha_msg_add(ret, F_LRM_RTYPE, rsc->type)) {
			return HA_FAIL;
		}

		if (HA_FAIL == ha_msg_add(ret, F_LRM_RCLASS, rsc->class))	{
			return HA_FAIL;
		}
		ha_msg_add_hash_table(ret, F_LRM_PARAM, rsc->params);
		
	}
	if (HA_OK != msg2ipcchan(ret, client->ch_cmd)) {
		cl_log(LOG_ERR, "on_msg_get_rsc: can not send the ret msg");
	}
	ha_msg_del(ret);

	cl_log(LOG_INFO, "on_msg_get_rsc: end.");
	return HA_OK;
}
int
on_msg_del_rsc(lrmd_client_t* client, struct ha_msg* msg)
{
	rsc_id_t id;
	lrmd_rsc_t* rsc = NULL;
	GList* mon_node = NULL;
	GList* op_node = NULL;
	
	cl_log(LOG_INFO, "on_msg_del_rsc: start.");

	ha_msg_value_uuid(msg,F_LRM_RID,id);
	rsc = lookup_rsc(id);

	if (NULL == rsc) {
		cl_log(LOG_INFO, "on_msg_del_rsc: no rsc with such id.");
		return HA_FAIL;
	}
	else {
		rsc_list = g_list_remove(rsc_list, rsc);
		mon_node = g_list_first(rsc->mon_list);
		while (NULL != mon_node) {
			lrmd_mon_t* mon = (lrmd_mon_t*)mon_node->data;
			if (mon->client == client) {
				mon_node = g_list_next(mon_node);
				rsc->mon_list =
					g_list_remove(rsc->mon_list, mon);
				free_mon(mon);
			}
			else {
				mon_node = g_list_next(mon_node);
			}

		}
		//remove pending ops
		op_node = g_list_first(rsc->op_list);
		if (NULL == op_node) {
			//no ops, just remove the resource.
			free_rsc(rsc);
		}
		else {
			//the first op is running, so skip it
			//and remove others.
			//when the running op done,
			//it will release the memory of rsc.
			op_node = g_list_next(op_node);
			while (NULL != op_node) {
				lrmd_op_t* op = (lrmd_op_t*)op_node->data;
				if (op->client == client) {
					op_node = g_list_next(op_node);
					rsc->op_list =
						g_list_remove(rsc->op_list, op);
					ha_msg_del(op->msg);
					g_free(op);
				}
				else {
					op_node = g_list_next(op_node);
				}
			}
		}
	}

	cl_log(LOG_INFO, "on_msg_del_rsc: end.");
	return HA_OK;
}

int
on_msg_add_rsc(lrmd_client_t* client, struct ha_msg* msg)
{
	GList* node;
	gboolean ra_type_exist = FALSE;
	char* type = NULL;
	lrmd_rsc_t* rsc = NULL;
	rsc_id_t id;

	cl_log(LOG_INFO, "on_msg_add_rsc: start.");

	ha_msg_value_uuid(msg,F_LRM_RID,id);
	if (NULL != lookup_rsc(id)) {
		cl_log(LOG_ERR,
				"on_msg_add_rsc: same id resource exists.");
		return HA_FAIL;
	}

	rsc = g_new(lrmd_rsc_t,1);
	uuid_copy(rsc->id,id);
	rsc->type = g_strdup(ha_msg_value(msg, F_LRM_RTYPE));
	rsc->class = g_strdup(ha_msg_value(msg, F_LRM_RCLASS));

	ra_type_exist = FALSE;
	for(node=g_list_first(ra_list); NULL!=node; node=g_list_next(node)){
		type = (char*)node->data;
		if (0 == strcmp(type, rsc->class)) {
			ra_type_exist = TRUE;
			break;
		}
	}
	if (!ra_type_exist) {
		g_free(rsc);
		cl_log(LOG_ERR,
				"on_msg_add_rsc: ra type does not exist.");
		return HA_FAIL;
	}
	rsc->params = NULL;
	rsc->op_list = NULL;
	rsc->mon_list = NULL;
	rsc->last_op = NULL;
	rsc->params = ha_msg_value_hash_table(msg,F_LRM_PARAM);
	rsc_list = g_list_append(rsc_list, rsc);

	cl_log(LOG_INFO, "on_msg_add_rsc: end.");
	return HA_OK;
}

int
on_msg_perform_op(lrmd_client_t* client, struct ha_msg* msg)
{
	rsc_id_t id;
	lrmd_rsc_t* rsc = NULL;
	GList* node = NULL;
	const char* type = NULL;
	lrmd_op_t* op = NULL;
	int timeout = 0;
	
	cl_log(LOG_INFO, "on_msg_perform_op: start.");

	ha_msg_value_uuid(msg,F_LRM_RID,id);
	rsc = lookup_rsc(id);
	if (NULL == rsc) {
		cl_log(LOG_ERR,
			"on_msg_perform_op: no rsc with such id.");
		return HA_FAIL;
	}

	call_id++;
	if (HA_FAIL == ha_msg_add_int(msg, F_LRM_CALLID, call_id)) {
		cl_log(LOG_ERR, "on_msg_perform_op: can not add callid.");
		return HA_FAIL;
	}

	type = ha_msg_value(msg, F_LRM_TYPE);
	//when a flush request arrived, flush all pending ops
	if (0 == strncmp(type, FLUSHOPS, strlen(FLUSHOPS))) {
		node = g_list_first(rsc->op_list);
		while (NULL != node ) {
			op = (lrmd_op_t*)node->data;
			node = g_list_next(node);
			rsc->op_list = g_list_remove(rsc->op_list, op);
			flush_op(op);
		}
	}
	else {
		op = g_new(lrmd_op_t, 1);
		op->call_id = call_id;
		op->exec_pid = -1;
		op->client = client;
		op->timeout_tag = -1;
		op->rsc = rsc;
		op->mon	= NULL;
		op->app_name = client->app_name;
		op->msg = ha_msg_copy(msg);
		rsc->op_list = g_list_append(rsc->op_list, op);
		if (HA_FAIL==ha_msg_add(op->msg, F_LRM_APP, client->app_name)) {
			cl_log(LOG_ERR,
				"on_msg_perform_op: can not add app_name.");
		}
		ha_msg_value_int(op->msg, F_LRM_TIMEOUT, &timeout);
		if (0 < timeout ) {
			op->timeout_tag = g_timeout_add(timeout*1000,
						on_timeout_op_done, op);
		}
		perform_op(rsc);
	}

	cl_log(LOG_INFO, "on_msg_perform_op: end.");
	return call_id;
}
int
on_msg_set_monitor(lrmd_client_t* client, struct ha_msg* msg)
{
	rsc_id_t id;
	lrmd_rsc_t* rsc = NULL;
	mon_mode_t mode;
	lrmd_mon_t* mon = NULL;
	
	cl_log(LOG_INFO, "on_msg_set_monitor: start.");

	ha_msg_value_uuid(msg,F_LRM_RID,id);
	rsc = lookup_rsc(id);
	if (NULL == rsc) {
		cl_log(LOG_ERR,
			"on_msg_set_monitor: no rsc with such id.");
		return HA_FAIL;
	}

	call_id++;

	if (HA_FAIL == ha_msg_add_int(msg, F_LRM_CALLID, call_id)) {
		cl_log(LOG_ERR,
			"on_msg_set_monitor: can not add callid.");
		return HA_FAIL;
	}

	//if the monitor mode is clear, remove all monitors on the resource.
	if (HA_FAIL == ha_msg_value_int(msg, F_LRM_MONMODE, (int*)&mode)) {
		cl_log(LOG_ERR,
			"on_msg_set_monitor: can not get monitor mode.");
		return HA_FAIL;
	}
	if (LRM_MONITOR_CLEAR == mode) {
		GList* first = g_list_first(rsc->mon_list);
		while (NULL != first) {
			lrmd_mon_t* mon = (lrmd_mon_t*)first->data;
			rsc->mon_list = g_list_remove(rsc->mon_list, mon);
			free_mon(mon);
			first = g_list_first(rsc->mon_list);
		}
	}
	else {
	//otherwise, create a mon object
		mon = g_new(lrmd_mon_t, 1);
		mon->mode = mode;
		mon->rsc = rsc;
		mon->call_id = call_id;
		mon->client = client;
		mon->app_name = client->app_name;
		mon->pending_op = 0;
		mon->is_deleted = FALSE;
		mon->last_status = -1;
		if (HA_FAIL == ha_msg_value_int(msg, F_LRM_MONINTVL,
						&mon->interval)) {
			g_free(mon);
			cl_log(LOG_ERR,
				"on_msg_set_monitor: can not get interval.");
			return HA_FAIL;
		}
		if (0 >= mon->interval) {
			g_free(mon);
			cl_log(LOG_ERR,
				"on_msg_set_monitor: interal less 1 second.");
			return HA_FAIL;

		}
		if (HA_FAIL == ha_msg_value_int(msg, F_LRM_MONTGT,
						&mon->target)) {
			g_free(mon);
			cl_log(LOG_ERR,
				"on_msg_set_monitor: can not get target.");
			return HA_FAIL;
		}
		mon->msg = ha_msg_copy(msg);
		//add a time GSource to g_loop
		mon->timeout_tag = g_timeout_add(mon->interval*1000,
						 on_timeout_monitor, mon);
		//insert the monitor to the list of resource
		rsc->mon_list = g_list_append(rsc->mon_list, mon);
	}

	cl_log(LOG_INFO, "on_msg_set_monitor: end.");
	return call_id;
}

int
on_msg_get_state(lrmd_client_t* client, struct ha_msg* msg)
{
	rsc_id_t id;
	int op_count = 0;
	lrmd_rsc_t* rsc = NULL;
	GList* node;
	struct ha_msg* ret = NULL;
	lrmd_op_t* op = NULL;
	struct ha_msg* op_msg = NULL;

	cl_log(LOG_INFO, "on_msg_get_state: start.");

	ha_msg_value_uuid(msg,F_LRM_RID,id);
	rsc = lookup_rsc(id);
	if (NULL == rsc) {
		cl_log(LOG_ERR, "on_msg_get_state: no rsc with such id.");
		send_rc_msg(client->ch_cmd, HA_FAIL);
		return HA_FAIL;
	}
	if ( NULL == rsc->op_list )
	{
		ret = NULL;
		if (NULL != rsc->last_op) {
			ret = op_to_msg(rsc->last_op);
		}
		if (NULL == ret) {
			ret = ha_msg_new(5);
		}

		if (HA_FAIL == ha_msg_add_int(ret, F_LRM_STATE, LRM_RSC_IDLE)) {
			cl_log(LOG_ERR,
				"on_msg_get_state: can not add state to msg.");
			ha_msg_del(ret);
			return HA_FAIL;
		}
		if (HA_OK != msg2ipcchan(ret, client->ch_cmd)) {
			cl_log(LOG_ERR,
				"on_msg_get_state: can not send the ret msg");
		}
		ha_msg_del(ret);
	}
	else {
		ret = ha_msg_new(5);

		if (HA_FAIL == ha_msg_add_int(ret, F_LRM_STATE, LRM_RSC_BUSY)) {
			cl_log(LOG_ERR,
				"on_msg_get_state: can not add state to msg.");
			ha_msg_del(ret);
			return HA_FAIL;
		}
		op_count = g_list_length(rsc->op_list);
		if (HA_FAIL == ha_msg_add_int(ret, F_LRM_OPCNT, op_count)) {
			cl_log(LOG_ERR,
				"on_msg_get_state: can not add state count.");
			ha_msg_del(ret);
			return HA_FAIL;
		}
		if (HA_OK != msg2ipcchan(ret, client->ch_cmd)) {
			cl_log(LOG_ERR,
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
				cl_log(LOG_ERR,
					"on_msg_get_state: can not add op.");
				ha_msg_del(op_msg);
				continue;
			}
			if (HA_OK != msg2ipcchan(op_msg, client->ch_cmd)) {
				cl_log(LOG_ERR,
					"on_msg_get_state: can not send msg");
			}
			ha_msg_del(op_msg);
		}
	}
	cl_log(LOG_INFO, "on_msg_get_state: end.");
	return HA_OK;
}
///////////////////////op functions////////////////////////////////////////////

/* this function return the op result to client if it is generated by client.
 * or do some monitor check if it is generated by monitor.
 * then remove it from the op list and put it into the lastop field of rsc.
 */
int
op_done(lrmd_op_t* op)
{
	gboolean need_send = FALSE;
	lrmd_mon_t* mon = NULL;

	cl_log(LOG_INFO, "op_done: start.");
	// we should check if the resource exists.
	if (NULL == g_list_find(rsc_list, op->rsc)) {
		if( op->timeout_tag > 0 ) {
			g_source_remove(op->timeout_tag);
		}
		//delete the op
		ha_msg_del(op->msg);
		g_free(op);

		cl_log(LOG_INFO,
			"op_done: the resource of this op does not exists");
		return HA_FAIL;

	}

	//if the op is create by client
	if (NULL != op->client) {
		//send the result to client
		cl_log(LOG_INFO, "op_done: a normal op done.");
		//we have to check whether the client still exists
		//for the client may signoff during the op running.
		if (NULL != g_list_find(client_list, op->client)) {
			//the client still exists
			if (NULL == op->client->ch_cbk) {
				cl_log(LOG_ERR,
					"op_done: client->ch_cbk is null");
			}
			else
			if (HA_OK != msg2ipcchan(op->msg, op->client->ch_cbk)) {
				cl_log(LOG_ERR,
					"op_done: can not send the ret msg");
			}
		}
		//release the old last_op
		if (NULL != op->rsc->last_op) {
			ha_msg_del(op->rsc->last_op->msg);
			g_free(op->rsc->last_op);
		}
		//remove the op from op_list and assign to last_op
		op->rsc->op_list = g_list_remove(op->rsc->op_list,op);
		op->rsc->last_op = op;
		if( op->timeout_tag > 0 ) {
			g_source_remove(op->timeout_tag);
		}

	}
	else {
	//if the op is created by monitor
		cl_log(LOG_INFO, "op_done: a monitor op done.");

		mon = op->mon;
		mon->pending_op--;
		if (!mon->is_deleted) {
			//check status
			op_status_t status = LRM_OP_ERROR;
			int rc = -1;
			ha_msg_value_int(op->msg,F_LRM_OPSTATUS,(int*)&status);
			ha_msg_value_int(op->msg, F_LRM_RC, &rc);

			need_send = FALSE;
			if (LRM_OP_TIMEOUT == status||LRM_OP_ERROR == status) {
				need_send = TRUE;
			}
			else
			if (LRM_OP_DONE == status) {
				if ((LRM_MONITOR_SET == mon->mode &&
				     rc == mon->target &&
				     mon->last_status != rc) ||
				    (LRM_MONITOR_CHANGE == mon->mode &&
				     rc != mon->last_status)) {
					need_send = TRUE;
				}
				mon->last_status = rc;
			}
			//send monitor msg to client
			if (need_send) {
				if (NULL == mon->client->ch_cbk) {
					cl_log(LOG_ERR,
						"op_done: ch_cbk is null");
				}
				else
				if (HA_OK != msg2ipcchan(op->msg,
						mon->client->ch_cbk)) {
					cl_log(LOG_ERR,
						"op_done: can not send msg");
				}
			}

		}
		else {
			//delete the monitor
			if (0 == mon->pending_op) {
				ha_msg_del(mon->msg);
				g_free(mon);
			}
		}
		//remove timeout source
		if( op->timeout_tag > 0 ) {
			g_source_remove(op->timeout_tag);
		}

		//delete the op
		op->rsc->op_list = g_list_remove(op->rsc->op_list,op);
		ha_msg_del(op->msg);
		g_free(op);
	}
	cl_log(LOG_INFO, "op_done: end.");
	return HA_OK;
}
/* this function flush one op */
int
flush_op(lrmd_op_t* op)
{
	cl_log(LOG_INFO, "flush_op: start.");
	if (HA_FAIL == ha_msg_add_int(op->msg, F_LRM_RC, HA_FAIL)) {
		cl_log(LOG_ERR,"flush_op: can not add rc ");
		return HA_FAIL;
	}

	if (HA_FAIL==ha_msg_add_int(op->msg,F_LRM_OPSTATUS,LRM_OP_CANCELLED)) {
		cl_log(LOG_ERR,"flush_op: can not add op status");
		return HA_FAIL;
	}

	op_done(op);

	cl_log(LOG_INFO, "flush_op: end.");
	return HA_OK;
}

/* this function gets the first op in the rsc op list and execute it*/
int
perform_op(lrmd_rsc_t* rsc)
{
	GList* node = NULL;
	lrmd_op_t* op = NULL;

	cl_log(LOG_INFO, "perform_op: start.");
	if (NULL == g_list_find(rsc_list, rsc)) {
		cl_log(LOG_INFO,
			"op_done: the resource of this op does not exists");
		return HA_FAIL;

	}
	if (NULL == rsc->op_list) {
		cl_log(LOG_INFO,"perform_op: no op to perform");
		return HA_OK;
	}

	node = g_list_first(rsc->op_list);
	while ( NULL != node ) {
		op = node->data;
		if (-1 != op->exec_pid )	{
			cl_log(LOG_INFO, "perform_op: current op is performing");
			break;
		}
		if ( HA_FAIL == perform_ra_op(op)) {
			cl_log(LOG_ERR,	"perform_op: perform_ra_op failed");
			if (HA_FAIL == ha_msg_add_int(op->msg, F_LRM_OPSTATUS,
						LRM_OP_ERROR)) {
				cl_log(LOG_ERR, "perform_op: can not add opstatus to msg");
			}
			op_done(op);
			node = g_list_first(rsc->op_list);
		}
		else {
			cl_log(LOG_INFO,"perform_op: perform a new op");
			break;
		}
	}



	cl_log(LOG_INFO, "perform_op: end.");
	return HA_OK;
}

struct ha_msg*
op_to_msg(lrmd_op_t* op)
{
	struct ha_msg* msg = NULL;

	cl_log(LOG_INFO, "op_to_msg: start.");
	msg = ha_msg_copy(op->msg);
	if (NULL == msg) {
		cl_log(LOG_ERR,"op_to_msg: can not copy the msg");
		return NULL;
	}
	if (HA_FAIL == ha_msg_add_int(msg, F_LRM_CALLID, op->call_id)) {
		ha_msg_del(msg);
		cl_log(LOG_ERR,"op_to_msg: can not add call_id");
		return NULL;
	}
	if (HA_FAIL == ha_msg_add(msg, F_LRM_APP, op->app_name)) {
		ha_msg_del(msg);
		cl_log(LOG_ERR,"op_to_msg: can not add app_name");
		return NULL;
	}
	cl_log(LOG_INFO, "op_to_msg: end.");
	return msg;
}

////////////////////////////////RA wrap funcs///////////////////////////////////
int
perform_ra_op(lrmd_op_t* op)
{
	int fd[2];
	pid_t pid;
	struct RAExecOps * RAExec = NULL;
	const char* op_type = NULL;
        GHashTable* params_table = NULL;
	
	cl_log(LOG_INFO, "perform_ra_op: start.");

	if ( pipe(fd) < 0 ) {
		cl_log(LOG_ERR,"pipe create error.");
	}

	switch(pid=fork()) {
		case -1:
			cl_log(LOG_ERR,	"start_a_child_client: Cannot fork.");
			return HA_FAIL;

		default:	/* Parent */
			NewTrackedProc(pid, 1, PT_LOGVERBOSE,op, &ManagedChildTrackOps);
			close(fd[1]);
			op->output_fd = fd[0];
			op->exec_pid = pid;

			cl_log(LOG_INFO, "perform_ra_op: end(parent).");
			return HA_OK;

		case 0:		/* Child */
			close(fd[0]);
			if ( STDOUT_FILENO != fd[1]) {
				if (dup2(fd[1], STDOUT_FILENO)!=STDOUT_FILENO) {
					cl_log(LOG_ERR,"dup2 error.");
				}
			}
			close(fd[1]);
			RAExec = g_hash_table_lookup(RAExecFuncs,op->rsc->class);
			if (NULL == RAExec) {
				cl_log(LOG_ERR,"perform_ra_op: can not find RAExec");
				return HA_FAIL;
			}
			op_type = ha_msg_value(op->msg, F_LRM_OP);
			params_table = ha_msg_value_hash_table(op->msg, F_LRM_PARAM);
			RAExec->execra(op->rsc->type,op_type,params_table, NULL);

			//execra should never return.
			exit(EXECRA_EXEC_UNKNOWN_ERROR);

	}
	cl_log(LOG_ERR, "perform_ra_op: end(impossible).");
	return HA_OK;
}
/*g_source_add */
static gboolean
on_polled_input_prepare(gpointer source_data, GTimeVal* current_time
,	gint* timeout, gpointer user_data)
{
	return signal_pending != 0;
}


static gboolean
on_polled_input_check(gpointer source_data, GTimeVal* current_time
,	gpointer	user_data)
{
	return signal_pending != 0;
}

static gboolean
on_polled_input_dispatch(gpointer source_data, GTimeVal* current_time
,	gpointer	user_data)
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
	
	cl_log(LOG_INFO, "on_ra_proc_finished: start.");
	if (9 == signo) {
		p->privatedata = NULL;
		cl_log(LOG_INFO, "on_ra_proc_finished: this op is timeout.");
		return;
	}

	op = p->privatedata;
	rsc = op->rsc;
	RAExec = g_hash_table_lookup(RAExecFuncs,op->rsc->class);
	if (NULL == RAExec) {
		cl_log(LOG_ERR,"on_ra_proc_finished: can not find RAExec");
		return;
	}
	op_type = ha_msg_value(op->msg, F_LRM_OP);
	rc = RAExec->map_ra_retvalue(exitcode, op_type);

	if (EXECRA_EXEC_UNKNOWN_ERROR == rc || EXECRA_NO_RA == rc) {
		if (HA_FAIL == ha_msg_add_int(op->msg, F_LRM_OPSTATUS, LRM_OP_ERROR)) {
			cl_log(LOG_ERR,	"on_ra_proc_finished: can not add opstatus to msg");
			return ;
		}
	}
	else {
		if (HA_FAIL == ha_msg_add_int(op->msg, F_LRM_OPSTATUS, LRM_OP_DONE)) {
			cl_log(LOG_ERR,	"on_ra_proc_finished: can not add opstatus to msg");
			return ;
		}
		if (HA_FAIL == ha_msg_add_int(op->msg, F_LRM_RC, rc)) {
			cl_log(LOG_ERR,"on_ra_proc_finished: can not add rc to msg");
			return ;
		}
	}

	data = NULL;
	read_pipe(op->output_fd, &data);
	if (NULL != data) {
		ret = ha_msg_addbin(op->msg, F_LRM_DATA,data,strlen(data));
		if (HA_FAIL == ret) {
			cl_log(LOG_ERR,	"on_ra_proc_finished: can not add data to msg");
		}
		g_free(data);
	}

	op_done(op);
	perform_op(rsc);
	p->privatedata = NULL;
	cl_log(LOG_INFO, "on_ra_proc_finished: end.");
}

/* Handle the death of one of our managed child processes */
static const char *
on_ra_proc_query_name(ProcTrack* p)
{
	cl_log(LOG_INFO, "on_ra_proc_query_name: start.");
	cl_log(LOG_INFO, "on_ra_proc_query_name: end.");
	return "no name yet;)";
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
		cl_log(LOG_ERR, "hb_signal_set_common(): "
			"CL_SIGEMPTYSET(): %s", strerror(errno));
		return;
	}

	if (cl_signal_set_handler_mode(mode, &our_set) < 0) {
		cl_log(LOG_ERR, "hb_signal_set_common(): "
			"cl_signal_set_handler_mode()");
		return;
	}
}

///////////////////Util Functions//////////////////////////////////////////////
int
send_rc_msg (IPC_Channel* ch, int rc)
{
	struct ha_msg* ret = NULL;
	
	cl_log(LOG_INFO, "send_rc_msg: start.");

	ret = create_lrm_ret(rc, 1);
	if (NULL == ret) {
		cl_log(LOG_ERR, "send_rc_msg: can not create ret msg");
		return HA_FAIL;
	}

	if (HA_OK != msg2ipcchan(ret, ch)) {
		cl_log(LOG_ERR, "send_rc_msg: can not send the ret msg");
	}
	ha_msg_del(ret);
	cl_log(LOG_INFO, "send_rc_msg: end.");
	return HA_OK;
}

lrmd_client_t*
lookup_client (pid_t pid)
{
	GList* node;
	lrmd_client_t* client;
	cl_log(LOG_INFO, "lookup_client: start.");
	for(node = g_list_first(client_list);
		NULL != node; node = g_list_next(node)){
		client = (lrmd_client_t*)node->data;
		if (pid == client->pid) {
			cl_log(LOG_INFO, "lookup_client: end.");
			return client;
		}
	}

	cl_log(LOG_INFO, "lookup_client: end.");
	return NULL;
}

lrmd_rsc_t*
lookup_rsc (rsc_id_t rid)
{
	GList* node;
	lrmd_rsc_t* rsc = NULL;
	
	cl_log(LOG_INFO, "lookup_rsc: start.");

	for(node=g_list_first(rsc_list); NULL!=node; node=g_list_next(node)){
		rsc = (lrmd_rsc_t*)node->data;
		if (0 == uuid_compare(rid,rsc->id)) {
			cl_log(LOG_INFO, "lookup_rsc: end.");
			return rsc;
		}
	}

	cl_log(LOG_INFO, "lookup_rsc: end.");
	return NULL;
}

void
free_rsc(lrmd_rsc_t* rsc)
{
	g_free(rsc->type);
	g_free(rsc->class);
	if (NULL != rsc->params) {
		free_hash_table(rsc->params);
	}
	g_free(rsc);
}

void
free_mon(lrmd_mon_t* mon)
{
	if (mon->timeout_tag > 0 ) {
		g_source_remove(mon->timeout_tag);
	}
	//if there is no status op is pending, just release it.
	if (!mon->pending_op) {
		ha_msg_del(mon->msg);
		g_free(mon);
	}
	else {
		// the op stores this pointer so let the op done routine release
		// the memory
		mon->is_deleted = TRUE;
	}
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
		readlen = read(fd, buffer, BUFFLEN - 1);
		if ( readlen > 0 ) {
			g_string_append(gstr_tmp, buffer);
		}
	} while (readlen == BUFFLEN - 1);
	close(fd);

	if (readlen < 0) {
		cl_log(LOG_ERR, "read pipe error when execute RA.");
		return -1;
	}
	if ( gstr_tmp->len == 0 ) {
		cl_log(LOG_INFO, "read 0 byte from this pipe when execute RA.");
		return 0;
	}

	*data = malloc(gstr_tmp->len + 1);
	if ( *data == NULL ) {
		cl_log(LOG_ERR, "malloc error in read_pipe.");
		return -1;
	}

	(*data)[0] = '\0';
	(*data)[gstr_tmp->len] = '\0';
	strncpy(*data, gstr_tmp->str, gstr_tmp->len);
	g_string_free(gstr_tmp, TRUE);
	return 0;
}
