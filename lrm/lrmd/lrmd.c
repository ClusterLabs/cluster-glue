
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
#include <dirent.h>

#include <glib.h>
#include <heartbeat.h>
#include <pils/plugin.h>
#include <pils/generic.h>
#include <clplumbing/cl_log.h>
#include <clplumbing/ipc.h>
#include <clplumbing/GSource.h>
#include <clplumbing/cl_poll.h>
#include <clplumbing/lsb_exitcodes.h>
#include <clplumbing/cl_signal.h>

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
	int		callback_id;
	guint 		timeout_tag;
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
	char*		name;
	char*		type;
	GHashTable* 	params;

	GList*		op_list;
	GList*		mon_list;
	lrmd_op_t*	last_op;
};

//glib loop call back functions
static gboolean on_connect_cmd(IPC_Channel* ch_cmd, gpointer user_data);
static gboolean on_connect_cbk(IPC_Channel* ch_cbk, gpointer user_data);
static gboolean on_recieve_cmd(IPC_Channel* ch_cmd, gpointer user_data);
static gboolean on_timeout_monitor(gpointer data);
static gboolean on_timeout_op_done(gpointer data);
//static gboolean on_idle (gpointer data);
gboolean on_idle (gpointer data);
static void on_remove_client(gpointer user_data);

//message handlers
static int on_msg_unregister(lrmd_client_t* client, struct ha_msg* msg);
static int on_msg_register(lrmd_client_t* client, struct ha_msg* msg);
static int on_msg_get_ra_types(lrmd_client_t* client, struct ha_msg* msg);
static int on_msg_add_rsc(lrmd_client_t* client, struct ha_msg* msg);
static int on_msg_get_rsc(lrmd_client_t* client, struct ha_msg* msg);
static int on_msg_get_all(lrmd_client_t* client, struct ha_msg* msg);
static int on_msg_del_rsc(lrmd_client_t* client, struct ha_msg* msg);
static int on_msg_perform_op(lrmd_client_t* client, struct ha_msg* msg);
static int on_msg_set_monitor(lrmd_client_t* client, struct ha_msg* msg);
static int on_msg_get_state(lrmd_client_t* client, struct ha_msg* msg);

//functions wrap the call to ra plugins
static int check_ra_rc(struct RAExecOps * RAExec, int callback_id, int* rc,
					   char** data);
static int perform_ra_op(struct RAExecOps * RAExec, lrmd_op_t* op);

//Utility functions
static int flush_op(lrmd_op_t* op);
static int perform_op(lrmd_rsc_t* rsc);
static int check_op(lrmd_op_t* op);
static int op_done(lrmd_op_t* op);
static void free_mon(lrmd_mon_t* mon);
static void free_rsc(lrmd_rsc_t* rsc);
static int send_rc_msg ( IPC_Channel* ch, int rc);
static lrmd_client_t* lookup_client (pid_t pid);
static lrmd_rsc_t* lookup_rsc (rsc_id_t rid);
static struct ha_msg* op_to_msg(lrmd_op_t* op);

static void lrmd_log (int priority, int level, const char* fmt);


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
	{GETRATYPES,	FALSE,	on_msg_get_ra_types},
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
	cl_log_set_entity(lrm_system_name);
	cl_log_enable_stderr(TRUE);
	cl_log_set_facility(LOG_USER);

	int req_stop = FALSE;
	int argerr = 0;
	int flag;

	while ((flag = getopt(argc, argv, OPTARGS)) != EOF) {
		switch(flag) {
			case 'k':		/* Stop (kill) */
				req_stop = TRUE;
				break;
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

	if (req_stop) {
		return init_stop(PID_FILE);
	}
	return init_start();
}

int
init_stop(const char *pid_file)
{
	if (pid_file == NULL) {
		cl_log(LOG_ERR, "No pid file specified to kill process");
		return LSB_EXIT_GENERIC;
	}
	long	pid;
	int	rc = LSB_EXIT_OK;
	pid =	get_running_pid(pid_file, NULL);

	if (pid > 0) {
		if (CL_KILL((pid_t)pid, SIGTERM) < 0) {
			rc = (errno == EPERM
			      ?	LSB_EXIT_EPERM : LSB_EXIT_GENERIC);
			fprintf(stderr, "Cannot kill pid %ld\n", pid);
		}else{
			cl_log(LOG_INFO,
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

	fprintf(stream, "usage: %s [-kh]\n", cmd);
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

	if (do_fork) {
		pid = fork();

		if (pid < 0) {
			cl_log(LOG_CRIT, "cannot start daemon");
			exit(LSB_EXIT_GENERIC);
		}else if (pid > 0) {
			exit(LSB_EXIT_OK);
		}
	}

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

	if ((pid = get_running_pid(PID_FILE, NULL)) > 0) {
		cl_log(LOG_CRIT, "already running: [pid %ld].", pid);
		exit(LSB_EXIT_OK);
	}

	register_pid(PID_FILE, TRUE, FALSE);

	cl_log_set_logfile(DAEMON_LOG);
	cl_log_set_debugfile(DAEMON_DEBUG);

	//load RA plugins
	PILPluginUniv * PluginLoadingSystem = NULL;

	PILGenericIfMgmtRqst RegisterRqsts[]= {
		{"RAExec", &RAExecFuncs, NULL, NULL, NULL},
		{ NULL, NULL, NULL, NULL, NULL} };

	PluginLoadingSystem = NewPILPluginUniv (PLUGIN_DIR);
	PILLoadPlugin(PluginLoadingSystem , "InterfaceMgr", "generic" ,
				  &RegisterRqsts);

	DIR* dir = opendir(RA_PLUGIN_DIR);
	if (NULL == dir) {
		lrmd_log(LOG_ERR, -1, "main: can not open RA plugin dir.");
		return 1;
	}

	struct dirent* subdir;
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
		char* dot = strchr(subdir->d_name,'.');
		char* ra_name;
		if (NULL != dot) {
			int len = (int)(dot - subdir->d_name);
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

	lrmd_log(LOG_INFO, 1, "main: start.");
	IPC_WaitConnection* conn_cmd = NULL;
	IPC_WaitConnection* conn_cbk = NULL;

	GHashTable* conn_cmd_attrs;
	GHashTable* conn_cbk_attrs;

	char path[] = IPC_PATH_ATTR;
	char cmd_path[] = LRM_CMDPATH;
	char cbk_path[] = LRM_CALLBACKPATH;

	/*Create a waiting connection to accept command connect from client*/
	conn_cmd_attrs = g_hash_table_new(g_str_hash, g_str_equal);
	g_hash_table_insert(conn_cmd_attrs, path, cmd_path);
	conn_cmd = ipc_wait_conn_constructor(IPC_ANYTYPE, conn_cmd_attrs);
	if (NULL == conn_cmd) {
		lrmd_log(LOG_ERR, -1,
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
		lrmd_log(LOG_ERR, -1,
			"main: can not create wait connection for callback.");
		return 1;
	}

	/*Create a source to handle new connect rquests for callback*/
	G_main_add_IPC_WaitConnection( G_PRIORITY_HIGH, conn_cbk, NULL, FALSE,
	                               on_connect_cbk, conn_cbk, NULL);
	g_idle_add(on_idle,NULL);
//	g_timeout_add(5, on_idle,NULL);
	g_main_set_poll_func(cl_glibpoll);

	/*Create the mainloop and run it*/
	mainloop = g_main_new(FALSE);
	lrmd_log(LOG_INFO, 0, "main: run the loop...");
	g_main_run(mainloop);

	conn_cmd->ops->destroy(conn_cmd);
	conn_cmd = NULL;

	conn_cbk->ops->destroy(conn_cbk);
	conn_cbk = NULL;

	if (unlink(PID_FILE) == 0) {
		cl_log(LOG_INFO, "[%s] stopped", lrm_system_name);
	}

	lrmd_log(LOG_INFO, -1, "main: end.");

	return 0;
}

/*
 *GLoop Message Handlers
 */
gboolean
on_connect_cmd (IPC_Channel* ch, gpointer user_data)
{
	lrmd_log(LOG_INFO, 1, "on_connect_cmd: start.");
	//check paremeters
	if (NULL == ch) {
		lrmd_log(LOG_ERR, -1, "on_connect_cmd: channel is null");
		return TRUE;
	}
	//create new client
	//the register will be finished in on_msg_register
	lrmd_client_t* client = g_new(lrmd_client_t, 1);
	client->app_name = NULL;
	client->ch_cmd = ch;
	client->g_src = G_main_add_IPC_Channel(G_PRIORITY_DEFAULT,
				ch, FALSE, on_recieve_cmd, (gpointer)client,
				on_remove_client);

	lrmd_log(LOG_INFO, -1, "on_connect_cmd: end.");

	return TRUE;
}

gboolean
on_connect_cbk (IPC_Channel* ch, gpointer user_data)
{
	/*client connect for create the second channel for call back*/
	pid_t pid;
	lrmd_log(LOG_INFO, 1, "on_connect_cbk: start.");
	if (NULL == ch) {
		lrmd_log(LOG_INFO, -1, "on_connect_cbk: channel is null");
		return TRUE;
	}

	/*get the message */
	struct ha_msg* msg = msgfromIPC_noauth(ch);
	if (NULL == msg) {
		lrmd_log(LOG_ERR, -1, "on_connect_cbk: can not recieve msg");
		return TRUE;
	}

	/*check if it is a register message*/
	const char* type = ha_msg_value(msg, F_LRM_TYPE);
	if (0 != strncmp(type, REGISTER, strlen(REGISTER))) {
		lrmd_log(LOG_ERR, -1, "on_connect_cbk: msg is not register");
		send_rc_msg(ch, HA_FAIL);
		return TRUE;
	}

	/*get the pid of client */
	if (HA_OK != ha_msg_value_int(msg, F_LRM_PID, &pid)) {
		lrmd_log(LOG_ERR, -1, "on_connect_cbk: can not get pid");
		send_rc_msg(ch, HA_FAIL);
		return TRUE;
	}

	/*get the client in the client list*/
	lrmd_client_t* client = lookup_client(pid);
	if (NULL == client) {
		lrmd_log(LOG_ERR, -1,
			"on_connect_cbk: can not find client in client list");
		send_rc_msg(ch, HA_FAIL);
		return TRUE;
	}

	/*fill the channel of callback field*/
	client->ch_cbk = ch;
	send_rc_msg(ch, HA_OK);
	lrmd_log(LOG_INFO, -1, "on_connect_cbk: end.");
	return TRUE;
}

gboolean
on_recieve_cmd (IPC_Channel* ch, gpointer user_data)
{
	int i;
	lrmd_log(LOG_INFO, 1, "on_recieve_cmd: start.");

	lrmd_client_t* client = (lrmd_client_t*)user_data;
	if (IPC_DISCONNECT == ch->ch_status) {
		lrmd_log(LOG_INFO, -1, 
			"on_recieve_cmd: channel status is disconnect");
		return FALSE;
	}

	if (!ch->ops->is_message_pending(ch)) {
		lrmd_log(LOG_INFO, -1, "on_recieve_cmd: no pending message");
		return TRUE;
	}


	/*get the message */
	struct ha_msg* msg = msgfromIPC_noauth(ch);
	if (NULL == msg) {
		lrmd_log(LOG_ERR, -1, "on_recieve_cmd: can not recieve msg");
		return TRUE;
	}

	/*dispatch the message*/
	const char* type = ha_msg_value(msg, F_LRM_TYPE);

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
		lrmd_log(LOG_INFO, 0, "on_recieve_cmd: unknown msg");
	}

	/*delete the msg*/
	ha_msg_del(msg);

	lrmd_log(LOG_INFO, -1, "on_recieve_cmd: end.");

	return TRUE;
}

void
on_remove_client (gpointer user_data)
{
	lrmd_log(LOG_INFO, 1, "on_remove_client: start.");
	lrmd_client_t* client = (lrmd_client_t*) user_data;

	g_free(client->app_name);
	g_free(client);

	lrmd_log(LOG_INFO, -1, "on_remove_client: end.");
}
gboolean
on_idle (gpointer data)
{
	//check whether some running operations finished in idle
	GList* node;
	for(node=g_list_first(rsc_list); NULL!=node; node=g_list_next(node)){
		lrmd_rsc_t* rsc = (lrmd_rsc_t*)node->data;
		if (NULL != rsc->op_list) {
			GList* first = g_list_first(rsc->op_list);
			lrmd_op_t* op = first->data;
			check_op(op);
		}
	}
	return TRUE;
}

gboolean
on_timeout_op_done(gpointer data)
{
	lrmd_log(LOG_INFO, 1, "on_timeout_op_done: start.");
	/*this operation is timeout*/
	lrmd_op_t* op = (lrmd_op_t*)data;
	if (HA_FAIL==ha_msg_add_int(op->msg, F_LRM_OPSTATUS, LRM_OP_TIMEOUT)) {
		lrmd_log(LOG_ERR,0,
			"on_timeout_op_done: can not add opstatus to msg");
	}
	lrmd_rsc_t* rsc = op->rsc;
	op_done(op);
	perform_op(rsc);
	lrmd_log(LOG_INFO, -1, "on_timeout_op_done: end.");
	return TRUE;
}

gboolean
on_timeout_monitor(gpointer data)
{
	lrmd_log(LOG_INFO, 1, "on_timeout_monitor: start.");
	lrmd_mon_t* mon = (lrmd_mon_t*)data;
	mon->pending_op++;
	//create a op
	lrmd_op_t* op = g_new(lrmd_op_t, 1);
	op->call_id = mon->call_id;
	op->callback_id = -1;
	op->client = NULL;
	op->timeout_tag = 0;
	op->rsc = mon->rsc;
	op->mon	= mon;
	op->app_name = mon->app_name;
	op->msg = ha_msg_copy(mon->msg);
	mon->rsc->op_list = g_list_append(mon->rsc->op_list, op);

	if (HA_FAIL == ha_msg_add(op->msg, F_LRM_APP, mon->app_name)) {
		lrmd_log(LOG_ERR, 0,"on_msg_perform_op: can not add app_name.");
	}
	
	int timeout = 0;
	ha_msg_value_int(op->msg, F_LRM_TIMEOUT, &timeout);
	if( 0 < timeout ) {
		op->timeout_tag = g_timeout_add(timeout*1000, 
						on_timeout_op_done, op);
	}

	perform_op(mon->rsc);
	lrmd_log(LOG_INFO, -1, "on_timeout_monitor: end.");
	return TRUE;
}

/*LRM Message Handlers*/
int
on_msg_register(lrmd_client_t* client, struct ha_msg* msg)
{
	lrmd_log(LOG_INFO, 1, "on_msg_register: start.");

	lrmd_client_t* exist = NULL;
	const char* app_name = ha_msg_value(msg, F_LRM_APP);
	if (NULL == app_name) {
		lrmd_log(LOG_ERR, -1, "on_msg_register: app_name is null.");
		return HA_FAIL;
	}
	client->app_name = g_strdup(app_name);

	if (HA_OK != ha_msg_value_int(msg, F_LRM_PID, &client->pid)) {
		lrmd_log(LOG_ERR, -1, 
			"on_msg_register: can not find pid field.");
		return HA_FAIL;
	}

	if (HA_OK != ha_msg_value_int(msg, F_LRM_GID, &client->gid)) {
		lrmd_log(LOG_ERR, -1, 
			"on_msg_register: can not find gid field.");
		return HA_FAIL;
	}

	if (HA_OK != ha_msg_value_int(msg, F_LRM_UID, &client->uid)) {
		lrmd_log(LOG_ERR, -1, 
			"on_msg_register: can not find uid field.");
		return HA_FAIL;
	}

	exist = lookup_client(client->pid);
	if (NULL != exist) {
		client_list = g_list_remove(client_list, exist);
		on_remove_client(exist);
		lrmd_log(LOG_ERR, 0, 
			"on_msg_register: client exist, remove first.");

	}

	client_list = g_list_append (client_list, client);
	lrmd_log(LOG_INFO, -1, "on_msg_register: end.");
	return HA_OK;
}

int
on_msg_unregister(lrmd_client_t* client, struct ha_msg* msg)
{
	lrmd_log(LOG_INFO, 1, "on_msg_unregister: start.");

	if (NULL == client_list || NULL == lookup_client(client->pid)) {
		lrmd_log(LOG_ERR, -1, 
			"on_msg_unregister: can not find the client.");
		return HA_FAIL;
	}
	//remove from client_list
	client_list = g_list_remove(client_list, client);
	//remove all monitors and pending ops
	GList* rsc_node;
	for(rsc_node = g_list_first(rsc_list);
		NULL != rsc_node; rsc_node = g_list_next(rsc_node)){
		lrmd_rsc_t* rsc = (lrmd_rsc_t*)rsc_node->data;
		//remove monitors belong to this client
		GList* mon_node = g_list_first(rsc->mon_list);
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
		//remove pending ops belong to this client
		GList* op_node = g_list_first(rsc->op_list);
		op_node = g_list_next(op_node);
		while (NULL != op_node) {
			lrmd_op_t* op = (lrmd_op_t*)op_node->data;
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
	lrmd_log(LOG_INFO, -1, "on_msg_unregister: end.");
	return HA_OK;
}

int
on_msg_get_ra_types(lrmd_client_t* client, struct ha_msg* msg)
{
	lrmd_log(LOG_INFO, 1, "on_msg_get_rsc_types: start.");
	struct ha_msg* ret = create_lrm_ret(HA_OK, 4);
	if (NULL == ret) {
		lrmd_log(LOG_ERR, -1, 
			"on_msg_get_rsc_types: can not create msg.");
		return HA_FAIL;
	}

	ha_msg_add_list(ret,F_LRM_RTYPE,ra_list);

	if (HA_OK != msg2ipcchan(ret, client->ch_cmd)) {
		lrmd_log(LOG_ERR, 0, 
			"on_msg_get_rsc_types: can not send the ret msg");
	}
	ha_msg_del(ret);

	lrmd_log(LOG_INFO, -1, "on_msg_get_rsc_types: end.");
	return HA_OK;
}
int
on_msg_get_all(lrmd_client_t* client, struct ha_msg* msg)
{
	lrmd_log(LOG_INFO, 1, "on_msg_get_all: start.");
	int i = 1;
	char value[UUID_SLEN];
	char key[MAX_NAME_LEN];
	struct ha_msg* ret = create_lrm_ret(HA_OK, g_list_length(rsc_list) + 1);
	if (NULL == ret) {
		lrmd_log(LOG_ERR, -1, "on_msg_get_all: can not create msg.");
		return HA_FAIL;
	}

	GList* node;
	for(node=g_list_first(rsc_list); NULL!=node; node=g_list_next(node)) {
		lrmd_rsc_t* rsc = (lrmd_rsc_t*)node->data;
		uuid_unparse(rsc->id, value);
		snprintf(key,MAX_NAME_LEN,"%s%d",F_LRM_RID,i);
		ha_msg_add(ret,key,value);
		i++;
	}

	if (HA_OK != msg2ipcchan(ret, client->ch_cmd)) {
		lrmd_log(LOG_ERR, 0,"on_msg_get_all: can not send the ret msg");
	}
	ha_msg_del(ret);

	lrmd_log(LOG_INFO, -1, "on_msg_get_all: end.");
	return HA_OK;
}
int
on_msg_get_rsc(lrmd_client_t* client, struct ha_msg* msg)
{
	rsc_id_t id;
	struct ha_msg* ret = NULL;
	lrmd_rsc_t* rsc = NULL;
	lrmd_log(LOG_INFO, 1, "on_msg_get_rsc: start.");

	ha_msg_value_uuid(msg,F_LRM_RID,id);
	rsc = lookup_rsc(id);

	if (NULL == rsc) {
		lrmd_log(LOG_INFO, 0, "on_msg_get_rsc: no rsc with such id.");
		ret = create_lrm_ret(HA_FAIL, 1);
		if (NULL == ret) {
			lrmd_log(LOG_ERR, -1,
				"on_msg_get_rsc: can not create msg.");
			return HA_FAIL;
		}
	}
	else {
		ret = create_lrm_ret(HA_OK, 5);
		if (NULL == ret) {
			lrmd_log(LOG_ERR, -1, 
				"on_msg_get_rsc: can not create msg.");
			return HA_FAIL;
		}
		if (HA_FAIL == ha_msg_add_uuid(ret, F_LRM_RID, rsc->id)) {
			return HA_FAIL;
		}

		if (HA_FAIL == ha_msg_add(ret, F_LRM_RNAME, rsc->name)) {
			return HA_FAIL;
		}

		if (HA_FAIL == ha_msg_add(ret, F_LRM_RTYPE, rsc->type))	{
			return HA_FAIL;
		}

		if (NULL != rsc->params) {
			char* param_str = hash_table_to_string(rsc->params);
			if (HA_FAIL==ha_msg_add(ret, F_LRM_PARAM, param_str)){
				return HA_FAIL;
			}
		}
	}
	if (HA_OK != msg2ipcchan(ret, client->ch_cmd)) {
		lrmd_log(LOG_ERR, 0,"on_msg_get_rsc: can not send the ret msg");
	}
	ha_msg_del(ret);

	lrmd_log(LOG_INFO, -1, "on_msg_get_rsc: end.");
	return HA_OK;
}
int
on_msg_del_rsc(lrmd_client_t* client, struct ha_msg* msg)
{
	rsc_id_t id;
	lrmd_rsc_t* rsc = NULL;
	lrmd_log(LOG_INFO, 1, "on_msg_del_rsc: start.");

	ha_msg_value_uuid(msg,F_LRM_RID,id);
	rsc = lookup_rsc(id);

	if (NULL == rsc) {
		lrmd_log(LOG_INFO, -1, "on_msg_del_rsc: no rsc with such id.");
		return HA_FAIL;
	}
	else {
		rsc_list = g_list_remove(rsc_list, rsc);
		GList* mon_node = g_list_first(rsc->mon_list);
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
		GList* op_node = g_list_first(rsc->op_list);
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

	lrmd_log(LOG_INFO, -1, "on_msg_del_rsc: end.");
	return HA_OK;
}

int
on_msg_add_rsc(lrmd_client_t* client, struct ha_msg* msg)
{
	lrmd_log(LOG_INFO, 1, "on_msg_add_rsc: start.");
	rsc_id_t id;

	ha_msg_value_uuid(msg,F_LRM_RID,id);
	if (NULL != lookup_rsc(id)) {
		lrmd_log(LOG_ERR, -1,
				"on_msg_add_rsc: same id resource exists.");
		return HA_FAIL;
	}

	lrmd_rsc_t* rsc = g_new(lrmd_rsc_t,1);
	uuid_copy(rsc->id,id);
	rsc->name = g_strdup(ha_msg_value(msg, F_LRM_RNAME));
	rsc->type = g_strdup(ha_msg_value(msg, F_LRM_RTYPE));

	gboolean ra_type_exist = FALSE;
	GList* node;
	for(node=g_list_first(ra_list); NULL!=node; node=g_list_next(node)){
		char* type = (char*)node->data;
		if (0 == strcmp(type, rsc->type)) {
			ra_type_exist = TRUE;
			break;
		}
	}
	if (!ra_type_exist) {
		g_free(rsc);
		lrmd_log(LOG_ERR, -1,
				"on_msg_add_rsc: ra type does not exist.");
		return HA_FAIL;
	}
	rsc->params = NULL;
	rsc->op_list = NULL;
	rsc->mon_list = NULL;
	rsc->last_op = NULL;
	char* params = g_strdup(ha_msg_value(msg, F_LRM_PARAM));
	if (NULL != params) {
		rsc->params = string_to_hash_table(params);
	}
/*	rsc->params = ha_msg_value_hash_table(msg, F_LRM_PARAM);*/
	rsc_list = g_list_append(rsc_list, rsc);


	lrmd_log(LOG_INFO, -1, "on_msg_add_rsc: end.");
	return HA_OK;
}

int
on_msg_perform_op(lrmd_client_t* client, struct ha_msg* msg)
{
	rsc_id_t id;
	lrmd_rsc_t* rsc = NULL;
	lrmd_log(LOG_INFO, 1, "on_msg_perform_op: start.");

	ha_msg_value_uuid(msg,F_LRM_RID,id);
	rsc = lookup_rsc(id);
	if (NULL == rsc) {
		lrmd_log(LOG_ERR, -1, 
			"on_msg_perform_op: no rsc with such id.");
		return HA_FAIL;
	}

	call_id++;
	if (HA_FAIL == ha_msg_add_int(msg, F_LRM_CALLID, call_id)) {
		lrmd_log(LOG_ERR, -1, "on_msg_perform_op: can not add callid.");
		return HA_FAIL;
	}

	const char* type = ha_msg_value(msg, F_LRM_TYPE);
	//when a flush request arrived, flush all pending ops
	if (0 == strncmp(type, FLUSHOPS, strlen(FLUSHOPS))) {
		GList* node = g_list_first(rsc->op_list);
		while (NULL != node ) {
			lrmd_op_t* op = (lrmd_op_t*)node->data;
			node = g_list_next(node);
			rsc->op_list = g_list_remove(rsc->op_list, op);
			flush_op(op);
		}
	}
	else {
		lrmd_op_t* op = g_new(lrmd_op_t, 1);
		op->call_id = call_id;
		op->callback_id = -1;
		op->client = client;
		op->timeout_tag = 0;
		op->rsc = rsc;
		op->mon	= NULL;
		op->app_name = client->app_name;
		op->msg = ha_msg_copy(msg);
		rsc->op_list = g_list_append(rsc->op_list, op);
		if (HA_FAIL==ha_msg_add(op->msg, F_LRM_APP, client->app_name)) {
			lrmd_log(LOG_ERR, 0, 
				"on_msg_perform_op: can not add app_name.");
		}
		int timeout = 0;
		ha_msg_value_int(op->msg, F_LRM_TIMEOUT, &timeout);
		if (0 < timeout ) {
			op->timeout_tag = g_timeout_add(timeout*1000, 
						on_timeout_op_done, op);
		}
		perform_op(rsc);
	}

	lrmd_log(LOG_INFO, -1, "on_msg_perform_op: end.");
	return call_id;
}
int
on_msg_set_monitor(lrmd_client_t* client, struct ha_msg* msg)
{
	rsc_id_t id;
	lrmd_rsc_t* rsc = NULL;
	lrmd_log(LOG_INFO, 1, "on_msg_set_monitor: start.");

	ha_msg_value_uuid(msg,F_LRM_RID,id);
	rsc = lookup_rsc(id);
	if (NULL == rsc) {
		lrmd_log(LOG_ERR, -1, 
			"on_msg_set_monitor: no rsc with such id.");
		return HA_FAIL;
	}

	call_id++;

	if (HA_FAIL == ha_msg_add_int(msg, F_LRM_CALLID, call_id)) {
		lrmd_log(LOG_ERR, -1, 
			"on_msg_set_monitor: can not add callid.");
		return HA_FAIL;
	}

	//if the monitor mode is clear, remove all monitors on the resource.
	mon_mode_t mode;
	if (HA_FAIL == ha_msg_value_int(msg, F_LRM_MONMODE, (int*)&mode)) {
		lrmd_log(LOG_ERR, -1, 
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
		lrmd_mon_t*	mon = g_new(lrmd_mon_t, 1);
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
			lrmd_log(LOG_ERR, -1,
				"on_msg_set_monitor: can not get interval.");
			return HA_FAIL;
		}
		if (0 >= mon->interval) {
			g_free(mon);
			lrmd_log(LOG_ERR, -1, 
				"on_msg_set_monitor: interal less 1 second.");
			return HA_FAIL;

		}
		if (HA_FAIL == ha_msg_value_int(msg, F_LRM_MONTGT, 
						&mon->target)) {
			g_free(mon);
			lrmd_log(LOG_ERR, -1,
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

	lrmd_log(LOG_INFO, -1, "on_msg_set_monitor: end.");
	return call_id;
}

int
on_msg_get_state(lrmd_client_t* client, struct ha_msg* msg)
{
	rsc_id_t id;
	lrmd_rsc_t* rsc = NULL;
	lrmd_log(LOG_INFO, 1, "on_msg_get_state: start.");

	ha_msg_value_uuid(msg,F_LRM_RID,id);
	rsc = lookup_rsc(id);
	if (NULL == rsc) {
		lrmd_log(LOG_ERR, -1, "on_msg_get_state: no rsc with such id.");
		send_rc_msg(client->ch_cmd, HA_FAIL);
		return HA_FAIL;
	}
	if ( NULL == rsc->op_list )
	{
		struct ha_msg* ret = NULL;
		if (NULL != rsc->last_op) {
			ret = op_to_msg(rsc->last_op);
		}
		if (NULL == ret) {
			ret = ha_msg_new(5);
		}

		if (HA_FAIL == ha_msg_add_int(ret, F_LRM_STATE, LRM_RSC_IDLE)) {
			lrmd_log(LOG_ERR, -1, 
				"on_msg_get_state: can not add state to msg.");
			ha_msg_del(ret);
			return HA_FAIL;
		}
		if (HA_OK != msg2ipcchan(ret, client->ch_cmd)) {
			lrmd_log(LOG_ERR, 0, 
				"on_msg_get_state: can not send the ret msg");
		}
		ha_msg_del(ret);

	}
	else {
		struct ha_msg* ret = ha_msg_new(5);

		if (HA_FAIL == ha_msg_add_int(ret, F_LRM_STATE, LRM_RSC_BUSY)) {
			lrmd_log(LOG_ERR, -1, 
				"on_msg_get_state: can not add state to msg.");
			ha_msg_del(ret);
			return HA_FAIL;
		}
		int op_count = g_list_length(rsc->op_list);
		if (HA_FAIL == ha_msg_add_int(ret, F_LRM_OPCNT, op_count)) {
			lrmd_log(LOG_ERR, -1, 
				"on_msg_get_state: can not add state count.");
			ha_msg_del(ret);
			return HA_FAIL;
		}
		if (HA_OK != msg2ipcchan(ret, client->ch_cmd)) {
			lrmd_log(LOG_ERR, -1, 
				"on_msg_get_state: can not send the ret msg");
			ha_msg_del(ret);
			return HA_FAIL;
		}
		ha_msg_del(ret);

		GList* node;
		for(node = g_list_first(rsc->op_list);
			NULL != node; node = g_list_next(node)){
			lrmd_op_t* op = (lrmd_op_t*)node->data;
			struct ha_msg* op_msg = op_to_msg(op);
			if ( NULL == op_msg  ) {
				lrmd_log(LOG_ERR, 0, 
					"on_msg_get_state: can not add op.");
				ha_msg_del(op_msg);
				continue;
			}
			if (HA_OK != msg2ipcchan(op_msg, client->ch_cmd)) {
				lrmd_log(LOG_ERR, 0,
					"on_msg_get_state: can not send msg");
			}
			ha_msg_del(op_msg);
		}
	}
	lrmd_log(LOG_INFO, -1, "on_msg_get_state: end.");
	return HA_OK;
}
///////////////////////op functions////////////////////////////////////////////
int
check_op(lrmd_op_t* op)
{
	lrmd_log(LOG_INFO, 1, "check_op: start.");
	int rc;
	char* data=NULL;
	struct RAExecOps * RAExec = NULL;

	RAExec = g_hash_table_lookup(RAExecFuncs,op->rsc->type);

	if (NULL == RAExec) {
		lrmd_log(LOG_ERR,-1,"check_op: can not find RAExec");
		return HA_FAIL;
	}
	if ( 0 > op->callback_id ) {
		if (HA_FAIL == ha_msg_add_int(op->msg, F_LRM_OPSTATUS,
						LRM_OP_ERROR)) {
			lrmd_log(LOG_ERR,-1,
				"check_op: can not add opstatus to msg");
			return HA_FAIL;
		}
		lrmd_rsc_t* rsc = op->rsc;
		op_done(op);
		perform_op(rsc);
		lrmd_log(LOG_INFO, -1, "check_op: end.");
		return HA_OK;
	}
	int ret = check_ra_rc(RAExec,op->callback_id, &rc, &data);
	if ( 0 < ret ) {
		if (HA_FAIL == ha_msg_add_int(op->msg, F_LRM_RC, rc)) {
			lrmd_log(LOG_ERR,-1,"check_op: can not add rc to msg");
			return HA_FAIL;
		}
		if (HA_FAIL == ha_msg_add_int(op->msg, F_LRM_OPSTATUS, 
						LRM_OP_DONE)) {
			lrmd_log(LOG_ERR,-1,
				"check_op: can not add opstatus to msg");
			return HA_FAIL;
		}
		if (NULL != data) {
			int ret = ha_msg_addbin(op->msg, F_LRM_DATA,data, 
						strlen(data));
			if (HA_FAIL == ret) {
				lrmd_log(LOG_ERR,-1,
					"check_op: can not add data to msg");
				return HA_FAIL;
			}
		}
		lrmd_rsc_t* rsc = op->rsc;
		op_done(op);
		perform_op(rsc);
	}
	lrmd_log(LOG_INFO, -1, "check_op: end.");
	return HA_OK;
}
int
op_done(lrmd_op_t* op)
{
	lrmd_log(LOG_INFO, 1, "op_done: start.");
	// we should check if the resource exists.
	if (NULL == g_list_find(rsc_list, op->rsc)) {
		if( op->timeout_tag > 0 ) {
			g_source_remove(op->timeout_tag);
		}
		//delete the op
		ha_msg_del(op->msg);
		g_free(op);

		lrmd_log(LOG_INFO,-1,
			"op_done: the resource of this op does not exists");
		return HA_FAIL;

	}

	//if the op is create by client
	if (NULL != op->client) {
		//send the result to client
		lrmd_log(LOG_INFO, 0, "op_done: a normal op done.");
		//we have to check whether the client still exists
		//for the client may signoff during the op running.
		if (NULL != g_list_find(client_list, op->client)) {
			//the client still exists
			if (NULL == op->client->ch_cbk) {
				lrmd_log(LOG_ERR, 0, 
					"op_done: client->ch_cbk is null");
			}
			else
			if (HA_OK != msg2ipcchan(op->msg, op->client->ch_cbk)) {
				lrmd_log(LOG_ERR, 0, 
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
		lrmd_log(LOG_INFO, 0, "op_done: a monitor op done.");

		lrmd_mon_t* mon = op->mon;
		mon->pending_op--;
		if (!mon->is_deleted) {
			//check status
			op_status_t status = LRM_OP_ERROR;
			int rc = -1;
			ha_msg_value_int(op->msg,F_LRM_OPSTATUS,(int*)&status);
			ha_msg_value_int(op->msg, F_LRM_RC, &rc);

			gboolean need_send = FALSE;
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
					lrmd_log(LOG_ERR, 0, 
						"op_done: ch_cbk is null");
				}
				else
				if (HA_OK != msg2ipcchan(op->msg, 
						mon->client->ch_cbk)) {
					lrmd_log(LOG_ERR, 0, 
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
	lrmd_log(LOG_INFO, -1, "op_done: end.");
	return HA_OK;
}
int
flush_op(lrmd_op_t* op)
{
	lrmd_log(LOG_INFO, 1, "flush_op: start.");
	if (HA_FAIL == ha_msg_add_int(op->msg, F_LRM_RC, HA_FAIL)) {
		lrmd_log(LOG_ERR,-1,"flush_op: can not add rc ");
		return HA_FAIL;
	}

	if (HA_FAIL==ha_msg_add_int(op->msg,F_LRM_OPSTATUS,LRM_OP_CANCELLED)) {
		lrmd_log(LOG_ERR,-1,"flush_op: can not add op status");
		return HA_FAIL;
	}

	op_done(op);

	lrmd_log(LOG_INFO, -1, "flush_op: end.");
	return HA_OK;
}

int
perform_op(lrmd_rsc_t* rsc)
{
	lrmd_log(LOG_INFO, 1, "perform_op: start.");
	if (NULL == g_list_find(rsc_list, rsc)) {

		lrmd_log(LOG_INFO,-1,
			"op_done: the resource of this op does not exists");
		return HA_FAIL;

	}
	if (NULL == rsc->op_list) {
		lrmd_log(LOG_INFO,-1,"perform_op: no op to perform");
		return HA_OK;
	}
	GList* first = g_list_first(rsc->op_list);
	lrmd_op_t* op = first->data;
	if (-1 != op->callback_id )	{
		lrmd_log(LOG_INFO,-1,"perform_op: current op is performing");
		return HA_OK;
	}
	struct RAExecOps * RAExec = NULL;
	RAExec = g_hash_table_lookup(RAExecFuncs,op->rsc->type);
	if (NULL == RAExec) {
		lrmd_log(LOG_ERR,-1,"check_op: can not find RAExec");
		return HA_FAIL;
	}
	op->callback_id = perform_ra_op(RAExec, op);

	lrmd_log(LOG_INFO, -1, "perform_op: end.");
	return HA_OK;
}

struct ha_msg*
op_to_msg(lrmd_op_t* op)
{
	lrmd_log(LOG_INFO, 1, "op_to_msg: start.");
	struct ha_msg* msg = ha_msg_copy(op->msg);
	if (NULL == msg) {
		lrmd_log(LOG_ERR,-1,"op_to_msg: can not copy the msg");
		return NULL;
	}
	if (HA_FAIL == ha_msg_add_int(msg, F_LRM_CALLID, op->call_id)) {
		ha_msg_del(msg);
		lrmd_log(LOG_ERR,-1,"op_to_msg: can not add call_id");
		return NULL;
	}
	if (HA_FAIL == ha_msg_add(msg, F_LRM_APP, op->app_name)) {
		ha_msg_del(msg);
		lrmd_log(LOG_ERR,-1,"op_to_msg: can not add app_name");
		return NULL;
	}
	lrmd_log(LOG_INFO, -1, "op_to_msg: end.");
	return msg;
}

////////////////////////////////RA wrap funcs///////////////////////////////////
int
check_ra_rc(struct RAExecOps * RAExec ,int callback_id, int* rc, char** data)
{
	lrmd_log(LOG_INFO, 1, "check_ra_rc: start.");
	int ret = RAExec->post_query_result(callback_id, rc, data);
	*rc = *rc / 256;

	lrmd_log(LOG_INFO, -1, "check_ra_rc: end.");

	return ret;
}
int
perform_ra_op(struct RAExecOps * RAExec, lrmd_op_t* op)
{
	int key, ret;
	lrmd_log(LOG_INFO, 1, "perform_ra_op: start.");
	char* rsc_name = op->rsc->name;
	const char* op_type = ha_msg_value(op->msg, F_LRM_OP);
	GHashTable* params_table = NULL;
	const char* temp_params = ha_msg_value(op->msg, F_LRM_PARAM);
	if (NULL != temp_params) {
		char* params = g_strdup(temp_params);
		params_table = string_to_hash_table(params);
	}
	ret=RAExec->execra(rsc_name, op_type, params_table, NULL, TRUE, &key);

	lrmd_log(LOG_INFO, -1, "perform_ra_op: end.");

	return ret == 0 ? key : ret;
}
///////////////////Util Functions//////////////////////////////////////////////
int
send_rc_msg (IPC_Channel* ch, int rc)
{
	lrmd_log(LOG_INFO, 1, "send_rc_msg: start.");
	struct ha_msg* ret = create_lrm_ret(rc, 1);
	if (NULL == ret) {
		lrmd_log(LOG_ERR, -1, "send_rc_msg: can not create ret msg");
		return HA_FAIL;
	}

	if (HA_OK != msg2ipcchan(ret, ch)) {
		lrmd_log(LOG_ERR, 0, "send_rc_msg: can not send the ret msg");
	}
	ha_msg_del(ret);
	lrmd_log(LOG_INFO, -1, "send_rc_msg: end.");
	return HA_OK;
}

lrmd_client_t*
lookup_client (pid_t pid)
{
	lrmd_log(LOG_INFO, 1, "lookup_client: start.");

	GList* node;
	for(node = g_list_first(client_list);
		NULL != node; node = g_list_next(node)){
		lrmd_client_t* client = (lrmd_client_t*)node->data;
		if (pid == client->pid) {
			lrmd_log(LOG_INFO, -1, "lookup_client: end.");
			return client;
		}
	}

	lrmd_log(LOG_INFO, -1, "lookup_client: end.");
	return NULL;
}

lrmd_rsc_t*
lookup_rsc (rsc_id_t rid)
{
	lrmd_log(LOG_INFO, 1, "lookup_rsc: start.");

	GList* node;
	for(node=g_list_first(rsc_list); NULL!=node; node=g_list_next(node)){
		lrmd_rsc_t* rsc = (lrmd_rsc_t*)node->data;
		if (0 == uuid_compare(rid,rsc->id)) {
			lrmd_log(LOG_INFO, -1, "lookup_rsc: end.");
			return rsc;
		}
	}

	lrmd_log(LOG_INFO, -1, "lookup_rsc: end.");
	return NULL;
}

void
free_rsc(lrmd_rsc_t* rsc)
{
	g_free(rsc->name);
	g_free(rsc->type);
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
void
lrmd_log (int priority, int level, const char* fmt)
{
	cl_log(priority, "%s",fmt);
}
