/*
 * ha_logd.c logging daemon
 *
 * Copyright (C) 2004 Guochun Shi <gshi@ncsa.uiuc.edu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */
#include <lha_internal.h>
#include <glib.h>
#include <clplumbing/cl_log.h>
#include <clplumbing/ipc.h>
#include <clplumbing/GSource.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <clplumbing/loggingdaemon.h>
#include <netinet/in.h>
#include <clplumbing/lsb_exitcodes.h>
#include <sys/types.h>
#include <signal.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdarg.h>
#include <clplumbing/Gmain_timeout.h>
#include <clplumbing/coredumps.h>
#include <clplumbing/setproctitle.h>
#include <clplumbing/cl_signal.h>
#include <clplumbing/cl_misc.h>
#include <sys/wait.h>
#include <clplumbing/cl_pidfile.h>
#include <clplumbing/cl_syslog.h>

/*two processes involved
  1. parent process which reads messages from all client channels 
  and writes them to the child process 
  
  2. the child process which reads messages from the parent process through IPC
  and writes them to syslog/disk
  
  I call the parent process READ process, and the child process WRITE one,
  for convenience.

*/
  


#define DEFAULT_CFG_FILE	HA_SYSCONFDIR "/logd.cf"
#define	LOGD_PIDFILE		HA_VARRUNDIR "/logd.pid"

#define	FD_STDIN	0
#define	FD_STDOUT	1

#define	FD_STDERR	2


#define WRITE_PROC_CHAN	0
#define READ_PROC_CHAN	1
#define LOGD_QUEUE_LEN  128

#define EOS '\0'
#define	nullchk(a)	((a) ? (a) : "<null>")

static const int logd_keepalive_ms = 1000;
static const int logd_warntime_ms = 5000;
static const int logd_deadtime_ms = 10000;
static gboolean verbose = FALSE;
static pid_t write_process_pid;
static IPC_Channel *chanspair[2];
static gboolean stop_reading = FALSE;
static gboolean needs_shutdown = FALSE;

static struct {
	char		debugfile[MAXLINE];
	char		logfile[MAXLINE];
	char		entity[MAXENTITY];
	char		syslogprefix[MAXENTITY];
	int		log_facility;
	mode_t		logmode;
	gboolean	syslogfmtmsgs;
} logd_config =
	{
		.debugfile = "",
		.logfile   = "",
		.entity    = "logd",
		.syslogprefix = "",
		.log_facility = HA_LOG_FACILITY,
		.logmode  = 0644,
		.syslogfmtmsgs = FALSE
	};

static void	logd_log(const char * fmt, ...) G_GNUC_PRINTF(1,2);
static int	set_debugfile(const char* option);
static int	set_logfile(const char* option);
static int	set_facility(const char * value);
static int	set_entity(const char * option);
static int	set_syslogprefix(const char * option);
static int	set_sendqlen(const char * option);
static int	set_recvqlen(const char * option);
static int	set_logmode(const char * option);
static int	set_syslogfmtmsgs(const char * option);


static char*			cmdname = NULL;


static struct directive {
	const char* name;
	int (*add_func)(const char*);
} Directives[] = {
	{"debugfile",	set_debugfile},
	{"logfile",	set_logfile},
	{"logfacility",	set_facility},
	{"entity",	set_entity},
	{"syslogprefix",set_syslogprefix},
	{"sendqlen",	set_sendqlen},
	{"recvqlen",	set_recvqlen},
	{"logmode",	set_logmode},
	{"syslogmsgfmt",set_syslogfmtmsgs}
};

static void
logd_log( const char * fmt, ...)
{
	char		buf[MAXLINE];
	va_list		ap;
	
	buf[MAXLINE-1] = EOS;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf)-1, fmt, ap);
	va_end(ap);
	
	fprintf(stderr, "%s", buf);

	return;
}

static int
set_debugfile(const char* option)
{
    	if (!option){
		logd_config.debugfile[0] = EOS;
		return FALSE;
	}
	
	cl_log(LOG_INFO, "setting debug file to %s", option);
	strncpy(logd_config.debugfile, option, MAXLINE);
	return TRUE;
}
static int
set_logfile(const char* option)
{
    	if (!option){
		logd_config.logfile[0] = EOS;
		return FALSE;
	}
	cl_log(LOG_INFO, "setting log file to %s", option);
	strncpy(logd_config.logfile, option, MAXLINE);
	return TRUE;
}

/* set syslog facility config variable */
static int
set_facility(const char * value)
{
	int		i;	 

	i = cl_syslogfac_str2int(value);
	if (i >= 0) {
		cl_log(LOG_INFO,  "setting log facility to %s", value);
		logd_config.log_facility = i;
		return(TRUE);
	}
	else {
		return(FALSE);
	}
}

static int
set_entity(const char * option)
{
	if (!option){
		logd_config.entity[0] = EOS;
		return FALSE;
	}
	strncpy(logd_config.entity, option, MAXENTITY);
	logd_config.entity[MAXENTITY-1] = '\0';
	if (strlen(option) >= MAXENTITY)
		cl_log(LOG_WARNING, "setting entity to %s (truncated from %s)",
			logd_config.entity, option);
	else
		cl_log(LOG_INFO, "setting entity to %s", logd_config.entity);
	return TRUE;

}

static int
set_syslogprefix(const char * option)
{
	if (!option){
		logd_config.syslogprefix[0] = EOS;
		return FALSE;
	}
	strncpy(logd_config.syslogprefix, option, MAXENTITY);
	logd_config.syslogprefix[MAXENTITY-1] = '\0';
	if (strlen(option) >= MAXENTITY)
		cl_log(LOG_WARNING,
			"setting syslogprefix to %s (truncated from %s)",
			logd_config.syslogprefix, option);
	else
		cl_log(LOG_INFO,
			"setting syslogprefix to %s",
			logd_config.syslogprefix);
	return TRUE;

}

static int
set_sendqlen(const char * option)
{
	int length;

	if (!option){
		cl_log(LOG_ERR, "NULL send queue length");
		return FALSE;
	}

	length = atoi(option);
	if (length < 0){
		cl_log(LOG_ERR, "negative send queue length");
		return FALSE;
	}
	
	cl_log(LOG_INFO, "setting send queue length to %d", length);
	chanspair[READ_PROC_CHAN]->ops->set_send_qlen(chanspair[READ_PROC_CHAN],
						      length);
	
	return TRUE;

}

static int
set_recvqlen(const char * option)
{
	int length;
	
	if (!option){
		cl_log(LOG_ERR, "NULL recv queue length");
		return FALSE;
	}

	length = atoi(option);
	if (length < 0){
		cl_log(LOG_ERR, "negative recv queue length");
		return FALSE;
	}
	
	cl_log(LOG_INFO, "setting recv queue length to %d", length);
	chanspair[WRITE_PROC_CHAN]->ops->set_recv_qlen(chanspair[WRITE_PROC_CHAN],
						       length);
	
	return TRUE;
	
}

static int
set_logmode(const char * option)
{
	unsigned long	mode;
	char *		endptr;
	if (!option){
		cl_log(LOG_ERR, "NULL logmode parameter");
		return FALSE;
	}
	mode = strtoul(option, &endptr, 8);
	if (*endptr != EOS) {
		cl_log(LOG_ERR, "Invalid log mode [%s]", option);
		return FALSE;
	}
	if (*option != '0') {
		/* Whine if mode doesn't start with '0' */
		cl_log(LOG_WARNING, "Log mode [%s] assumed to be octal"
		,	option);
	}
	logd_config.logmode = (mode_t)mode;
	return TRUE;
}
static int
set_syslogfmtmsgs(const char * option)
{
	gboolean	dosyslogfmt;

	if (cl_str_to_boolean(option, &dosyslogfmt) == HA_OK) {
		cl_log_enable_syslog_filefmt(dosyslogfmt);
	}else{
		return FALSE;
	}
	return TRUE;
}


typedef struct {
	char		app_name[MAXENTITY];
	pid_t		pid;
	gid_t		gid;
	uid_t		uid;
	
	IPC_Channel*	chan;
	IPC_Channel*	logchan;
	GCHSource*	g_src;
}ha_logd_client_t;

static GList*	logd_client_list = NULL;

static IPC_Message*
getIPCmsg(IPC_Channel* ch)
{
	
	int		rc;
	IPC_Message*	ipcmsg;
	
	/* FIXME:  Should we block here?? */
	rc = ch->ops->waitin(ch);
	
	switch(rc) {
	default:
	case IPC_FAIL:
		cl_log(LOG_ERR, "getIPCmsg: waitin failure\n");
		return NULL;
		
	case IPC_BROKEN:
		sleep(1);
		return NULL;
		
	case IPC_INTR:
		return NULL;
		
	case IPC_OK:
		break;
	}

	ipcmsg = NULL;
	rc = ch->ops->recv(ch, &ipcmsg);	
	if (rc != IPC_OK) {
		return NULL;
	}
	
	return ipcmsg;

}

/* Flow control all clients off */
static void
logd_suspend_clients(IPC_Channel* notused1, gpointer notused2)
{
	GList *	gl;

	stop_reading = TRUE;
	for (gl=g_list_first(logd_client_list); gl != NULL
		     ;	gl = g_list_next(gl)) {
		ha_logd_client_t* client = gl->data;
		if (client && client->g_src) {
			G_main_IPC_Channel_pause(client->g_src);
		}else if (client) {
			cl_log(LOG_ERR, "Could not suspend client [%s] pid %d"
			,	nullchk(client->app_name), client->pid);
		}else{
			cl_log(LOG_ERR, "%s: Could not suspend NULL client",
			__FUNCTION__);
		}
	}
}

/* Resume input from clients - Flow control all clients back on */
static void
logd_resume_clients(IPC_Channel* notused1, gpointer notused2)
{
	GList *	gl;

	stop_reading = FALSE;
	for (gl=g_list_first(logd_client_list); gl != NULL
	;	gl = g_list_next(gl)) {
		ha_logd_client_t* client = gl->data;
		if (client && client->g_src) {
			G_main_IPC_Channel_resume(client->g_src);
		}else if (client) {
			cl_log(LOG_ERR, "Could not resume client [%s] pid %d"
			,	nullchk(client->app_name), client->pid);
		}else{
		cl_log(LOG_ERR, "%s: Could not suspend NULL client",
			__FUNCTION__);
		}
	}
}

static gboolean
on_receive_cmd (IPC_Channel* ch, gpointer user_data)
{
	IPC_Message*		ipcmsg;
	ha_logd_client_t* client = (ha_logd_client_t*)user_data;
	IPC_Channel*		logchan= client->logchan;

	
	if (!ch->ops->is_message_pending(ch)) {
		goto getout;
	}
	
	ipcmsg = getIPCmsg(ch);
	if (ipcmsg == NULL){
		if (IPC_ISRCONN(ch)) {
			cl_log(LOG_ERR, "%s: read error on connected channel [%s:%d]"
			,	__FUNCTION__, client->app_name, client->pid);
		}
		return FALSE;
	}
	
	if( ipcmsg->msg_body &&	ipcmsg->msg_len > 0 ){
		
		if (client->app_name[0] == '\0'){
			LogDaemonMsgHdr*	logmsghdr;
			logmsghdr = (LogDaemonMsgHdr*) ipcmsg->msg_body;
			strncpy(client->app_name, logmsghdr->entity, MAXENTITY);
		}

		if (!IPC_ISWCONN(logchan)){
			cl_log(LOG_ERR
			,	"%s: channel to write process disconnected"
			,	__FUNCTION__);
			return FALSE;
		}
		if (logchan->ops->send(logchan, ipcmsg) != IPC_OK){
			cl_log(LOG_ERR
			,	"%s: forwarding msg from [%s:%d] to"
			" write process failed"
			,	__FUNCTION__
		       ,	client->app_name, client->pid);
			cl_log(LOG_ERR, "queue too small? (max=%ld, current len =%ld)",
			       (long)logchan->send_queue->max_qlen,
			       (long)logchan->send_queue->current_qlen);
			return TRUE;
		}
		
	}else {
		cl_log(LOG_ERR, "on_receive_cmd:"
		       " invalid ipcmsg\n");
	}
	
 getout:
	return TRUE;
}

static void
on_remove_client (gpointer user_data)
{
	
	logd_client_list = g_list_remove(logd_client_list, user_data);
	if (user_data){
		free(user_data);
	}
	return;
}



/*
 *GLoop Message Handlers
 */
static gboolean
on_connect_cmd (IPC_Channel* ch, gpointer user_data)
{
	ha_logd_client_t* client = NULL;
	
	/* check paremeters */
	if (NULL == ch) {
		cl_log(LOG_ERR, "on_connect_cmd: channel is null");
		return TRUE;
	}
	/* create new client */
	if (NULL == (client = malloc(sizeof(ha_logd_client_t)))) {
		return FALSE;
	}
	memset(client, 0, sizeof(ha_logd_client_t));
	client->pid = ch->farside_pid;	
	client->chan = ch;
	client->logchan = (IPC_Channel*)user_data;
	client->g_src = G_main_add_IPC_Channel(G_PRIORITY_DEFAULT,
					       ch, FALSE, on_receive_cmd,
					       (gpointer)client,
					       on_remove_client);
	if (client->g_src == NULL){
		cl_log(LOG_ERR, "add the client to main loop failed");
		free(client);
		return TRUE;
	}
	if (stop_reading){
		G_main_IPC_Channel_pause(client->g_src);
	}
	
	logd_client_list = g_list_append(logd_client_list, client);
	
	
	return TRUE;
}



static void
logd_make_daemon(gboolean daemonize)
{
	long			pid;

	if (daemonize) {
		if (daemon(0,0)) {
			fprintf(stderr, "%s: could not start daemon\n"
				,	cmdname);
			perror("fork");
			exit(LSB_EXIT_GENERIC);
		}
	}
	
	if (cl_lock_pidfile(LOGD_PIDFILE) < 0 ){
		pid = cl_read_pidfile(LOGD_PIDFILE);
		if (pid > 0)
			fprintf(stderr, "%s: already running [pid %ld].\n",
				cmdname, pid);
		else
			fprintf(stderr, "%s: problem creating pid file %s\n",
				cmdname, LOGD_PIDFILE);
		exit(LSB_EXIT_OK);
	}
	
	if (daemonize || !verbose){
		cl_log_enable_stderr(FALSE);
	}

	if (daemonize){
		mode_t	mask;
		/*
		 *	Some sample umask calculations:
		 *
		 *	logmode		= 0644
		 *
		 *	(~0644)&0777	= 0133
		 *	(0133 & ~0111)	= 0022
		 *	=> umask will be 022 (the expected result)
		 *
		 *	logmode		= 0600
		 *	(~0600)&0777	= 0177
		 *	(0177 & ~0111)	= 0066
		 */
		mask = (mode_t)(((~logd_config.logmode) & 0777) & (~0111));
		umask(mask);
	}
}



static void
logd_stop(void)
{
	
	long running_logd_pid = cl_read_pidfile(LOGD_PIDFILE);
	int	err;
	
	if (running_logd_pid < 0) {
		fprintf(stderr, "ha_logd already stopped.\n");
		cl_log(LOG_INFO, "ha_logd already stopped.");
		exit(LSB_EXIT_OK);
	}
	
	cl_log(LOG_DEBUG, "Stopping ha_logd with pid %ld", running_logd_pid);
	if (kill((pid_t)running_logd_pid, SIGTERM) >= 0) {
		/* Wait for the running logd to die */
		cl_log(LOG_INFO, "Waiting for pid=%ld to exit",
		       running_logd_pid);
		alarm(0);
		do {
			sleep(1);
		}while (IsRunning(running_logd_pid));
	} else if (errno != ESRCH) {
		err = errno;
		cl_perror("Pid %ld not killed", running_logd_pid);
		exit((err == EPERM || err == EACCES)
		     ?	LSB_EXIT_EPERM
		     :	LSB_EXIT_GENERIC);
	}

	cl_log(LOG_INFO, "Pid %ld exited", running_logd_pid);
	exit(LSB_EXIT_OK);
}


static int 
get_dir_index(const char* directive)
{
	int j;
	for(j=0; j < DIMOF(Directives); j++){
		if (0 == strcasecmp(directive, Directives[j].name)){
			return j;
		}
	}
	return -1;
}


/* Adapted from parse_config in config.c */
static gboolean
parse_config(const char* cfgfile)
{
	FILE*	f;
	char	buf[MAXLINE];
	char*	bp;
	char*	cp;
	char	directive[MAXLINE];
	int	dirlength;
	int 	optionlength;
	char	option[MAXLINE];
	int	dir_index;

	gboolean	ret = TRUE;

	if ((f = fopen(cfgfile, "r")) == NULL){
		cl_log(LOG_WARNING, "Cannot open config file [%s]", cfgfile);
		return(FALSE);
	}

	while(fgets(buf, MAXLINE, f) != NULL){
		bp = buf;
		/* Skip over white space*/
		bp += strspn(bp, " \t\n\r\f");

		/* comments */
		if ((cp = strchr(bp, '#')) != NULL){
			*cp = EOS;
		}

		if (*bp == EOS){
			continue;
		}
		
		dirlength = strcspn(bp, " \t\n\f\r");
		strncpy(directive, bp, dirlength);
		directive[dirlength] = EOS;

		if ((dir_index = get_dir_index(directive)) == -1){
			fprintf(stderr, "Illegal directive [%s] in %s\n"
				,	directive, cfgfile);
			ret = FALSE;
			continue;
		}

		bp += dirlength;

		/* skip delimiters */
		bp += strspn(bp, " ,\t\n\f\r");

		/* Set option */
		optionlength = strcspn(bp, " ,\t\n\f\r");
		strncpy(option, bp, optionlength);
		option[optionlength] = EOS;
		if (!(*Directives[dir_index].add_func)(option)) {
			ret = FALSE;
		}
	}/*while*/
	fclose(f);
	return ret;
}

static gboolean
logd_term_action(int sig, gpointer userdata)
{      
	GList *log_iter   = logd_client_list;
	GMainLoop *mainloop = (GMainLoop*)userdata;
	ha_logd_client_t *client = NULL;
	
        cl_log(LOG_DEBUG, "logd_term_action: received SIGTERM");
        if (mainloop == NULL){
                cl_log(LOG_ERR, "logd_term_action: invalid arguments");
                return FALSE;
        }

	stop_reading = TRUE;

	while(log_iter != NULL) {
		client = log_iter->data;
		log_iter = log_iter->next;

		cl_log(LOG_DEBUG, "logd_term_action:"
		       " waiting for %d messages to be read for process %s",
		       (int)client->logchan->send_queue->current_qlen,
		       client->app_name);
		
		client->logchan->ops->waitout(client->logchan);
	}

	cl_log(LOG_DEBUG, "logd_term_action"
	": waiting for %d messages to be read by write process"
	,	(int)chanspair[WRITE_PROC_CHAN]->send_queue->current_qlen);
	chanspair[WRITE_PROC_CHAN]->ops->waitout(chanspair[WRITE_PROC_CHAN]);
	
        cl_log(LOG_DEBUG, "logd_term_action: sending SIGTERM to write process");
	if (CL_KILL(write_process_pid, SIGTERM) >= 0){
		
		pid_t pid;
		pid = wait4(write_process_pid, NULL, 0, NULL);
		if (pid < 0){
			cl_log(LOG_ERR, "wait4 for write process failed");
		}
		
	}
	
        g_main_quit(mainloop);
	
        return TRUE;
}

/*
 * Handle SIGHUP to re-open log files
 */
static gboolean
logd_hup_action(int sig, gpointer userdata)
{
	cl_log_close_log_files();
	if (write_process_pid)
		/* do we want to propagate the HUP,
		 * or do we assume that it was a killall anyways? */
		CL_KILL(write_process_pid, SIGHUP);
	else
		cl_log(LOG_INFO, "SIGHUP received, re-opened log files");
	return TRUE;
}

static void
read_msg_process(IPC_Channel* chan)
{
	GHashTable*		conn_cmd_attrs;
	IPC_WaitConnection*	conn_cmd = NULL;
	char			path[] = "path";
	char			socketpath[] = HA_LOGDAEMON_IPC;
	GMainLoop*		mainloop;

	

	mainloop = g_main_new(FALSE);       
	
	G_main_add_SignalHandler(G_PRIORITY_HIGH, SIGTERM, 
				 logd_term_action,mainloop, NULL);
	
	conn_cmd_attrs = g_hash_table_new(g_str_hash, g_str_equal);
	
	g_hash_table_insert(conn_cmd_attrs, path, socketpath);
	
	conn_cmd = ipc_wait_conn_constructor(IPC_ANYTYPE, conn_cmd_attrs);
	g_hash_table_destroy(conn_cmd_attrs);
	
	if (conn_cmd == NULL){
		fprintf(stderr, "ERROR: create waiting connection failed");
		exit(1);
	}
	
	/*Create a source to handle new connect rquests for command*/
	G_main_add_IPC_WaitConnection( G_PRIORITY_HIGH, conn_cmd, NULL, FALSE
	,	on_connect_cmd, chan, NULL);
	chan->ops->set_high_flow_callback(chan, logd_suspend_clients, NULL);
	chan->ops->set_low_flow_callback(chan, logd_resume_clients, NULL);
	chan->high_flow_mark = chan->send_queue->max_qlen;
	chan->low_flow_mark = (chan->send_queue->max_qlen*3)/4;

	G_main_add_IPC_Channel(G_PRIORITY_DEFAULT, chan, FALSE,NULL,NULL,NULL);
	
	G_main_add_SignalHandler(G_PRIORITY_DEFAULT, SIGHUP, 
				 logd_hup_action, mainloop, NULL);
	g_main_run(mainloop);
	
	return;
}

static gboolean
direct_log(IPC_Channel* ch, gpointer user_data)
{
	IPC_Message*		ipcmsg;
	GMainLoop*		loop;
	int			pri = LOG_DEBUG + 1;

	loop =(GMainLoop*)user_data;
	
	while(ch->ops->is_message_pending(ch)){
		if (ch->ch_status == IPC_DISCONNECT){
			cl_log(LOG_ERR, "read channel is disconnected:"
			       "something very wrong happened");
			return FALSE;
		}
		
		ipcmsg = getIPCmsg(ch);
		if (ipcmsg == NULL){
			return TRUE;
		}
		
		if( ipcmsg->msg_body 
		    && ipcmsg->msg_len > 0 ){
			LogDaemonMsgHdr *logmsghdr;
			LogDaemonMsgHdr	copy;
			char *msgtext;
			
			logmsghdr = (LogDaemonMsgHdr*) ipcmsg->msg_body;
			/* this copy nonsense is here because apparently ia64
			 * complained about "unaligned memory access. */
#define	COPYFIELD(copy, msg, field) memcpy(((u_char*)&copy.field), ((u_char*)&msg->field), sizeof(copy.field))
			COPYFIELD(copy, logmsghdr, use_pri_str);
			COPYFIELD(copy, logmsghdr, entity);
			COPYFIELD(copy, logmsghdr, entity_pid);
			COPYFIELD(copy, logmsghdr, timestamp);
			COPYFIELD(copy, logmsghdr, priority);
			/* Don't want to copy the following message text */
		
			msgtext = (char *)logmsghdr + sizeof(LogDaemonMsgHdr);
			cl_direct_log(copy.priority, msgtext
			,	copy.use_pri_str
			,	copy.entity, copy.entity_pid
			,	copy.timestamp);

			if (copy.priority < pri)
				pri = copy.priority;

			(void)logd_log;
/*
			if (verbose){
				logd_log("%s[%d]: %s %s\n", 
					 logmsg->entity[0]=='\0'?
					 "unknown": copy.entity,
					 copy.entity_pid, 
					 ha_timestamp(copy.timestamp),
					 msgtext);
				 }
 */
			if (ipcmsg->msg_done){
				ipcmsg->msg_done(ipcmsg);
			}
		}
	}
	/* current message backlog processed,
	 * about to return to mainloop,
	 * fflush and potentially fsync stuff */
	cl_log_do_fflush(pri <= LOG_ERR);

	if(needs_shutdown) {
		cl_log(LOG_INFO, "Exiting write process");
		g_main_quit(loop);
		return FALSE;
	}
	return TRUE;
}

static gboolean
logd_term_write_action(int sig, gpointer userdata)
{
	/* as a side-effect, the log message makes sure we enter direct_log()
	 * one last time (so we always exit)
	 */
	needs_shutdown = TRUE;
	cl_log(LOG_INFO, "logd_term_write_action: received SIGTERM");
	cl_log(LOG_DEBUG, "Writing out %d messages then quitting",
	       (int)chanspair[WRITE_PROC_CHAN]->recv_queue->current_qlen);

	direct_log(chanspair[WRITE_PROC_CHAN], userdata);

	return TRUE;
}

static void
write_msg_process(IPC_Channel* readchan)
{
	
	GMainLoop*	mainloop;
	IPC_Channel*	ch = readchan;
	
	
	mainloop = g_main_new(FALSE);   
	
	G_main_add_IPC_Channel(G_PRIORITY_DEFAULT,
			       ch, FALSE,
			       direct_log, mainloop, NULL);

	G_main_add_SignalHandler(G_PRIORITY_HIGH, SIGTERM, 
				 logd_term_write_action, mainloop, NULL);
				 
	G_main_add_SignalHandler(G_PRIORITY_DEFAULT, SIGHUP, 
				 logd_hup_action, mainloop, NULL);
	
	g_main_run(mainloop);
	
}






static void
usage(void)
{
	printf("usage: \n"
	       "%s [options]\n\n"
	       "options: \n"
	       "-d	make the program a daemon\n"
	       "-k	stop the logging daemon if it is already running\n"
	       "-s	return logging daemon status \n"
	       "-c	use this config file\n"
	       "-v	verbosely print debug messages"
	       "-h	print out this message\n\n",
	       cmdname);
	
	return;
}
int
main(int argc, char** argv, char** envp)
{

	int			c;
	gboolean		daemonize = FALSE;
	gboolean		stop_logd = FALSE;
	gboolean		ask_status= FALSE;
	const char*		cfgfile = NULL;
	pid_t			pid;
	
	cmdname = argv[0];
	while ((c = getopt(argc, argv, "c:dksvh")) != -1){

		switch(c){
			
		case 'd':	/* daemonize */
			daemonize = TRUE;
			break;
		case 'k':	/* stop */
			stop_logd = TRUE;
			break;
		case 's':	/* status */
			ask_status = TRUE;
			break;
		case 'c':	/* config file*/
			cfgfile = optarg;
			break;
		case 'v':
			verbose = TRUE;
			break;
		case 'h':	/*help message */
		default:
			usage();
			exit(1);
		}
		
	}
	
	set_ipc_time_debug_flag(FALSE);
	cl_log_set_uselogd(FALSE);

	if (!cfgfile && access(DEFAULT_CFG_FILE, F_OK) == 0) {
		cfgfile = DEFAULT_CFG_FILE;
	}
	

	/* default one set to "logd"
	 * by setting facility, we enable syslog
	 */
	cl_log_enable_stderr(TRUE);
	cl_log_set_entity(logd_config.entity);
	cl_log_set_facility(logd_config.log_facility);
	
	
	if (ask_status){
		long pid;
		
		if( (pid = cl_read_pidfile(LOGD_PIDFILE)) > 0 ){
			printf("logging daemon is running [pid = %ld].\n", pid);
			exit(LSB_EXIT_OK);
		}else{
			if (pid ==  - LSB_STATUS_VAR_PID) {
				printf("logging daemon is stopped: %s exists.\n"
				       ,	LOGD_PIDFILE);
			}else{
				printf("logging daemon is stopped.\n");
			}
		}
		exit(-pid);
		
	}
	if (stop_logd){
		logd_stop();
		exit(LSB_EXIT_OK);
	}

	logd_make_daemon(daemonize);

	
	if (ipc_channel_pair(chanspair) != IPC_OK){
		cl_perror("cannot create channel pair IPC");
		return -1;
	}
	
	
	if (cfgfile && !parse_config(cfgfile)) {
		FILE* f;
		if ((f = fopen(cfgfile, "r")) != NULL){
			fclose(f);
			cl_log(LOG_ERR, "Config file [%s] is incorrect."
			       ,	cfgfile);
			exit(LSB_EXIT_NOTCONFIGED);
		}
	}
	
	if (strlen(logd_config.debugfile) > 0) {
		cl_log_set_debugfile(logd_config.debugfile);
	}
	if (strlen(logd_config.logfile) > 0) {
		cl_log_set_logfile(logd_config.logfile);
	}
	cl_log_set_syslogprefix(logd_config.syslogprefix);
	cl_log_set_entity(logd_config.entity);
	cl_log_set_facility(logd_config.log_facility);
	
	cl_log(LOG_INFO, "logd started with %s.",
	       cfgfile ? cfgfile : "default configuration");

	if (cl_enable_coredumps(TRUE) < 0){
		cl_log(LOG_ERR, "enabling core dump failed");
	}
	cl_cdtocoredir();

	

	
	chanspair[WRITE_PROC_CHAN]->ops->set_recv_qlen(chanspair[WRITE_PROC_CHAN],
						  LOGD_QUEUE_LEN);
	
	chanspair[READ_PROC_CHAN]->ops->set_send_qlen(chanspair[READ_PROC_CHAN],
						 LOGD_QUEUE_LEN);
	
	if (init_set_proc_title(argc, argv, envp) < 0) {
		cl_log(LOG_ERR, "Allocation of proc title failed.");
                return -1;
        }

	switch(pid = fork()){
	case -1:	
		cl_perror("Can't fork child process!");
		return -1;
	case 0:
		/*child*/
		cl_log_use_buffered_io(1);
		set_proc_title("ha_logd: write process");
		write_msg_process(chanspair[WRITE_PROC_CHAN]);		
		break;
	default:
		/*parent*/
		set_proc_title("ha_logd: read process");
		write_process_pid = pid;
		/* we don't expect to log anything in the parent. */
		cl_log_close_log_files();

		read_msg_process(chanspair[READ_PROC_CHAN]);
		break;
	}
	return 0;
}




