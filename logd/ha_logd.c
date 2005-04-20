/*
 * ha_logd.c logging daemon
 *
 * Copyright (C) 2004 Guochun Shi <gshi@ncsa.uiuc.edu>
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
#include <glib.h>
#include <clplumbing/cl_log.h>
#include <clplumbing/ipc.h>
#include <clplumbing/GSource.h>
#include <clplumbing/cl_malloc.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <ha_config.h>
#include <clplumbing/loggingdaemon.h>
#include <netinet/in.h>
#include <clplumbing/lsb_exitcodes.h>
#include <sys/types.h>
#include <signal.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <portability.h>
#include <stdarg.h>
#include <apphb.h>
#include <clplumbing/Gmain_timeout.h>
#include <clplumbing/coredumps.h>

#ifndef DEFAULT_CFG_FILE
#	define DEFAULT_CFG_FILE	"/etc/logd.cf"
#endif
#ifndef	LOGD_PIDFILE
#	define	LOGD_PIDFILE	VAR_RUN_D "/logd.pid"
#endif

#define	FD_STDIN	0
#define	FD_STDOUT	1

#define	FD_STDERR	2


#define MAXLINE 128
#define EOS '\0'

int	logd_keepalive_ms = 1000;
int	logd_warntime_ms = 5000;
int	logd_deadtime_ms = 10000;
gboolean RegisteredWithApphbd = FALSE;
gboolean	verbose =FALSE;

struct {
	char		debugfile[MAXLINE];
	char		logfile[MAXLINE];
	char		entity[MAXLINE];
	int		log_facility;
	gboolean	useapphbd;
} logd_config =
	{
		"",
		"",
		"logd",
		LOG_LOCAL7,
		FALSE
	};

static void	logd_log(const char * fmt, ...) G_GNUC_PRINTF(1,2);
static int	set_debugfile(const char* option);
static int	set_logfile(const char* option);
static int	set_facility(const char * value);
static int	set_entity(const char * option);
static int	set_useapphbd(const char* option);

int		pidstatuscode = LSB_STATUS_UNKNOWN;

GMainLoop*			mainloop 		= NULL;
static long			logd_pid_in_file = 0L;
static char*			cmdname = NULL;


struct directive{
	const char* name;
	int (*add_func)(const char*);
} Directives[]= {
	{"debugfile", set_debugfile},
	{"logfile", set_logfile},
	{"logfacility", set_facility},
	{"entity", set_entity},
	{"useapphbd", set_useapphbd}
};

struct _syslog_code {
        const char    *c_name;
        int     c_val;
};

struct _syslog_code facilitynames[] = {
	{ "user",	LOG_USER },
	{ "mail",	LOG_MAIL },
	{ "daemon",	LOG_DAEMON },
	{ "auth",	LOG_AUTH },
	{ "syslog",	LOG_SYSLOG },
	{ "lpr",	LOG_LPR },
	{ "news",	LOG_NEWS },
	{ "uucp",	LOG_UUCP },
	{ "cron",	LOG_CRON },
	{ "local0",	LOG_LOCAL0 },
	{ "local1",	LOG_LOCAL1 },
	{ "local2",	LOG_LOCAL2 },
	{ "local3",	LOG_LOCAL3 },
	{ "local4",	LOG_LOCAL4 },
	{ "local5",	LOG_LOCAL5 },
	{ "local6",	LOG_LOCAL6 },
	{ "local7",	LOG_LOCAL7 },
	{ NULL, -1 }
};

static void
logd_log( const char * fmt, ...)
{
	char		buf[MAXLINE];
	va_list		ap;
	int		nbytes;
	
	buf[MAXLINE-1] = EOS;
	va_start(ap, fmt);
	nbytes=vsnprintf(buf, sizeof(buf)-1, fmt, ap);
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
	for(i = 0; facilitynames[i].c_name != NULL; ++i) {
		if(strcasecmp(value, facilitynames[i].c_name) == 0) {
			cl_log(LOG_INFO,  "setting log facility to %s", value);
			logd_config.log_facility = facilitynames[i].c_val;
			return(TRUE);
		}
	}
	return(FALSE);
}

static int
set_entity(const char * option)
{
	if (!option){
		logd_config.entity[0] = EOS;
		return FALSE;
	}
	cl_log(LOG_INFO, "setting entity to %s", option);
	strncpy(logd_config.entity, option, MAXLINE);
	return TRUE;

}

static int
set_useapphbd(const char* option)
{
	if (!option){
		cl_log(LOG_ERR,"set_useapphbd: option is NULL");
		return FALSE;
	}
	
	cl_log(LOG_INFO, "setting useapphbd to %s", option);
	if (0 == strcmp(option, "yes")){
		logd_config.useapphbd = TRUE;
		return TRUE;
	} else if (0 == strcmp(option, "no")){
		logd_config.useapphbd = FALSE;
		return TRUE;
	} else {
		cl_log(LOG_INFO,"invalid useapphbd option");
		return FALSE;
	}
}


typedef struct {
	char*		app_name;
	pid_t		pid;
	gid_t		gid;
	uid_t		uid;

	IPC_Channel*	chan;

	GCHSource*	g_src;
}ha_logd_client_t;

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

static gboolean
on_receive_cmd (IPC_Channel* ch, gpointer user_data)
{
	ha_logd_client_t *	client = user_data;
	IPC_Message*		ipcmsg;
	
	
	
	
	if (!client->chan->ops->is_message_pending(client->chan)) {
		goto getout;
	}
	
	ipcmsg = getIPCmsg(ch);
	if (ipcmsg == NULL){
		return FALSE;
	}
	
	if( ipcmsg->msg_body 
	    && ipcmsg->msg_len > 0 ){
		
		LogDaemonMsg*	logmsg = (LogDaemonMsg*) ipcmsg->msg_body;
		int		priority = logmsg->priority;
		
		cl_direct_log(priority, logmsg->message, logmsg->use_pri_str,
			      logmsg->entity, logmsg->entity_pid, logmsg->timestamp);
		
		if (verbose){
			logd_log("%s[%d]: %s %s\n", 
				 logmsg->entity[0]=='\0'?
				 "unknown": logmsg->entity,
				 logmsg->entity_pid, 
				 ha_timestamp(logmsg->timestamp),
				 logmsg->message);
		}
		
		if (ipcmsg->msg_done){
			ipcmsg->msg_done(ipcmsg);
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
	
	if (user_data){
		cl_free(user_data);
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
	/* the register will be finished in on_msg_register */
	if (NULL == (client = cl_malloc(sizeof(ha_logd_client_t)))) {
		return FALSE;
	}
	client->app_name = NULL;
	client->chan = ch;
	client->g_src = G_main_add_IPC_Channel(G_PRIORITY_DEFAULT
			,	ch, FALSE, on_receive_cmd
			,	(gpointer)client
			,	on_remove_client);
	

	return TRUE;
}


static long
get_running_logd_pid(void)
{
	long	pid;
	FILE *	lockfd = NULL;
	if ((lockfd = fopen(LOGD_PIDFILE, "r")) != NULL
	&&	fscanf(lockfd, "%ld", &pid) == 1 && pid > 0) {
		logd_pid_in_file = pid;
		if (kill((pid_t)pid, 0) >= 0 || errno != ESRCH) {
			fclose(lockfd);
			pidstatuscode = LSB_STATUS_OK;
			return pid;
		}
		pidstatuscode = LSB_STATUS_VAR_PID;
	}else{
		pidstatuscode = LSB_STATUS_STOPPED;
	}
	if (lockfd != NULL) {
		fclose(lockfd);
	}
	return -1L;
}


static void
logd_make_daemon(gboolean daemonize)
{
	long			pid;
	FILE *			lockfd = NULL;
	const char *		devnull = "/dev/null";

	if ((pid = get_running_logd_pid()) > 0  && pid != getpid()){
		fprintf(stderr, "%s: already running [pid %ld].\n",
			cmdname, pid);
		exit(LSB_EXIT_OK);
	}

	if (daemonize){		
		pid = fork();
		if (pid < 0) {
			fprintf(stderr, "%s: could not start daemon\n"
				,	cmdname);
			perror("fork");
			exit(LSB_EXIT_GENERIC);
		}else if (pid > 0) {
			exit(LSB_EXIT_OK);
		}
	}
	
	pid = (long) getpid();
	lockfd = fopen(LOGD_PIDFILE, "w");
	if (lockfd != NULL) {
		fprintf(lockfd, "%ld\n", pid);
		fclose(lockfd);
	}else{
		fprintf(stderr, "%s: could not create pidfile [%s]\n"
		,	cmdname, LOGD_PIDFILE);
		exit(LSB_EXIT_EPERM);
	}
	
	cl_log_enable_stderr(FALSE);
	
	if (daemonize){
		umask(022);
		close(FD_STDIN);
		(void)open(devnull, O_RDONLY);		/* Stdin:  fd 0 */
		close(FD_STDOUT);
		(void)open(devnull, O_WRONLY);		/* Stdout: fd 1 */
		close(FD_STDERR);
		(void)open(devnull, O_WRONLY);		/* Stderr: fd 2 */
	}
}

static void
logd_stop(void){

	long running_logd_pid = get_running_logd_pid();
	int	err;
	
	if (running_logd_pid < 0) {
		fprintf(stderr, "ha_logd already stopped.\n");
		exit(LSB_EXIT_OK);
	}
	
	if (kill((pid_t)running_logd_pid, SIGTERM) >= 0) {
		/* Wait for the running logd to die */
		alarm(0);
		do {
			sleep(1);
			continue;
		}while (kill((pid_t)running_logd_pid, 0) >= 0);
		exit(LSB_EXIT_OK);
	}
	err = errno;
	cl_log(LOG_ERR, "Could not kill pid %ld\n",
	       running_logd_pid);
	exit((err == EPERM || err == EACCES)
		  ?	LSB_EXIT_EPERM
		  :	LSB_EXIT_GENERIC);
	
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
		cl_perror("Cannot open config file [%s]", cfgfile);
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

#define APPLOGDINSTANCE "logging daemon"

static void
logd_init_register_with_apphbd(void)
{
	static int	failcount = 0;
	if (!logd_config.useapphbd || RegisteredWithApphbd) {
		return;
	}
		
	if (apphb_register(cmdname, APPLOGDINSTANCE) != 0) {
		/* Log attempts once an hour or so... */
		if ((failcount % 60) ==  0) {
			cl_log(LOG_INFO, "Unable to register with apphbd."
			       "Continuing to try and register.\n");
		}
		++failcount;
		return;
	}

	RegisteredWithApphbd = TRUE;
	cl_log(LOG_INFO, "Registered with apphbd as %s/%s.\n",
		 cmdname, APPLOGDINSTANCE); 
	
	if (apphb_setinterval(logd_deadtime_ms) < 0
	    ||	apphb_setwarn(logd_warntime_ms) < 0) {
		cl_log(LOG_ERR, "Unable to setup with apphbd.\n");
		apphb_unregister();
		RegisteredWithApphbd = FALSE;
		++failcount;
	}else{
		failcount = 0;
	}
}


static gboolean
logd_reregister_with_apphbd(gpointer dummy)
{
	if (logd_config.useapphbd) {
		logd_init_register_with_apphbd();
	}
	return logd_config.useapphbd;
}


static gboolean
logd_apphb_hb(gpointer dummy)
{
	if (logd_config.useapphbd) {
		if (RegisteredWithApphbd) {
			if (apphb_hb() < 0) {
				/* apphb_hb() will fail if apphbd exits */
				cl_log(LOG_ERR, "apphb_hb() failed.\n");
				apphb_unregister();
				RegisteredWithApphbd = FALSE;
			}
		}	
		/*
		 * Our timeout job (hb_reregister_with_apphbd) will
		 * reregister us if we become unregistered somehow...
		 */
	}
	
	return TRUE;

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
main(int argc, char** argv)
{
	GHashTable*		conn_cmd_attrs;
	IPC_WaitConnection*	conn_cmd = NULL;
	char			path[] = "path";
	char			socketpath[] = HA_LOGDAEMON_IPC;
	int			c;
	gboolean		daemonize = FALSE;
	gboolean		stop_logd = FALSE;
	gboolean		ask_status= FALSE;
	const char*		cfgfile = NULL;
	

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

		if( (pid = get_running_logd_pid()) > 0 ){
			printf("logging daemon is running [pid = %ld].\n", pid);
		}else{
			if (pidstatuscode ==  LSB_STATUS_VAR_PID) {
				printf("logging daemon is stopped: %s exists.\n"
				,	LOGD_PIDFILE);
			}else{
				printf("logging daemon is stopped.");
			}
		}
		exit(pidstatuscode);
		
	}
	if (stop_logd){
		logd_stop();
		exit(LSB_EXIT_OK);
	}
	

	
	if (cfgfile && !parse_config(cfgfile)) {
		cl_log(LOG_ERR, "Config file [%s] is incorrect."
		,	cfgfile);
		exit(LSB_EXIT_NOTCONFIGED);
	}
	
	if (strlen(logd_config.debugfile) > 0) {
		cl_log_set_debugfile(logd_config.debugfile);
	}
	if (strlen(logd_config.logfile) > 0) {
		cl_log_set_logfile(logd_config.logfile);
	}
	cl_log_set_entity(logd_config.entity);
	cl_log_set_facility(logd_config.log_facility);
	
	cl_log_enable_stderr(FALSE);
	cl_log(LOG_INFO, "%s started with %s."
	       ,	argv[0], cfgfile ? cfgfile : "default configuration");
	cl_log_enable_stderr(TRUE);
	
	logd_make_daemon(daemonize);
	
	if (cl_enable_coredumps(TRUE) < 0){
		cl_log(LOG_ERR, "enabling core dump failed");
	}
	cl_cdtocoredir();

	conn_cmd_attrs = g_hash_table_new(g_str_hash, g_str_equal);
	
	g_hash_table_insert(conn_cmd_attrs, path, socketpath);
	
	conn_cmd = ipc_wait_conn_constructor(IPC_ANYTYPE, conn_cmd_attrs);
	g_hash_table_destroy(conn_cmd_attrs);
	
	if (conn_cmd == NULL){
		fprintf(stderr, "ERROR: create waiting connection failed");
		exit(1);
	}
	
	/*Create a source to handle new connect rquests for command*/
	G_main_add_IPC_WaitConnection( G_PRIORITY_HIGH, conn_cmd, NULL, FALSE,
				       on_connect_cmd, conn_cmd, NULL);
	


	if (logd_config.useapphbd) {
		logd_reregister_with_apphbd(NULL);
		Gmain_timeout_add_full(G_PRIORITY_LOW,
				       60* 1000, 
				       logd_reregister_with_apphbd,
				       NULL, NULL);
		Gmain_timeout_add_full(G_PRIORITY_LOW,
				       logd_keepalive_ms,
				       logd_apphb_hb,
				       NULL, NULL);
	}

	mainloop = g_main_new(FALSE);       
	g_main_run(mainloop);
	
	conn_cmd->ops->destroy(conn_cmd);
	conn_cmd = NULL;
	
	return 0;
}





