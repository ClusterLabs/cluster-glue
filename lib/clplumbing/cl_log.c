/* $Id: cl_log.c,v 1.38 2005/03/14 16:31:20 gshi Exp $ */
#include <portability.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <time.h>
#include <clplumbing/ipc.h>
#include <clplumbing/cl_log.h>
#include <clplumbing/loggingdaemon.h>
#include <clplumbing/longclock.h>
#include <clplumbing/uids.h>
#include <glib.h>
#include <netinet/in.h>
#include <clplumbing/cl_malloc.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef MAXLINE
#	define MAXLINE	512
#endif
/*
 * <syslog.h> might not contain LOG_PRI...
 * So, we define it ourselves, or error out if we can't...
 */

#ifndef LOG_PRI
#  ifdef LOG_PRIMASK
 	/* David Lee <T.D.Lee@durham.ac.uk> reports this works on Solaris */
#	define	LOG_PRI(p)      ((p) & LOG_PRIMASK)
#  else
#	error	"Syslog.h does not define either LOG_PRI or LOG_PRIMASK."
#  endif 
#endif

#define	cl_malloc	malloc
#define	cl_free		free
#define	DFLT_ENTITY	"cluster"
#define NULLTIME 	0

char	log_entity[MAXENTITY];
static IPC_Channel*	logging_daemon_chan = NULL;

int LogToLoggingDaemon(int priority, const char * buf, int bstrlen, gboolean use_pri_str);
IPC_Message* ChildLogIPCMessage(int priority, const char *buf, int bstrlen, 
				gboolean use_priority_str, IPC_Channel* ch);
void	FreeChildLogIPCMessage(IPC_Message* msg);

int			use_logging_daemon =  FALSE;
int			conn_logd_intval = 0;
static int		cl_log_facility = LOG_USER;
static const char *	cl_log_entity = DFLT_ENTITY;

static void		cl_opensyslog(void);
static int		syslog_enabled = 0;
static int		stderr_enabled = 0;
static const char*	logfile_name = NULL;
static const char*	debugfile_name = NULL;
int cl_process_pid = -1;

void
cl_log_enable_stderr(int truefalse)
{
	stderr_enabled = truefalse;
}

void
cl_log_send_to_logging_daemon(int truefalse)
{
	use_logging_daemon = truefalse;
}

void
cl_log_set_facility(int facility)
{
	if (syslog_enabled && facility == cl_log_facility) {
		return;
	}
	cl_log_facility = facility;
	closelog();
	syslog_enabled = 0;
	if (facility > 0) {
		cl_opensyslog();
	}
}

void
cl_log_set_entity(const char *	entity)
{
	if (entity == NULL) {
		entity = DFLT_ENTITY;
	}
	cl_log_entity = cl_strdup(entity);
	if (syslog_enabled) {
		syslog_enabled = 0;
		cl_opensyslog();
	}
}

void
cl_log_set_logfile(const char *	path)
{
	logfile_name = path;
}
void
cl_log_set_debugfile(const char * path)
{
	debugfile_name = path;
}

/*
 * This function can cost us realtime unless use_logging_daemon
 * is enabled.  Then we log everything through a child process using
 * non-blocking IPC.
 */

/* Cluster logging function */
void
cl_direct_log(int priority, char* buf, gboolean use_priority_str,
	      const char* entity, int entity_pid, TIME_T ts)
{
	FILE *		fp = NULL;
	int		logpri;
	const char *	pristr;
	int	needprivs = !cl_have_full_privs();

	static const char *log_prio[8] = {
		"EMERG",
		"ALERT",
		"CRIT",
		"ERROR",
		"WARN",
		"notice",
		"info",
		"debug"
	};
	
	if (entity == NULL){
		entity =cl_log_entity;
	}
	
	if (use_priority_str){
		logpri =  LOG_PRI(priority);
		
		if (logpri < 0 || logpri >= DIMOF(log_prio)) {
			pristr = "(undef)";
		}else{
			pristr = log_prio[logpri];
		}
	}else{
		pristr = NULL;
	}
	
	if (needprivs) {
		return_to_orig_privs();
	}
	
	if (syslog_enabled) {
		if(entity){
			strncpy(log_entity, entity, MAXENTITY);
		}else{
			strncpy(log_entity, DFLT_ENTITY,MAXENTITY);
		}
		if (pristr){
			syslog(priority, "[%d]: %s: %s%c",
			       entity_pid, pristr,  buf, 0);
		}else {
			syslog(priority, "[%d]: %s%c", entity_pid, buf, 0);
		}
	}

	if (stderr_enabled) {
		if (pristr){
			fprintf(stderr, "%s[%d]: %s %s: %s\n"
				,	(entity ? entity : DFLT_ENTITY)
				,       entity_pid
				,	ha_timestamp(ts)
				,	pristr,  buf);
		}else {
			fprintf(stderr, "%s[%d]: %s %s\n"
				,	(entity ? entity : DFLT_ENTITY)
				,       entity_pid
				,	ha_timestamp(ts)
				,	buf);
			
		}
		
	}
	
	if (debugfile_name != NULL) {
		fp = fopen(debugfile_name, "a");
		if (fp != NULL) {
			if (pristr){
				fprintf(fp, "%s[%d]: %s %s: %s\n"
					,	(entity ? entity : DFLT_ENTITY)
					,       entity_pid
					,	ha_timestamp(ts)
					,	pristr,  buf);
			}else{
				fprintf(fp, "%s[%d]: %s %s\n"
					,	(entity ? entity : DFLT_ENTITY)
					,       entity_pid
					,	ha_timestamp(ts)
					,	buf);
				
			}
			
			fclose(fp);
		} else {
			fprintf(stderr, "Cannot open %s: %s\n",
				debugfile_name, strerror(errno));
		}
	}
	
	if (priority != LOG_DEBUG && logfile_name != NULL) { 
		fp = fopen(logfile_name, "a");
		if (fp != NULL) {
			if (pristr){
				fprintf(fp, "%s[%d]: %s %s: %s\n"
				,	(entity ? entity : DFLT_ENTITY)
				,       entity_pid
				,	ha_timestamp(ts)
				,	pristr,  buf);
			}else {
				fprintf(fp, "%s[%d]: %s %s\n"
					,	(entity ? entity : DFLT_ENTITY)
					,       entity_pid
					,	ha_timestamp(ts)
					,	buf);	
			}
			
				fclose(fp);
		} else {
			fprintf(stderr, "Cannot open %s: %s\n",
				logfile_name, strerror(errno));
		}
	}
	
	if (needprivs) {
		return_to_dropped_privs();
	}
	
	return;
}



/*
 * This function can cost us realtime unless use_logging_daemon
 * is enabled.  Then we log everything through a child process using
 * non-blocking IPC.
 */

/* Cluster logging function */
void
cl_log(int priority, const char * fmt, ...)
{
	va_list		ap;
	char		buf[MAXLINE];
	int		logpri = LOG_PRI(priority);
	ssize_t		nbytes;
	const char *	pristr;
	int	needprivs = !cl_have_full_privs();
	static int	cl_log_depth = 0;

	static const char *log_prio[8] = {
		"EMERG",
		"ALERT",
		"CRIT",
		"ERROR",
		"WARN",
		"notice",
		"info",
		"debug"
	};

	cl_process_pid = (int)getpid();

	cl_log_depth++;

	buf[MAXLINE-1] = EOS;
	va_start(ap, fmt);
	nbytes=vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	
	if (nbytes >= (ssize_t)sizeof(buf)){
		nbytes =  sizeof(buf) -1 ;
	}
	
	if (logpri < 0 || logpri >= DIMOF(log_prio)) {
		pristr = "(undef)";
	}else{
		pristr = log_prio[logpri];
	}

	if (needprivs) {
		return_to_orig_privs();
	}
	
	if ( use_logging_daemon && 
	     cl_log_depth <= 1 &&
	     LogToLoggingDaemon(priority, buf, nbytes + 1, TRUE) == HA_OK){
		goto LogDone;
	}else {
		cl_direct_log(priority, buf, TRUE, NULL, cl_process_pid, NULLTIME);
	}
	
 LogDone:
	cl_log_depth--;
	return;
}

void
cl_perror(const char * fmt, ...)
{
	const char *    err;

	va_list ap;
	char buf[MAXLINE];

	err = strerror(errno);
	va_start(ap, fmt);
	vsnprintf(buf, MAXLINE, fmt, ap);
	va_end(ap);

	cl_log(LOG_ERR, "%s: %s", buf, err);

}
void
cl_glib_msg_handler(const gchar *log_domain,	GLogLevelFlags log_level
,	const gchar *message, gpointer user_data)
{
	GLogLevelFlags	level = (log_level & G_LOG_LEVEL_MASK);
	int	ha_level;

	switch(level) {
		case G_LOG_LEVEL_ERROR:		ha_level = LOG_ERR; break;
		case G_LOG_LEVEL_CRITICAL:	ha_level = LOG_ERR; break;
		case G_LOG_LEVEL_WARNING:	ha_level = LOG_WARNING; break;
		case G_LOG_LEVEL_MESSAGE:	ha_level = LOG_NOTICE; break;
		case G_LOG_LEVEL_INFO:		ha_level = LOG_INFO; break;
		case G_LOG_LEVEL_DEBUG:		ha_level = LOG_DEBUG; break;

		default:			ha_level = LOG_WARNING; break;
	}


	cl_log(ha_level, "glib: %s", message);
}
char *
ha_timestamp(TIME_T t)
{
	static char ts[64];
	struct tm*	ttm;
	TIME_T		now;
	time_t		nowtt;
	
	/* Work around various weridnesses in different OSes and time_t definitions */
	if(t == 0){
		now = time(NULL);
	}else{
		now = t;
	}

	nowtt = (time_t)now;
	ttm = localtime(&nowtt);

	snprintf(ts, sizeof(ts), "%04d/%02d/%02d_%02d:%02d:%02d"
	,	ttm->tm_year+1900, ttm->tm_mon+1, ttm->tm_mday
	,	ttm->tm_hour, ttm->tm_min, ttm->tm_sec);
	return(ts);
}

static IPC_Channel* 
create_logging_channel(void)
{
	GHashTable*	attrs;
	char		path[] = IPC_PATH_ATTR;
	char		sockpath[] = HA_LOGDAEMON_IPC;	
	IPC_Channel*	chan;
	
	attrs = g_hash_table_new(g_str_hash, g_str_equal);
	g_hash_table_insert(attrs, path, sockpath);	

	chan =ipc_channel_constructor(IPC_ANYTYPE, attrs);       	
	
	g_hash_table_destroy(attrs);	
	
	if (chan == NULL) {
		cl_log(LOG_ERR, "create_logging_channel:"
		       "contructing ipc channel failed");
		return NULL;
	}
			
	if (chan->ops->initiate_connection(chan) != IPC_OK) {
		cl_log(LOG_WARNING, "Initializing connection"
		       " to logging daemon failed."
		       " Logging daemon may not be running");
		chan->ops->destroy(chan);
		
		return NULL;
	}
	
	return chan;
	
}

int
cl_set_logging_wqueue_maxlen(int qlen)
{
	int sendrc;
	IPC_Channel*		chan = logging_daemon_chan;
	
	if (chan == NULL){
		chan = logging_daemon_chan = create_logging_channel();
	}
	
	if (chan == NULL){
		return HA_FAIL;
	}
	
	if (chan->ch_status != IPC_CONNECT){		
		cl_log(LOG_ERR, "cl_set_logging_wqueue_maxle:"
		       "channel is not connected");
		chan->ops->destroy(chan);
		logging_daemon_chan = NULL;
		return HA_FAIL;
	}
	
	sendrc =  chan->ops->set_send_qlen(logging_daemon_chan, qlen);
	
	if (sendrc == IPC_OK) {
		return HA_OK;
	}else {
		return HA_FAIL;
	}
}


int
LogToLoggingDaemon(int priority, const char * buf, 
		   int bufstrlen, gboolean use_pri_str)
{
	IPC_Channel*		chan = logging_daemon_chan;
	static longclock_t	nexttime = 0;
	IPC_Message*		msg;
	int			sendrc;
	int			intval = conn_logd_intval;

	if (chan == NULL) {
		longclock_t	lnow = time_longclock();
		
		if (cmp_longclock(lnow,  nexttime) >= 0){
			nexttime = add_longclock(lnow, 
						 msto_longclock(intval));
			
			
			logging_daemon_chan = chan = create_logging_channel();
			
		}
	}

	if (chan == NULL){
		return HA_FAIL;
	}
	
	msg = ChildLogIPCMessage(priority, buf, bufstrlen, use_pri_str, chan);	
	if (msg == NULL) {
		return HA_FAIL;
	}
	
	if (chan->ch_status != IPC_CONNECT){		
		cl_log(LOG_ERR, "channel is not connected");
		chan->ops->destroy(chan);
		logging_daemon_chan = NULL;
		return HA_FAIL;
	}
	/* Logging_channel is all set up */
	
	sendrc =  chan->ops->send(chan, msg);
	if (sendrc == IPC_OK) {
		return HA_OK;
	}else {
		chan->ops->destroy(chan);
		logging_daemon_chan = NULL;
	}
	FreeChildLogIPCMessage(msg);
	return HA_FAIL;
}

IPC_Message*
ChildLogIPCMessage(int priority, const char *buf, int bufstrlen, 
		   gboolean use_prio_str, IPC_Channel* ch)
{
	IPC_Message*	ret;
	LogDaemonMsg	logbuf;
	int		msglen;
	char*		bodybuf;
	
	if (ch->msgpad > MAX_MSGPAD){
		cl_log(LOG_ERR, "ChildLogIPCMessage: invalid msgpad(%d)",
		       ch->msgpad);
		return NULL;
	}


	ret = (IPC_Message*)cl_malloc(sizeof(IPC_Message));

	if (ret == NULL) {
		return ret;
	}
	
	memset(ret, 0, sizeof(IPC_Message));
	
	/* Compute msg len: including room for the EOS byte */
	msglen = sizeof(LogDaemonMsg)+bufstrlen;
	bodybuf = cl_malloc(msglen + ch->msgpad + 1);
	if (bodybuf == NULL) {
		cl_free(ret);
		return NULL;
	}
	
	memset(bodybuf, 0, msglen + ch->msgpad + 1);
	memset(&logbuf, 0, sizeof(logbuf));
	logbuf.msgtype = LD_LOGIT;
	logbuf.facility = cl_log_facility;
	logbuf.priority = priority;
	logbuf.use_pri_str = use_prio_str;
	logbuf.entity_pid = getpid();
	logbuf.timestamp = time(NULL);
	if (cl_log_entity){
		strncpy(logbuf.entity,cl_log_entity,MAXENTITY);
	}else {
		strncpy(logbuf.entity,DFLT_ENTITY,MAXENTITY);
	}
	       
	logbuf.msglen = bufstrlen + 1;
	memcpy(bodybuf + ch->msgpad, &logbuf, sizeof(logbuf));
	memcpy(bodybuf + ch->msgpad + sizeof(logbuf),
		buf, 
		bufstrlen);
	       
	ret->msg_len = msglen;
	ret->msg_buf = bodybuf;
	ret->msg_body = bodybuf + ch->msgpad;
	ret->msg_done = FreeChildLogIPCMessage;
	ret->msg_ch = ch;
	return ret;
}


void
FreeChildLogIPCMessage(IPC_Message* msg)
{
	if (msg == NULL) {
		return;
	}
	if (msg->msg_buf != NULL) {
		memset(msg->msg_body, 0, msg->msg_len);
		cl_free(msg->msg_buf);
	}
	memset(msg, 0, sizeof (*msg));
	cl_free(msg);
}



static void
cl_opensyslog(void)
{
	if (cl_log_entity == NULL || cl_log_facility < 0) {
		return;
	}
	syslog_enabled = 1;
	openlog(log_entity, LOG_CONS, cl_log_facility);

}
