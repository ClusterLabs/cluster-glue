/* $Id: cl_log.c,v 1.14 2004/04/16 19:30:00 alan Exp $ */
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



static gboolean	LogToLoggingDaemon(int priority, const char * buf, int bstrlen);
static IPC_Message*
		ChildLogIPCMessage(int priority, const char *buf, int bstrlen);
static void	FreeChildLogIPCMessage(IPC_Message* msg);
static char *	ha_timestamp(void);

static int		use_logging_daemon = 0;
static int		cl_log_facility = LOG_USER;
static const char *	cl_log_entity = DFLT_ENTITY;

static void		cl_opensyslog(void);
static int		syslog_enabled = 0;
static int		stderr_enabled = 0;
static const char*	logfile_name = NULL;
static const char*	debugfile_name = NULL;

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
	cl_log_entity = entity;
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
cl_log(int priority, const char * fmt, ...)
{
	va_list		ap;
	FILE *		fp = NULL;
	const char *	fn = NULL;
	char		buf[MAXLINE];
	int		logpri = LOG_PRI(priority);
	int		nbytes;
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

	buf[MAXLINE-1] = EOS;
	va_start(ap, fmt);
	nbytes=vsnprintf(buf, sizeof(buf)-1, fmt, ap);
	va_end(ap);

	if (logpri < 0 || logpri >= DIMOF(log_prio)) {
		pristr = "(undef)";
	}else{
		pristr = log_prio[logpri];
	}

	if (needprivs) {
		return_to_orig_privs();
	}
	if (use_logging_daemon) {
		if (LogToLoggingDaemon(priority, buf, nbytes)) {
			goto LogDone;
		}
	}

	if (syslog_enabled) {
		syslog(priority, "%s: %s", pristr,  buf);
	}

	if (stderr_enabled) {
		fprintf(stderr, "%s: %s %s: %s\n"
		,	(cl_log_entity ? cl_log_entity : DFLT_ENTITY)
		,	ha_timestamp()
		,	pristr,  buf);
	}

	fn = (priority == LOG_DEBUG ? debugfile_name : logfile_name);

	if (fn) { 
		fp = fopen(fn, "a");
		if (fp != NULL) {
			fprintf(fp, "%s: %s %s: %s\n"
			,	(cl_log_entity ? cl_log_entity : DFLT_ENTITY)
			,	ha_timestamp()
			,	pristr,  buf);
			fclose(fp);
		}
	}

LogDone:
	if (needprivs) {
		return_to_dropped_privs();
	}
}

extern int      sys_nerr;
void
cl_perror(const char * fmt, ...)
{
	const char *    err;
	char    errornumber[16];

	va_list ap;
	char buf[MAXLINE];

	if (errno < 0 || errno >= sys_nerr) {
		sprintf(errornumber, "error %d\n", errno);
		err = errornumber;
	}else{
#ifdef HAVE_STRERROR
		err = strerror(errno);
#else
		err = sys_errlist[errno];
#endif
	}
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


	cl_log(ha_level, "%s", message);
}
static char *
ha_timestamp(void)
{
	static char ts[64];
	struct tm*	ttm;
	TIME_T		now;
	time_t		nowtt;

	/* Work around various weridnesses in different OSes and time_t definitions */
	now = time(NULL);
	nowtt = (time_t)now;
	ttm = localtime(&nowtt);

	snprintf(ts, sizeof(ts), "%04d/%02d/%02d_%02d:%02d:%02d"
	,	ttm->tm_year+1900, ttm->tm_mon+1, ttm->tm_mday
	,	ttm->tm_hour, ttm->tm_min, ttm->tm_sec);
	return(ts);
}


static gboolean
LogToLoggingDaemon(int priority, const char * buf, int bufstrlen)
{
	static IPC_Channel*	logging_channel;

	IPC_Message*		msg;
	int			sendrc;

	msg = ChildLogIPCMessage(priority, buf, bufstrlen);

	if (msg == NULL) {
		return FALSE;
	}
	if (logging_channel == NULL) {
		GHashTable*	attrs;
		char		path[] = IPC_PATH_ATTR;
		char		sockpath[] = HA_LOGDAEMON_IPC;
	
		attrs = g_hash_table_new(g_str_hash, g_str_equal);
		g_hash_table_insert(attrs, path, sockpath);

		logging_channel = ipc_channel_constructor(IPC_ANYTYPE, attrs);
		g_hash_table_destroy(attrs);

		if (logging_channel == NULL) {
			FreeChildLogIPCMessage(msg);
			return FALSE;
		}
	}

	/* Logging_channel is all set up */

	sendrc =  logging_channel->ops->send(logging_channel, msg);
	if (sendrc == IPC_OK) {
		return TRUE;
	}

	/* Too bad we can't log a message ;-) */

	if (sendrc == IPC_BROKEN) {
		logging_channel->ops->destroy(logging_channel);
		logging_channel = NULL;
	}
	FreeChildLogIPCMessage(msg);
	return FALSE;
}

static IPC_Message*
ChildLogIPCMessage(int priority, const char *buf, int bufstrlen)
{
	IPC_Message*	ret;
	LogDaemonMsg*	logbuf;
	int		msglen;

	ret = (IPC_Message*)cl_malloc(sizeof(IPC_Message));

	if (ret == NULL) {
		return ret;
	}

	/* Compute msg len: including room for the EOS byte */
	msglen = sizeof(LogDaemonMsg)+bufstrlen;
	logbuf = (LogDaemonMsg*)cl_malloc(msglen);

	if (logbuf == NULL) {
		cl_free(ret);
		return NULL;
	}

	logbuf->msgtype = LD_LOGIT;
	logbuf->facility = cl_log_facility;
	logbuf->priority = priority;
	logbuf->msglen = bufstrlen+1;
	strncpy(logbuf->message, buf, bufstrlen);
	logbuf->message[bufstrlen] = EOS;

	ret->msg_len = msglen;
	ret->msg_body = logbuf;
	ret->msg_done = FreeChildLogIPCMessage;
	return ret;
}


static void
FreeChildLogIPCMessage(IPC_Message* msg)
{
	if (msg == NULL) {
		return;
	}
	if (msg->msg_body != NULL) {
		memset(msg->msg_body, 0, msg->msg_len);
		cl_free(msg->msg_body);
	}
	memset(msg, 0, sizeof (*msg));
	free(msg);
}



static void
cl_opensyslog(void)
{
	if (cl_log_entity == NULL || cl_log_facility < 0) {
		return;
	}
	syslog_enabled = 1;
	openlog(cl_log_entity, LOG_CONS|LOG_PID, cl_log_facility);
}
