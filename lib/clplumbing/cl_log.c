/*
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
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <lha_internal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <time.h>
#include <sys/utsname.h>
#include <clplumbing/ipc.h>
#include <clplumbing/cl_log.h>
#include <clplumbing/loggingdaemon.h>
#include <clplumbing/longclock.h>
#include <clplumbing/uids.h>
#include <glib.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <clplumbing/GSource.h>
#include <clplumbing/cl_misc.h>
#include <clplumbing/cl_syslog.h>
#include <ha_msg.h>

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

#define	DFLT_ENTITY	"cluster"
#define	DFLT_PREFIX	""
#define NULLTIME 	0
#define QUEUE_SATURATION_FUZZ 10

static IPC_Channel*	logging_daemon_chan = NULL;
static gboolean		syslogformatfile = TRUE;
/*
 * If true, then output messages more or less like this...
 * Jul 14 21:45:18 beam logd: [1056]: info: setting log file to /dev/null
 */

int LogToDaemon(int priority, const char * buf, int bstrlen, gboolean use_pri_str);

static int LogToLoggingDaemon(int priority, const char * buf, int bstrlen, gboolean use_pri_str);
static IPC_Message* ChildLogIPCMessage(int priority, const char *buf, int bstrlen, 
				gboolean use_priority_str, IPC_Channel* ch);
static void	FreeChildLogIPCMessage(IPC_Message* msg);
static gboolean send_dropped_message(gboolean use_pri_str, IPC_Channel *chan);
static int cl_set_logging_wqueue_maxlen(int qlen);

static int		use_logging_daemon =  FALSE;
static int		conn_logd_time = 0;
static char		cl_log_entity[MAXENTITY]= DFLT_ENTITY;
static char		cl_log_syslogprefix[MAXENTITY] = DFLT_PREFIX;
static char		common_log_entity[MAXENTITY]= DFLT_ENTITY;
static int		cl_log_facility = LOG_USER;
static int		use_buffered_io = 0;

static void		cl_opensyslog(void);
static int		syslog_enabled = 0;
static int		stderr_enabled = 0;
static int		stdout_enabled = 0;
static const char*	logfile_name = NULL;
static const char*	debugfile_name = NULL;
static int		cl_process_pid = -1;
int			debug_level = 0;
static GDestroyNotify	destroy_logging_channel_callback;
static void		(*create_logging_channel_callback)(IPC_Channel* chan);
static gboolean		logging_chan_in_main_loop = FALSE;

/***********************
 *debug use only, do not use this function in your program
 */
IPC_Channel * get_log_chan(void);

IPC_Channel* get_log_chan(void){
	return logging_daemon_chan;
}
/*************************/

/**************************
 * check if the fd is in use for logging
 **************************/
int
cl_log_is_logd_fd(int fd)
{
	return logging_daemon_chan && (
		fd == logging_daemon_chan->ops->get_send_select_fd(logging_daemon_chan)
		||
		fd == logging_daemon_chan->ops->get_recv_select_fd(logging_daemon_chan)
		);
}

void
cl_log_enable_stderr(int truefalse)
{
	stderr_enabled = truefalse;
}

void
cl_log_enable_stdout(int truefalse)
{
	stdout_enabled = truefalse;
}

void
cl_log_set_uselogd(int truefalse)
{
	use_logging_daemon = truefalse;
}
void
cl_log_enable_syslog_filefmt(int truefalse)
{
	syslogformatfile = (gboolean)truefalse;
}

gboolean
cl_log_get_uselogd(void)
{
	return	use_logging_daemon;
}


int
cl_log_get_logdtime(void)
{
	return conn_logd_time;
	
}

void
cl_log_set_logdtime(int logdtime)
{
	conn_logd_time = logdtime;
	return;
}

void
cl_log_use_buffered_io(int truefalse)
{
	use_buffered_io = truefalse;
	cl_log_close_log_files();
}

#define ENVPRE		"HA_"

#define ENV_HADEBUGVAL	"HA_debug"
#define ENV_LOGFENV	"HA_logfile"	/* well-formed log file :-) */
#define ENV_DEBUGFENV	"HA_debugfile"	/* Debug log file */
#define ENV_LOGFACILITY	"HA_logfacility"/* Facility to use for logger */
#define ENV_SYSLOGFMT	"HA_syslogmsgfmt"/* TRUE if we should use syslog message formatting */
#define ENV_LOGDAEMON	"HA_use_logd"
#define	ENV_CONNINTVAL	"HA_conn_logd_time"
#define TRADITIONAL_COMPRESSION "HA_traditional_compression"
#define COMPRESSION	 "HA_compression"

static void
inherit_compress(void)
{
	char* inherit_env = NULL;
	
	inherit_env = getenv(TRADITIONAL_COMPRESSION);
	if (inherit_env != NULL && *inherit_env != EOS) {
		gboolean value;
		
		if (cl_str_to_boolean(inherit_env, &value)!= HA_OK){
			cl_log(LOG_ERR, "inherit traditional_compression failed");
		}else{
			cl_set_traditional_compression(value);
		}
	}
	
}

void
cl_inherit_logging_environment(int logqueuemax)
{
	char * inherit_env = NULL;

	/* Donnot need to free the return pointer from getenv */
	inherit_env = getenv(ENV_HADEBUGVAL);
	if (inherit_env != NULL && atoi(inherit_env) != 0 ) {
		debug_level = atoi(inherit_env);
		inherit_env = NULL;
	}

	inherit_env = getenv(ENV_LOGFENV);
	if (inherit_env != NULL && *inherit_env != EOS) {
		cl_log_set_logfile(inherit_env);
		inherit_env = NULL;
	}

	inherit_env = getenv(ENV_DEBUGFENV);
	if (inherit_env != NULL && *inherit_env != EOS) {
		cl_log_set_debugfile(inherit_env);
		inherit_env = NULL;
	}

	inherit_env = getenv(ENV_LOGFACILITY);
	if (inherit_env != NULL && *inherit_env != EOS) {
		int facility = -1;
		facility = cl_syslogfac_str2int(inherit_env);
		if ( facility >= 0 ) {
			cl_log_set_facility(facility);
		}
		inherit_env = NULL;
	}

	inherit_env = getenv(ENV_SYSLOGFMT);
	if (inherit_env != NULL && *inherit_env != EOS) {
		gboolean truefalse;
		if (cl_str_to_boolean(inherit_env, &truefalse) == HA_OK) {
			cl_log_enable_syslog_filefmt(truefalse);
		}
	}

	inherit_env = getenv(ENV_LOGDAEMON);
	if (inherit_env != NULL && *inherit_env != EOS) {
		gboolean	uselogd;
		cl_str_to_boolean(inherit_env, &uselogd);
		cl_log_set_uselogd(uselogd);
		if (uselogd) {
			if (logqueuemax > 0) {
				cl_set_logging_wqueue_maxlen(logqueuemax);
			}
		}
	}

	inherit_env = getenv(ENV_CONNINTVAL);
	if (inherit_env != NULL && *inherit_env != EOS) {
		int logdtime;
		logdtime = cl_get_msec(inherit_env);
		cl_log_set_logdtime(logdtime);
	}

	inherit_compress();
	return;
}


static void
add_logging_channel_mainloop(IPC_Channel* chan)
{
	GCHSource* chp=
		G_main_add_IPC_Channel(	G_PRIORITY_DEFAULT,
					chan,
					FALSE,
					NULL,
					NULL,
					destroy_logging_channel_callback);
	
	if (chp == NULL){
		cl_log(LOG_INFO, "adding logging channel to mainloop failed");
	}

	logging_chan_in_main_loop = TRUE;
	

	return;
}

static void
remove_logging_channel_mainloop(gpointer userdata)
{
	logging_chan_in_main_loop = FALSE;
	
	return;
}


static IPC_Channel* 
create_logging_channel(void)
{
	GHashTable*	attrs;
	char		path[] = IPC_PATH_ATTR;
	char		sockpath[] = HA_LOGDAEMON_IPC;
	IPC_Channel*	chan;
	static gboolean	complained_yet = FALSE;
	
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
		if (!complained_yet) {
			complained_yet = TRUE;
			cl_log(LOG_WARNING, "Initializing connection"
			       " to logging daemon failed."
			       " Logging daemon may not be running");
		}
		if (!logging_chan_in_main_loop){
			chan->ops->destroy(chan);
		}
		
		return NULL;
	}
	complained_yet = FALSE;

	if (create_logging_channel_callback){
		create_logging_channel_callback(chan);
	}
	
	
	return chan;
	
}

gboolean
cl_log_test_logd(void)
{
	IPC_Channel*		chan = logging_daemon_chan;

	if (chan && chan->ops->get_chan_status(chan) == IPC_CONNECT){
		return TRUE;
	}
	if (chan ){
		if (!logging_chan_in_main_loop){
			chan->ops->destroy(chan);
		}
		logging_daemon_chan = chan = NULL;
	}
	
	logging_daemon_chan = chan = create_logging_channel();
	
	if (chan == NULL){
		return FALSE;
	}
		
	if(chan->ops->get_chan_status(chan) != IPC_CONNECT){
		if (!logging_chan_in_main_loop){
			chan->ops->destroy(chan);
		}
		logging_daemon_chan = chan = NULL;
		return FALSE;
	}
	
	return TRUE;
	
}

/* FIXME: This is way too ugly to bear */

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
	strncpy(cl_log_entity, entity, MAXENTITY);
	cl_log_entity[MAXENTITY-1] = '\0';
	if (syslog_enabled) {
		syslog_enabled = 0;
		cl_opensyslog();
	}
}

void
cl_log_set_syslogprefix(const char *prefix)
{
	if (prefix == NULL) {
		prefix = DFLT_PREFIX;
	}
	strncpy(cl_log_syslogprefix, prefix, MAXENTITY);
	cl_log_syslogprefix[MAXENTITY-1] = '\0';
	if (syslog_enabled) {
		syslog_enabled = 0;
		cl_opensyslog();
	}
}

void
cl_log_set_logfile(const char *	path)
{
	if(path != NULL && strcasecmp("/dev/null", path) == 0) {
		path = NULL;
	}
	logfile_name = path;
	cl_log_close_log_files();
}
void
cl_log_set_debugfile(const char * path)
{
	if(path != NULL && strcasecmp("/dev/null", path) == 0) {
		path = NULL;
	}
	debugfile_name = path;
	cl_log_close_log_files();
}


/* 
 * This function sets two callback functions.
 * One for creating a channel and 
 * the other for destroying a channel*
 */
int
cl_log_set_logd_channel_source( void (*create_callback)(IPC_Channel* chan),
				GDestroyNotify destroy_callback)
{
	IPC_Channel* chan = logging_daemon_chan ;
	
	if (destroy_callback == NULL){
		destroy_logging_channel_callback = remove_logging_channel_mainloop;
	}else{		
		destroy_logging_channel_callback = destroy_callback;
	}
	
	if (create_callback == NULL){
		create_logging_channel_callback = add_logging_channel_mainloop;	
	}else{
		create_logging_channel_callback = create_callback;	
	}
	
	if (chan != NULL 
	    && chan->ops->get_chan_status(chan) ==  IPC_CONNECT){		
		add_logging_channel_mainloop(chan);
	}
	
	return 0;
}

const char *
prio2str(int priority)
{
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
	int		logpri;

	logpri =  LOG_PRI(priority);

	return (logpri < 0 || logpri >= DIMOF(log_prio)) ?
		"(undef)" : log_prio[logpri];
}

/* print log line to a FILE *f */
#define print_logline(fp,entity,entity_pid,ts,pristr,buf) { \
			fprintf(fp, "%s[%d]: %s ",entity,entity_pid,ha_timestamp(ts)); \
			if (pristr) \
				fprintf(fp,"%s: %s\n",pristr,buf); \
			else \
				fprintf(fp,"%s\n",buf); \
		}

static char * syslog_timestamp(TIME_T t);
static void cl_limit_log_update(struct msg_ctrl *ml, time_t ts);

static void
append_log(FILE * fp, const char * entity, int entity_pid
,	TIME_T timestamp, const char * pristr, const char * msg)
{
	static int		got_uname = FALSE;
	static struct utsname	un;

	if (!syslogformatfile) {
		print_logline(fp, entity, entity_pid, timestamp, pristr, msg);
		return;
	}
	if (!got_uname) {
		uname(&un);
	}
	/*
	 * Jul 14 21:45:18 beam logd: [1056]: info: setting log file to /dev/null
	 */
	fprintf(fp, "%s %s %s: [%d]: %s%s%s\n"
	,	syslog_timestamp(timestamp)
	,	un.nodename, entity, entity_pid
	,	(pristr ? pristr : "")
	,	(pristr ? ": " : "")
	,	msg);
}

/* As performance optimization we try to keep the file descriptor
 * open all the time, but as logrotation needs to work, the calling
 * program actually needs a signal handler.
 *
 * To be able to keep files open even without signal handler,
 * we remember the stat info, and close/reopen if the inode changed.
 * We keep the number of stat() calls to one per file per minute.
 * logrotate should be configured for delayed compression, if any.
 */

struct log_file_context {
	FILE *fp;
	struct stat stat_buf;
};

static struct log_file_context log_file, debug_file;

static void close_log_file(struct log_file_context *lfc)
{
	/* ignore errors, we cannot do anything about them anyways */
	fflush(lfc->fp);
	fsync(fileno(lfc->fp));
	fclose(lfc->fp);
	lfc->fp = NULL;
}

void cl_log_close_log_files(void)
{
	if (log_file.fp)
		close_log_file(&log_file);
	if (debug_file.fp)
		close_log_file(&debug_file);
}

static void maybe_close_log_file(const char *fname, struct log_file_context *lfc)
{
	struct stat buf;
	if (!lfc->fp)
		return;
	if (stat(fname, &buf) || buf.st_ino != lfc->stat_buf.st_ino) {
		close_log_file(lfc);
		cl_log(LOG_INFO, "log-rotate detected on logfile %s", fname);
	}
}

/* Default to unbuffered IO.  logd or others can use cl_log_use_buffered_io(1)
 * to enable fully buffered mode, and then use fflush appropriately.
 */
static void open_log_file(const char *fname, struct log_file_context *lfc)
{
	lfc->fp = fopen(fname ,"a");
	if (!lfc->fp) {
		syslog(LOG_ERR, "Failed to open log file %s: %s\n" ,
		       fname, strerror(errno));
	} else {
		setvbuf(lfc->fp, NULL,
				use_buffered_io ? _IOFBF : _IONBF,
				BUFSIZ);
		fstat(fileno(lfc->fp), &lfc->stat_buf);
	}
}

static void maybe_reopen_log_files(const char *log_fname, const char *debug_fname)
{
	static TIME_T last_stat_time;

	if (log_file.fp || debug_file.fp) {
		TIME_T now = time(NULL);
		if (now - last_stat_time > 59) {
			/* Don't use an exact minute, have it jitter around a
			 * bit against cron or others.  Note that, if there
			 * is no new log message, it can take much longer
			 * than this to notice logrotation and actually close
			 * our file handle on the possibly already rotated,
			 * or even deleted.
			 *
			 * As long as at least one minute pases between
			 * renaming the log file, and further processing,
			 * no message will be lost, so this should do fine:
			 * (mv ha-log ha-log.1; sleep 60; gzip ha-log.1)
			 */
			maybe_close_log_file(log_fname, &log_file);
			maybe_close_log_file(debug_fname, &debug_file);
			last_stat_time = now;
		}
	}

	if (log_fname && !log_file.fp)
		open_log_file(log_fname, &log_file);

	if (debug_fname && !debug_file.fp)
		open_log_file(debug_fname, &debug_file);
}

/*
 * This function can cost us realtime unless use_logging_daemon
 * is enabled.  Then we log everything through a child process using
 * non-blocking IPC.
 */

/* Cluster logging function */
void
cl_direct_log(int priority, const char* buf, gboolean use_priority_str,
	      const char* entity, int entity_pid, TIME_T ts)
{
	const char *	pristr;
	int	needprivs = !cl_have_full_privs();

	pristr = use_priority_str ? prio2str(priority) : NULL;
	
	if (!entity)
		entity = *cl_log_entity	? cl_log_entity : DFLT_ENTITY;

	if (needprivs) {
		return_to_orig_privs();
	}
	
	if (syslog_enabled) {
		snprintf(common_log_entity, MAXENTITY, "%s",
			*cl_log_syslogprefix ? cl_log_syslogprefix : entity);

		/* The extra trailing '\0' is supposed to work around some
		 * "known syslog bug that ends up concatinating entries".
		 * Knowledge about which syslog package, version, platform and
		 * what exactly the bug was has been lost, but leaving it in
		 * won't do any harm either. */
		syslog(priority, "%s[%d]: %s%s%s%c",
			*cl_log_syslogprefix ? entity : "",
			entity_pid,
			pristr ?: "",  pristr ? ": " : "",
			buf, 0);
	}

	maybe_reopen_log_files(logfile_name, debugfile_name);

	if (debug_file.fp)
		append_log(debug_file.fp, entity, entity_pid, ts, pristr, buf);

	if (priority != LOG_DEBUG && log_file.fp)
		append_log(log_file.fp, entity, entity_pid, ts, pristr, buf);

	if (needprivs) {
		return_to_dropped_privs();
	}
	return;
}

void cl_log_do_fflush(int do_fsync)
{
	if (log_file.fp) {
		fflush(log_file.fp);
		if (do_fsync)
			fsync(fileno(log_file.fp));
	}
	if (debug_file.fp) {
		fflush(debug_file.fp);
		if (do_fsync)
			fsync(fileno(debug_file.fp));
	}
}

/*
 * This function can cost us realtime unless use_logging_daemon
 * is enabled.  Then we log everything through a child process using
 * non-blocking IPC.
 */

static int	cl_log_depth = 0;

/* Cluster logging function */
void
cl_log(int priority, const char * fmt, ...)
{
	va_list		ap;
	char		buf[MAXLINE];
	ssize_t		nbytes;

	cl_process_pid = (int)getpid();

	cl_log_depth++;

	buf[MAXLINE-1] = EOS;
	va_start(ap, fmt);
	nbytes=vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	
	if (nbytes >= (ssize_t)sizeof(buf)){
		nbytes =  sizeof(buf) -1 ;
	}

	if (stderr_enabled) {
		append_log(stderr, cl_log_entity,cl_process_pid,
			NULLTIME, prio2str(priority), buf);
	}

	if (stdout_enabled) {
		append_log(stdout, cl_log_entity,cl_process_pid,
			NULLTIME, prio2str(priority), buf);
	}

	if (use_logging_daemon && cl_log_depth <= 1) {
		LogToLoggingDaemon(priority, buf, nbytes, TRUE);
	}else{
		/* this may cause blocking... maybe should make it optional? */ 
		cl_direct_log(priority, buf, TRUE, NULL, cl_process_pid, NULLTIME);
	}
	
	cl_log_depth--;
	return;
}

/*
 * Log a message only if there were not too many messages of this
 * kind recently. This is too prevent log spamming in case a
 * condition persists over a long period of time. The maximum
 * number of messages for the timeframe and other details are
 * provided in struct logspam (see cl_log.h).
 *
 * Implementation details:
 * - max number of time_t slots is allocated; slots keep time
 *   stamps of previous max number of messages
 * - we check if the difference between now (i.e. new message just
 *   arrived) and the oldest message is _less_ than the window
 *   timeframe
 * - it's up to the user to do cl_limit_log_new and afterwards
 *   cl_limit_log_destroy, though the latter is usually not
 *   necessary; the memory allocated with cl_limit_log_new stays
 *   constant during the lifetime of the process
 *
 * NB on Thu Aug  4 15:26:49 CEST 2011:
 * This interface is very new, use with caution and report bugs.
 */

struct msg_ctrl *
cl_limit_log_new(struct logspam *lspam)
{
	struct msg_ctrl *ml;

	ml = (struct msg_ctrl *)malloc(sizeof(struct msg_ctrl));
	if (!ml) {
		cl_log(LOG_ERR, "%s:%d: out of memory"
			, __FUNCTION__, __LINE__);
		return NULL;
	}
	ml->msg_slots = (time_t *)calloc(lspam->max, sizeof(time_t));
	if (!ml->msg_slots) {
		cl_log(LOG_ERR, "%s:%d: out of memory"
			, __FUNCTION__, __LINE__);
		return NULL;
	}
	ml->lspam = lspam;
	cl_limit_log_reset(ml);
	return ml; /* to be passed later to cl_limit_log() */
}

void
cl_limit_log_destroy(struct msg_ctrl *ml)
{
	if (!ml)
		return;
	g_free(ml->msg_slots);
	g_free(ml);
}

void
cl_limit_log_reset(struct msg_ctrl *ml)
{
	ml->last = -1;
	ml->cnt = 0;
	ml->suppress_t = (time_t)0;
	memset(ml->msg_slots, 0, ml->lspam->max * sizeof(time_t));
}

static void
cl_limit_log_update(struct msg_ctrl *ml, time_t ts)
{
	ml->last = (ml->last + 1) % ml->lspam->max;
	*(ml->msg_slots + ml->last) = ts;
	if (ml->cnt < ml->lspam->max)
		ml->cnt++;
}

void
cl_limit_log(struct msg_ctrl *ml, int priority, const char * fmt, ...)
{
	va_list ap;
	char buf[MAXLINE];
	time_t last_ts, now = time(NULL);

	if (!ml)
		goto log_msg;
	if (ml->suppress_t) {
		if ((now - ml->suppress_t) < ml->lspam->reset_time)
			return;
		/* message blocking expired */
		cl_limit_log_reset(ml);
	}
	last_ts = ml->last != -1 ? *(ml->msg_slots + ml->last) : (time_t)0;
	if (
		ml->cnt < ml->lspam->max || /* not so many messages logged */
		(now - last_ts) > ml->lspam->window /* messages far apart */
	) {
		cl_limit_log_update(ml, now);
		goto log_msg;
	} else {
		cl_log(LOG_INFO
			, "'%s' messages logged too often, "
			"suppressing messages of this kind for %ld seconds"
			, ml->lspam->id, ml->lspam->reset_time);
		cl_log(priority, "%s", ml->lspam->advice);
		ml->suppress_t = now;
		return;
	}

log_msg:
	va_start(ap, fmt);
	vsnprintf(buf, MAXLINE, fmt, ap);
	va_end(ap);
	cl_log(priority, "%s", buf);
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
static char *
syslog_timestamp(TIME_T t)
{
	static char		ts[64];
	struct tm*		ttm;
	TIME_T			now;
	time_t			nowtt;
	static const char*	monthstr [12] = {
		"Jan", "Feb", "Mar",
		"Apr", "May", "Jun",
		"Jul", "Aug", "Sep",
		"Oct", "Nov", "Dec"
	};
	
	/* Work around various weridnesses in different OSes and time_t definitions */
	if (t == 0){
		now = time(NULL);
	}else{
		now = t;
	}

	nowtt = (time_t)now;
	ttm = localtime(&nowtt);

	snprintf(ts, sizeof(ts), "%3s %02d %02d:%02d:%02d"
	,	monthstr[ttm->tm_mon], ttm->tm_mday
	,	ttm->tm_hour, ttm->tm_min, ttm->tm_sec);
	return(ts);
}



char *
ha_timestamp(TIME_T t)
{
	static char ts[64];
	struct tm*	ttm;
	TIME_T		now;
	time_t		nowtt;
	
	/* Work around various weridnesses in different OSes and time_t definitions */
	if (t == 0){
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


static int
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
		if (!logging_chan_in_main_loop){
			chan->ops->destroy(chan);
		}
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
LogToDaemon(int priority, const char * buf, 
	    int bufstrlen, gboolean use_pri_str)
{
	int rc;
	
	cl_log_depth++;

	rc= LogToLoggingDaemon(priority, buf, bufstrlen, use_pri_str);
	
	cl_log_depth--;
	
	return rc;
}

static int		drop_msg_num = 0;

void
cl_flush_logs(void) 
{
	if(logging_daemon_chan == NULL) {
		return;
	}
	logging_daemon_chan->ops->waitout(logging_daemon_chan);
}

static int
LogToLoggingDaemon(int priority, const char * buf, 
		   int bufstrlen, gboolean use_pri_str)
{
	IPC_Channel*		chan = logging_daemon_chan;
	static longclock_t	nexttime = 0;
	IPC_Message*		msg;
	int			sendrc = IPC_FAIL;
	int			intval = conn_logd_time;
	
	/* make sure we don't hold file descriptors open
	 * we don't intend to use again */
	cl_log_close_log_files();

	if (chan == NULL) {
		longclock_t	lnow = time_longclock();
		
		if (cmp_longclock(lnow,  nexttime) >= 0){
			nexttime = add_longclock(
				lnow,  msto_longclock(intval));
			
			logging_daemon_chan = chan = create_logging_channel();
		}
	}

	if (chan == NULL){
		cl_direct_log(
			priority, buf, TRUE, NULL, cl_process_pid, NULLTIME);
		return HA_FAIL;
	}

	msg = ChildLogIPCMessage(priority, buf, bufstrlen, use_pri_str, chan);	
	if (msg == NULL) {
		drop_msg_num++;
		return HA_FAIL;
	}
	
	if (chan->ch_status == IPC_CONNECT){		
		
		if (chan->ops->is_sending_blocked(chan)) {
			chan->ops->resume_io(chan);
		}
		/* Make sure there is room for the drop message _and_ the
		 * one we wish to log.  Otherwise there is no point.
		 *
		 * Try to avoid bouncing on the limit by additionally
		 * waiting until there is room for QUEUE_SATURATION_FUZZ
		 * messages.
		 */
		if (drop_msg_num > 0
		    && chan->send_queue->current_qlen
		    < (chan->send_queue->max_qlen -1 -QUEUE_SATURATION_FUZZ))
		{
			/* have to send it this way so the order is correct */
			send_dropped_message(use_pri_str, chan);
		}
	
		/* Don't log a debug message if we're
		 * approaching the queue limit and already
		 * dropped a message
		 */
		if (drop_msg_num == 0
		    || chan->send_queue->current_qlen <
		      (chan->send_queue->max_qlen -1 -QUEUE_SATURATION_FUZZ)
		    || priority != LOG_DEBUG )
		{
			sendrc =  chan->ops->send(chan, msg);
		}
	}

	if (sendrc == IPC_OK) {
		return HA_OK;
		
	} else {
		
		if (chan->ops->get_chan_status(chan) != IPC_CONNECT) {
			if (!logging_chan_in_main_loop){
				chan->ops->destroy(chan);
			}
			logging_daemon_chan = NULL;
			cl_direct_log(priority, buf, TRUE, NULL, cl_process_pid, NULLTIME);

			if (drop_msg_num > 0){
				/* Direct logging here is ok since we're
				 *    switching to that for everything
				 *    "for a while"
				 */
				cl_log(LOG_ERR,
				       "cl_log: %d messages were dropped"
				       " : channel destroyed", drop_msg_num);
			}
			
			drop_msg_num=0;
			FreeChildLogIPCMessage(msg);
			return HA_FAIL;
		}

		drop_msg_num++;

	}
	
	FreeChildLogIPCMessage(msg);
	return HA_FAIL;
}


static gboolean
send_dropped_message(gboolean use_pri_str, IPC_Channel *chan)
{
	int sendrc;
	char buf[64];
	int buf_len = 0;
	IPC_Message *drop_msg = NULL;

	memset(buf, 0, 64);
	snprintf(buf, 64, "cl_log: %d messages were dropped", drop_msg_num);
	buf_len = strlen(buf)+1;
	drop_msg = ChildLogIPCMessage(LOG_ERR, buf, buf_len, use_pri_str, chan);

	if(drop_msg == NULL || drop_msg->msg_len == 0) {
		return FALSE;
	}
	
	sendrc = chan->ops->send(chan, drop_msg);

	if(sendrc == IPC_OK) {
		drop_msg_num = 0;
	}else{
		FreeChildLogIPCMessage(drop_msg);
	}
	return sendrc == IPC_OK;
}


static IPC_Message*
ChildLogIPCMessage(int priority, const char *buf, int bufstrlen, 
		   gboolean use_prio_str, IPC_Channel* ch)
{
	IPC_Message*	ret;
	LogDaemonMsgHdr	logbuf;
	int		msglen;
	char*		bodybuf;
	
	
	if (ch->msgpad > MAX_MSGPAD){
		cl_log(LOG_ERR, "ChildLogIPCMessage: invalid msgpad(%d)",
		       ch->msgpad);
		return NULL;
	}


	ret = (IPC_Message*)malloc(sizeof(IPC_Message));

	if (ret == NULL) {
		return ret;
	}
	
	memset(ret, 0, sizeof(IPC_Message));
	
	/* Compute msg len: including room for the EOS byte */
	msglen = sizeof(LogDaemonMsgHdr)+bufstrlen + 1;
	bodybuf = malloc(msglen + ch->msgpad);
	if (bodybuf == NULL) {
		free(ret);
		return NULL;
	}
	
	memset(bodybuf, 0, msglen + ch->msgpad);
	memset(&logbuf, 0, sizeof(logbuf));
	logbuf.msgtype = LD_LOGIT;
	logbuf.facility = cl_log_facility;
	logbuf.priority = priority;
	logbuf.use_pri_str = use_prio_str;
	logbuf.entity_pid = getpid();
	logbuf.timestamp = time(NULL);
	if (*cl_log_entity){
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


static void
FreeChildLogIPCMessage(IPC_Message* msg)
{
	if (msg == NULL) {
		return;
	}
	memset(msg->msg_body, 0, msg->msg_len);
	free(msg->msg_buf);
	
	memset(msg, 0, sizeof (*msg));
	free(msg);
		
	return;

}



static void
cl_opensyslog(void)
{
	if (*cl_log_entity == '\0' || cl_log_facility < 0) {
		return;
	}
	syslog_enabled = 1;
	strncpy(common_log_entity, cl_log_entity, MAXENTITY);
	openlog(common_log_entity, LOG_CONS, cl_log_facility);
}


void
cl_log_args(int argc, char **argv)
{
	int lpc = 0;
	int len = 0;
	int existing_len = 0;
	char *arg_string = NULL;

	if(argc == 0 || argv == NULL) {
	    return;
	}
	
	for(;lpc < argc; lpc++) {
		if(argv[lpc] == NULL) {
			break;
		}
		
		len = 2 + strlen(argv[lpc]); /* +1 space, +1 EOS */
		if(arg_string) {
			existing_len = strlen(arg_string);
		}

		arg_string = realloc(arg_string, len + existing_len);
		sprintf(arg_string + existing_len, "%s ", argv[lpc]);
	}
	cl_log(LOG_INFO, "Invoked: %s", arg_string);
	free(arg_string);
}
