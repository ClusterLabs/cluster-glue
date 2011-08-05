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

#ifndef _CLPLUMBING_CL_LOG_H
#	define _CLPLUMBING_CL_LOG_H
#	include <glib.h>
#	include <syslog.h>

#define TIME_T  unsigned long
#define	HA_FAIL		0
#define	HA_OK		1
#define	MAXLINE		(512*10)

/* this is defined by the caller */
struct logspam {
	const char *id; /* identifier */
	int max; /* maximum number of messages ... */
	time_t window; /* ... within this timeframe */
	time_t reset_time; /* log new messages after this time */
	const char *advice; /* what to log in case messages get suppressed */
};

/* this is internal (oblique to the caller) */
struct msg_ctrl {
	struct logspam *lspam; /*  */
	time_t *msg_slots; /* msg slot root (space for lspam->max) */
	int last; /* last used msg slot [0..lspam->max-1]; -1 on init */
	int cnt; /* current msg count [0..lspam->max] */
	time_t suppress_t; /* messages blocked since this time */
};

struct IPC_CHANNEL;

extern int		debug_level;
#define	ANYDEBUG	(debug_level)
#define	DEBUGDETAILS	(debug_level >= 2)
#define	DEBUGAUTH	(debug_level >=3)
#define	DEBUGMODULE	(debug_level >=3)
#define	DEBUGPKT	(debug_level >= 4)
#define	DEBUGPKTCONT	(debug_level >= 5)

void		cl_direct_log(int priority, const char* buf, gboolean, const char*, int, TIME_T);
void            cl_log(int priority, const char * fmt, ...) G_GNUC_PRINTF(2,3);
void            cl_limit_log(struct msg_ctrl *ml, int priority, const char * fmt, ...) G_GNUC_PRINTF(3,4);
struct msg_ctrl *cl_limit_log_new(struct logspam *lspam);
void            cl_limit_log_destroy(struct msg_ctrl *ml);
void            cl_limit_log_reset(struct msg_ctrl *ml);
void            cl_perror(const char * fmt, ...) G_GNUC_PRINTF(1,2);
void		cl_log_enable_stderr(int truefalse);
void		cl_log_enable_stdout(int truefalse);
gboolean	cl_log_test_logd(void);
void		cl_log_set_uselogd(int truefalse);
void		cl_log_enable_syslog_filefmt(int truefalse);
void		cl_log_use_buffered_io(int truefalse);
gboolean	cl_log_get_uselogd(void);
void		cl_log_set_facility(int facility);
void		cl_log_set_entity(const char *	entity);
void		cl_log_set_syslogprefix(const char *prefix);
void		cl_log_set_logfile(const char *	path);
void		cl_log_set_debugfile(const char * path);
void		cl_inherit_logging_environment(int maxqlen);
int		cl_log_set_logd_channel_source( void (*create_callback)(struct IPC_CHANNEL* chan),
						GDestroyNotify destroy_callback);
int		cl_log_get_logdtime(void);
void		cl_log_set_logdtime(int logdintval);

char *		ha_timestamp(TIME_T t);
void		cl_glib_msg_handler(const gchar *log_domain
,		GLogLevelFlags log_level, const gchar *message
,		gpointer user_data);

void		cl_flush_logs(void);
void		cl_log_args(int argc, char **argv);
int		cl_log_is_logd_fd(int fd);
const char *	prio2str(int priority);

/* cl_log_use_buffered_io and cl_log_do_fflush as optimization for logd,
 * so it may buffer a few message lines, then fflush them out in one write.
 * Set do_fsync != 0, if you even want it to fsync. */
void            cl_log_do_fflush(int do_fsync);
void            cl_log_use_buffered_io(int truefalse);
/* We now keep the file handles open for a potentially very long time.
 * Sometimes we may need to close them explicitly. */
void            cl_log_close_log_files(void);

#endif
