/* $Id: cl_log.h,v 1.6 2005/01/26 13:58:13 andrew Exp $ */
#ifndef _CLPLUMBING_CL_LOG_H
#	define _CLPLUMBING_CL_LOG_H
#	include <glib.h>
#	include <syslog.h>

#define	HA_FAIL		0
#define	HA_OK		1

void		cl_direct_log(int priority, char* buf, gboolean);
void            cl_log(int priority, const char * fmt, ...) G_GNUC_PRINTF(2,3);
void            cl_perror(const char * fmt, ...) G_GNUC_PRINTF(1,2);
void		cl_log_enable_stderr(int truefalse);
int		cl_set_logging_wqueue_maxlen(int);
void		cl_log_send_to_logging_daemon(int truefalse);
void		cl_log_set_facility(int facility);
void		cl_log_set_entity(const char *	entity);
void		cl_log_set_logfile(const char *	path);
void		cl_log_set_debugfile(const char * path);
const char *    cl_log_get_debugfile(void);

void		cl_glib_msg_handler(const gchar *log_domain
,		GLogLevelFlags log_level, const gchar *message
,		gpointer user_data);
#endif
