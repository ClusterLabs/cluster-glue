/* $Id: cl_log.h,v 1.3 2004/02/17 22:11:58 lars Exp $ */
#ifndef _CLPLUMBING_CL_LOG_H
#	define _CLPLUMBING_CL_LOG_H
#	include <glib.h>
#	include <syslog.h>
void            cl_log(int priority, const char * fmt, ...) G_GNUC_PRINTF(2,3);
void            cl_perror(const char * fmt, ...) G_GNUC_PRINTF(1,2);
void		cl_log_enable_stderr(int truefalse);
void		cl_log_send_to_logging_daemon(int truefalse);
void		cl_log_set_facility(int facility);
void		cl_log_set_entity(const char *	entity);
void		cl_log_set_logfile(const char *	path);
void		cl_log_set_debugfile(const char * path);

void		cl_glib_msg_handler(const gchar *log_domain
,		GLogLevelFlags log_level, const gchar *message
,		gpointer user_data);
#endif
